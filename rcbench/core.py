"""Gateway and executor decision logic of an edge domain.

DomainCore holds every authorization decision of the benchmark: evidence
intake, token issuance for presentations, renewals and handovers, session
enforcement, and the check made when a protected command is about to execute.
It performs no input or output itself. The live prototype and the simulator
both drive this class through the small Io interface, so they apply identical
rules.
"""
import json
import os
import sqlite3
import threading

from .policy import POLICY_VERSION, Policy
from .statuslist import Evidence, StatusError


class Io:
    """Operations that DomainCore delegates to its environment."""

    def fetch_lists(self, issuer: str):
        """Return the issuer's current status list credentials, or None when unreachable."""
        raise NotImplementedError

    def verify_list(self, credential: dict) -> bool:
        raise NotImplementedError

    def provision(self, session: dict) -> None:
        raise NotImplementedError

    def unprovision(self, session: dict) -> None:
        raise NotImplementedError

    def sign_token(self, claims: dict) -> str:
        raise NotImplementedError

    def new_id(self) -> str:
        raise NotImplementedError

    def parse_list(self, raw: dict, now: float, source: str) -> Evidence:
        """Turn a verified status list credential into evidence."""
        return Evidence(raw, now, len(json.dumps(raw)), source)


class Store:
    """Volatile domain state: accepted evidence, high-water marks, and sessions."""

    def __init__(self):
        self.evidence = {}
        self.marks = {}
        self.sessions = {}

    def put_evidence(self, evidence: Evidence, raw: dict, mark: tuple) -> None:
        self.evidence[evidence.list_id] = evidence
        self.marks[evidence.list_id] = mark

    def put_session(self, session: dict) -> None:
        self.sessions[session["sid"]] = session

    def drop_session(self, sid: str) -> None:
        self.sessions.pop(sid, None)


class DurableStore(Store):
    """State written through to SQLite so that it survives a process restart."""

    def __init__(self, path: str):
        super().__init__()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS kv (space TEXT, key TEXT, value TEXT, PRIMARY KEY (space, key))")
        for space, key, value in self._db.execute("SELECT space, key, value FROM kv").fetchall():
            item = json.loads(value)
            if space == "evidence":
                self.evidence[key] = Evidence(item["raw"], item["received_at"], item["size"], item["source"])
                self.marks[key] = tuple(item["mark"])
            elif space == "session":
                self.sessions[key] = item

    def _write(self, space: str, key: str, value) -> None:
        with self._lock:
            if value is None:
                self._db.execute("DELETE FROM kv WHERE space=? AND key=?", (space, key))
            else:
                self._db.execute("INSERT OR REPLACE INTO kv VALUES (?,?,?)", (space, key, json.dumps(value)))

    def put_evidence(self, evidence: Evidence, raw: dict, mark: tuple) -> None:
        super().put_evidence(evidence, raw, mark)
        self._write("evidence", evidence.list_id, {"raw": raw, "received_at": evidence.received_at,
                                                    "size": evidence.size_bytes, "source": evidence.source,
                                                    "mark": list(mark)})

    def put_session(self, session: dict) -> None:
        super().put_session(session)
        self._write("session", session["sid"], session)

    def drop_session(self, sid: str) -> None:
        super().drop_session(sid)
        self._write("session", sid, None)


class DomainCore:
    def __init__(self, name: str, policy: Policy, budget: float, trust: dict, store: Store, io: Io, log,
                 clock_uncertainty: float = 0.0):
        """trust maps an issuer DID to {"lists": {purpose: list_id}, "organizations": [..]}."""
        self.name = name
        self.policy = policy
        self.budget = budget
        self.trust = trust
        self.store = store
        self.io = io
        self.log = log
        self.clock_uncertainty = clock_uncertainty
        self.lock = threading.RLock()
        self._last_reauth = 0.0
        self._list_owner = {lid: did for did, t in trust.items() for lid in t["lists"].values()}

    # ---- evidence -------------------------------------------------------

    def _origin(self, evidence: Evidence) -> float:
        if self.policy.use_coverage and evidence.covered_through is not None:
            return evidence.covered_through
        return evidence.valid_from

    def _mark(self, evidence: Evidence) -> tuple:
        if self.policy.use_coverage and evidence.epoch is not None:
            return (evidence.epoch, evidence.sequence, evidence.covered_through)
        return ("", 0, evidence.valid_from)

    def evidence_deadline(self, evidence: Evidence) -> float:
        """Latest time at which the evidence may still support an authorization."""
        if self.policy.status_mode == "origin":
            return min(evidence.valid_until, self._origin(evidence) + self.budget - self.clock_uncertainty)
        return min(evidence.valid_until, evidence.received_at + self.budget)

    def ingest(self, raw: dict, source: str, now: float) -> str:
        """Verify one status list credential and store it if it is acceptable."""
        with self.lock:
            list_id = raw.get("id") if isinstance(raw, dict) else None
            owner = self._list_owner.get(list_id)
            if owner is None:
                outcome = "rejected_authority"
            elif source == "stapled" and not self.policy.accept_stapled:
                outcome = "rejected_source"
            elif not self.io.verify_list(raw):
                outcome = "rejected_proof"
            else:
                outcome = self._store_evidence(raw, owner, source, now)
            if outcome != "rejected_source" and (outcome != "accepted" or source != "fetch"):
                self.log("evidence", source=source, outcome=outcome, list=list_id,
                         evd=_ref(self.store.evidence.get(list_id)) if outcome == "accepted" else None)
            return outcome

    def _store_evidence(self, raw: dict, owner: str, source: str, now: float) -> str:
        try:
            evidence = self.io.parse_list(raw, now, source)
        except (StatusError, KeyError, TypeError, ValueError):
            return "rejected_malformed"
        if evidence.issuer != owner or self.trust[owner]["lists"].get(evidence.purpose) != evidence.list_id:
            return "rejected_authority"
        if evidence.valid_from > now + self.clock_uncertainty + 1.0:
            return "rejected_not_yet_valid"
        if evidence.valid_until < now:
            return "rejected_expired"
        mark = self._mark(evidence)
        previous = self.store.marks.get(evidence.list_id)
        if self.policy.monotonic_evidence and previous is not None:
            if mark[0] != previous[0]:
                return "rejected_epoch"
            if mark[1:] < tuple(previous[1:]):
                return "rejected_older"
        replaced = self.store.evidence.get(evidence.list_id)
        self.store.put_evidence(evidence, raw, mark)
        # Sessions need a new look only when the content of the list differs from the list it replaces.
        if self.policy.revoke_live_sessions and (replaced is None or replaced.bits != evidence.bits):
            for session in list(self.store.sessions.values()):
                reason = self._status_reason(session["entries"])
                if reason:
                    self._kill(session, reason, now)
        return "accepted"

    def refresh(self, clock) -> None:
        """Fetch current lists from every trusted issuer; unreachable issuers are skipped."""
        for issuer in self.trust:
            raws = self.io.fetch_lists(issuer)
            for raw in raws or []:
                self.ingest(raw, "fetch", clock())

    def on_push(self, raws: list, now: float) -> None:
        if self.policy.push:
            for raw in raws:
                self.ingest(raw, "push", now)

    def _status_reason(self, entries: list) -> str:
        """Return revoked or suspended if current evidence sets a bit for these entries."""
        for entry in entries:
            evidence = self.store.evidence.get(entry.get("statusListCredential"))
            if evidence is not None:
                try:
                    if evidence.status(entry):
                        return "revoked" if entry["statusPurpose"] == "revocation" else "suspended"
                except StatusError:
                    return "status_error"
        return ""

    def _gather(self, issuer: str, entries: list, stapled: list, now: float):
        """Take stapled evidence and fetch lists when needed. Fetching may block, so the lock is not held."""
        if self.policy.status_mode == "online":
            return self.io.fetch_lists(issuer)
        with self.lock:
            for raw in stapled or []:
                self.ingest(raw, "stapled", now)
            if self._usable(entries, now) == "ok":
                return []
        return self.io.fetch_lists(issuer) or []

    def _check_status(self, entries: list, fetched, now: float):
        """Decide whether status evidence supports a new grant. Returns (reason, deadline, references)."""
        if fetched is None:
            return "status_unreachable", 0.0, []
        outcomes = [self.ingest(raw, "fetch", now) for raw in fetched]
        if self.policy.status_mode == "online" and (not outcomes or any(o != "accepted" for o in outcomes)):
            return "status_unverified", 0.0, []
        state = self._usable(entries, now)
        if state != "ok":
            return state, 0.0, []
        reason = self._status_reason(entries)
        if reason:
            return reason, 0.0, []
        used = [self.store.evidence[e["statusListCredential"]] for e in entries]
        return "ok", min(self.evidence_deadline(e) for e in used), [_ref(e) for e in used]

    def _usable(self, entries: list, now: float) -> str:
        if not entries:
            return "evidence_unknown"
        for entry in entries:
            evidence = self.store.evidence.get(entry.get("statusListCredential"))
            if evidence is None:
                return "evidence_unknown"
            if now > self.evidence_deadline(evidence):
                return "evidence_stale"
        return "ok"

    # ---- grants ---------------------------------------------------------

    def present(self, verification: dict, credential: dict, holder: str, stapled: list, now: float) -> dict:
        """Handle a verified presentation of a device credential."""
        subject = credential.get("credentialSubject", {})
        issuer = credential["issuer"] if isinstance(credential.get("issuer"), str) else credential["issuer"]["id"]
        base = dict(kind="present", dev=subject.get("deviceId"), cred=credential.get("id"), iss=issuer)
        if not verification.get("verified"):
            return self._deny("credential_" + verification.get("category", "error").lower(), now, **base)
        trusted = self.trust.get(issuer)
        if trusted is None or subject.get("organization") not in trusted["organizations"]:
            return self._deny("untrusted_issuer", now, **base)
        if subject.get("id") != holder:
            return self._deny("holder_mismatch", now, **base)
        actions = subject.get("allowedAction", [])
        if "command" not in (actions if isinstance(actions, list) else [actions]):
            return self._deny("action_not_allowed", now, **base)
        entries = credential.get("credentialStatus", [])
        entries = entries if isinstance(entries, list) else [entries]
        owned = set(trusted["lists"].values())
        if not entries or any(e.get("statusListCredential") not in owned for e in entries):
            return self._deny("status_authority", now, **base)
        fetched = self._gather(issuer, entries, stapled, now)
        with self.lock:
            reason, ev_deadline, refs = self._check_status(entries, fetched, now)
            if reason != "ok":
                return self._deny(reason, now, **base)
            lineage = dict(dev=subject["deviceId"], holder=holder, cred=credential["id"], iss=issuer, entries=entries,
                           cred_until=_ts(credential.get("validUntil")))
            return self._grant("present", lineage, ev_deadline, refs, None, now)

    def renew(self, claims: dict, stapled: list, now: float) -> dict:
        """Handle a renewal request that carries a token issued by this domain."""
        base = dict(kind="renew", dev=claims.get("dev"), cred=claims.get("src"), iss=claims.get("src_iss"),
                    tok=claims.get("jti"))
        if claims.get("sid") not in self.store.sessions:
            return self._deny("unknown_session", now, **base)
        if now > claims["exp"]:
            return self._deny("token_expired", now, **base)
        fetched = self._gather(claims["src_iss"], claims["st"], stapled, now)
        with self.lock:
            session = self.store.sessions.get(claims.get("sid"))
            if session is None:
                return self._deny("unknown_session", now, **base)
            reason, ev_deadline, refs = self._check_status(claims["st"], fetched, now)
            if reason != "ok":
                return self._deny(reason, now, **base)
            lineage = dict(dev=claims["dev"], holder=claims["sub"], cred=claims["src"], iss=claims["src_iss"],
                           entries=claims["st"], cred_until=claims["cu"])
            return self._grant("renew", lineage, ev_deadline, refs, claims, now, session)

    def handover(self, claims: dict, stapled: list, now: float) -> dict:
        """Handle a token exchange that carries a token issued by a federated peer domain."""
        base = dict(kind="handover", dev=claims.get("dev"), cred=claims.get("src"), iss=claims.get("src_iss"),
                    tok=claims.get("jti"))
        trusted = self.trust.get(claims.get("src_iss"))
        if trusted is None:
            return self._deny("untrusted_issuer", now, **base)
        if now > claims["exp"]:
            return self._deny("token_expired", now, **base)
        owned = set(trusted["lists"].values())
        if any(e.get("statusListCredential") not in owned for e in claims["st"]):
            return self._deny("status_authority", now, **base)
        fetched = self._gather(claims["src_iss"], claims["st"], stapled, now)
        with self.lock:
            reason, ev_deadline, refs = self._check_status(claims["st"], fetched, now)
            if reason != "ok":
                return self._deny(reason, now, **base)
            lineage = dict(dev=claims["dev"], holder=claims["sub"], cred=claims["src"], iss=claims["src_iss"],
                           entries=claims["st"], cred_until=claims["cu"])
            return self._grant("handover", lineage, ev_deadline, refs, claims, now)

    def _grant(self, kind, lineage, ev_deadline, refs, parent, now, session=None) -> dict:
        policy = self.policy
        deadline = min(now + policy.token_lifetime, lineage["cred_until"])
        if policy.inherit_deadline:
            deadline = min(deadline, ev_deadline)
            if parent is not None and not _fresher(refs, parent.get("ev", [])):
                deadline = min(deadline, parent["dl"])
        if deadline <= now:
            return self._deny("deadline_passed", now, kind=kind, dev=lineage["dev"], cred=lineage["cred"],
                              iss=lineage["iss"])
        token_id = self.io.new_id()
        if session is None:
            session = dict(sid=token_id, username="s-" + token_id, password=self.io.new_id(), dev=lineage["dev"],
                           cred=lineage["cred"], iss=lineage["iss"], entries=lineage["entries"],
                           topic=f"rc/{self.name}/cmd/{lineage['dev']}", created=now, root=token_id)
            fresh = True
        else:
            fresh = False
        lifetime = policy.session_lifetime
        session["deadline"] = (session["created"] + lifetime) if lifetime else deadline
        session["token_deadline"] = deadline
        claims = {"iss": self.name, "sub": lineage["holder"], "aud": "mqtt:" + self.name, "jti": token_id,
                  "sid": session["sid"], "iat": now, "exp": deadline, "dl": deadline, "act": "publish",
                  "topic": session["topic"], "pv": POLICY_VERSION, "pol": policy.key, "dev": lineage["dev"],
                  "src": lineage["cred"], "src_iss": lineage["iss"], "st": lineage["entries"],
                  "cu": lineage["cred_until"], "ev": refs,
                  "par": parent["jti"] if parent else None,
                  "root": (parent.get("root") or parent["jti"]) if parent else token_id}
        if fresh:
            self.io.provision(session)
        self.store.put_session(session)
        token = self.io.sign_token(claims)
        self.log("grant", kind=kind, dev=lineage["dev"], cred=lineage["cred"], iss=lineage["iss"], tok=token_id,
                 sess=session["sid"], par=claims["par"], dl=deadline, evd=refs, dec="allow", why="ok")
        return {"granted": True, "token": token, "username": session["username"], "password": session["password"],
                "deadline": deadline, "topic": session["topic"], "session": session["sid"]}

    def _deny(self, reason: str, now: float, **fields) -> dict:
        self.log("grant", dec="deny", why=reason, **fields)
        return {"granted": False, "reason": reason}

    # ---- sessions and operations ----------------------------------------

    def _kill(self, session: dict, reason: str, now: float) -> None:
        self.store.drop_session(session["sid"])
        self.io.unprovision(session)
        self.log("session_end", sess=session["sid"], dev=session["dev"], cred=session["cred"], iss=session["iss"],
                 why=reason)

    def tick(self, now: float) -> None:
        """Enforce session deadlines and run the periodic session recheck."""
        with self.lock:
            policy = self.policy
            if policy.enforce_session_expiry:
                for session in list(self.store.sessions.values()):
                    if now >= session["deadline"]:
                        self._kill(session, "deadline", now)
            if policy.reauth_interval and now - self._last_reauth >= policy.reauth_interval:
                self._last_reauth = now
                for session in list(self.store.sessions.values()):
                    reason = self._status_reason(session["entries"])
                    if reason:
                        self._kill(session, reason, now)

    def authorize_operation(self, claims, topic: str, now: float) -> str:
        """Decide whether a received command may execute. Returns ok or a denial reason."""
        mode = self.policy.per_op
        if mode == "none":
            return "ok"
        if claims is None:
            return "token_invalid"
        if claims.get("topic") != topic or claims.get("aud") != "mqtt:" + self.name:
            return "scope"
        if now > claims["exp"]:
            return "token_expired"
        if mode == "token":
            return "ok"
        if mode == "online":
            raws = self.io.fetch_lists(claims["src_iss"])
            if raws is None:
                return "status_unreachable"
            with self.lock:
                outcomes = [self.ingest(raw, "fetch", now) for raw in raws]
                if not outcomes or any(o != "accepted" for o in outcomes):
                    return "status_unverified"
                return self._status_reason(claims["st"]) or "ok"
        with self.lock:
            session = self.store.sessions.get(claims.get("sid"))
            if session is None:
                return "no_session"
            if now > claims["dl"]:
                return "deadline"
            return self._status_reason(claims["st"]) or "ok"

    def restart(self, provisioned: list, now: float) -> None:
        """Reconcile broker sessions with the state available after a process restart."""
        with self.lock:
            mode = self.policy.restart_sessions
            known = {s["username"] for s in self.store.sessions.values()}
            for username in provisioned:
                if mode == "drop" or (mode == "restore" and username not in known):
                    self.io.unprovision({"username": username, "sid": username[2:]})
            self.log("restart", why=mode, n=len(self.store.sessions))


def _ref(evidence) -> dict | None:
    if evidence is None:
        return None
    return {"list": evidence.list_id, "epoch": evidence.epoch, "seq": evidence.sequence,
            "ct": evidence.covered_through, "vf": evidence.valid_from, "src": evidence.source}


def _fresher(refs: list, parent_refs: list) -> bool:
    """True when every list reference is strictly newer than the parent's reference to the same list."""
    old = {r["list"]: r for r in parent_refs or []}
    if not refs or not old:
        return False
    for ref in refs:
        prior = old.get(ref["list"])
        if prior is None:
            return False
        key_new = (ref["ct"] if ref["ct"] is not None else ref["vf"])
        key_old = (prior["ct"] if prior["ct"] is not None else prior["vf"])
        if ref.get("epoch") != prior.get("epoch") or key_new <= key_old:
            return False
    return True


def _ts(text) -> float:
    from .di import from_timestamp
    return from_timestamp(text) if text else float("inf")
