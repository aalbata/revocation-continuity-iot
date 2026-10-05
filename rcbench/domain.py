"""Edge domain service: gateway, enforcement loop, and command executor.

The gateway verifies presentations with the selected verification stack,
exchanges credentials and peer tokens for local access tokens, and provisions
broker sessions. The executor subscribes to the command topics of the domain's
broker and represents the protected application: a command counts as executed
only when the executor accepts it.

Usage: python -m rcbench.domain <config.json> <domain> [restarted]
"""
import json
import os
import queue
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import paho.mqtt.client as mqtt
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from paho.mqtt.enums import CallbackAPIVersion

from . import di, tokens, vc
from .broker import DynsecAdmin
from .core import DomainCore, DurableStore, Io, Store
from .events import EventLog
from .net import LinkDown, Links, serve
from .policy import Policy, refresh_interval

TICK = 0.2
BREAKER = 1.0


class LiveIo(Io):
    def __init__(self, service):
        self.s = service
        self.down_until = {}
        self.verified = {}
        self.roles = set()
        self.removals = queue.Queue()
        threading.Thread(target=self._remove_loop, daemon=True).start()

    def fetch_lists(self, issuer: str):
        s = self.s
        if time.time() < self.down_until.get(issuer, 0.0):
            return None
        port = s.issuer_ports[issuer]
        try:
            return s.links.call(s.name, "status_fetch", f"http://127.0.0.1:{port}/status")["lists"]
        except (LinkDown, OSError):
            self.down_until[issuer] = time.time() + BREAKER
            return None

    def verify_list(self, credential: dict) -> bool:
        key = (credential.get("proof") or {}).get("proofValue")
        if key in self.verified:
            return self.verified[key]
        s = self.s
        result = s.verify(credential, lambda docs: s.verifier.verify_credential(credential, docs, s.now()))
        if len(self.verified) > 5000:
            self.verified.clear()
        self.verified[key] = result["verified"]
        return result["verified"]

    def provision(self, session: dict) -> None:
        role = "dev-" + session["dev"]
        if role not in self.roles:
            acl = {"acltype": "publishClientSend", "topic": session["topic"], "allow": True}
            self.s.admin.create_role(role, [acl])
            self.roles.add(role)
        start = time.perf_counter()
        self.s.admin.create_client(session["username"], session["password"], role)
        self.s.log("broker_admin", kind="create", ms=(time.perf_counter() - start) * 1000.0)

    def unprovision(self, session: dict) -> None:
        """Queue the broker removal. The caller has already removed the session from the decision state."""
        self.removals.put((session, time.perf_counter()))

    def _remove_loop(self) -> None:
        while True:
            session, queued = self.removals.get()
            start = time.perf_counter()
            try:
                self.s.admin.delete_client(session["username"])
                done = time.perf_counter()
                self.s.log("broker_admin", kind="delete", ms=(done - start) * 1000.0,
                           wait=(start - queued) * 1000.0, sess=session["sid"])
            except TimeoutError:
                self.s.log("error", why="broker_admin_timeout", sess=session["sid"])

    def sign_token(self, claims: dict) -> str:
        return tokens.sign(claims, self.s.key, self.s.name)

    def new_id(self) -> str:
        return uuid.uuid4().hex[:16]


class DomainService:
    def __init__(self, config: dict, name: str, restarted: bool):
        self.config, self.name = config, name
        settings = config["domains"][name]
        self.skew = settings.get("skew", 0.0)
        self.log = EventLog(f"{config['dir']}/events.{name}.jsonl", config, "domain", name)
        self.links = Links(config)
        self.policy = Policy(**config["policy"])
        self.key = tokens.private_key(bytes.fromhex(settings["seed"]))
        self.public = tokens.public_raw(self.key)
        self.peers = {d: bytes.fromhex(v["public"]) for d, v in config["domains"].items()}
        self.issuer_ports = {v["did"]: v["port"] for v in config["issuers"].values()}
        self.documents = {v["did"]: v["document"] for v in config["issuers"].values()}
        self.trust_file = f"{config['dir']}/trust-{name}.json"
        if os.path.exists(self.trust_file):
            with open(self.trust_file, encoding="utf-8") as handle:
                self.documents.update(json.load(handle))
        self.verifier = vc.NodeVerifier(config["node_port"]) if config["stack"] == "node" else vc.PythonVerifier()
        trust = {v["did"]: {"lists": v["lists"], "organizations": [v["organization"]]}
                 for v in config["issuers"].values()}
        store = DurableStore(f"{config['dir']}/{name}.sqlite") if self.policy.persistent else Store()
        self.admin = DynsecAdmin(settings["broker_port"], settings["admin_pw"], name)
        self.io = LiveIo(self)
        self.core = DomainCore(name, self.policy, config["budget"], trust, store, self.io, self.log,
                               config.get("clock_uncertainty", 0.0))
        self.challenges = {}
        self.claims_cache = {}
        self.pool = ThreadPoolExecutor(max_workers=48)
        if restarted:
            provisioned = [u for u in self.admin.list_clients() if u.startswith("s-")]
            self.core.restart(provisioned, self.now())
            if self.policy.restart_sessions != "drop":
                self.io.roles = {"dev-" + d["id"] for d in config["devices"]}
        if self.policy.status_mode != "online":
            self.core.refresh(self.now)
        self.executor = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=f"executor-{name}", protocol=mqtt.MQTTv5)
        self.executor.username_pw_set("executor", settings["executor_pw"])
        self.executor.on_connect = lambda c, u, f, rc, p: c.subscribe(f"rc/{name}/cmd/#", qos=1)
        self.executor.on_message = self.on_command
        self.executor.connect("127.0.0.1", settings["broker_port"])
        self.executor.loop_start()
        serve(settings["gateway_port"], {
            "/challenge": self.challenge, "/present": self._timed("present", self.present),
            "/renew": self._timed("renew", self.renew), "/handover": self._timed("handover", self.handover),
            "/notify": self._timed("notify", self.notify), "/health": lambda body: {"ok": True}})
        self.log("domain_ready", why="restarted" if restarted else "started")

    def now(self) -> float:
        return time.time() + self.skew

    def _timed(self, kind: str, handler):
        """Wrap a route so that its service time is logged."""
        def run(body: dict) -> dict:
            start = time.perf_counter()
            result = handler(body)
            self.log("service", kind=kind, ms=(time.perf_counter() - start) * 1000.0)
            return result
        return run

    # ---- verification with trust anchors ---------------------------------

    def verify(self, signed: dict, call) -> dict:
        """Run a verification after making sure the issuer keys named in the proofs are known.

        The issuer DID documents provisioned in the configuration are the trust anchors. When a proof
        names a verification method that the stored document lacks, the document is resolved again
        from the issuer's pinned endpoint. Resolved documents are written to the domain's trust file
        under every policy, so key rotation is handled the same way in all comparisons.
        """
        start = time.perf_counter()
        embedded = signed.get("verifiableCredential") or []
        for item in [signed] + (embedded if isinstance(embedded, list) else [embedded]):
            method = (item.get("proof") or {}).get("verificationMethod", "")
            issuer = method.split("#", 1)[0]
            known = self.documents.get(issuer)
            if known is None or any(m.get("id") == method for m in known.get("verificationMethod", [])):
                continue
            try:
                url = f"http://127.0.0.1:{self.issuer_ports[issuer]}/.well-known/did.json"
                fresh = self.links.call(self.name, "did_resolve", url)
            except (LinkDown, OSError):
                continue
            if fresh.get("id") == issuer:
                self.documents[issuer] = fresh
                with open(self.trust_file, "w", encoding="utf-8") as handle:
                    json.dump({d: self.documents[d] for d in self.issuer_ports}, handle)
                self.log("did_update", iss=issuer)
        result = call(self.documents)
        result["ms"] = (time.perf_counter() - start) * 1000.0
        return result

    # ---- gateway routes --------------------------------------------------

    def challenge(self, body: dict) -> dict:
        value = uuid.uuid4().hex
        self.challenges[value] = time.time() + 30.0
        if len(self.challenges) > 2000:
            cutoff = time.time()
            self.challenges = {k: v for k, v in self.challenges.items() if v > cutoff}
        return {"challenge": value, "domain": self.name}

    def _take_challenge(self, value) -> bool:
        return self.challenges.pop(value, 0.0) > time.time()

    def present(self, body: dict) -> dict:
        presentation = body["presentation"]
        challenge = (presentation.get("proof") or {}).get("challenge")
        if not self._take_challenge(challenge):
            return {"granted": False, "reason": "challenge"}
        now = self.now()
        result = self.verify(presentation, lambda docs: self.verifier.verify_presentation(
            presentation, docs, challenge, self.name, now))
        credentials = presentation.get("verifiableCredential") or [{}]
        credential = credentials[0] if isinstance(credentials, list) else credentials
        self.log("verify", stack=self.verifier.name, ms=result["ms"], out=result["category"],
                 dev=(credential.get("credentialSubject") or {}).get("deviceId"))
        return self.core.present(result, credential, presentation.get("holder"), body.get("stapled"), now)

    def _possession(self, body: dict, public: bytes):
        """Verify the token signature and the proof of possession by the holder; return the claims or None."""
        claims = tokens.verify(body.get("token", ""), public)
        if claims is None or not self._take_challenge(body.get("challenge")):
            return None
        try:
            holder = di.multibase_to_public(claims["sub"].split(":", 2)[2])
            message = f"{body['challenge']}|{claims['jti']}".encode()
            VerifyKey(holder).verify(message, di.b58decode(body["signature"]))
        except (BadSignatureError, di.ProofError, KeyError, IndexError):
            return None
        return claims

    def renew(self, body: dict) -> dict:
        claims = self._possession(body, self.public)
        if claims is None or claims.get("iss") != self.name:
            return {"granted": False, "reason": "token_invalid"}
        return self.core.renew(claims, body.get("stapled"), self.now())

    def handover(self, body: dict) -> dict:
        peer = self.peers.get(body.get("from"))
        claims = self._possession(body, peer) if peer and body.get("from") != self.name else None
        if claims is None or claims.get("iss") != body.get("from"):
            return {"granted": False, "reason": "token_invalid"}
        return self.core.handover(claims, body.get("stapled"), self.now())

    def notify(self, body: dict) -> dict:
        self.core.on_push(body.get("lists", []), self.now())
        return {"ok": True}

    # ---- executor --------------------------------------------------------

    def on_command(self, client, userdata, message) -> None:
        received = time.time()
        if self.policy.per_op == "online":
            self.pool.submit(self.execute, message, received)
        else:
            self.execute(message, received)

    def execute(self, message, received: float) -> None:
        try:
            payload = json.loads(message.payload)
        except ValueError:
            payload = {}
        token = dict(getattr(message.properties, "UserProperty", None) or []).get("token", "")
        claims = self.claims_cache.get(token)
        if claims is None and token:
            claims = tokens.verify(token, self.public)
            if claims is not None:
                if len(self.claims_cache) > 5000:
                    self.claims_cache.clear()
                self.claims_cache[token] = claims
        began = time.perf_counter()
        reason = self.core.authorize_operation(claims, message.topic, self.now())
        finished = time.perf_counter()
        latency = (finished - payload["sp"]) * 1000.0 if "sp" in payload else None
        self.log("op", dev=payload.get("dev"), n=payload.get("n"), sent=payload.get("sent"), rx=received, lat=latency,
                 svc=(finished - began) * 1000.0,
                 tok=(claims or {}).get("jti"), sess=(claims or {}).get("sid"), cred=(claims or {}).get("src"),
                 topic=message.topic, dec="allow" if reason == "ok" else "deny", why=reason,
                 out="executed" if reason == "ok" else "rejected")

    # ---- loops -----------------------------------------------------------

    def run(self) -> None:
        end = self.config["t0"] + self.config["horizon"] + 2.0
        period = refresh_interval(self.config["budget"])
        next_refresh = time.time() + period
        while time.time() < end:
            time.sleep(TICK)
            self.core.tick(self.now())
            if self.policy.status_mode != "online" and time.time() >= next_refresh:
                next_refresh = time.time() + period
                threading.Thread(target=self.core.refresh, args=(self.now,), daemon=True).start()
        self.log("traffic", bytes=self.links.bytes, calls=self.links.calls)
        self.executor.loop_stop()
        self.admin.close()
        self.log.close()


def main(path: str, name: str, restarted: bool) -> None:
    with open(path, encoding="utf-8") as handle:
        config = json.load(handle)
    DomainService(config, name, restarted).run()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], len(sys.argv) > 3)
