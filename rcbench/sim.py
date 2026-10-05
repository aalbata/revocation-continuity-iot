"""Discrete-event simulation of the benchmark for larger device populations.

The simulator replays the same trace generator as the live prototype and drives
the same decision code (core.DomainCore). Cryptography, the broker, and the
network are replaced by models: a gateway is a first-come first-served queue with
one worker per 100 devices (the largest live configuration has one worker for 100
devices), evidence intake does not wait in that queue, the broker of a domain
executes one administration command at a time, and backhaul calls take the
configured round-trip time. Broker and executor throughput limits for commands are
not modeled. Component times come from a calibration file measured on the live
prototype. Simulated time is model time, not measured throughput.
"""
import heapq
import math
import random
from collections import deque

from .core import DomainCore, Io, Store
from .policy import get as get_policy
from .policy import refresh_interval
from .statuslist import MIN_ENTRIES, Evidence
from .trace import DOMAINS, scenario

DEFAULT_COSTS = {"present": 0.012, "renew": 0.002, "handover": 0.002, "ingest": 0.001, "create": 0.005,
                 "delete": 0.005, "op": 0.0002, "net": 0.001, "restart_gap": 2.5, "fetch_bytes": 2600.0,
                 "push_bytes": 2700.0}
TICK = 0.5
RETRY = 1.0
LIST_REFRESH = 2.0
PROBE = 5.0
DEADLINE = 1.0
OUTAGE_TIMEOUT = 1.0
BREAKER = 1.0
LEAD = 6.0
DEVICES_PER_WORKER = 100
ISSUERS = {"issuer-a": "contractor", "issuer-b": "operator"}


class _Bits:
    __slots__ = ("flags", "length")

    def __init__(self, flags: frozenset):
        self.flags, self.length = flags, MIN_ENTRIES

    def get(self, index: int) -> bool:
        return index in self.flags

    def __eq__(self, other) -> bool:
        return isinstance(other, _Bits) and self.flags == other.flags

    __hash__ = None


class SimIssuer:
    def __init__(self, name: str):
        self.name, self.did = name, f"did:web:{name}.rcbench.test"
        self.lists = {p: f"https://{name}.rcbench.test/status/{p}" for p in ("revocation", "suspension")}
        self.flags = {p: set() for p in self.lists}
        self.sequence = {p: 1 for p in self.lists}
        self.next_index = 0
        self._cache = {}

    def snapshot(self, now: float) -> list:
        """Lists as signed at most a quarter second ago, signed again at once after a status change."""
        out = []
        for purpose, list_id in self.lists.items():
            cached = self._cache.get(purpose)
            if cached is None or cached[0] != self.sequence[purpose] or now - cached[1] > 0.25:
                raw = {"id": list_id, "sim": (self.did, purpose, self.sequence[purpose], now,
                                              frozenset(self.flags[purpose]))}
                cached = (self.sequence[purpose], now, raw)
                self._cache[purpose] = cached
            out.append(cached[2])
        return out


class SimIo(Io):
    def __init__(self, world, domain: str):
        self.w, self.domain = world, domain
        self.start = 0.0
        self.cost = 0.0
        self.delay = 0.0
        self.down_until = {}
        self._parsed = {}

    def begin(self, start: float, base: float) -> None:
        self.start, self.cost, self.delay = start, base, 0.0

    def fetch_lists(self, issuer: str):
        w = self.w
        if w.now < self.down_until.get(issuer, float("-inf")):
            return None
        if not w.link_up(self.domain, w.now):
            self.delay += OUTAGE_TIMEOUT
            self.down_until[issuer] = w.now + OUTAGE_TIMEOUT + BREAKER
            w.traffic["status_fetch_failed"] += 1
            return None
        self.delay += w.rtt
        w.traffic["status_fetch"] += 1
        return w.issuers[issuer].snapshot(w.now)

    def verify_list(self, credential: dict) -> bool:
        return True

    def parse_list(self, raw: dict, now: float, source: str) -> Evidence:
        did, purpose, sequence, stamp, flags = raw["sim"]
        evidence = Evidence.__new__(Evidence)
        evidence.issuer, evidence.list_id, evidence.purpose = did, raw["id"], purpose
        evidence.valid_from, evidence.valid_until, evidence.ttl = stamp, stamp + 300.0, 5.0
        evidence.epoch, evidence.sequence, evidence.covered_through = "sim", sequence, stamp
        evidence.bits = _Bits(flags)
        evidence.received_at, evidence.size_bytes, evidence.source = now, 0, source
        return evidence

    def provision(self, session: dict) -> None:
        """Broker commands of a domain run one at a time. The grant is answered when its session exists,
        and the gateway worker is free again after its own service time."""
        domain = self.w.domains[self.domain]
        served = self.start + self.cost
        ready = max(served, domain.admin_busy_until) + self.w.costs["create"]
        domain.admin_busy_until = ready
        self.delay += ready - served
        self.w.at(ready, self.w.broker_add, self.domain, session["username"])

    def unprovision(self, session: dict) -> None:
        """Removals are queued behind earlier broker commands and do not hold the gateway."""
        domain = self.w.domains[self.domain]
        ready = max(self.w.now, domain.admin_busy_until) + self.w.costs["delete"]
        domain.admin_busy_until = ready
        self.w.at(ready, self.w.broker_remove, self.domain, session["username"])

    def sign_token(self, claims: dict):
        return claims

    def new_id(self) -> str:
        self.w.ids += 1
        return f"{self.w.ids:x}"


class SimDomain:
    def __init__(self, world, name: str):
        self.w, self.name = world, name
        self.io = SimIo(world, name)
        self.store = Store()
        self.clients = {}
        self.queue = deque()
        self.active = 0
        self.admin_busy_until = -1e9
        self.exec_busy_until = 0.0
        self.up = True
        self.generation = 0
        self.core = self._core()

    def _core(self) -> DomainCore:
        w = self.w
        trust = {i.did: {"lists": i.lists, "organizations": [ISSUERS[i.name]]} for i in w.issuers.values()}
        return DomainCore(self.name, w.policy, w.budget, trust, self.store, self.io, w.log)

    def submit(self, kind: str, call, callback) -> None:
        """Queue a gateway job. call(now) runs when the server is free; callback gets its result."""
        if not self.up:
            if callback:
                self.w.at(self.w.now + self.w.costs["net"], callback, None)
            return
        self.queue.append((kind, call, callback, self.generation))
        self.w.peak_queue = max(self.w.peak_queue, len(self.queue))
        self._next()

    def _next(self) -> None:
        w = self.w
        while self.queue and self.active < w.servers:
            kind, call, callback, generation = self.queue.popleft()
            if generation != self.generation:
                if callback:
                    w.at(w.now, callback, None)
                continue
            self.active += 1
            self.io.begin(w.now, w.costs[kind])
            result = call(w.now)
            w.busy_time += self.io.cost
            w.at(w.now + self.io.cost, self._done, generation)
            if callback:
                w.at(w.now + self.io.cost + self.io.delay, callback, result)

    def _done(self, generation: int) -> None:
        if generation == self.generation:
            self.active -= 1
            self._next()


class SimDevice:
    __slots__ = ("spec", "id", "role", "adversarial", "issuer", "credential", "holder", "domain", "session",
                 "old", "lists", "script", "next_attempt", "last_lists", "last_probe", "tried_reconnect",
                 "revoked_at", "suspended", "pending", "phase")

    def __init__(self, spec: dict, issuer: SimIssuer, rng: random.Random):
        self.spec, self.id, self.role = spec, spec["id"], spec["role"]
        self.adversarial, self.issuer = spec["adversarial"], issuer
        entries = []
        for purpose, list_id in issuer.lists.items():
            entries.append({"type": "BitstringStatusListEntry", "statusPurpose": purpose,
                            "statusListIndex": str(issuer.next_index), "statusListCredential": list_id})
        issuer.next_index += 1
        self.holder = "did:key:sim-" + self.id
        self.credential = {"id": "urn:sim:" + self.id, "issuer": issuer.did, "credentialStatus": entries,
                           "credentialSubject": {"id": self.holder, "deviceId": self.id,
                                                 "organization": ISSUERS[issuer.name], "allowedAction": ["command"]}}
        self.domain, self.session, self.old, self.lists = spec["home"], None, [], []
        self.script = sorted(spec["script"], key=lambda e: e["t"])
        self.next_attempt = self.last_lists = self.last_probe = -1e9
        self.tried_reconnect = False
        self.revoked_at, self.suspended, self.pending = None, None, False
        self.phase = rng.uniform(0.0, TICK)


class SimWorld:
    def __init__(self, seed: int, policy_key: str, devices: int = 1000, outage: float = 0.0, budget: float = 30.0,
                 rtt_ms: float = 50.0, failure: str = "shared", costs: dict | None = None,
                 overrides: dict | None = None, servers: int = 0):
        self.costs = dict(DEFAULT_COSTS, **(costs or {}))
        self.servers = servers or max(1, math.ceil(devices / DEVICES_PER_WORKER))
        self.busy_time = 0.0
        self.op_cost = 0.0
        self.policy = get_policy(policy_key, **(overrides or {}))
        self.op_cost = self.costs.get("op_" + self.policy.per_op, self.costs["op"])
        self.budget, self.rtt, self.seed = budget, rtt_ms / 1000.0, seed
        self.trace = scenario(seed, devices, outage, budget, failure)
        self.horizon, self.outages = self.trace["horizon"], self.trace["outages"]
        self.rng = random.Random(seed * 7919 + 13)
        # Warm-up long enough for every device to obtain its first session before observation starts.
        gateway_time = 0.5 * devices * (self.costs["present"] + self.costs["create"]) / self.servers
        broker_time = 0.5 * devices * self.costs["create"]
        self.lead = max(LEAD, 6.0 + 2.5 * max(gateway_time, broker_time))
        self.now, self.heap, self.order, self.ids = -self.lead, [], 0, 0
        self.traffic = {"status_fetch": 0, "status_fetch_failed": 0, "push": 0}
        self.peak_queue = 0
        self.counts = {"grants": 0, "denials": 0, "renewals": 0, "requests": 0}
        self.issuers = {name: SimIssuer(name) for name in ISSUERS}
        self.by_did = {i.did: i for i in self.issuers.values()}
        self.issuers.update(self.by_did)
        self.domains = {name: SimDomain(self, name) for name in DOMAINS}
        self.devices = [SimDevice(s, self.issuers[s["issuer"]], self.rng) for s in self.trace["devices"]]
        self.by_user = {}
        self.stats = {"benign": 0, "completed": 0, "no_session": 0, "rejected": 0, "late": 0, "lost": 0,
                      "attempts": 0, "unauthorized": 0, "suspended_executed": 0, "ops": 0}
        self.latency = [0] * 2002
        self.exposure = {}
        self.last_bad = {}

    # ---- engine ----------------------------------------------------------

    def at(self, time: float, call, *args) -> None:
        self.order += 1
        heapq.heappush(self.heap, (time, self.order, call, args))

    def log(self, ev: str, **fields) -> None:
        if ev == "grant" and self.now >= 0.0:
            self.counts["requests"] += 1
            if fields.get("dec") == "allow":
                self.counts["grants"] += 1
                if fields.get("kind") == "renew":
                    self.counts["renewals"] += 1
            else:
                self.counts["denials"] += 1

    def link_up(self, domain: str, t: float) -> bool:
        return not any(o["start"] <= t < o["end"] and domain in o["domains"] for o in self.outages)

    def broker_add(self, domain: str, username: str) -> None:
        self.domains[domain].clients[username] = True

    def broker_remove(self, domain: str, username: str) -> None:
        self.domains[domain].clients.pop(username, None)

    # ---- issuers and domains ---------------------------------------------

    def change(self, event: dict) -> None:
        device = next(d for d in self.devices if d.id == event["device"])
        issuer = device.issuer
        purpose = "revocation" if event["action"] == "revoke" else "suspension"
        index = int(device.credential["credentialStatus"][0]["statusListIndex"])
        if event["action"] == "reinstate":
            issuer.flags[purpose].discard(index)
            device.suspended[1] = self.now
        else:
            issuer.flags[purpose].add(index)
            if event["action"] == "revoke":
                device.revoked_at = self.now
            else:
                device.suspended = [self.now, float("inf")]
        issuer.sequence[purpose] += 1
        snapshot = issuer.snapshot(self.now)
        for name in DOMAINS:
            self.at(self.now + self.rtt / 2 + self.rng.uniform(0.0, 0.3), self.push, name, issuer, snapshot)

    def push(self, name: str, issuer: SimIssuer, snapshot) -> None:
        if not self.link_up(name, self.now):
            self.at(self.now + 0.5 + OUTAGE_TIMEOUT, self.push, name, issuer, None)
            return
        if not self.domains[name].up:
            self.at(self.now + 0.5, self.push, name, issuer, None)
            return
        lists = snapshot or issuer.snapshot(self.now)
        domain = self.domains[name]
        self.traffic["push"] += 1
        self._intake(domain, lambda now: domain.core.on_push(lists, now))

    def _intake(self, domain: SimDomain, call) -> None:
        """Evidence intake runs on its own thread in the prototype and does not wait behind token requests."""
        if domain.up:
            domain.io.begin(self.now + self.costs["ingest"], 0.0)
            call(self.now + self.costs["ingest"])

    def refresh(self, name: str) -> None:
        domain = self.domains[name]
        if domain.up and self.link_up(name, self.now):
            for issuer in self.by_did.values():
                lists = issuer.snapshot(self.now)
                self.traffic["status_fetch"] += 1
                self.at(self.now + self.rtt, self._ingest, domain, lists, domain.generation)
        elif domain.up:
            self.traffic["status_fetch_failed"] += len(self.by_did)
        self.at(self.now + refresh_interval(self.budget), self.refresh, name)

    def _ingest(self, domain: SimDomain, lists: list, generation: int) -> None:
        if generation == domain.generation:
            self._intake(domain, lambda now: [domain.core.ingest(raw, "fetch", now) for raw in lists])

    def tick(self, name: str) -> None:
        domain = self.domains[name]
        if domain.up:
            domain.io.begin(self.now, 0.0)
            domain.core.tick(self.now)
        self.at(self.now + 0.2, self.tick, name)

    def restart(self, name: str) -> None:
        domain = self.domains[name]
        domain.up, domain.generation, domain.active = False, domain.generation + 1, 0
        while domain.queue:
            callback = domain.queue.popleft()[2]
            if callback:
                self.at(self.now, callback, None)
        self.at(self.now + self.costs["restart_gap"], self._restarted, name)

    def _restarted(self, name: str) -> None:
        domain = self.domains[name]
        if not self.policy.persistent:
            domain.store = Store()
        domain.io.down_until = {}
        domain.core = domain._core()
        domain.io.begin(self.now, 0.0)
        domain.core.restart(list(domain.clients), self.now)
        if self.policy.status_mode != "online" and self.link_up(name, self.now):
            # As in the prototype, the gateway refreshes its lists before it serves requests again.
            for issuer in self.by_did.values():
                lists = issuer.snapshot(self.now)
                self.traffic["status_fetch"] += 1
                for raw in lists:
                    domain.core.ingest(raw, "fetch", self.now)
            self.at(self.now + self.rtt * len(self.by_did), self._serve, domain)
        else:
            domain.up = True

    def _serve(self, domain: SimDomain) -> None:
        domain.up = True

    # ---- devices ---------------------------------------------------------

    def connected(self, session) -> bool:
        return session is not None and session["username"] in self.domains[session["domain"]].clients

    def request(self, device: SimDevice, kind: str, target: str, then) -> None:
        domain = self.domains[target]
        lists = device.lists
        if kind == "present":
            call = lambda now: domain.core.present({"verified": True}, device.credential, device.holder, lists, now)
        elif kind == "renew":
            claims = device.session["claims"]
            call = lambda now: domain.core.renew(claims, lists, now)
        else:
            claims = device.session["claims"]
            call = lambda now: domain.core.handover(claims, lists, now)
        device.pending = True

        def done(result):
            device.pending = False
            then(result if result is not None else {"granted": False})

        self.at(self.now + self.costs["net"], domain.submit, kind, call, done)

    def adopt(self, device: SimDevice, target: str, grant: dict) -> None:
        previous = device.session
        device.session = {"domain": target, "username": grant["username"], "claims": grant["token"]}
        device.domain, device.tried_reconnect = target, False
        if previous is not None and previous["domain"] != target and device.adversarial:
            device.old.append(previous)

    def recover(self, device: SimDevice) -> None:
        session = device.session
        if session is not None and session["domain"] == device.domain:
            if not device.tried_reconnect:
                device.tried_reconnect = True
                if self.connected(session):
                    return
            if self.now < session["claims"]["exp"]:
                def renewed(grant):
                    if grant.get("granted"):
                        session["claims"] = grant["token"]
                        if self.connected(session):
                            device.tried_reconnect = False
                            return
                    self.request(device, "present", device.domain,
                                 lambda g: g.get("granted") and self.adopt(device, device.domain, g))
                self.request(device, "renew", device.domain, renewed)
                return
        self.request(device, "present", device.domain,
                     lambda g: g.get("granted") and self.adopt(device, device.domain, g))

    def handover(self, device: SimDevice, target: str) -> None:
        def moved(grant):
            if grant.get("granted"):
                self.adopt(device, target, grant)
                return
            previous = device.session
            if previous is not None and device.adversarial:
                device.old.append(previous)
            device.session, device.domain = None, target

        def exchanged(grant):
            if grant.get("granted"):
                self.adopt(device, target, grant)
            else:
                self.request(device, "present", target, moved)

        if device.session is not None and device.session["domain"] == device.domain:
            self.request(device, "handover", target, exchanged)
        else:
            self.request(device, "present", target, moved)

    def operation(self, device: SimDevice, session: dict, sent: float) -> None:
        """Deliver one command to the executor of the session's domain and record the outcome."""
        domain = self.domains[session["domain"]]
        stats = self.stats
        commit = None
        if device.revoked_at is not None and sent >= device.revoked_at:
            commit = device.revoked_at
        elif device.suspended is not None and device.suspended[0] <= sent < device.suspended[1]:
            commit = device.suspended[0]
        benign = commit is None and not device.adversarial
        if not domain.up:
            if benign:
                stats["lost"] += 1
            return
        claims = session["claims"]
        topic = f"rc/{session['domain']}/cmd/{device.id}"
        if self.policy.per_op == "online":
            done = sent + self.costs["net"] + self.op_cost
            domain.io.begin(self.now, 0.0)
            reason = domain.core.authorize_operation(claims, topic, self.now)
            done += domain.io.delay
        else:
            start = max(sent + self.costs["net"], domain.exec_busy_until)
            done = start + self.op_cost
            domain.exec_busy_until = done
            reason = domain.core.authorize_operation(claims, topic, done)
        stats["ops"] += 1
        if commit is not None:
            if reason == "ok" and device.revoked_at is not None:
                stats["unauthorized"] += 1
                self.exposure[device.id] = max(self.exposure.get(device.id, 0.0), done - commit)
                self.last_bad[device.id] = done
            elif reason == "ok":
                stats["suspended_executed"] += 1
        elif benign:
            if reason != "ok":
                stats["rejected"] += 1
            elif done - sent > DEADLINE:
                stats["late"] += 1
            else:
                stats["completed"] += 1
                self.latency[min(2001, int((done - sent) * 1000.0))] += 1

    def device_tick(self, device: SimDevice) -> None:
        now = self.now
        if now + TICK < self.horizon:
            self.at(now + TICK, self.device_tick, device)
        if device.pending:
            pass
        else:
            while device.script and device.script[0]["t"] <= now:
                self.handover(device, device.script.pop(0)["to"])
                break
        if now - device.last_lists >= LIST_REFRESH and self.link_up(device.domain, now):
            device.last_lists = now
            lists = device.issuer.snapshot(now)
            if device.adversarial and device.lists:
                index = int(device.credential["credentialStatus"][0]["statusListIndex"])
                lists = [old if index in new["sim"][4] else new for old, new in zip(device.lists, lists)]
            device.lists = lists
        session = device.session
        live = self.connected(session)
        if not device.pending and now - device.next_attempt >= RETRY:
            if not live:
                device.next_attempt = now
                self.recover(device)
            else:
                claims = session["claims"]
                if claims["exp"] - now < max(2.0, 0.2 * (claims["exp"] - claims["iat"])):
                    device.next_attempt = now

                    def renewed(grant, session=session):
                        if grant.get("granted"):
                            session["claims"] = grant["token"]
                    self.request(device, "renew", device.domain, renewed)
        if now < 0:
            return
        unauthorized = (device.revoked_at is not None and now >= device.revoked_at) or \
            (device.suspended is not None and device.suspended[0] <= now < device.suspended[1])
        if unauthorized and device.revoked_at is not None:
            self.stats["attempts"] += 1
        elif not unauthorized and not device.adversarial:
            self.stats["benign"] += 1
        if live:
            self.operation(device, session, now)
        elif not unauthorized and not device.adversarial:
            self.stats["no_session"] += 1
        if device.adversarial and now - device.last_probe >= PROBE:
            device.last_probe = now
            if live and unauthorized:
                self.stats["attempts"] += 1
            for old in device.old:
                if device.revoked_at is not None and now >= device.revoked_at:
                    self.stats["attempts"] += 1
                if self.connected(old):
                    self.operation(device, old, now)

    # ---- run -------------------------------------------------------------

    def run(self) -> dict:
        spread = max(0.0, self.lead - 4.0)
        for device in self.devices:
            first = -self.lead + 0.5 + self.rng.uniform(0.0, spread)
            self.at(first - (first % TICK) + device.phase, self.device_tick, device)
        for name in DOMAINS:
            if self.policy.status_mode != "online":
                self.at(-self.lead + 0.1, self.refresh, name)
            self.at(-self.lead + 0.2, self.tick, name)
        for event in self.trace["events"]:
            if event["type"] == "change":
                self.at(event["t"], self.change, event)
            elif event["type"] == "restart":
                self.at(event["t"], self.restart, event["domain"])
        heap = self.heap
        while heap:
            time, _, call, args = heapq.heappop(heap)
            if time > self.horizon:
                break
            self.now = time
            call(*args)
        return self.result()

    def result(self) -> dict:
        s = self.stats
        revoked = [d for d in self.devices if d.revoked_at is not None]
        total = sum(self.latency)

        def quantile(q: float):
            if not total:
                return None
            seen, target = 0, q * total
            for ms, count in enumerate(self.latency):
                seen += count
                if seen >= target:
                    return float(ms)
            return None

        calls = self.traffic
        return {
            "seed": self.seed, "policy": self.policy.key, "devices": len(self.devices), "budget": self.budget,
            "rtt_ms": self.rtt * 1000.0, "outage": self.outages[0]["end"] - self.outages[0]["start"] if self.outages else 0.0,
            "security": {
                "exposure_max": max(self.exposure.values(), default=0.0),
                "exposure_mean": sum(self.exposure.get(d.id, 0.0) for d in revoked) / len(revoked) if revoked else 0.0,
                "unauthorized_executed": s["unauthorized"], "attempts": s["attempts"],
                "unauthorized_fraction": s["unauthorized"] / s["attempts"] if s["attempts"] else 0.0,
                "censored": any(self.horizon - t < 1.5 for t in self.last_bad.values())},
            "availability": {
                "benign_requests": s["benign"], "completed": s["completed"],
                "completion": s["completed"] / s["benign"] if s["benign"] else None,
                "failures": {k: s[k] for k in ("no_session", "rejected", "late", "lost")},
                "latency_ms_median": quantile(0.5), "latency_ms_p95": quantile(0.95)},
            "cost": {
                "backhaul_bytes": calls["status_fetch"] * self.costs["fetch_bytes"] + calls["push"] * self.costs["push_bytes"],
                "calls": dict(calls), "renewals": self.counts["renewals"], "grants": self.counts["grants"],
                "token_requests": self.counts["requests"], "peak_gateway_queue": self.peak_queue,
                "gateway_servers": self.servers,
                "gateway_utilization": self.busy_time / (3 * self.servers * (self.horizon + self.lead)),
                "operations": s["ops"]},
        }


def simulate(seed: int, policy: str, **settings) -> dict:
    return SimWorld(seed, policy, **settings).run()


if __name__ == "__main__":
    import json
    import sys
    import time as clock
    began = clock.time()
    out = simulate(int(sys.argv[3]) if len(sys.argv) > 3 else 1, sys.argv[1], devices=int(sys.argv[2]),
                   outage=float(sys.argv[4]) if len(sys.argv) > 4 else 0.0)
    out["wall_seconds"] = clock.time() - began
    print(json.dumps(out, indent=1))
