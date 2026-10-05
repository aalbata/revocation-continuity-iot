"""Credential issuer services.

One process hosts the two issuers of a run. Each issuer has its own key, DID
document, status lists, and HTTP port; they share no state. An issuer is the
only authority for the status of its credentials. A revocation index is never
reused, and only suspension can be reversed.

Usage: python -m rcbench.issuer <config.json>
"""
import hashlib
import json
import random
import sys
import threading
import time

from . import di, vc
from .events import EventLog
from .net import LinkDown, Links, http_json, serve
from .statuslist import MIN_ENTRIES, Bitstring, list_credential, status_entry

RESIGN_INTERVAL = 0.25
PURPOSES = ("revocation", "suspension")


def list_id(host: str, purpose: str) -> str:
    return f"https://{host}/status/{purpose}"


class Issuer:
    def __init__(self, name: str, settings: dict, config: dict, links: Links, log: EventLog):
        self.name, self.did, self.host = name, settings["did"], settings["host"]
        self.organization = settings["organization"]
        self.config, self.links, self.log = config, links, log
        self.seed = bytes.fromhex(settings["seed"])
        self.keys = [di.KeyPair(self.did, "key-1", hashlib.sha256(self.seed + b"key-1").digest())]
        self.lock = threading.Lock()
        self.bits = {p: Bitstring() for p in PURPOSES}
        self.sequence = {p: 1 for p in PURPOSES}
        self.epoch = hashlib.sha256(self.seed + b"epoch").hexdigest()[:16]
        self.signed = {}
        self.credentials = {}
        self.random = random.Random(int.from_bytes(self.seed[:8], "big"))
        self.used = set()

    def document(self) -> dict:
        methods = [k.method() for k in self.keys]
        ids = [k.id for k in self.keys]
        return {"@context": [di.DID_CONTEXT, di.MULTIKEY_CONTEXT], "id": self.did,
                "verificationMethod": methods, "assertionMethod": ids, "authentication": ids}

    def lists(self) -> list:
        """Return both signed status lists, signed again when older than the re-sign interval."""
        now = time.time()
        with self.lock:
            out = []
            for purpose in PURPOSES:
                cached = self.signed.get(purpose)
                if cached is None or now - cached[0] > RESIGN_INTERVAL:
                    coverage = {"authority": self.did, "epoch": self.epoch, "sequence": self.sequence[purpose],
                                "covered_through": now}
                    unsigned = list_credential(list_id(self.host, purpose), self.did, purpose, self.bits[purpose],
                                               now, now + self.config["list_validity"], 5000, coverage)
                    cached = (now, di.add_proof(unsigned, self.keys[-1], "assertionMethod", now))
                    self.signed[purpose] = cached
                out.append(cached[1])
            return out

    def issue(self, body: dict) -> dict:
        """Issue a device credential with fresh, never reused status indices."""
        now = time.time()
        with self.lock:
            entries = []
            for purpose in PURPOSES:
                index = self.random.randrange(MIN_ENTRIES)
                while (purpose, index) in self.used:
                    index = self.random.randrange(MIN_ENTRIES)
                self.used.add((purpose, index))
                entries.append(status_entry(list_id(self.host, purpose), purpose, index))
            credential_id = "urn:uuid:" + _uuid(self.random)
            unsigned = vc.device_credential(credential_id, self.did, body["holder"], body["device"],
                                            self.organization, ["command"], now - 1.0,
                                            now + self.config["credential_validity"], entries)
            signed = di.add_proof(unsigned, self.keys[-1], "assertionMethod", now)
            self.credentials[body["device"]] = {"id": credential_id, "entries": entries}
        return {"credential": signed}

    def change(self, body: dict) -> dict:
        """Commit a revocation, suspension, or reinstatement and notify the domains."""
        action, device = body["action"], body["device"]
        purpose = "revocation" if action == "revoke" else "suspension"
        record = self.credentials[device]
        entry = next(e for e in record["entries"] if e["statusPurpose"] == purpose)
        with self.lock:
            if action == "reinstate" and purpose != "suspension":
                return {"ok": False}
            self.bits[purpose].set(int(entry["statusListIndex"]), action != "reinstate")
            self.sequence[purpose] += 1
            self.signed.pop(purpose, None)
            commit = time.time()
            sequence = self.sequence[purpose]
        event = {"revoke": "revocation_commit", "suspend": "suspension_commit",
                 "reinstate": "reinstatement_commit"}[action]
        self.log(event, iss=self.did, dev=device, cred=record["id"], commit=commit,
                 evd={"list": entry["statusListCredential"], "epoch": self.epoch, "seq": sequence})
        self._notify(sequence, commit, body.get("push_jitter", 0.0))
        return {"ok": True, "commit": commit}

    def rotate(self, body: dict) -> dict:
        """Add a new signing key to the DID document; the earlier key stays valid for earlier proofs."""
        with self.lock:
            name = f"key-{len(self.keys) + 1}"
            self.keys.append(di.KeyPair(self.did, name, hashlib.sha256(self.seed + name.encode()).digest()))
            self.signed.clear()
        self.log("key_rotation", iss=self.did, key=name)
        return {"ok": True, "key": name}

    def _notify(self, sequence: int, commit: float, jitter: float) -> None:
        snapshot = self.lists()
        for domain, settings in self.config["domains"].items():
            delay = self.random.uniform(0.0, jitter) if jitter else 0.0
            threading.Thread(target=self._push, args=(domain, settings, sequence, commit, delay, snapshot),
                             daemon=True).start()

    def _push(self, domain, settings, sequence, commit, delay, snapshot) -> None:
        """Deliver the lists as of the commit; after a failed attempt, deliver the current lists."""
        url = f"http://127.0.0.1:{settings['gateway_port']}/notify"
        end = self.config["t0"] + self.config["horizon"]
        time.sleep(delay)
        lists = snapshot
        while time.time() < end:
            try:
                lists = lists or self.lists()
                self.links.call(domain, "push", url, {"issuer": self.did, "lists": lists})
                self.log("push_delivered", iss=self.did, dom=domain, seq=sequence, delay=time.time() - commit)
                return
            except (LinkDown, OSError):
                lists = None
                time.sleep(0.5)


def _uuid(rng: random.Random) -> str:
    raw = bytearray(rng.getrandbits(8) for _ in range(16))
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    text = raw.hex()
    return f"{text[:8]}-{text[8:12]}-{text[12:16]}-{text[16:20]}-{text[20:]}"


def main(path: str) -> None:
    with open(path, encoding="utf-8") as handle:
        config = json.load(handle)
    log = EventLog(f"{config['dir']}/events.issuers.jsonl", config, "issuers")
    links = Links(config)
    for name, settings in config["issuers"].items():
        issuer = Issuer(name, settings, config, links, log)
        serve(settings["port"], {
            "/.well-known/did.json": lambda body, i=issuer: i.document(),
            "/status": lambda body, i=issuer: {"lists": i.lists()},
            "/control/issue": lambda body, i=issuer: i.issue(body),
            "/control/change": lambda body, i=issuer: i.change(body),
            "/control/rotate": lambda body, i=issuer: i.rotate(body),
            "/health": lambda body: {"ok": True},
        })
    end = config["t0"] + config["horizon"] + 3.0
    while time.time() < end:
        time.sleep(0.5)
    log("traffic", bytes=links.bytes, calls=links.calls)
    log.close()


if __name__ == "__main__":
    main(sys.argv[1])
