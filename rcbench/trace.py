"""Lifecycle traces.

A trace is generated from a seed and the world settings only, never from the
policy, so every policy replays the same devices, event times, and outage
windows for a given seed. Times are seconds from the start of the observation
window.

Each block of ten devices contains five benign devices and five devices whose
credentials are revoked:

  stay_a, stay_b      benign, remain in the home domain
  move_a, move_b      benign, hand over to another domain
  suspended           benign, suspended and reinstated ten seconds later
  r_stay              revoked while holding a live session
  r_after             revoked, then hands over
  r_during            revoked while a handover is in progress
  r_before            hands over, then is revoked
  r_restart           revoked before the outage; the domain it stays in then restarts. In a
                      ten-device run no other holder of the same issuer visits that domain;
                      larger runs have several such devices there, revoked at different times
"""
import hashlib
import random

DOMAINS = ["building", "contractor", "provider"]
OUTAGE_START = 16.0
TOKEN_REFERENCE = 60.0

ROLES = [
    ("stay_a", "issuer-a", "contractor", False),
    ("move_a", "issuer-a", "contractor", False),
    ("stay_b", "issuer-b", "building", False),
    ("move_b", "issuer-b", "building", False),
    ("suspended", "issuer-a", "contractor", False),
    ("r_stay", "issuer-b", "building", True),
    ("r_after", "issuer-a", "contractor", True),
    ("r_during", "issuer-b", "building", True),
    ("r_before", "issuer-a", "contractor", True),
    ("r_restart", "issuer-a", "building", True),
]


def horizon(outage: float, budget: float) -> float:
    """Observation length that covers the latest bounded exposure and the recovery after an outage."""
    if outage <= 0:
        return 30.0 + TOKEN_REFERENCE
    return max(30.0 + TOKEN_REFERENCE, OUTAGE_START + min(outage, budget) + TOKEN_REFERENCE + 6.0,
               OUTAGE_START + outage + 15.0)


def scenario(seed: int, devices: int = 10, outage: float = 0.0, budget: float = 30.0,
             failure: str = "shared") -> dict:
    rng = random.Random(seed)
    t_first = 10.0 + rng.uniform(0.0, 2.0)
    t_main = 20.0 + rng.uniform(0.0, 2.0)
    specs, events = [], []
    for i in range(devices):
        role, issuer, home, adversarial = ROLES[i % 10]
        ident = f"d{i:03d}"
        jitter = rng.uniform(0.0, 1.5)
        spec = {"id": ident, "issuer": issuer, "home": home, "role": role, "adversarial": adversarial,
                "seed": hashlib.sha256(f"{seed}:{ident}".encode()).hexdigest(), "script": [],
                "other": f"d{(i + 1) % devices:03d}"}
        if role == "move_a":
            spec["script"].append({"t": 24.0 + jitter, "type": "handover", "to": "provider"})
        elif role == "move_b":
            spec["script"].append({"t": 12.0 + jitter, "type": "handover", "to": "provider"})
        elif role == "suspended":
            events.append({"t": t_main + 1.0 + jitter, "type": "change", "action": "suspend", "device": ident})
            events.append({"t": t_main + 11.0 + jitter, "type": "change", "action": "reinstate", "device": ident})
        elif role == "r_stay":
            events.append({"t": t_main + jitter, "type": "change", "action": "revoke", "device": ident})
        elif role == "r_after":
            events.append({"t": t_main + jitter, "type": "change", "action": "revoke", "device": ident})
            spec["script"].append({"t": t_main + jitter + 3.0, "type": "handover", "to": "provider"})
        elif role == "r_during":
            events.append({"t": t_main + jitter, "type": "change", "action": "revoke", "device": ident})
            spec["script"].append({"t": t_main + jitter - 0.3, "type": "handover", "to": "provider"})
        elif role == "r_before":
            events.append({"t": t_main + jitter, "type": "change", "action": "revoke", "device": ident})
            spec["script"].append({"t": t_main + jitter - 6.0, "type": "handover", "to": "provider"})
        elif role == "r_restart":
            events.append({"t": t_first + jitter, "type": "change", "action": "revoke", "device": ident})
        specs.append(spec)
    for event in events:
        event["issuer"] = next(s["issuer"] for s in specs if s["id"] == event["device"])
    events.append({"t": 6.0 + rng.uniform(0.0, 1.0), "type": "rotate", "issuer": "issuer-b"})
    events.append({"t": 18.0 + rng.uniform(0.0, 1.0), "type": "restart", "domain": "building"})
    events.sort(key=lambda e: e["t"])
    outages = []
    if outage > 0:
        affected = DOMAINS if failure == "shared" else ["provider"]
        outages.append({"start": OUTAGE_START, "end": OUTAGE_START + outage, "domains": affected})
    return {"devices": specs, "events": events, "outages": outages, "horizon": horizon(outage, budget)}
