"""Per-run measures computed from the event logs.

Ground truth comes from the issuers: a command is unauthorized when it was sent
at or after the commit of a revocation of its device credential, or inside a
suspension interval. Commands sent before a commit but executed after it are
counted separately as in flight. The run is the unit of analysis; nothing here
pools messages across runs.
"""
import glob
import json
import os

from .events import read_events

DEADLINE = 1.0
CENSOR_WINDOW = 1.5


def _percentile(values: list, q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def run_metrics(run_dir: str) -> dict:
    """Return the measures of one run, or a failure record if the run is unusable."""
    with open(os.path.join(run_dir, "config.json"), encoding="utf-8") as handle:
        config = json.load(handle)
    record_path = os.path.join(run_dir, "record.json")
    record = json.load(open(record_path, encoding="utf-8")) if os.path.exists(record_path) else {"failed": True}
    out = {"run": config["run_id"], "seed": config["seed"], "policy": config["policy"]["key"],
           "config": config["config_id"], "outage": config["outage"], "budget": config["budget"],
           "rtt_ms": config["rtt_ms"], "devices": len(config["devices"]), "stack": config["stack"],
           "failure": config["failure"], "failed": bool(record.get("failed")), "errors": record.get("errors", [])}
    if out["failed"]:
        return out
    events = read_events(glob.glob(os.path.join(run_dir, "events.*.jsonl")))
    t0, end = config["t0"], config["t0"] + config["horizon"]
    roles = {e["dev"]: e for e in events if e["ev"] == "credential"}
    revoked, suspended = {}, {}
    for e in events:
        if e["ev"] == "revocation_commit":
            revoked[e["dev"]] = e["commit"]
        elif e["ev"] == "suspension_commit":
            suspended[e["dev"]] = [e["commit"], float("inf")]
        elif e["ev"] == "reinstatement_commit":
            suspended[e["dev"]][1] = e["commit"]

    def unauthorized(dev: str, t: float) -> bool:
        if dev in revoked and t >= revoked[dev]:
            return True
        return dev in suspended and suspended[dev][0] <= t < suspended[dev][1]

    def commit_of(dev: str) -> float:
        return revoked[dev] if dev in revoked else suspended[dev][0]

    ops = [e for e in events if e["ev"] == "op" and e.get("dev") in roles and e.get("sent") is not None]
    sends = [e for e in events if e["ev"] == "send" and t0 <= e["ts"] < end]
    executed = {(e["dev"], e["n"]): e for e in ops if e["out"] == "executed"}

    per_device = {}
    for dev in list(revoked) + [d for d in suspended if d not in revoked]:
        commit = commit_of(dev)
        mine = [e for e in ops if e["dev"] == dev]
        bad_exec = [e for e in mine if e["out"] == "executed" and unauthorized(dev, e["sent"])]
        bad_admit = [e for e in mine if unauthorized(dev, e["sent"])]
        in_flight = [e for e in mine if e["out"] == "executed" and e["sent"] < commit <= e["ts"]]
        attempts = [e for e in sends if e["dev"] == dev and unauthorized(dev, e["ts"])]
        last_exec = max((e["ts"] for e in bad_exec), default=None)
        limit = end if dev in revoked else min(end, suspended[dev][1])
        per_device[dev] = {
            "role": roles[dev]["role"], "kind": "revoked" if dev in revoked else "suspended",
            "commit": commit - t0,
            "exposure_exec": (last_exec - commit) if last_exec else 0.0,
            "exposure_admit": max((e["rx"] - commit for e in bad_admit), default=0.0),
            "unauthorized_executed": len(bad_exec), "unauthorized_admitted": len(bad_admit),
            "in_flight_executed": len(in_flight), "attempts": len(attempts),
            "censored": bool(last_exec and limit - last_exec < CENSOR_WINDOW),
            "old_session_executed": sum(1 for e in bad_exec if e["dom"] != _domain_at(sends, dev, e["sent"])),
        }
    rev = [v for v in per_device.values() if v["kind"] == "revoked"]
    sus = [v for v in per_device.values() if v["kind"] == "suspended"]
    attempts = sum(v["attempts"] for v in rev)
    out["security"] = {
        "exposure_max": max((v["exposure_exec"] for v in rev), default=0.0),
        "exposure_mean": sum(v["exposure_exec"] for v in rev) / len(rev) if rev else 0.0,
        "exposure_admit_max": max((v["exposure_admit"] for v in rev), default=0.0),
        "unauthorized_executed": sum(v["unauthorized_executed"] for v in rev),
        "unauthorized_admitted": sum(v["unauthorized_admitted"] for v in rev),
        "in_flight_executed": sum(v["in_flight_executed"] for v in rev),
        "attempts": attempts,
        "unauthorized_fraction": sum(v["unauthorized_executed"] for v in rev) / attempts if attempts else 0.0,
        "censored": any(v["censored"] for v in rev),
        "suspension_exposure_max": max((v["exposure_exec"] for v in sus), default=0.0),
        "by_role": {role: max(v["exposure_exec"] for v in per_device.values() if v["role"] == role)
                    for role in sorted({v["role"] for v in per_device.values()})},
    }

    benign = [e for e in sends if e.get("kind") == "command" and not roles[e["dev"]]["adversarial"]
              and not unauthorized(e["dev"], e["ts"])]
    done, latency, reasons = 0, [], {}
    rejected = {(e["dev"], e["n"]): e["why"] for e in ops if e["out"] == "rejected"}
    denied = {(e["dev"], e["n"]) for e in events if e["ev"] == "puback_denied"}
    phases = {"before": [0, 0], "during": [0, 0], "after": [0, 0]}
    window = config["outages"][0] if config["outages"] else None
    for e in benign:
        key = (e["dev"], e["n"])
        hit = executed.get(key)
        took = None if hit is None else hit.get("lat", (hit["ts"] - hit["sent"]) * 1000.0)
        ok = hit is not None and took <= DEADLINE * 1000.0
        rel = e["ts"] - t0
        phase = "before" if (window is None or rel < window["start"]) else ("during" if rel < window["end"] else "after")
        phases[phase][0] += 1
        if ok:
            done += 1
            phases[phase][1] += 1
            latency.append(took)
        else:
            if e["out"] == "no_session":
                why = "no_session"
            elif key in denied:
                why = "broker_denied"
            elif key in rejected:
                why = "executor_" + rejected[key]
            elif hit is not None:
                why = "late"
            else:
                why = "lost"
            reasons[why] = reasons.get(why, 0) + 1
    requests = [e for e in events if e["ev"] == "request" and not roles[e["dev"]]["adversarial"]]
    out["availability"] = {
        "benign_requests": len(benign), "completed": done,
        "completion": done / len(benign) if benign else None,
        "failures": reasons,
        "completion_by_phase": {k: (v[1] / v[0] if v[0] else None) for k, v in phases.items()},
        "latency_ms_median": _percentile(latency, 0.5), "latency_ms_p95": _percentile(latency, 0.95),
        "token_requests": len(requests),
        "token_denials": sum(1 for e in requests if e["dec"] == "deny"),
        "token_request_ms_median": _percentile([e["ms"] for e in requests], 0.5),
        "token_request_ms_p95": _percentile([e["ms"] for e in requests], 0.95),
    }

    traffic_bytes, traffic_calls = {}, {}
    for e in events:
        if e["ev"] == "traffic":
            for k, v in e["bytes"].items():
                traffic_bytes[k] = traffic_bytes.get(k, 0) + v
            for k, v in e["calls"].items():
                traffic_calls[k] = traffic_calls.get(k, 0) + v
    grants = [e for e in events if e["ev"] == "grant"]
    decisions = len(ops) + len(grants)
    verify = [e["ms"] for e in events if e["ev"] == "verify"]
    out["cost"] = {
        "backhaul_bytes": sum(traffic_bytes.values()), "bytes_by_category": traffic_bytes,
        "calls": traffic_calls, "decisions": decisions,
        "bytes_per_decision": sum(traffic_bytes.values()) / decisions if decisions else None,
        "renewals": sum(1 for e in grants if e.get("kind") == "renew" and e["dec"] == "allow"),
        "grants": sum(1 for e in grants if e["dec"] == "allow"),
        "operations_per_second": len(ops) / config["horizon"],
        "verify_ms_median": _percentile(verify, 0.5), "verify_ms_p95": _percentile(verify, 0.95),
        "memory_mb": {k: v / 1e6 for k, v in record.get("memory_bytes", {}).items()},
        "push_rejected_older": sum(1 for e in events if e["ev"] == "evidence" and e.get("source") == "push"
                                   and e.get("outcome") == "rejected_older"),
        "stapled_rejected_older": sum(1 for e in events if e["ev"] == "evidence" and e.get("source") == "stapled"
                                      and e.get("outcome") == "rejected_older"),
        "errors": sum(1 for e in events if e["ev"] == "error"),
    }
    out["devices_detail"] = per_device
    return out


def _domain_at(sends: list, dev: str, t: float) -> str | None:
    """Domain in which the device was publishing commands at time t."""
    current = None
    for e in sends:
        if e["dev"] == dev and e.get("kind") == "command":
            if e["ts"] > t + 0.5:
                break
            current = e["dom"]
    return current


if __name__ == "__main__":
    import sys
    result = run_metrics(sys.argv[1])
    detail = result.pop("devices_detail", {})
    print(json.dumps(result, indent=1))
    for dev, row in sorted(detail.items()):
        print(dev, json.dumps(row))
