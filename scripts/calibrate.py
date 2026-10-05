"""Measure component times on live runs for use by the simulator.

Reads the compressed event logs of completed live runs and writes
results/calibration.json: medians and 95th percentiles of gateway service time by
request kind, broker administration time, executor check time by enforcement
mode, command delivery time, restart gap, and bytes per backhaul call.

Usage: python scripts/calibrate.py <raw batch folder> [<raw batch folder> ...]
"""
import glob
import gzip
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

MAX_RUNS_PER_CONDITION = 5


def percentile(values: list, q: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def main(folders: list) -> None:
    samples = {}

    def add(name: str, value: float) -> None:
        samples.setdefault(name, []).append(value)

    used = 0
    for folder in folders:
        for condition in sorted(glob.glob(os.path.join(folder, "*"))):
            for run_dir in sorted(glob.glob(os.path.join(condition, "s*")))[:MAX_RUNS_PER_CONDITION]:
                log_path = os.path.join(run_dir, "events.jsonl.gz")
                if not os.path.exists(log_path):
                    continue
                with open(os.path.join(run_dir, "config.json"), encoding="utf-8") as handle:
                    config = json.load(handle)
                with open(os.path.join(run_dir, "record.json"), encoding="utf-8") as handle:
                    record = json.load(handle)
                if config["devices"].__len__() != 10 or config["rtt_ms"] != 50.0:
                    continue
                used += 1
                stack, mode = config["stack"], config["policy"]["per_op"]
                restart = next((c for c in record.get("control", []) if c["type"] == "restart"), None)
                traffic = {}
                with gzip.open(log_path, "rt", encoding="utf-8") as handle:
                    for line in handle:
                        e = json.loads(line)
                        kind = e["ev"]
                        if kind == "service":
                            name = "ingest" if e["kind"] == "notify" else e["kind"]
                            add(f"{name}_{stack}" if name == "present" else name, e["ms"] / 1000.0)
                        elif kind == "broker_admin":
                            add(e["kind"], e["ms"] / 1000.0)
                        elif kind == "op" and "svc" in e:
                            if mode != "online":
                                add("op_" + mode, e["svc"] / 1000.0)
                            if e.get("lat") is not None and mode != "online":
                                add("net", max(0.0, (e["lat"] - e["svc"]) / 1000.0))
                        elif kind == "verify":
                            add("verify_" + e["stack"], e["ms"] / 1000.0)
                        elif kind == "domain_ready" and e.get("why") == "restarted" and restart:
                            add("restart_gap", e["ts"] - config["t0"] - restart["actual"])
                        elif kind == "traffic":
                            for name, value in e["bytes"].items():
                                traffic[name] = traffic.get(name, [0, 0])
                                traffic[name][0] += value
                                traffic[name][1] += e["calls"].get(name, 0)
                for name, (total, calls) in traffic.items():
                    if calls:
                        add(name + "_bytes", total / calls)
    table = {name: {"n": len(values), "median": percentile(values, 0.5), "p95": percentile(values, 0.95)}
             for name, values in sorted(samples.items())}
    create = table["create"]["median"]
    # A grant for a new session includes one broker command, which the simulator adds separately.
    costs = {"present": table["present_node"]["median"] - create, "renew": table["renew"]["median"],
             "handover": table["handover"]["median"] - create, "ingest": table["ingest"]["median"],
             "create": create, "delete": table["delete"]["median"],
             "op": table["op_token"]["median"], "op_full": table["op_full"]["median"],
             "op_none": table["op_none"]["median"], "op_token": table["op_token"]["median"],
             "net": table["net"]["median"], "restart_gap": table["restart_gap"]["median"],
             "fetch_bytes": table["status_fetch_bytes"]["median"], "push_bytes": table["push_bytes"]["median"]}
    out = {"runs_used": used, "measurements": table, "simulator_costs": costs}
    with open(os.path.join(ROOT, "results", "calibration.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(out, handle, indent=1)
        handle.write("\n")
    print(json.dumps(costs, indent=1))


if __name__ == "__main__":
    main(sys.argv[1:])
