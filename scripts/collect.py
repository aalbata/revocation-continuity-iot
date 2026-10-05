"""Collect per-run measures and sample traces from raw batch folders into results/.

For every batch folder (pilot, primary, sensitivity) the measures of each run are
written to results/runs/<batch>.jsonl, one run per line, including failed runs.
The compressed event logs of one seed per policy are copied to results/traces/ as
minimized synthetic traces. The environment is recorded in
results/environment.json.

Usage: python scripts/collect.py <raw folder that contains the batch folders>
"""
import glob
import json
import os
import platform
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rcbench.broker import mosquitto_home  # noqa: E402
from rcbench.policy import ALL, POLICIES  # noqa: E402

TRACE_SEED = 1001
TRACE_OUTAGE = 30


def version(command: list) -> str:
    try:
        out = subprocess.run(command, capture_output=True, text=True, timeout=20)
        return (out.stdout + out.stderr).strip().splitlines()[0]
    except (OSError, IndexError, subprocess.TimeoutExpired):
        return "unavailable"


def main(raw: str) -> None:
    runs_dir = os.path.join(ROOT, "results", "runs")
    os.makedirs(runs_dir, exist_ok=True)
    for batch in ("pilot", "primary", "sensitivity"):
        folder = os.path.join(raw, batch)
        if not os.path.isdir(folder):
            continue
        rows = []
        for path in sorted(glob.glob(os.path.join(folder, "*", "s*", "metrics.json"))):
            with open(path, encoding="utf-8") as handle:
                rows.append(json.load(handle))
        rows.sort(key=lambda m: (m["config"], m["seed"]))
        with open(os.path.join(runs_dir, batch + ".jsonl"), "w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        print(batch, len(rows), "runs,", sum(1 for r in rows if r.get("failed")), "failed")
    traces = os.path.join(ROOT, "results", "traces")
    os.makedirs(traces, exist_ok=True)
    for policy in ALL:
        source = os.path.join(raw, "primary", f"{policy}-o{TRACE_OUTAGE}", f"s{TRACE_SEED:03d}")
        if os.path.exists(os.path.join(source, "events.jsonl.gz")):
            name = f"{policy}-o{TRACE_OUTAGE}-s{TRACE_SEED}"
            shutil.copyfile(os.path.join(source, "events.jsonl.gz"), os.path.join(traces, name + ".events.jsonl.gz"))
            with open(os.path.join(source, "config.json"), encoding="utf-8") as handle:
                config = json.load(handle)
            config["dir"] = "."
            config["policy"]["label"] = POLICIES[policy].label
            with open(os.path.join(traces, name + ".config.json"), "w", encoding="utf-8", newline="\n") as handle:
                json.dump(config, handle, sort_keys=True)
                handle.write("\n")
    home = mosquitto_home()
    environment = {
        "system": platform.platform(), "processor": platform.processor(),
        "logical_processors": os.cpu_count(),
        "python": platform.python_version(), "node": version(["node", "--version"]),
        "mosquitto": version([os.path.join(home, "mosquitto"), "-h"]),
    }
    with open(os.path.join(ROOT, "results", "environment.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(environment, handle, indent=1)
        handle.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
