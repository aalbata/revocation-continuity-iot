"""Run the simulation study with the calibrated component times.

Two groups of runs are produced. The validation group repeats live conditions
(10 and 100 devices) so that simulated and measured outcomes can be compared.
The scaling group uses 1,000 and 10,000 devices with one gateway worker per 100
devices. Results are written to results/sim_runs.jsonl, one run per line.

Usage: python scripts/run_sim.py [--processes 8] [--quick]
"""
import argparse
import json
import os
import sys
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rcbench.policy import ALL, MAIN  # noqa: E402
from rcbench.sim import simulate  # noqa: E402


def plan(quick: bool) -> list:
    tasks = []
    seeds30, seeds10 = list(range(1001, 1031)), list(range(1001, 1011))
    for policy in ALL:
        for outage in (0.0, 5.0, 30.0, 120.0):
            for seed in (seeds30[:3] if quick else seeds30):
                tasks.append(("validation", policy, 10, outage, seed))
    for policy in MAIN:
        for outage in (0.0, 30.0):
            for seed in (seeds10[:2] if quick else seeds10):
                tasks.append(("validation", policy, 100, outage, seed))
    for devices in (1000, 10000):
        for policy in ALL:
            for outage in (0.0, 30.0):
                for seed in (seeds10[:1] if quick else seeds10):
                    tasks.append(("scaling", policy, devices, outage, seed))
    return tasks


def work(task):
    group, policy, devices, outage, seed = task
    result = simulate(seed, policy, devices=devices, outage=outage, costs=work.costs)
    result["group"] = group
    return result


def _init(costs):
    work.costs = costs


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the simulation study")
    parser.add_argument("--processes", type=int, default=8)
    parser.add_argument("--quick", action="store_true", help="run a small subset")
    args = parser.parse_args()
    with open(os.path.join(ROOT, "results", "calibration.json"), encoding="utf-8") as handle:
        costs = json.load(handle)["simulator_costs"]
    tasks = plan(args.quick)
    tasks.sort(key=lambda t: -t[2])
    name = "sim_runs_quick.jsonl" if args.quick else "sim_runs.jsonl"
    with Pool(min(args.processes, 12), initializer=_init, initargs=(costs,)) as pool:
        results = pool.map(work, tasks, chunksize=1)
    results.sort(key=lambda r: (r["group"], r["devices"], r["policy"], r["outage"], r["seed"]))
    with open(os.path.join(ROOT, "results", name), "w", encoding="utf-8", newline="\n") as handle:
        for result in results:
            handle.write(json.dumps(result, sort_keys=True) + "\n")
    print(len(results), "simulation runs written to results/" + name)


if __name__ == "__main__":
    main()
