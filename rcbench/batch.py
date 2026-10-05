"""Run a manifest of conditions with a bounded number of parallel worlds.

A manifest lists conditions; each condition names a policy, the world settings,
and the seeds to run. Every (condition, seed) pair is one independent run in its
own folder. Completed runs are skipped, so an interrupted batch can be resumed.
Failed runs keep their folder and are reported, never silently dropped.
Conditions with 100 devices are run two at a time, because more parallel worlds
of that size exhaust local sockets on a laptop computer.

Usage: python -m rcbench.batch <manifest.json> <output folder> [--workers 8]
"""
import argparse
import glob
import gzip
import json
import os
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import psutil

from .metrics import run_metrics
from .world import _kill, build_config, run_world, start_node_verifier

MAX_WORKERS = 12
LARGE_WORLD_DEVICES = 100
LARGE_WORLD_WORKERS = 2
RUN_MEMORY_BYTES = 350e6
MEMORY_SHARE = 0.70


def worker_limit(requested: int) -> int:
    """Largest worker count that keeps the batch within the memory share of available RAM."""
    available = psutil.virtual_memory().available
    return max(1, min(requested, MAX_WORKERS, int(MEMORY_SHARE * available / RUN_MEMORY_BYTES)))


def tasks_of(manifest: dict, out: str) -> list:
    tasks = []
    for condition in manifest["conditions"]:
        for seed in condition["seeds"]:
            run_dir = os.path.join(out, condition["id"], f"s{seed:03d}")
            tasks.append((seed, condition, run_dir))
    tasks.sort(key=lambda t: (t[0], t[1]["id"]))
    return tasks


def compact(run_dir: str) -> None:
    """Keep the configuration, record, measures, and one compressed event log; remove working files."""
    paths = sorted(glob.glob(os.path.join(run_dir, "events.*.jsonl")))
    with gzip.open(os.path.join(run_dir, "events.jsonl.gz"), "wt", encoding="utf-8") as merged:
        for path in paths:
            with open(path, encoding="utf-8") as handle:
                shutil.copyfileobj(handle, merged)
    for path in paths + glob.glob(os.path.join(run_dir, "*.sqlite*")):
        os.remove(path)
    for path in glob.glob(os.path.join(run_dir, "broker-*")):
        shutil.rmtree(path, ignore_errors=True)
    for path in glob.glob(os.path.join(run_dir, "proc.*.log")):
        if os.path.getsize(path) == 0:
            os.remove(path)


def run_task(seed: int, condition: dict, run_dir: str, slot: int, node_port: int) -> dict:
    settings = {k: condition[k] for k in ("outage", "budget", "rtt_ms", "devices", "stack", "failure", "skew",
                                          "clock_uncertainty", "overrides") if k in condition}
    config = build_config(os.path.abspath(run_dir), seed, condition["policy"], slot=slot, node_port=node_port,
                          config_id=condition["id"], **settings)
    record = run_world(config, own_node=False)
    try:
        measures = run_metrics(run_dir)
    except Exception as exc:
        measures = {"run": config["run_id"], "seed": seed, "policy": condition["policy"], "config": condition["id"],
                    "failed": True, "errors": record.get("errors", []) + [f"metrics: {type(exc).__name__}: {exc}"]}
    with open(os.path.join(run_dir, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(measures, handle)
    if not measures.get("failed"):
        compact(run_dir)
    return measures


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a benchmark manifest")
    parser.add_argument("manifest")
    parser.add_argument("out")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int, default=0, help="stop after this many new runs")
    args = parser.parse_args()
    with open(args.manifest, encoding="utf-8") as handle:
        manifest = json.load(handle)
    os.makedirs(args.out, exist_ok=True)
    pending = [t for t in tasks_of(manifest, args.out) if not os.path.exists(os.path.join(t[2], "metrics.json"))]
    large = [t for t in pending if t[1].get("devices", 10) >= LARGE_WORLD_DEVICES]
    selected = [t for t in pending if t not in large] or large
    if args.limit:
        selected = selected[:args.limit]
    workers = worker_limit(args.workers)
    if selected and selected[0] in large:
        workers = min(workers, LARGE_WORLD_WORKERS)
    print(f"{len(selected)} runs to do with {workers} workers; {len(pending) - len(selected)} left for a later call",
          flush=True)
    slots = list(range(workers))
    lock = threading.Lock()
    nodes = {}
    if any(t[1].get("stack", "node") == "node" for t in selected):
        for slot in slots:
            port = 21000 + slot * 40 + 30
            nodes[slot] = start_node_verifier(port, os.path.join(args.out, f"node-{slot}.log"))
    done = [0]
    started = time.time()

    def work(task):
        with lock:
            slot = slots.pop()
        try:
            seed, condition, run_dir = task
            if os.path.isdir(run_dir):
                shutil.rmtree(run_dir, ignore_errors=True)
            measures = run_task(seed, condition, run_dir, slot, 21000 + slot * 40 + 30)
            with lock:
                done[0] += 1
                state = "FAILED" if measures.get("failed") else "ok"
                print(f"[{done[0]}/{len(selected)}] {condition['id']} s{seed:03d} {state} "
                      f"elapsed {time.time() - started:.0f}s", flush=True)
        finally:
            with lock:
                slots.append(slot)

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = []
            for task in selected:
                futures.append(pool.submit(work, task))
                time.sleep(1.0)
            for future in futures:
                future.result()
    finally:
        for process in nodes.values():
            _kill(process)


if __name__ == "__main__":
    main()
