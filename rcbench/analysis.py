"""Aggregate per-run measures into condition summaries with run-level uncertainty.

The independent unit is the run. Every interval is a percentile bootstrap over
runs (or over per-seed paired differences), with a fixed resampling seed so the
numbers are reproducible. Runs that failed are counted and excluded from the
statistics; right-censored runs are counted and their exposure enters as the
observed lower bound.
"""
import glob
import json
import os
import random

RESAMPLES = 10000
BOOT_SEED = 20261004

MEASURES = {
    "exposure_max": lambda m: m["security"]["exposure_max"],
    "exposure_mean": lambda m: m["security"]["exposure_mean"],
    "exposure_admit_max": lambda m: m["security"].get("exposure_admit_max"),
    "unauthorized_executed": lambda m: m["security"]["unauthorized_executed"],
    "unauthorized_fraction": lambda m: m["security"]["unauthorized_fraction"],
    "in_flight_executed": lambda m: m["security"].get("in_flight_executed"),
    "suspension_exposure_max": lambda m: m["security"].get("suspension_exposure_max"),
    "completion": lambda m: m["availability"]["completion"],
    "latency_ms_median": lambda m: m["availability"]["latency_ms_median"],
    "latency_ms_p95": lambda m: m["availability"]["latency_ms_p95"],
    "token_request_ms_p95": lambda m: m["availability"].get("token_request_ms_p95"),
    "token_denials": lambda m: m["availability"].get("token_denials"),
    "backhaul_kb": lambda m: m["cost"]["backhaul_bytes"] / 1000.0,
    "bytes_per_decision": lambda m: m["cost"].get("bytes_per_decision"),
    "renewals": lambda m: m["cost"]["renewals"],
    "verify_ms_median": lambda m: m["cost"].get("verify_ms_median"),
    "memory_mb": lambda m: sum(m["cost"]["memory_mb"].values()) if m["cost"].get("memory_mb") else None,
}
ROLES = ["r_stay", "r_after", "r_during", "r_before", "r_restart", "suspended"]


def mean(values: list) -> float:
    return sum(values) / len(values)


def median(values: list) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2.0


def bootstrap(values: list, statistic=mean) -> tuple:
    """Percentile 95 percent interval of a statistic over resampled runs."""
    if len(values) < 2:
        return (None, None)
    rng = random.Random(BOOT_SEED)
    n = len(values)
    estimates = sorted(statistic([values[rng.randrange(n)] for _ in range(n)]) for _ in range(RESAMPLES))
    return (estimates[int(0.025 * RESAMPLES)], estimates[int(0.975 * RESAMPLES) - 1])


def summarize(values: list) -> dict | None:
    values = [v for v in values if v is not None]
    if not values:
        return None
    low, high = bootstrap(values)
    return {"n": len(values), "mean": mean(values), "median": median(values), "min": min(values),
            "max": max(values), "ci_low": low, "ci_high": high}


def load_runs(folder: str) -> dict:
    """Return {condition id: [run measures]} for every run folder under a batch output folder."""
    runs = {}
    for path in sorted(glob.glob(os.path.join(folder, "*", "s*", "metrics.json"))):
        with open(path, encoding="utf-8") as handle:
            measures = json.load(handle)
        runs.setdefault(measures["config"], []).append(measures)
    return runs


def condition_summary(runs: list) -> dict:
    good = [m for m in runs if not m.get("failed")]
    first = good[0] if good else runs[0]
    out = {key: first.get(key) for key in ("policy", "outage", "budget", "rtt_ms", "devices", "stack", "failure")}
    out.update({"runs": len(runs), "failed": len(runs) - len(good),
                "censored": sum(1 for m in good if m["security"]["censored"]),
                "seeds": sorted(m["seed"] for m in good)})
    for name, getter in MEASURES.items():
        out[name] = summarize([getter(m) for m in good])
    out["exposure_by_role"] = {role: summarize([m["security"]["by_role"].get(role) for m in good]) for role in ROLES}
    failures = {}
    for m in good:
        for reason, count in m["availability"]["failures"].items():
            failures[reason] = failures.get(reason, 0) + count
    total = sum(m["availability"]["benign_requests"] for m in good)
    out["failure_share"] = {k: v / total for k, v in sorted(failures.items())} if total else {}
    return out


def paired(runs_a: list, runs_b: list, measure: str) -> dict | None:
    """Mean per-seed difference (a minus b) with a bootstrap interval over seeds."""
    getter = MEASURES[measure]
    a = {m["seed"]: getter(m) for m in runs_a if not m.get("failed")}
    b = {m["seed"]: getter(m) for m in runs_b if not m.get("failed")}
    seeds = sorted(s for s in a if s in b and a[s] is not None and b[s] is not None)
    if len(seeds) < 2:
        return None
    diffs = [a[s] - b[s] for s in seeds]
    low, high = bootstrap(diffs)
    return {"n": len(seeds), "mean_diff": mean(diffs), "ci_low": low, "ci_high": high,
            "mean_a": mean([a[s] for s in seeds]), "mean_b": mean([b[s] for s in seeds])}
