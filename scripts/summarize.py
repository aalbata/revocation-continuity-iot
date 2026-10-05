"""Build results/manifest.json, the single source of every reported number.

Inputs are the per-run files in results/ (live runs, simulation runs,
calibration, interoperability table). The manifest holds condition summaries with
run-level bootstrap intervals, paired differences against the continuity profile,
simulation summaries, and the comparison of simulated with measured outcomes.

Usage: python scripts/summarize.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rcbench import analysis  # noqa: E402
from rcbench.policy import ALL, POLICIES  # noqa: E402

OUTAGES = [0, 5, 30, 120]
PAIRED_MEASURES = ["exposure_max", "unauthorized_fraction", "completion", "backhaul_kb", "renewals", "latency_ms_p95"]


def read_lines(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def by_condition(rows: list) -> dict:
    out = {}
    for row in rows:
        out.setdefault(row["config"], []).append(row)
    return out


def live_section(name: str) -> tuple:
    groups = by_condition(read_lines(os.path.join(ROOT, "results", "runs", name + ".jsonl")))
    return {key: analysis.condition_summary(runs) for key, runs in sorted(groups.items())}, groups


def sim_section(rows: list) -> dict:
    groups = {}
    for row in rows:
        key = f"{row['group']}-n{row['devices']}-{row['policy']}-o{int(row['outage'])}"
        groups.setdefault(key, []).append(row)
    out = {}
    for key, runs in sorted(groups.items()):
        first = runs[0]
        entry = {"group": first["group"], "devices": first["devices"], "policy": first["policy"],
                 "outage": first["outage"], "runs": len(runs),
                 "censored": sum(1 for r in runs if r["security"]["censored"])}
        for label, getter in (
                ("exposure_max", lambda r: r["security"]["exposure_max"]),
                ("exposure_mean", lambda r: r["security"]["exposure_mean"]),
                ("unauthorized_fraction", lambda r: r["security"]["unauthorized_fraction"]),
                ("completion", lambda r: r["availability"]["completion"]),
                ("latency_ms_p95", lambda r: r["availability"]["latency_ms_p95"]),
                ("renewals_per_device", lambda r: r["cost"]["renewals"] / r["devices"]),
                ("token_requests_per_device", lambda r: r["cost"]["token_requests"] / r["devices"]),
                ("backhaul_kb_per_device", lambda r: r["cost"]["backhaul_bytes"] / 1000.0 / r["devices"]),
                ("gateway_utilization", lambda r: r["cost"]["gateway_utilization"]),
                ("peak_gateway_queue", lambda r: r["cost"]["peak_gateway_queue"])):
            entry[label] = analysis.summarize([getter(r) for r in runs])
        out[key] = entry
    return out


def main() -> None:
    manifest = {"policies": {key: POLICIES[key].to_dict() for key in ALL}}
    for name in ("environment", "calibration", "interop"):
        path = os.path.join(ROOT, "results", name + ".json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                manifest[name] = json.load(handle)
    live, groups = {}, {}
    for name in ("pilot", "primary", "sensitivity"):
        live[name], groups[name] = live_section(name)
    manifest["live"] = live

    paired = {}
    primary = groups["primary"]
    for outage in OUTAGES:
        reference = primary.get(f"profile-o{outage}")
        for policy in ALL:
            other = primary.get(f"{policy}-o{outage}")
            if policy == "profile" or not reference or not other:
                continue
            for measure in PAIRED_MEASURES:
                result = analysis.paired(other, reference, measure)
                if result:
                    paired[f"{policy}-minus-profile-o{outage}-{measure}"] = result
    sensitivity = groups["sensitivity"]
    for prefix in ("rtt10", "rtt200", "budget5", "budget120", "independent", "n100", "python"):
        for suffix in ("", "-o0", "-o30"):
            reference = sensitivity.get(f"{prefix}-profile{suffix}")
            for policy in ("online", "cached", "shortlived", "coordinated"):
                other = sensitivity.get(f"{prefix}-{policy}{suffix}")
                if reference and other:
                    for measure in ("exposure_max", "completion"):
                        result = analysis.paired(other, reference, measure)
                        if result:
                            paired[f"{prefix}-{policy}-minus-profile{suffix}-{measure}"] = result
    for policy in ("online", "cached", "shortlived", "coordinated", "profile"):
        for outage in (0, 30):
            node = primary.get(f"{policy}-o{outage}")
            python = sensitivity.get(f"python-{policy}-o{outage}")
            if node and python:
                seeds = {m["seed"] for m in python}
                node10 = [m for m in node if m["seed"] in seeds]
                for measure in ("exposure_max", "completion", "verify_ms_median", "token_request_ms_p95"):
                    result = analysis.paired(node10, python, measure)
                    if result:
                        paired[f"node-minus-python-{policy}-o{outage}-{measure}"] = result
    for prefix in ("rtt10", "rtt200", "independent", "skew", "skew-allow"):
        for policy in ("online", "cached", "shortlived", "coordinated", "profile"):
            varied, base = sensitivity.get(f"{prefix}-{policy}"), primary.get(f"{policy}-o30")
            if varied and base:
                seeds = {m["seed"] for m in varied}
                for measure in ("exposure_max", "completion"):
                    result = analysis.paired(varied, [m for m in base if m["seed"] in seeds], measure)
                    if result:
                        paired[f"{prefix}-{policy}-minus-base-{measure}"] = result
    manifest["paired"] = paired

    sim_rows = read_lines(os.path.join(ROOT, "results", "sim_runs.jsonl"))
    manifest["sim"] = sim_section(sim_rows)
    checks = []
    for key, entry in manifest["sim"].items():
        if entry["group"] != "validation":
            continue
        if entry["devices"] == 10:
            measured = live["primary"].get(f"{entry['policy']}-o{int(entry['outage'])}")
        else:
            measured = live["sensitivity"].get(f"n100-{entry['policy']}-o{int(entry['outage'])}")
        if not measured or measured["exposure_max"] is None:
            continue
        checks.append({"condition": key, "censored_live": measured["censored"],
                       "exposure_sim": entry["exposure_max"]["mean"], "exposure_live": measured["exposure_max"]["mean"],
                       "completion_sim": entry["completion"]["mean"], "completion_live": measured["completion"]["mean"]})
    usable = [c for c in checks if not c["censored_live"]]
    if usable:
        manifest["sim_validation"] = {
            "conditions": len(checks), "conditions_without_censoring": len(usable),
            "exposure_mean_abs_error_s": analysis.mean([abs(c["exposure_sim"] - c["exposure_live"]) for c in usable]),
            "exposure_max_abs_error_s": max(abs(c["exposure_sim"] - c["exposure_live"]) for c in usable),
            "completion_mean_abs_error": analysis.mean([abs(c["completion_sim"] - c["completion_live"]) for c in checks]),
            "completion_max_abs_error": max(abs(c["completion_sim"] - c["completion_live"]) for c in checks),
            "rows": checks}
    def total(name: str, failed: bool = False) -> int:
        rows = [m for runs in groups[name].values() for m in runs]
        return sum(1 for m in rows if m.get("failed")) if failed else len(rows)

    profile_runs = [m for key, runs in primary.items() if key.startswith("profile-o") for m in runs
                    if not m.get("failed")]
    every_profile_run = [m for section in (primary, sensitivity) for runs in section.values() for m in runs
                         if m["policy"] == "profile" and not m.get("failed")]
    budget30 = [m for m in every_profile_run if m["budget"] == 30.0]
    below_budget = {}
    for section in (primary, sensitivity):
        for runs in section.values():
            for m in runs:
                if m.get("failed"):
                    continue
                entry = below_budget.setdefault(m["policy"], {"runs": 0, "below": 0})
                entry["runs"] += 1
                entry["below"] += int(m["security"]["exposure_max"] < m["budget"])
    manifest["headline"] = {
        "pilot_runs": total("pilot"), "primary_runs": total("primary"), "sensitivity_runs": total("sensitivity"),
        "live_runs": total("pilot") + total("primary") + total("sensitivity"),
        "final_runs": total("primary") + total("sensitivity"),
        "failed_runs": total("pilot", True) + total("primary", True) + total("sensitivity", True),
        "primary_conditions": len(primary), "sensitivity_conditions": len(sensitivity),
        "simulation_runs": len(sim_rows),
        "profile_exposure_largest_run": max((m["security"]["exposure_max"] for m in profile_runs), default=None),
        "profile_final_runs": len(every_profile_run),
        "profile_final_runs_below_budget": sum(1 for m in every_profile_run
                                               if m["security"]["exposure_max"] < m["budget"]),
        "final_runs_below_budget": below_budget,
        "profile_budget30_runs": len(budget30),
        "profile_budget30_exposure_largest": max((m["security"]["exposure_max"] for m in budget30), default=None),
        "profile_budget30_largest_condition": max(budget30, key=lambda m: m["security"]["exposure_max"])["config"]
        if budget30 else None,
        "profile_in_flight_total": sum(m["security"]["in_flight_executed"] for m in profile_runs),
        "primary_in_flight_total": sum(m["security"]["in_flight_executed"] for runs in primary.values()
                                       for m in runs if not m.get("failed")),
        "primary_push_rejected_older": sum(m["cost"]["push_rejected_older"] for runs in primary.values()
                                           for m in runs if not m.get("failed")),
    }
    with open(os.path.join(ROOT, "results", "manifest.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=1, sort_keys=True)
        handle.write("\n")
    print("manifest written:", {k: len(v) for k, v in live.items()}, "live conditions;", len(manifest["sim"]),
          "simulation conditions;", len(paired), "paired comparisons")


if __name__ == "__main__":
    main()
