"""Write the run manifests: pilot, primary matrix, and sensitivity sweeps.

Pilot seeds (1 to 10) are used to check the labeling of commands as authorized
or unauthorized and to choose baseline settings. Final seeds (1001 to 1030) are
held out and are run only after the policies, traces, and analysis rules are fixed.

Usage: python scripts/make_manifests.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from rcbench.policy import ALL, MAIN  # noqa: E402

PILOT_SEEDS = list(range(1, 11))
FINAL_SEEDS = list(range(1001, 1031))
SWEEP_SEEDS = list(range(1001, 1011))
OUTAGES = [0.0, 5.0, 30.0, 120.0]


def condition(ident, policy, seeds, outage=30.0, budget=30.0, rtt_ms=50.0, devices=10, stack="node",
              failure="shared", **extra):
    return dict(id=ident, policy=policy, seeds=seeds, outage=outage, budget=budget, rtt_ms=rtt_ms,
                devices=devices, stack=stack, failure=failure, **extra)


def pilot():
    out = []
    for policy in ("online", "coordinated", "profile"):
        for outage in (0.0, 30.0):
            out.append(condition(f"pilot-{policy}-o{int(outage)}", policy, PILOT_SEEDS, outage))
    for outage in (0.0, 30.0):
        out.append(condition(f"pilot-cached-o{int(outage)}", "cached", PILOT_SEEDS, outage,
                             overrides={"token_lifetime": 60.0}))
        out.append(condition(f"pilot-shortlived-o{int(outage)}", "shortlived", PILOT_SEEDS, outage,
                             overrides={"token_lifetime": 10.0}))
    for lifetime in (30.0, 120.0):
        for outage in (0.0, 30.0):
            out.append(condition(f"pilot-cached-T{int(lifetime)}-o{int(outage)}", "cached", PILOT_SEEDS[:3], outage,
                                 overrides={"token_lifetime": lifetime}))
    for lifetime in (5.0, 20.0):
        for outage in (0.0, 30.0):
            out.append(condition(f"pilot-shortlived-T{int(lifetime)}-o{int(outage)}", "shortlived", PILOT_SEEDS[:3],
                                 outage, overrides={"token_lifetime": lifetime}))
    return out


def primary():
    return [condition(f"{policy}-o{int(outage)}", policy, FINAL_SEEDS, outage) for policy in ALL for outage in OUTAGES]


def sensitivity():
    out = []
    for policy in MAIN:
        for rtt in (10.0, 200.0):
            out.append(condition(f"rtt{int(rtt)}-{policy}", policy, SWEEP_SEEDS, 30.0, rtt_ms=rtt))
        out.append(condition(f"budget5-{policy}", policy, SWEEP_SEEDS, 30.0, budget=5.0))
        out.append(condition(f"budget120-{policy}", policy, SWEEP_SEEDS, 120.0, budget=120.0))
        for outage in (0.0, 30.0):
            out.append(condition(f"n100-{policy}-o{int(outage)}", policy, SWEEP_SEEDS, outage, devices=100))
            out.append(condition(f"python-{policy}-o{int(outage)}", policy, SWEEP_SEEDS, outage, stack="python"))
        out.append(condition(f"independent-{policy}", policy, SWEEP_SEEDS, 30.0, failure="independent"))
    for lifetime in (60.0, 120.0, 300.0):
        out.append(condition(f"life-cached-T{int(lifetime)}", "cached", SWEEP_SEEDS, 30.0,
                             overrides={"token_lifetime": lifetime}))
    for lifetime in (10.0, 20.0):
        out.append(condition(f"life-shortlived-T{int(lifetime)}", "shortlived", SWEEP_SEEDS, 30.0,
                             overrides={"token_lifetime": lifetime}))
    out.append(condition("life-cached-S300", "cached", SWEEP_SEEDS, 30.0, overrides={"session_lifetime": 300.0}))
    out.append(condition("life-shortlived-S300", "shortlived", SWEEP_SEEDS, 30.0, overrides={"session_lifetime": 300.0}))
    out.append(condition("life-profile-T10", "profile", SWEEP_SEEDS, 30.0, overrides={"token_lifetime": 10.0}))
    for policy in ("coordinated", "profile"):
        out.append(condition(f"skew-{policy}", policy, SWEEP_SEEDS, 30.0, skew=-2.0))
        out.append(condition(f"skew-allow-{policy}", policy, SWEEP_SEEDS, 30.0, skew=-2.0, clock_uncertainty=2.0))
    return out


def main() -> None:
    folder = os.path.join(ROOT, "configs")
    os.makedirs(folder, exist_ok=True)
    for name, conditions in (("pilot", pilot()), ("primary", primary()), ("sensitivity", sensitivity())):
        with open(os.path.join(folder, name + ".json"), "w", encoding="utf-8", newline="\n") as handle:
            json.dump({"name": name, "conditions": conditions}, handle, indent=1)
            handle.write("\n")
        print(name, len(conditions), "conditions,", sum(len(c["seeds"]) for c in conditions), "runs")


if __name__ == "__main__":
    main()
