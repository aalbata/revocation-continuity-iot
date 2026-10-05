"""Reproduce the reported results.

Fast path (default): rebuild results/manifest.json and the figures from the
per-run files shipped in results/, and report whether the rebuilt files are
identical to the shipped ones. This needs Python and the pinned packages only.

    python reproduce.py

Simulation path: also rerun the simulation study from the shipped calibration.
The simulator is deterministic, so results/sim_runs.jsonl is reproduced exactly.

    python reproduce.py --simulate

Full path: rerun the live experiments (Mosquitto and Node.js required, about
ten hours on the machine described in the README), then calibration, simulation,
summaries, and figures. Live timings vary between runs, so measured values will differ
slightly from the shipped ones.

    python reproduce.py --full --raw <folder for raw run output>
"""
import argparse
import hashlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
CHECKED = ["results/manifest.json", "figures/fig1_overview.pdf", "figures/fig2_timeline.pdf",
           "figures/fig3_frontier.pdf", "figures/fig4_scaling.pdf"]


def digest(path: str) -> str:
    full = os.path.join(ROOT, path)
    if not os.path.exists(full):
        return "missing"
    with open(full, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def run(*args: str) -> None:
    print(">", " ".join(args), flush=True)
    subprocess.run([sys.executable, *args], cwd=ROOT, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce the reported results")
    parser.add_argument("--simulate", action="store_true", help="rerun the simulation study")
    parser.add_argument("--full", action="store_true", help="rerun the live experiments")
    parser.add_argument("--raw", default=os.path.join(ROOT, "raw"), help="folder for raw live output")
    parser.add_argument("--workers", default="8")
    args = parser.parse_args()
    before = {path: digest(path) for path in CHECKED + ["results/sim_runs.jsonl"]}
    if args.full:
        run("scripts/make_manifests.py")
        run("scripts/run_interop.py")
        # The batch runner leaves the 100-device conditions of a manifest for a second call.
        for batch in ("pilot", "primary", "sensitivity", "sensitivity"):
            run("-m", "rcbench.batch", f"configs/{batch}.json", os.path.join(args.raw, batch), "--workers", args.workers)
        run("scripts/collect.py", args.raw)
        run("scripts/calibrate.py", os.path.join(args.raw, "primary"))
    if args.full or args.simulate:
        run("scripts/run_sim.py")
    run("scripts/summarize.py")
    run("scripts/make_figures.py")
    run("scripts/report.py")
    print()
    same = True
    for path in CHECKED + ["results/sim_runs.jsonl"]:
        after = digest(path)
        state = "identical" if after == before[path] else ("created" if before[path] == "missing" else "CHANGED")
        same = same and state == "identical"
        print(f"{state:10} {path}  sha256 {after[:16]}")
    if not args.full:
        print("\nAll checked files are identical to the shipped ones." if same else
              "\nSome files differ from the shipped ones.")


if __name__ == "__main__":
    main()
