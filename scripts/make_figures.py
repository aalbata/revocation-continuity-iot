"""Draw the figures from the files in results/.

Fig. 1 is a schematic of the system under test and the benchmark workflow.
Fig. 2 is drawn from the sample event traces in results/traces/. Fig. 3 and
Fig. 4 are drawn from results/manifest.json. Each figure is written as a vector
PDF and as a PNG to figures/.

Usage: python scripts/make_figures.py [1 2 3 4]
"""
import gzip
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "figures")
plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"], "font.size": 7,
                     "axes.linewidth": 0.5, "lines.linewidth": 0.9, "xtick.major.width": 0.5,
                     "ytick.major.width": 0.5, "xtick.major.size": 2.5, "ytick.major.size": 2.5,
                     "legend.frameon": False, "pdf.fonttype": 42, "savefig.dpi": 600,
                     "mathtext.fontset": "stix"})
ONE, TWO = 3.45, 7.1
STYLE = {
    "online": ("Online checks", "#4477AA", "s"),
    "cached": ("Cached status", "#EE6677", "v"),
    "shortlived": ("Short-lived grants", "#CCBB44", "^"),
    "coordinated": ("Coordinated practice", "#228833", "D"),
    "profile": ("Continuity profile", "#000000", "o"),
    "no_inherit": ("Profile without inheritance", "#AA3377", "P"),
    "no_persist": ("Profile without persistence", "#66CCEE", "X"),
    "no_session": ("Profile without session enforcement", "#999999", "*"),
    "timer_reset": ("Timer-reset control", "#EE7733", "h"),
}
MAIN = ["online", "cached", "shortlived", "coordinated", "profile"]
ORDER = MAIN + ["no_inherit", "no_persist", "no_session", "timer_reset"]


def save(fig, name: str) -> None:
    os.makedirs(OUT, exist_ok=True)
    meta = {"Creator": "Matplotlib", "Producer": "Matplotlib", "Title": "", "Author": "", "Subject": "",
            "Keywords": "", "CreationDate": None, "ModDate": None}
    fig.savefig(os.path.join(OUT, name + ".pdf"), metadata=meta)
    fig.savefig(os.path.join(OUT, name + ".png"), metadata={"Software": "Matplotlib"})
    plt.close(fig)


def manifest() -> dict:
    with open(os.path.join(ROOT, "results", "manifest.json"), encoding="utf-8") as handle:
        return json.load(handle)


def _box(ax, x, y, w, h, text, face="#FFFFFF", edge="#333333", size=6.5, weight="normal", style="round"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"{style},pad=0.0,rounding_size=0.012", linewidth=0.6,
                                facecolor=face, edgecolor=edge))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size, fontweight=weight, linespacing=1.15)


def _arrow(ax, start, end, color="#333333", style="-|>", width=0.6, dashed=False):
    ax.add_patch(FancyArrowPatch(start, end, arrowstyle=style, mutation_scale=6, linewidth=width, color=color,
                                 linestyle=(0, (3, 2)) if dashed else "solid", shrinkA=0, shrinkB=0))


def figure1() -> None:
    fig = plt.figure(figsize=(TWO, 3.35))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.text(0.305, 0.965, "System under test", ha="center", fontsize=8)
    ax.text(0.835, 0.965, "Benchmark", ha="center", fontsize=8)
    ax.plot([0.655, 0.655], [0.03, 0.97], color="#999999", linewidth=0.5, linestyle=(0, (2, 2)))
    for x, label in ((0.10, "Issuer A\n(contractor)"), (0.36, "Issuer B\n(building operator)")):
        _box(ax, x, 0.80, 0.19, 0.115, label + "\nDID document, status lists", face="#EEF3F9")
    ax.add_patch(FancyBboxPatch((0.02, 0.675), 0.61, 0.07, boxstyle="round,pad=0.0,rounding_size=0.012",
                                linewidth=0.5, facecolor="#F6F6F6", edgecolor="#888888", linestyle=(0, (3, 2))))
    ax.text(0.325, 0.71, "Backhaul with configured delay and scheduled outage: status fetch, "
            "revocation notification, key resolution", ha="center", va="center", fontsize=6.3)
    for x in (0.195, 0.455):
        _arrow(ax, (x, 0.80), (x, 0.745), style="<|-|>")
    names = ("Building domain", "Contractor domain", "Provider domain")
    for i, name in enumerate(names):
        x = 0.02 + i * 0.21
        ax.add_patch(FancyBboxPatch((x, 0.27), 0.19, 0.345, boxstyle="round,pad=0.0,rounding_size=0.012",
                                    linewidth=0.7, facecolor="#FBF7EE", edgecolor="#555555"))
        ax.text(x + 0.095, 0.59, name, ha="center", va="center", fontsize=6.8)
        _box(ax, x + 0.012, 0.475, 0.166, 0.085, "Gateway: verify credential,\nissue local token", size=5.9)
        _box(ax, x + 0.012, 0.38, 0.166, 0.075, "MQTT broker: session,\ntopic permission", size=5.9)
        _box(ax, x + 0.012, 0.285, 0.166, 0.075, "Executor: protected\ncommand", size=5.9)
        _arrow(ax, (x + 0.095, 0.675), (x + 0.095, 0.615), style="<|-|>")
    _box(ax, 0.03, 0.06, 0.17, 0.10, "Device\nholder key, credential", face="#EEF6EE")
    _arrow(ax, (0.075, 0.16), (0.075, 0.27))
    ax.text(0.069, 0.215, "1 present", ha="right", va="center", fontsize=5.9)
    _arrow(ax, (0.105, 0.27), (0.105, 0.16))
    ax.text(0.111, 0.238, "2 token", ha="left", va="center", fontsize=5.9)
    _arrow(ax, (0.175, 0.16), (0.175, 0.27))
    ax.text(0.181, 0.192, "3 publish", ha="left", va="center", fontsize=5.9)
    _box(ax, 0.455, 0.06, 0.14, 0.10, "Device after\nhandover", face="#EEF6EE")
    _arrow(ax, (0.20, 0.11), (0.455, 0.11), dashed=True)
    ax.text(0.33, 0.125, "4 handover: exchange the token\nat the next domain", ha="center", va="bottom", fontsize=5.9)
    _arrow(ax, (0.525, 0.16), (0.525, 0.27))
    ax.text(0.33, 0.045, "Two verification stacks process the same credentials:\n"
            "Node.js (Digital Bazaar libraries) and Python", ha="center", va="center", fontsize=5.9)
    steps = [
        (0.815, "Seeded lifecycle trace\nrevoke, suspend, hand over, restart,\nrotate key, outage of 0 to 120 s", "#EEF3F9"),
        (0.645, "Nine integration policies\nfour baselines, the profile,\nthree ablations, one negative control", "#FBF7EE"),
        (0.475, "Live runs on real broker and proofs\n30 runs per primary condition (10 devices),\n"
                "10 runs per sensitivity condition (up to 100)", "#EEF6EE"),
        (0.305, "Calibrated simulation\nsame decision code,\n1,000 and 10,000 devices", "#EEF6EE"),
        (0.075, "Measures per run\ntime from revocation commit to last\nunauthorized command, share of "
                "unauthorized\nattempts executed, benign completion,\nlatency, traffic", "#F6F6F6"),
    ]
    for y, text, face in steps:
        height = 0.16 if y == 0.075 else 0.115
        _box(ax, 0.685, y, 0.30, height, text, face=face, size=6.2)
    for top, bottom in ((0.815, 0.76), (0.645, 0.59), (0.475, 0.42), (0.305, 0.235)):
        _arrow(ax, (0.835, top), (0.835, bottom))
    save(fig, "fig1_overview")


def _trace(policy: str):
    base = os.path.join(ROOT, "results", "traces", f"{policy}-o30-s1001")
    with open(base + ".config.json", encoding="utf-8") as handle:
        config = json.load(handle)
    with gzip.open(base + ".events.jsonl.gz", "rt", encoding="utf-8") as handle:
        events = [json.loads(line) for line in handle]
    return config, events


def figure2() -> None:
    fig, ax = plt.subplots(figsize=(ONE, 2.75))
    fig.subplots_adjust(left=0.40, right=0.975, top=0.90, bottom=0.15)
    first_commit = None
    for row, policy in enumerate(ORDER):
        config, events = _trace(policy)
        t0 = config["t0"]
        revoked = {e["dev"]: e["commit"] for e in events if e["ev"] == "revocation_commit"}
        times = [e["ts"] - t0 for e in events if e["ev"] == "op" and e.get("out") == "executed"
                 and e.get("dev") in revoked and e.get("sent", 0) >= revoked[e["dev"]]]
        y = len(ORDER) - 1 - row
        ax.vlines(times, y - 0.36, y + 0.36, color=STYLE[policy][1], linewidth=0.35)
        if first_commit is None:
            window = config["outages"][0]
            main = sorted(v - t0 for v in revoked.values())
            first_commit = (main[0], main[1], main[-1], window["start"], window["end"], config["horizon"],
                            next(e["t"] for e in config["events"] if e["type"] == "restart"))
    early, start, end, o1, o2, horizon, restart = first_commit
    ax.axvspan(o1, o2, color="#DDDDDD", alpha=0.55, linewidth=0)
    ax.axvspan(start, end, color="#CC3311", alpha=0.35, linewidth=0)
    ax.axvline(early, color="#CC3311", linewidth=0.7, linestyle=(0, (1, 1)))
    ax.axvline(restart, color="#333333", linewidth=0.6, linestyle=(0, (4, 2)))
    ax.set_yticks(range(len(ORDER)))
    ax.set_yticklabels([STYLE[p][0].replace("without session ", "without session\n") for p in reversed(ORDER)],
                       linespacing=0.9)
    ax.set_ylim(-0.6, len(ORDER) - 0.4)
    ax.set_xlim(0, horizon)
    ax.set_xlabel("Time since start of observation (s)")
    ax.tick_params(axis="y", length=0)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    top = len(ORDER) - 0.35
    ax.text((o1 + o2) / 2 + 3.0, top, "outage", ha="center", va="bottom", fontsize=6)
    ax.annotate("restart", xy=(restart, top), xytext=(restart, top + 0.5), fontsize=6, va="bottom",
                ha="center", annotation_clip=False,
                arrowprops={"arrowstyle": "-", "linewidth": 0.4, "color": "#333333", "shrinkA": 1, "shrinkB": 0,
                            "relpos": (0.5, 0.0)})
    save(fig, "fig2_timeline")


def figure3() -> None:
    data = manifest()["live"]["primary"]
    fig, ax = plt.subplots(figsize=(ONE, 2.9))
    fig.subplots_adjust(left=0.14, right=0.975, top=0.80, bottom=0.14)
    sizes = {0: 9, 5: 16, 30: 26, 120: 40}
    for policy in ["no_persist"] + [p for p in ORDER if p != "no_persist"]:
        label, color, marker = STYLE[policy]
        xs, ys = [], []
        for outage in (0, 5, 30, 120):
            entry = data.get(f"{policy}-o{outage}")
            if not entry:
                continue
            x, y = 100.0 * entry["completion"]["mean"], entry["exposure_max"]["mean"]
            xs.append(x)
            ys.append(y)
            face = "white" if entry["censored"] else color
            grow = 2.0 if marker == "*" else 1.0
            ax.scatter([x], [y], s=grow * sizes[outage], marker=marker, facecolor=face, edgecolor=color,
                       linewidth=0.4 if entry["censored"] else 0.6, zorder=3)
        ax.plot(xs, ys, color=color, linewidth=0.5, alpha=0.7, zorder=2, label=label)
    ax.set_yscale("symlog", linthresh=1.0, linscale=0.6)
    ax.set_ylim(-0.08, 300)
    ax.set_yticks([0, 1, 10, 100])
    ax.set_yticklabels(["0", "1", "10", "100"])
    ax.set_xlabel("Benign commands completed within 1 s (%)")
    ax.set_ylabel("Exposure (s)")
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    handles = [plt.Line2D([], [], color=STYLE[p][1], marker=STYLE[p][2], linewidth=0.6,
                          markersize=5.0 if STYLE[p][2] == "*" else 3.5,
                          markeredgewidth=0.4 if data[f"{p}-o0"]["censored"] else 0.6,
                          markerfacecolor="white" if data[f"{p}-o0"]["censored"] else STYLE[p][1],
                          label=STYLE[p][0]) for p in ORDER]
    fig.legend(handles=handles, loc="upper center", ncol=3, fontsize=5.4, columnspacing=0.8, handletextpad=0.3,
               bbox_to_anchor=(0.5, 1.0))
    key = [plt.scatter([], [], s=sizes[o], marker="o", facecolor="#666666", edgecolor="#666666", linewidth=0.4,
                       label=f"{o} s") for o in (0, 5, 30, 120)]
    ax.legend(handles=key, title="Outage", loc="lower left", fontsize=5.6, title_fontsize=5.6, borderpad=0.2,
              labelspacing=0.35, handletextpad=0.2, bbox_to_anchor=(0.02, 0.08))
    save(fig, "fig3_frontier")


def figure4() -> None:
    data = manifest()
    sim, live = data["sim"], data["live"]
    fig, axes = plt.subplots(1, 2, figsize=(TWO, 2.3))
    fig.subplots_adjust(left=0.07, right=0.99, top=0.84, bottom=0.19, wspace=0.22)
    populations = [10, 100, 1000, 10000]
    panels = (("exposure_max", 0, "Exposure (s)", 1.0),
              ("completion", 30, "Benign completion (%)", 100.0))
    for ax, (measure, outage, label, scale) in zip(axes, panels):
        for policy in MAIN:
            name, color, marker = STYLE[policy]
            xs, ys = [], []
            for n in populations:
                group = "validation" if n <= 100 else "scaling"
                entry = sim.get(f"{group}-n{n}-{policy}-o{outage}")
                if entry and entry[measure]:
                    xs.append(n)
                    ys.append(entry[measure]["mean"] * scale)
            ax.plot(xs, ys, color=color, marker=marker, markersize=3, linewidth=0.8, label=name)
            for n, section, key in ((10, "primary", f"{policy}-o{outage}"),
                                    (100, "sensitivity", f"n100-{policy}-o{outage}")):
                entry = live[section].get(key)
                if entry:
                    ax.scatter([n], [entry[measure]["mean"] * scale], s=30, marker="x", color=color,
                               linewidth=0.8, zorder=4)
        ax.set_xscale("log")
        ax.set_xticks(populations)
        ax.set_xticklabels(["10", "100", "1,000", "10,000"])
        ax.minorticks_off()
        ax.set_xlabel("Devices")
        ax.set_ylabel(label)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
    axes[0].set_yscale("symlog", linthresh=1.0, linscale=0.6)
    axes[0].set_ylim(-0.08, 100)
    axes[0].set_yticks([0, 1, 10, 100])
    axes[0].set_yticklabels(["0", "1", "10", "100"])
    axes[1].set_ylim(60, 100)
    axes[0].text(-0.13, 1.05, "(a)", transform=axes[0].transAxes, fontsize=7.5)
    axes[1].text(-0.13, 1.05, "(b)", transform=axes[1].transAxes, fontsize=7.5)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=5, fontsize=6.2, columnspacing=1.2, handletextpad=0.4,
               bbox_to_anchor=(0.5, 1.0))
    save(fig, "fig4_scaling")


if __name__ == "__main__":
    wanted = sys.argv[1:] or ["1", "2", "3", "4"]
    for number, draw in (("1", figure1), ("2", figure2), ("3", figure3), ("4", figure4)):
        if number in wanted:
            draw()
            print("figure", number, "written")
