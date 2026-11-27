"""Render exact resource curves and the conceptual separating-cohort diagram."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, Rectangle
from matplotlib.ticker import PercentFormatter


HERE = Path(__file__).resolve().parent
F, C = 20, 1
BLUE = "#0072B2"
TEAL = "#008C66"
INK = "#263348"
GREY = "#545D69"
BAND = "#F8E7E1"


def adaptive_cap(f, c):
    return 2 * f + 1, (4 * f + 2 * c) // 3 + 1, (6 * f + 4 * c) // 5 + 1, f + c + 1


def two_epoch_points(path):
    reference = json.loads(path.read_text(encoding="utf-8"))["reference"]
    points = {}
    for n in range(40, 46):
        finite = [row for row in reference[str(n)].values() if row is not None]
        best = min(finite, key=lambda row: row["cap"], default=None)
        if best is not None:
            points[n] = best["cap"], best["work"]
    if points != {41: (41, 41), 42: (28, 55), 43: (22, 43), 44: (22, 43), 45: (22, 43)}:
        raise ValueError("Unexpected verified minimum caps or work values in two-epoch audit.")
    return points


def save(figure, path, title):
    figure.savefig(path, metadata={"Title": title, "Creator": None,
                                    "Producer": None, "CreationDate": None})
    plt.close(figure)


def graph_style(axis, title, xlabel, ylabel):
    axis.set_title(title, loc="left", weight="bold", pad=5)
    axis.set_xlabel(xlabel, labelpad=2.7)
    axis.set_ylabel(ylabel, labelpad=3.2)
    axis.tick_params(length=2.5, pad=2)
    axis.set_axisbelow(True)
    axis.grid(axis="y", color="#DDDDE1", linewidth=0.5)


def horizon_panel(axis):
    h = (1, 2, 3, 4)
    majority = 2 * F + 1
    cap = adaptive_cap(F, C)
    axis.axhspan(16, F + C, color=BAND, linewidth=0)
    axis.plot(h, [majority] * len(h), color=GREY, linestyle="--", linewidth=1.0)
    axis.plot(h, cap, color=BLUE, linewidth=1.15, marker="o",
              markerfacecolor="white", markeredgewidth=0.85, markersize=3.8)
    axis.scatter(4, F + C + 1, marker="D", color=BLUE, s=16, zorder=3)
    axis.annotate("Predetermined", (3.95, majority), xytext=(0, 3),
                  textcoords="offset points", ha="right", color=GREY, fontsize=7.1)
    axis.text(1.66, 34.8, "Adaptive", color=BLUE, fontsize=7.1)
    axis.annotate("O-TBC", (4, F + C + 1), xytext=(-2, 8),
                  textcoords="offset points", ha="right", color=BLUE, fontsize=7.1)
    axis.text(2.53, 18.35, r"Infeasible for all $T$", ha="center",
              va="center", color="#7B4943", fontsize=7.0)
    axis.set_xticks(h, labels=("1", "2", "3", "4+"))
    axis.set_xlim(0.85, 4.18)
    axis.set_ylim(16, 45)
    axis.set_yticks((20, 25, 30, 35, 40))
    graph_style(axis, "(a) Adaptive vs. fixed", "Allowed epochs", "Minimum cap")


def mobility_panel(axis):
    h = (1, 2, 3, 4)
    for churn, color, marker, style in (
        (12, "#7951A1", "^", ":"), (8, TEAL, "D", "-."),
        (4, "#A14D00", "s", "--"), (1, BLUE, "o", "-"),
    ):
        cap = adaptive_cap(F, churn)
        normalized = [value / cap[0] for value in cap]
        axis.plot(h, normalized, color=color, marker=marker, linestyle=style,
                  linewidth=1.08, markerfacecolor="white", markeredgewidth=0.75,
                  markersize=3.1)
        axis.annotate(f"{churn/F:.2f}", (4, normalized[-1]), xytext=(5, 0),
                      textcoords="offset points", color=color, va="center", fontsize=7.1)
    axis.text(4.1, .898, r"$c/f$", fontsize=7.4, color=INK)
    axis.set_xticks(h, labels=("1", "2", "3", "4+"))
    axis.set_xlim(0.85, 4.74)
    axis.set_ylim(.49, 1.045)
    axis.set_yticks((.50, .60, .70, .80, .90, 1.00))
    axis.yaxis.set_major_formatter(PercentFormatter(xmax=1, decimals=0))
    graph_style(axis, "(b) Mobility sensitivity", "Allowed epochs", r"Cap / $(2f+1)$")


def work_panel(axis, points):
    positions = tuple(points)
    caps, works = zip(*points.values())
    axis.axvspan(39.55, 40.42, color=BAND, linewidth=0)
    axis.text(40, 36.8, "Infeasible", rotation=90, ha="center",
              va="center", color="#7B4943", fontsize=7.2)
    axis.plot(positions, works, linestyle="none", color=TEAL, marker="s",
              markersize=4.4, markeredgewidth=0.8, markerfacecolor="white",
              label="Work at min. cap", zorder=2.7)
    axis.plot(positions, caps, linestyle="none", color=BLUE, marker="o",
              markersize=2.9, label="Minimum cap", zorder=3)
    for n, target, text, offset in (
        (41, 41, "41", (-5, 3)), (42, 55, "55", (-2, 3)), (42, 28, "28", (-2, 3)),
        (43, 43, "43", (-2, 3)), (43, 22, "22", (-2, 3)),
    ):
        axis.annotate(text, (n, target), xytext=offset, textcoords="offset points",
                      color=INK, ha="right", fontsize=6.8)
    axis.set_xticks(range(40, 46))
    axis.set_xlim(39.55, 45.35)
    axis.set_ylim(17, 62)
    axis.set_yticks((20, 30, 40, 50, 60))
    graph_style(axis, "(c) Two-epoch resources", r"Eligible population $n$", "Identities or jobs")
    axis.legend(loc="upper right", frameon=False, fontsize=6.6, handlelength=1.15,
                borderaxespad=0.25, handletextpad=0.35, labelspacing=0.3, markerscale=1.0)


def frontiers(points, output):
    figure, axes = plt.subplots(1, 3, figsize=(7.0, 1.91))
    figure.subplots_adjust(left=0.059, right=0.987, bottom=0.248, top=0.83, wspace=0.46)
    horizon_panel(axes[0])
    mobility_panel(axes[1])
    work_panel(axes[2], points)
    save(figure, output, "Exact horizons, admission caps, and two-epoch work")


def node(axis, x, y, width, height, label, face, edge):
    axis.add_patch(Rectangle((x, y), width, height, facecolor=face,
                             edgecolor=edge, linewidth=0.75))
    axis.text(x + width / 2, y + height / 2, label, color=INK,
              ha="center", va="center", linespacing=1.14, fontsize=8.2)


def arrow(axis, start, end):
    axis.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>",
                                   mutation_scale=6.5, linewidth=0.8,
                                   shrinkA=0, shrinkB=0, color=GREY))


def concept(output):
    figure = plt.figure(figsize=(3.42, 2.14))
    axis = figure.add_axes((0.02, 0.016, 0.96, 0.968), xlim=(0, 1), ylim=(0, 1))
    axis.axis("off")
    node(axis, .218, .83, .564, .15, "Sealed replies\nSigned positive and negative labels",
         "#E9F2FA", "#7598B3")
    axis.plot((.5, .5), (.83, .76), color=GREY, linewidth=0.8)
    axis.plot((.25, .75), (.76, .76), color=GREY, linewidth=0.8)
    for x, label in ((.025, r"If $b=0$"), (.525, r"If $b=1$")):
        node(axis, x, .52, .45, .168, label + "\nFeasible exposure histories",
             "#F4F6F9", "#939DAD")
        mid = x + .225
        arrow(axis, (mid, .76), (mid, .688))
        axis.plot((mid, mid), (.52, .456), color=GREY, linewidth=0.8)
    axis.plot((.25, .75), (.456, .456), color=GREY, linewidth=0.8)
    arrow(axis, (.5, .456), (.5, .40))
    node(axis, .13, .235, .74, .165, "Select a separating cohort\nif one fits the admission cap",
         "#E9F2FA", "#7598B3")
    arrow(axis, (.5, .235), (.5, .153))
    node(axis, .10, .005, .8, .148, "A feasible complete reply\nleaves one result hypothesis",
         "#EAF5EE", "#72947D")
    save(figure, output, "Conceptual path from sealed evidence to separation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--two-epoch-checks", type=Path, default=HERE / "two_epoch_checks.json")
    parser.add_argument("--output-dir", type=Path, default=HERE.parent / "outputs" / "figures")
    args = parser.parse_args()
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
        "font.size": 8.25, "axes.titlesize": 8.4, "axes.labelsize": 8.1,
        "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.65,
        "xtick.labelsize": 7.4, "ytick.labelsize": 7.4, "legend.fontsize": 7.3,
        "pdf.fonttype": 42, "pdf.compression": 9, "mathtext.fontset": "stix",
    })
    points = two_epoch_points(args.two_epoch_checks)
    if adaptive_cap(F, C) != (41, 28, 25, 22):
        raise ValueError("Exact horizon formula disagrees with reference.")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    frontiers(points, args.output_dir / "tpds_exact_frontiers.pdf")
    concept(args.output_dir / "tpds_cohort_concept.pdf")
    print("n=40 infeasible; minimum finite cap, work at that cap:", points)


if __name__ == "__main__":
    main()
