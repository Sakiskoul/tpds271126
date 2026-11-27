import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


STYLES = {
    "O-TBC": ("#145c87", "o", "O-TBC"),
    "L4": ("#99682b", "^", "L4"),
    "T2": ("#3d7450", "s", "T2"),
    "Direct": ("#54445f", "D", "DM"),
    "ES-QM": ("#6e777e", "v", "ES-QM"),
    "ES-stream": ("#b96451", "P", "ES-S"),
}


def read_data(files):
    for path in files:
        with path.open(newline="", encoding="utf-8") as stream:
            yield from csv.DictReader(stream)


def plot(data, output):
    populations = sorted({int(row["n"]) for row in data})
    scenarios = [name for name in ("honest", "mobile") if any(row["scenario"] == name for row in data)]
    plt.rcParams.update(
        {"font.size": 8, "axes.labelsize": 8, "axes.titlesize": 8, "legend.fontsize": 7, "pdf.fonttype": 42}
    )
    fig, axes = plt.subplots(
        len(scenarios), len(populations), squeeze=False, sharey=True,
        figsize=(3.32 * len(populations), 1.95 * len(scenarios) + 0.50), layout="constrained",
    )
    styles = [policy for policy in STYLES if any(row["policy"] == policy for row in data)]
    for column, n in enumerate(populations):
        for line, scenario in enumerate(scenarios):
            axis = axes[line, column]
            subset = [row for row in data if int(row["n"]) == n and row["scenario"] == scenario]
            for row in subset:
                color, marker, label = STYLES[row["policy"]]
                filled = row["placement"] == "split"
                x = float(row["peak_median"])
                median = float(row["producer_median_ms"])
                upper = float(row["producer_p95_ms"]) - median
                axis.errorbar(
                    x, median, yerr=[[0], [upper]], color=color, marker=marker,
                    markerfacecolor=color if filled else "white", markeredgecolor=color,
                    markersize=4.4, linestyle="none", linewidth=0.65, capsize=2,
                )
            axis.set_title(f"{scenario.capitalize()} workload, {n} workers")
            axis.set_yscale("log")
            axis.grid(axis="y", color="#d3d8db", linewidth=0.5, alpha=0.8)
            axis.set_xticks(sorted({float(row["peak_median"]) for row in subset}))
            if column == 0:
                axis.set_ylabel("Producer latency (ms)")
            if line == len(scenarios) - 1:
                axis.set_xlabel("Median peak admitted identities")
            axis.spines[["top", "right"]].set_visible(False)
    policy_keys = [
        Line2D([], [], color=STYLES[name][0], marker=STYLES[name][1], markersize=4.4,
               label=STYLES[name][2], linestyle="none")
        for name in styles
    ]
    placement_keys = [
        Line2D([], [], color="#24292c", marker="o", markerfacecolor=fill, markersize=4.4,
               label=name, linestyle="none")
        for fill, name in [("white", "Local"), ("#24292c", "Split")]
    ]
    fig.legend(handles=policy_keys + placement_keys, ncol=4, loc="outside lower center", frameon=False)
    fig.savefig(output, metadata={"CreationDate": None, "ModDate": None})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("summary", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plot(list(read_data(args.summary)), args.output)


if __name__ == "__main__":
    main()
