import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


POLICIES = {
    "O-TBC": ("O-TBC", "#145c87", "o"),
    "L4": ("L4", "#99682b", "^"),
    "T2": ("T2", "#3d7450", "s"),
    "Direct": ("DM", "#54445f", "D"),
}


def load_blocks(path):
    result = defaultdict(list)
    with path.open(newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            if (row["n"], row["placement"], row["scenario"]) == ("14", "split", "mobile"):
                result[row["policy"]].append(row)
    assert all(len(result[key]) == 10 for key in POLICIES)
    return result


def observed_range(axis, x, values, color, marker):
    middle = statistics.median(values)
    axis.errorbar(
        x,
        middle,
        yerr=[[middle - min(values)], [max(values) - middle]],
        fmt=marker,
        markersize=3.3,
        color=color,
        capsize=2.1,
        elinewidth=0.65,
        capthick=0.65,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("blocks", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = load_blocks(args.blocks)
    plt.rcParams.update({"font.size": 6.5, "axes.labelsize": 6.5, "pdf.fonttype": 42})
    fig, (goodput, latency) = plt.subplots(1, 2, figsize=(3.45, 1.39))
    fig.subplots_adjust(left=0.125, right=0.984, bottom=0.245, top=0.960, wspace=0.47)
    for position, (policy, (_, color, marker)) in enumerate(POLICIES.items()):
        rows = data[policy]
        observed_range(
            goodput, position, [float(row["sequential_goodput"]) for row in rows], color, marker
        )
        cap = statistics.median(float(row["peak_median"]) for row in rows)
        observed_range(
            latency, cap, [float(row["producer_median_ms"]) / 1000 for row in rows], color, marker
        )
    goodput.set_xlim(-0.42, 3.46)
    goodput.set_xticks(range(len(POLICIES)), [value[0] for value in POLICIES.values()])
    goodput.set_yticks([0.6, 0.8, 1.0, 1.2])
    goodput.set_ylabel("Correct decisions/s")
    latency.set_xlim(7.4, 13.55)
    latency.set_xticks([8, 9, 11, 13])
    latency.set_yticks([0.6, 0.8, 1.0, 1.2, 1.4])
    latency.set_xlabel("Peak identities per epoch")
    latency.set_ylabel("Producer latency (s)")
    for axis in (goodput, latency):
        axis.spines[["top", "right"]].set_visible(False)
        axis.spines[["left", "bottom"]].set_linewidth(0.5)
        axis.grid(axis="y", color="#d3d8db", linewidth=0.45, alpha=0.9)
        axis.set_axisbelow(True)
        axis.tick_params(width=0.45, length=2, pad=2)
    fig.savefig(args.output, metadata={"CreationDate": None, "ModDate": None})


if __name__ == "__main__":
    main()
