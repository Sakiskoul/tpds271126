"""Plot measured certificate size and CPU and the paired break-even model."""

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.summary.read_text())["certificates"]
    by_key = {(row["n"], row["B"], row["case"]): row for row in data}
    cases = ("honest", "two", "four", "l4")
    labels = ("1 epoch", "2 epochs", "4 epochs", "L4")
    colors = ("#0072b2", "#008768", "#b55731", "#555555")
    markers = ("o", "s", "^", "D")
    plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"],
                         "font.size": 7.5, "pdf.fonttype": 42,
                         "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(1, 4, figsize=(7, 1.74))
    fig.subplots_adjust(left=.07, right=.99, bottom=.22, top=.78, wspace=.53)
    for i, case in enumerate(cases):
        row = by_key[14, 256, case]
        for axis, field, factor in ((axes[0], "bytes", 1000), (axes[1], "cpu_ns", 1e6)):
            for j, format_name in enumerate(("full", "compact")):
                height = row[f"{format_name}_{field}"]["median"] / factor
                axis.bar(i + (j - .5) * .34, height, width=.32,
                         color=("#767676", "#0072b2")[j],
                         label=("Full", "Compact")[j] if i == 0 else None)
        for axis, mode in ((axes[2], "full"), (axes[3], "compact")):
            batches = (32, 128, 256)
            y = [by_key[14, batch, case][mode + "_median_finite_r"] for batch in batches]
            axis.plot((0, 1, 2), y, color=colors[i], marker=markers[i], label=labels[i],
                      linewidth=1, markersize=3)
    direct = by_key[14, 256, "honest"]["direct_cpu_ns"]["median"] / 1e6
    axes[1].set_title(f"Consumer CPU (ms)\nDirect: {direct:.1f} ms", fontsize=7.7)
    axes[0].set_title("Certificate size (kB)\nBatch 256", fontsize=7.7)
    axes[0].legend(frameon=False, fontsize=6.8)
    for axis in axes[:2]:
        axis.set_xticks(range(4), ("1", "2", "4", "L4"))
    for axis, label in ((axes[2], "Full"), (axes[3], "Compact")):
        axis.set_title(f"{label} break-even\nConsumer count", fontsize=7.7)
        axis.set_yscale("log")
        axis.set_xticks((0, 1, 2), ("32", "128", "256"))
    for axis in axes:
        axis.set_axisbelow(True)
        axis.grid(axis="y", color="#dfdfdf", linewidth=.45)
        axis.tick_params(length=2.2, pad=1.5)
    axes[2].set_xlabel("Batch size", labelpad=1)
    axes[3].set_xlabel("Batch size", labelpad=1)
    handles, names = axes[2].get_legend_handles_labels()
    fig.legend(handles, names, loc="upper center", ncol=4, frameon=False, bbox_to_anchor=(.73, 1.035))
    fig.savefig(args.output, metadata={"Title": "Certificate costs on paired traces",
                                      "Creator": None, "Producer": None, "CreationDate": None})
    plt.close(fig)


if __name__ == "__main__":
    main()
