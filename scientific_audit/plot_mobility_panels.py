"""Plot block-level mobility outcomes for the matched and fixed designs."""

import argparse
from collections import defaultdict
from pathlib import Path
from statistics import median

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from analyze_final_measurements import rows


POLICY = {
    "O-TBC": ("O-TBC", "#0072b2", "o", "-"),
    "L4": ("L4", "#555555", "^", ":"),
    "Direct": ("DM", "#d55e00", "D", "--"),
    "ES-QM": ("ES-QM", "#008c6b", "s", "-."),
    "ES-stream": ("ES-S", "#9658a1", "v", "--"),
}
METRICS = [
    ("goodput_cert_s", "Correct decisions/s"), ("latency_p95_ms", "Block p95 (ms)"),
    ("jobs_per_attempt", "Jobs/decision"), ("epochs_per_attempt", "Epochs/decision"),
]
CHURN = (1, 2, 4, 8, 12)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    trials = defaultdict(list)
    for trial in rows(args.run / "trials.csv"):
        trials[trial["block_id"]].append(trial)
    block_rows = rows(args.run / "blocks.csv")
    assert len(block_rows) == len(trials) == 180
    assert sum(map(len, trials.values())) == 1440
    series = defaultdict(list)
    for block in block_rows:
        requests = trials[block["block_id"]]
        assert len(requests) == 8 and all(row["correct"] == "1" for row in requests)
        block["jobs_per_attempt"] = median(int(row["jobs"]) for row in requests)
        block["epochs_per_attempt"] = median(int(row["epochs"]) for row in requests)
        series[block["dimension"], int(block["realized_churn"]), block["policy"]].append(block)
    plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"],
                         "font.size": 7.5, "pdf.fonttype": 42,
                         "axes.spines.top": False, "axes.spines.right": False})
    fig, axes = plt.subplots(2, 4, figsize=(7, 2.85), sharex=True, sharey="col")
    fig.subplots_adjust(left=.08, right=.995, bottom=.14, top=.84, wspace=.38, hspace=.22)
    for row, dimension in enumerate(("matched", "fixed")):
        for col, (metric, title) in enumerate(METRICS):
            ax = axes[row, col]
            for policy, (label, color, marker, ls) in POLICY.items():
                if metric in {"jobs_per_attempt", "epochs_per_attempt"} and policy in {"ES-QM", "ES-stream"}:
                    for a in CHURN:
                        arm = "matched" if a == 12 else dimension
                        assert [r[metric] for r in series[arm, a, "Direct"]] == [
                            r[metric] for r in series[arm, a, policy]]
                    continue
                cells = [[float(r[metric]) for r in series[
                    "matched" if a == 12 else dimension, a, policy]] for a in CHURN]
                assert all(len(cell) == 4 for cell in cells)
                values = [median(cell) for cell in cells]
                ranges = ([m - min(cell) for m, cell in zip(values, cells)],
                          [max(cell) - m for m, cell in zip(values, cells)])
                ax.errorbar(CHURN, values, yerr=ranges, color=color, linestyle=ls, marker=marker,
                            label=label, linewidth=1, markersize=3.5, capsize=1.5,
                            markerfacecolor="white", elinewidth=.7)
            if row == 0:
                ax.set_title(title, pad=3)
            if col == 0:
                ax.set_ylabel(dimension.capitalize(), labelpad=4)
            if metric == "epochs_per_attempt":
                ax.set_yticks((1, 2, 3, 4))
            ax.set_xticks(CHURN)
            ax.tick_params(pad=1.5, length=2.5)
            ax.grid(axis="y", color="#dddddd", linewidth=.5)
            ax.set_axisbelow(True)
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=5, frameon=False, bbox_to_anchor=(.52, 1.01))
    fig.supxlabel("Injected entry budget", y=.02, fontsize=7.5)
    fig.savefig(args.output, metadata={"Title": "Mobility, work, and latency",
                                      "Creator": None, "Producer": None, "CreationDate": None})
    plt.close(fig)


if __name__ == "__main__":
    main()
