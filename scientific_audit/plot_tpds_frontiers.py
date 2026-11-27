"""Plot the exact capacity frontier and retained mobile-workload observations."""
import argparse
import csv
from math import isclose
from pathlib import Path
from statistics import median

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator, PercentFormatter
from matplotlib.transforms import offset_copy


REVISION = Path(__file__).resolve().parent
SYSTEMS = (REVISION.parent / "reference-data" / "systems_v8")
WORKERS = (14, 42, 82, 162)
POLICIES = {
    "O-TBC": ("O-TBC", "#0072B2", "o", "-", 15),
    "L4": ("L4", "#4B4B4B", "^", ":", 11),
    "Direct": ("DM", "#008C66", "D", "--", 9),
    "ES-QM": ("ES-QM", "#A14D00", "s", "-.", 10),
    "ES-stream": ("ES-S", "#7951A1", "v", (0, (1, 1.8)), 12),
}


def exact_cap(f, c):
    """Return the theorem's integer cap at 1, 2, 3, and at least 4 epochs."""
    if not 1 <= c < f:
        raise ValueError("The frontier requires 1 <= c < f.")
    return 2 * f + 1, (4 * f + 2 * c) // 3 + 1, (6 * f + 4 * c) // 5 + 1, f + c + 1


def read_mobile_cells(path, populations, block_size):
    cells = {(policy, workers): [] for policy in POLICIES for workers in populations}
    with path.open(newline="", encoding="utf-8-sig") as data:
        for row in csv.DictReader(data):
            key = row["policy"], int(row["n"])
            if key not in cells or row["scenario"] != "mobile":
                continue
            if tuple(int(row[field]) for field in ("batch", "slots", "clients")) != (32, 4, 4):
                continue
            block = row["block_id"]
            attempts, correct, wrong, unresolved = (
                int(row[field]) for field in ("attempts", "correct", "wrong", "unresolved")
            )
            if attempts != block_size or correct + wrong + unresolved != attempts:
                raise ValueError(f"Unexpected request counts in {path}: {block}")
            if not isclose(float(row["goodput_cert_s"]), correct / float(row["elapsed_s"]),
                           abs_tol=1e-8, rel_tol=0.0):
                raise ValueError(f"Recorded goodput disagrees with decision count in {path}: {block}")
            cells[key].append(row)
    for key, rows in cells.items():
        if sorted(int(row["repeat"]) for row in rows) != [0, 1, 2]:
            raise ValueError(f"Expected exactly three repetitions for {key} in {path}")
        if len({row["block_id"] for row in rows}) != 3:
            raise ValueError(f"Repeated block ID for {key} in {path}")
    return cells


def by_admission(blocks, epochs_path):
    reference = {row["block_id"]: (policy, int(row["attempts"]))
                 for (policy, _), rows in blocks.items() for row in rows}
    block_peaks = {block: 0 for block in reference}
    attempts = {block: set() for block in reference}
    with epochs_path.open(newline="", encoding="utf-8-sig") as data:
        for epoch in csv.DictReader(data):
            block = epoch["block_id"]
            if block not in reference:
                continue
            admitted = int(epoch["admitted"])
            block_peaks[block] = max(block_peaks[block], admitted)
            attempts[block].add(epoch["attempt"])
    if any(block_peaks[block] <= 0 or len(attempts[block]) != expected
           for block, (_, expected) in reference.items()):
        raise ValueError(f"Incomplete epoch evidence in {epochs_path}")
    return {policy: max(block_peaks[row["block_id"]] for row in rows)
            for (policy, _), rows in blocks.items()}


def goodput(rows):
    rates = [float(row["goodput_cert_s"]) for row in rows]
    return median(rates), min(rates), max(rates)


def set_axes(axis, x_label, y_label):
    axis.set_xlabel(x_label, labelpad=2.5)
    axis.set_ylabel(y_label, labelpad=3)
    axis.set_axisbelow(True)
    axis.grid(axis="y", color="#D9D9D9", linewidth=0.5)
    axis.tick_params(length=2.5, pad=2)


def save(figure, path, title):
    figure.savefig(path, metadata={"Title": title, "Creator": None,
                                    "Producer": None, "CreationDate": None})
    plt.close(figure)


def plot_capacity(output):
    figure, axis = plt.subplots(figsize=(3.42, 1.76))
    figure.subplots_adjust(left=0.169, right=0.986, bottom=0.235, top=0.82)
    f = 20
    styles = ((1, "#0072B2", "o", "-"), (4, "#A14D00", "s", "--"),
              (8, "#008C66", "D", "-."), (12, "#7951A1", "^", ":"))
    for c, color, marker, line in reversed(styles):
        caps = exact_cap(f, c)
        axis.plot((1, 2, 3, 4), [value / caps[0] for value in caps],
                  color=color, marker=marker, linestyle=line, label=f"{c / f:g}",
                  linewidth=1.1, markersize=3.7, markerfacecolor="white",
                  markeredgewidth=0.8)
    axis.set_xlim(0.86, 4.16)
    axis.set_xticks((1, 2, 3, 4), labels=("1", "2", "3", "4+"))
    axis.set_ylim(0.50, 1.04)
    axis.set_yticks((.50, .60, .70, .80, .90, 1.00))
    axis.yaxis.set_major_formatter(PercentFormatter(xmax=1, decimals=0))
    set_axes(axis, "Allowed epochs", r"Minimum cap / $(2f+1)$")
    handles, labels = axis.get_legend_handles_labels()
    figure.legend(handles[::-1], [rf"$c/f={label}$" if i == 0 else label
                                  for i, label in enumerate(labels[::-1])],
                  loc="upper center", ncol=4, frameon=False, bbox_to_anchor=(0.55, 1.01),
                  handlelength=1.75, columnspacing=0.8, handletextpad=0.4)
    save(figure, output / "tpds_capacity_horizon.pdf", "Exact adaptive admission capacity")


def plot_mobile(population, reference, peaks, output):
    figure, (scale, tradeoff) = plt.subplots(1, 2, figsize=(7.0, 2.14))
    figure.subplots_adjust(left=0.083, right=0.982, bottom=0.212, top=0.77, wspace=0.24)
    handles = {}
    for policy, (label, color, marker, line, zorder) in POLICIES.items():
        values, lows, highs = zip(*(goodput(population[policy, workers]) for workers in WORKERS))
        lower = [value - low for value, low in zip(values, lows)]
        upper = [high - value for high, value in zip(highs, values)]
        handles[policy] = scale.errorbar(
            WORKERS, values, yerr=[lower, upper], label=label, color=color, linestyle=line,
            marker=marker, markerfacecolor="white", markeredgewidth=0.8, linewidth=1.1,
            markersize=3.7, capsize=1.4, elinewidth=0.6, capthick=0.6, zorder=zorder
        )
    scale.set_title("(a) Population scaling", loc="left", pad=4, fontweight="bold")
    scale.set_xlim(6, 171)
    scale.set_ylim(0, 25.8)
    scale.set_xticks(WORKERS)
    scale.yaxis.set_major_locator(MultipleLocator(5))
    set_axes(scale, "Logical workers", "Correct decisions/s")

    medians = {policy: goodput(reference[policy, 42])[0] for policy in POLICIES}
    nondominated = [policy for policy in POLICIES if not any(
        peaks[other] <= peaks[policy] and medians[other] >= medians[policy]
        and (peaks[other] < peaks[policy] or medians[other] > medians[policy])
        for other in POLICIES if other != policy
    )]
    nondominated.sort(key=lambda policy: peaks[policy])
    tradeoff.plot([peaks[policy] for policy in nondominated],
                  [medians[policy] for policy in nondominated],
                  linestyle="--", color="#737373", linewidth=0.85, zorder=2)
    offsets = {"Direct": -7, "ES-QM": 7, "ES-stream": 0}
    for policy, (_, color, marker, _, zorder) in POLICIES.items():
        value, low, high = goodput(reference[policy, 42])
        position = offset_copy(tradeoff.transData, fig=figure,
                               x=offsets.get(policy, 0), units="points")
        tradeoff.errorbar(peaks[policy], value, yerr=[[value - low], [high - value]],
                         transform=position, color=color, marker=marker, linestyle="none",
                         markerfacecolor="white", markeredgewidth=0.9, markersize=4,
                         elinewidth=0.8, capsize=2, zorder=zorder)
    tradeoff.set_title("(b) Observed admission tradeoff", loc="left", pad=4, fontweight="bold")
    tradeoff.set_xlim(16.5, 46.5)
    tradeoff.set_ylim(3, 7.7)
    tradeoff.set_xticks(sorted(set(peaks.values())))
    tradeoff.yaxis.set_major_locator(MultipleLocator(1))
    set_axes(tradeoff, "Peak admitted identities per epoch", "Correct decisions/s")
    figure.legend([handles[key] for key in POLICIES], [POLICIES[key][0] for key in POLICIES],
                  loc="upper center", ncol=5, frameon=False, bbox_to_anchor=(0.53, 1.01),
                  handlelength=2.1, columnspacing=2.1)
    save(figure, output / "tpds_population_admission.pdf", "Mobile goodput and peak admission")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--systems-dir", type=Path, default=SYSTEMS)
    parser.add_argument("--output-dir", type=Path, default=REVISION / "manuscript" / "figures")
    args = parser.parse_args()
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
        "font.size": 8.5, "axes.titlesize": 8.8, "axes.labelsize": 8.5,
        "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.65,
        "xtick.labelsize": 8.2, "ytick.labelsize": 8.2, "legend.fontsize": 8.3,
        "pdf.fonttype": 42, "pdf.compression": 9, "mathtext.fontset": "stix",
    })
    if exact_cap(20, 1) != (41, 28, 25, 22):
        raise ValueError("The exact-cap formulas disagree with the manuscript example.")
    sweep = read_mobile_cells(args.systems_dir / "results" / "blocks.csv", WORKERS, 16)
    longer = args.systems_dir / "results_long"
    reference = read_mobile_cells(longer / "blocks.csv", (42,), 64)
    peaks = by_admission(reference, longer / "epochs.csv")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    plot_capacity(args.output_dir)
    plot_mobile(sweep, reference, peaks, args.output_dir)
    for policy, (label, _, _, _, _) in POLICIES.items():
        medians = ", ".join(f"{goodput(sweep[policy, n])[0]:.3f}" for n in WORKERS)
        center, low, high = goodput(reference[policy, 42])
        print(f"{label}: population [{medians}], reference {center:.3f} "
              f"[{low:.3f}, {high:.3f}], peak {peaks[policy]}")


if __name__ == "__main__":
    main()
