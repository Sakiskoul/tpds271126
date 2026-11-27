"""Redraw the system boundaries and replay the paired consumer CPU accounting."""
import argparse
import csv
from math import isclose
from pathlib import Path
from statistics import median

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import FancyArrowPatch, Rectangle
from matplotlib.ticker import NullLocator


REVISION = Path(__file__).resolve().parent
RESULTS = (REVISION.parent / "reference-data" / "experiments" / "results_final")
BATCHES = (1, 32, 256)
BLUE = "#0072B2"
TEAL = "#008C66"
INK = "#283448"


def save(figure, output, title):
    figure.savefig(output, metadata={"Title": title, "Creator": None,
                                      "Producer": None, "CreationDate": None})
    plt.close(figure)


def frame(axis, x, y, width, height, color, edge, style="-"):
    axis.add_patch(Rectangle((x, y), width, height, facecolor=color,
                             edgecolor=edge, linewidth=0.75, linestyle=style))


def block(axis, left, right, bottom, top, label, color, edge):
    frame(axis, left, bottom, right - left, top - bottom, color, edge)
    axis.text((left + right) / 2, (bottom + top) / 2, label, ha="center",
              va="center", linespacing=1.1, fontsize=8.1, color=INK)


def arrow(axis, start, end, color=INK, style="-|>"):
    axis.add_patch(FancyArrowPatch(start, end, arrowstyle=style, mutation_scale=7,
                                   color=color, linewidth=0.85,
                                   shrinkA=0, shrinkB=0))


def route(axis, vertices, start_arrow=False):
    axis.add_line(Line2D(*zip(*vertices), linewidth=0.85, color=INK))
    if start_arrow:
        x, y = vertices[0]
        arrow(axis, (x, vertices[1][1]), (x, y))
    arrow(axis, vertices[-2], vertices[-1])


def architecture(output):
    figure = plt.figure(figsize=(7.0, 1.89))
    axis = figure.add_axes((0.005, 0.012, 0.990, 0.976), xlim=(0, 1), ylim=(0, 1))
    axis.set_axis_off()
    frame(axis, 0.012, 0.365, 0.976, 0.620, "#F6FAFD", "#7896AD")
    frame(axis, 0.012, 0.020, 0.976, 0.280, "#F7FAF7", "#6D8F82", "--")
    axis.text(0.031, 0.940, "Timed concurrent certification", fontweight="bold",
              va="center", color=INK)
    axis.text(0.969, 0.940, "One host, loopback TCP", ha="right",
              va="center", color="#445466", fontsize=7.8)

    timed_nodes = (
        (0.028, 0.124, "Concurrent\nclients"),
        (0.155, 0.345, "Scheduler\nShared RPC executor"),
        (0.396, 0.551, "ML-DSA workers\nSign result reports"),
        (0.583, 0.738, "SQLite closure\nDurable signed seal"),
        (0.767, 0.971, "Independent verifier\nChecks full transcript"),
    )
    for left, right, label in timed_nodes:
        block(axis, left, right, 0.600, 0.804, label, "#E9F2FA", "#7896AD")

    arrow(axis, (0.124, 0.702), (0.155, 0.702))
    arrow(axis, (0.345, 0.702), (0.396, 0.702), style="<->")
    route(axis, ((0.266, 0.804), (0.266, 0.869), (0.869, 0.869), (0.869, 0.804)))
    route(axis, ((0.266, 0.600), (0.266, 0.512), (0.661, 0.512), (0.661, 0.600)),
          start_arrow=True)
    axis.text(0.570, 0.880, "sealed transcript", ha="center", va="bottom",
              fontsize=7.6, color=INK)
    axis.text(0.464, 0.501, "reports to closure, seal to scheduler", ha="center",
              va="top", fontsize=7.6, color=INK)
    axis.text(0.031, 0.383, "Clients, scheduler, and verifier share the coordinator process.",
              va="bottom", color="#445466", fontsize=7.6)

    axis.text(0.031, 0.181, "Separate admission test", fontweight="bold",
              va="center", color=INK)
    axis.text(0.031, 0.107, "One pinned attempt", va="center",
              color="#445466", fontsize=7.7)
    admission_nodes = (
        (0.269, 0.462, "Admission authority\nSigns cohort ticket"),
        (0.538, 0.716, "Worker gate\nCheck ticket before task"),
        (0.792, 0.971, "Authority closure\nOwn cutoff timer"),
    )
    for left, right, label in admission_nodes:
        block(axis, left, right, 0.055, 0.253, label, "#E9F3EC", "#6D8F82")
    arrow(axis, (0.462, 0.141), (0.538, 0.141), color="#345548")
    arrow(axis, (0.716, 0.141), (0.792, 0.141), color="#345548")
    axis.text(0.500, 0.163, "ticket", ha="center", va="bottom",
              fontsize=7.2, color="#345548")
    axis.text(0.754, 0.163, "reports", ha="center", va="bottom",
              fontsize=7.2, color="#345548")
    save(figure, output, "Timed certification and separate ticket admission test")


def source_rows(path, encoding_keys=False):
    result = {}
    with path.open(newline="", encoding="utf-8-sig") as data:
        for row in csv.DictReader(data):
            if row["policy"] != "adaptive_four_work" or row["scenario"] != "adversarial_valid":
                continue
            key = (int(row["batch_size"]), int(row["session"]), int(row["repeat"]))
            if encoding_keys:
                key += (row["encoding"],)
            if key in result:
                raise ValueError(f"Duplicate pairing in {path}: {key}")
            result[key] = row
    return result


def paired_costs(root):
    trials = source_rows(root / "trials_raw.csv")
    direct = source_rows(root / "consumer_raw.csv")
    model = source_rows(root / "consumer_cost_model_raw.csv", encoding_keys=True)
    if set(trials) != set(direct) or set(model) != {
            key + (encoding,) for key in trials for encoding in ("full", "compact")}:
        raise ValueError("The direct, certificate, and model inputs have different pair keys.")
    batches = {batch: [] for batch in BATCHES}
    for key, trial in trials.items():
        direct_row = direct[key]
        if trial["decision"] != "1" or direct_row["operation"] != "direct_local_batch_verify":
            raise ValueError(f"Unexpected trace or operation in pair {key}")
        D = float(direct_row["cpu_ns_per_batch"])
        E = float(trial["total_online_cpu_ns"])
        F = float(trial["full_verify_cpu_ns"])
        V = float(trial["compact_verify_cpu_ns"])
        if D != float(trial["local_direct_cpu_ns"]) or min(D, E, F, V) <= 0:
            raise ValueError(f"Invalid costs in pair {key}")
        for encoding, cost in (("full", F), ("compact", V)):
            row = model[key + (encoding,)]
            expected = (D, E, cost)
            actual = tuple(float(row[field]) for field in
                           ("direct_cpu_ns", "producer_cpu_ns", "certificate_cpu_ns"))
            if actual != expected or not isclose((E + 14 * cost) / (14 * D),
                                                  float(row["model_cost_ratio_at_R14"])):
                raise ValueError(f"Model costs disagree with paired inputs in {key}, {encoding}")
        batches[key[0]].append((D, F, V, E))
    if any(len(rows) != 24 for rows in batches.values()):
        raise ValueError("Expected 24 paired trials per batch.")
    return batches


def axes_style(axis, x, y):
    axis.set_xlabel(x, labelpad=3)
    axis.set_ylabel(y, labelpad=3)
    axis.tick_params(length=2.5, pad=2)
    axis.set_axisbelow(True)
    axis.grid(axis="y", color="#D9D9D9", linewidth=0.5)


def median_ratio(rows, readers):
    return median((E + readers * V) / (readers * D) for D, _, V, E in rows)


def cpu_figure(batches, output):
    figure, (consumer, total) = plt.subplots(1, 2, figsize=(7.0, 2.24))
    figure.subplots_adjust(left=0.088, right=0.982, bottom=0.221, top=0.852, wspace=0.388)
    for index, label, color, marker, line in (
        (0, "Direct verification", BLUE, "o", "-"),
        (1, "Full certificate", "#8261A0", "D", "--"),
        (2, "Compact certificate", TEAL, "s", "-."),
    ):
        values = [median(row[index] for row in batches[batch]) / 1e6 for batch in BATCHES]
        consumer.plot(BATCHES, values, color=color, marker=marker, linestyle=line,
                      linewidth=1.15, markersize=4, markerfacecolor="white",
                      markeredgewidth=0.8, label=label)
    consumer.set_title("(a) Consumer verification", loc="left", pad=5, weight="bold")
    consumer.set_xscale("log", base=2)
    consumer.set_yscale("log")
    consumer.set_xlim(0.78, 350)
    consumer.set_ylim(0.125, 70)
    consumer.set_xticks(BATCHES, labels=[str(batch) for batch in BATCHES])
    consumer.set_yticks((0.2, 1, 5, 20, 50), labels=("0.2", "1", "5", "20", "50"))
    consumer.xaxis.set_minor_locator(NullLocator())
    consumer.yaxis.set_minor_locator(NullLocator())
    axes_style(consumer, "Signatures per batch", "Consumer CPU (ms, log scale)")
    consumer.legend(loc="upper left", frameon=False, borderaxespad=0.45,
                    handlelength=2.1, fontsize=7.8)

    readers = range(4, 129)
    offsets = ((20, 9), (20, 3))
    for (batch, color, marker, line), offset in zip(
            ((32, BLUE, "o", "-"), (256, TEAL, "s", "--")), offsets):
        rows = batches[batch]
        ratios = [median_ratio(rows, readers_count) for readers_count in readers]
        first_saving = next(readers_count for readers_count, ratio in zip(readers, ratios)
                            if ratio < 1)
        total.plot(readers, ratios, color=color, linestyle=line, linewidth=1.2,
                   label=rf"$B={batch}$")
        r14 = median_ratio(rows, 14)
        total.scatter((14, first_saving), (r14, median_ratio(rows, first_saving)),
                      color=color, marker=marker, s=14, facecolors="white",
                      linewidths=0.85, zorder=4)
        total.annotate(rf"{r14:.2f}$\times$", (14, r14), xytext=offset,
                       textcoords="offset points", color=color, fontsize=7.8,
                       va="center")
    total.axhline(1, color="#606060", linestyle=":", linewidth=0.9)
    total.annotate("Equal CPU cost", (126, 1), xytext=(0, 4),
                   textcoords="offset points", ha="right", fontsize=7.7, color="#515151")
    total.set_title("(b) Producer and all consumers", loc="left", pad=5, weight="bold")
    total.set_yscale("log", base=2)
    total.set_xlim(3, 130)
    total.set_ylim(0.275, 14)
    total.set_xticks((14, 32, 64, 96, 128))
    total.set_yticks((0.5, 1, 2, 4, 8), labels=("0.5", "1", "2", "4", "8"))
    total.yaxis.set_minor_locator(NullLocator())
    axes_style(total, r"Consumers $R$ (modeled)", r"CPU ratio $(E+RV)/(RD)$")
    total.legend(loc="upper right", frameon=False, borderaxespad=0.45, handlelength=2.3)
    save(figure, output, "Paired consumer CPU and aggregate CPU accounting")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=RESULTS)
    parser.add_argument("--output-dir", type=Path, default=REVISION / "manuscript" / "figures")
    parser.add_argument("--architecture-only", action="store_true")
    args = parser.parse_args()
    if args.architecture_only:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        architecture(args.output_dir / "tpds_architecture_review.pdf")
        return
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
        "font.size": 8.5, "axes.labelsize": 8.5, "axes.titlesize": 8.8,
        "xtick.labelsize": 8.2, "ytick.labelsize": 8.2, "legend.fontsize": 8.3,
        "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.65,
        "pdf.fonttype": 42, "pdf.compression": 9, "mathtext.fontset": "stix",
    })
    batches = paired_costs(args.results_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    architecture(args.output_dir / "tpds_architecture_review.pdf")
    cpu_figure(batches, args.output_dir / "tpds_consumer_accounting.pdf")
    for batch, rows in batches.items():
        medians = tuple(median(row[index] for row in rows) / 1e6 for index in range(3))
        saving = next((R for R in range(1, 129) if median_ratio(rows, R) < 1), None)
        print(f"B={batch}, n={len(rows)}: direct/full/compact ms={medians}; "
              f"median ratio at R=14={median_ratio(rows, 14):.3f}; "
              f"first saving R in 1–128={saving}")


if __name__ == "__main__":
    main()
