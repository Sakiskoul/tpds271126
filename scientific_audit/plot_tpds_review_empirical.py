"""Redraw the TPDS deadline, epoch, and CometBFT figures from retained trials."""

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import BoundaryNorm, LinearSegmentedColormap
from matplotlib.ticker import MaxNLocator


REVISION = Path(__file__).resolve().parent
ARTIFACT = (
    REVISION.parent
    / "O_TBC_Optimistic_Revision_Package (1)"
    / "O_TBC_Optimistic_Revision"
    / "artifact"
)
DEADLINE_POLICIES = (
    ("O-TBC", "O-TBC"),
    ("L4", "L4"),
    ("QT", "QT"),
    ("Direct", "DM"),
    ("ES-QM", "ES-QM"),
    ("ES-stream", "ES-S"),
)
COMET_POLICIES = {
    "O-TBC": ("O-TBC", "#0072B2", "o", "-"),
    "adaptive_four_work": ("L4", "#4B4B4B", "^", "--"),
    "direct_majority": ("DM", "#A64B00", "s", "-."),
    "local": ("Direct application", "#00755B", "D", ":"),
}
WINDOWS_AND_SLOTS = ((30, 4), (30, 8), (100, 4), (100, 8))
EXTENDED_WINDOWS = (25, 30, 40, 50, 65, 80, 100)
EPOCH_STYLES = {
    1: ("1 epoch", "#0072B2", "white", ""),
    2: ("2 epochs", "#86BFDD", "#161616", ""),
    3: ("3 epochs", "#389F88", "white", ""),
    4: ("4 epochs", "#7F507B", "white", ""),
    "unresolved": ("Unresolved", "#E5E5E5", "#161616", "///"),
}


def read_rows(path):
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def check_outcome(row):
    """Return the epoch count for a correct decision, or the unresolved outcome."""
    if row["correct"] == "1" and row["wrong"] == "0" and row["result"] == row["truth"]:
        epochs = int(row["epochs"])
        if 1 <= epochs <= 4:
            return epochs
    elif row["correct"] == "0" and row["wrong"] == "0" and row["result"] == "unresolved":
        return "unresolved"
    raise ValueError(f"Unexpected outcome for {row['attempt']}")


def read_deadlines(path, scenarios, policies, conditions, repeats):
    rows = read_rows(path)
    expected = {(scenario, policy, window, slots)
                for scenario in scenarios for policy in policies for window, slots in conditions}
    total = 2 * repeats * len(expected)
    if len(rows) != total or len({row["attempt"] for row in rows}) != total:
        raise ValueError(f"Expected {total} distinct deadline attempts in {path}")
    cells = defaultdict(list)
    for row in rows:
        if (row["n"], row["batch"], row["guard_ms"]) != ("42", "8", "100"):
            raise ValueError(f"Unexpected deadline configuration for {row['attempt']}")
        key = (row["scenario"], row["policy"], int(row["deadline_ms"]), int(row["slots"]))
        cells[key].append((int(row["truth"]), int(row["repeat"]), check_outcome(row)))

    if set(cells) != expected:
        raise ValueError(f"Unexpected configurations in {path}")
    repetitions = [(truth, rep) for truth in (0, 1) for rep in range(repeats)]
    for key, observations in cells.items():
        if sorted((truth, rep) for truth, rep, _ in observations) != repetitions:
            raise ValueError(f"Incomplete or duplicated deadline attempt in {key}")
    return cells


def save(figure, output, name, title):
    figure.savefig(
        output / name,
        metadata={"Title": title, "Creator": None, "Producer": None, "CreationDate": None},
    )
    plt.close(figure)


def add_heatmap(axis, cells, conditions, labels, total):
    counts = [
        [sum(outcome != "unresolved" for _, _, outcome in cells["mobile", policy, window, slots])
         for window, slots in conditions]
        for policy, _ in DEADLINE_POLICIES
    ]
    colors = LinearSegmentedColormap.from_list(
        "counts", ("#F4F4F4", "#B3D2E6", "#74B3D3", "#005D90"), N=total + 1
    )
    axis.imshow(counts, cmap=colors, norm=BoundaryNorm(range(total + 2), colors.N), aspect="auto")
    axis.set_xticks(range(len(conditions)), labels)
    axis.set_yticks(range(len(counts)), [label for _, label in DEADLINE_POLICIES])
    for row, values in enumerate(counts):
        for column, correct in enumerate(values):
            axis.text(column, row, f"{correct}/{total}", va="center", ha="center",
                      color="white" if correct / total >= 0.83 else "#18212A", fontsize=8.2)
    axis.set_xticks([index + 0.5 for index in range(len(conditions) - 1)], minor=True)
    axis.set_yticks([index + 0.5 for index in range(len(counts) - 1)], minor=True)
    axis.grid(which="minor", color="white", linewidth=1.2)
    axis.axhline(2.5, color="white", linewidth=3)
    axis.tick_params(which="both", length=0, pad=3)
    for spine in axis.spines.values():
        spine.set_visible(False)


def plot_deadlines(cells, output):
    figure, axis = plt.subplots(figsize=(3.42, 1.84))
    figure.subplots_adjust(left=0.20, right=0.99, top=0.98, bottom=0.255)
    labels = [f"{window} / {slots}" for window, slots in WINDOWS_AND_SLOTS]
    add_heatmap(axis, cells, WINDOWS_AND_SLOTS, labels, total=6)
    axis.axvline(1.5, color="white", linewidth=3)
    axis.set_xlabel("Report window (ms) / RPC slots", labelpad=2)
    save(figure, output, "tpds_deadline_heatmap.pdf", "Mobile deadline outcomes")


def plot_extended_deadlines(cells, output):
    figure, axes = plt.subplots(1, 2, figsize=(7.0, 1.78), sharey=True)
    figure.subplots_adjust(left=0.095, right=0.99, top=0.85, bottom=0.25, wspace=0.08)
    for index, (axis, slots) in enumerate(zip(axes, (4, 8))):
        conditions = [(window, slots) for window in EXTENDED_WINDOWS]
        add_heatmap(axis, cells, conditions, EXTENDED_WINDOWS, total=12)
        axis.set_title(f"({chr(97 + index)}) {slots} RPC slots", loc="left", pad=4)
        axis.set_xlabel("Report window (ms)", labelpad=2)
    axes[1].tick_params(axis="y", labelleft=False)
    save(figure, output, "tpds_extended_deadline_heatmap.pdf", "Extended mobile deadline outcomes")


def read_complete_response(path, scenarios):
    rows = read_rows(path)
    conditions = {"n": "42", "batch": "32", "slots": "4", "clients": "4",
                  "policy": "O-TBC", "deadline_ms": "0", "c": "1"}
    selected = [row for row in rows if all(row[key] == value for key, value in conditions.items())]
    groups = defaultdict(list)
    for row in selected:
        groups[row["scenario"]].append(row)
    if set(groups) != set(scenarios):
        raise ValueError(f"Unexpected complete-response scenarios in {path}")
    repetitions = [(rep, task) for rep in range(3) for task in range(64)]
    counts = {}
    for scenario, values in groups.items():
        if sorted((int(row["block_repeat"]), int(row["task_index"])) for row in values) != repetitions:
            raise ValueError(f"Incomplete or duplicated workload in {path}, {scenario}")
        if len({row["attempt"] for row in values}) != 192:
            raise ValueError(f"Duplicated attempts in {path}, {scenario}")
        counts[scenario] = Counter(check_outcome(row) for row in values)
    return counts


def plot_epochs(artifact, cells, output):
    systems = artifact / "systems_v8"
    complete = read_complete_response(systems / "results_long" / "trials.csv", ("honest", "mobile"))
    complete.update(read_complete_response(systems / "results_static" / "trials.csv", ("static",)))
    labels = ["Honest", "Static", "Mobile"]
    counts = [complete[label.lower()] for label in labels]
    for scenario in ("honest", "mobile"):
        for window in (30, 100):
            labels.append(f"{window} ms, {scenario}")
            counts.append(Counter(outcome for slots in (4, 8)
                                  for _, _, outcome in cells[scenario, "O-TBC", window, slots]))

    figure, axis = plt.subplots(figsize=(3.42, 2.12))
    figure.subplots_adjust(left=0.30, right=0.935, top=0.94, bottom=0.285)
    positions = [0, 1, 2, 3.4, 4.4, 5.4, 6.4]
    totals = [sum(group.values()) for group in counts]
    left = [0.0] * len(counts)
    for key, (label, color, text_color, hatch) in EPOCH_STYLES.items():
        heights = [group[key] for group in counts]
        if not any(heights):
            continue
        widths = [100 * count / total for count, total in zip(heights, totals)]
        axis.barh(positions, widths, left=left, height=0.72, color=color, label=label,
                  edgecolor="#5A5A5A" if hatch else "white", linewidth=0.35, hatch=hatch, zorder=2)
        for index, (width, count) in enumerate(zip(widths, heights)):
            if count:
                axis.text(left[index] + width / 2, positions[index], str(count), ha="center",
                          va="center", color=text_color, fontsize=7.3, zorder=3)
        left = [start + width for start, width in zip(left, widths)]
    axis.set_yticks(positions, labels)
    axis.set_xlim(0, 100)
    axis.set_xticks((0, 50, 100))
    axis.set_xlabel("Share of attempts (%)", labelpad=2)
    axis.axhline(2.7, color="#B6B6B6", linewidth=0.6)
    axis.set_ylim(6.95, -0.53)
    axis.tick_params(length=2.3, pad=2)
    axis.tick_params(axis="y", length=0)
    axis.grid(axis="x", color="#D8D8D8", linewidth=0.55, zorder=0)
    axis.spines["left"].set_visible(False)
    figure.legend(loc="lower center", bbox_to_anchor=(0.60, 0.010), frameon=False,
                  ncols=3, columnspacing=0.85, handlelength=1.4)
    save(figure, output, "tpds_optimistic_epochs.pdf", "Observed O-TBC certification epochs")


def read_comet(path):
    rows = read_rows(path)
    cells = defaultdict(list)
    if len(rows) != 72 or len({row["tx_hash"] for row in rows}) != 72:
        raise ValueError("Expected 72 distinct measured CometBFT submissions")
    for row in rows:
        key = (int(row["workers"]), row["policy"], int(row["batch"]))
        preparation = int(row["request_build_ns"])
        application = int(row["broadcast_to_all_applied_ns"])
        if min(preparation, application) <= 0 or int(row["signers"]) < 3:
            raise ValueError(f"Invalid measured submission {row['tx_hash']}")
        cells[key].append((int(row["repeat"]), preparation / 1e6, application / 1e6))

    expected = {(workers, policy, batch) for workers in (14, 42)
                for policy in COMET_POLICIES for batch in (1, 32, 128)}
    if set(cells) != expected:
        raise ValueError("CometBFT submissions do not match the deployment matrix")
    for key, observations in cells.items():
        if sorted(repeat for repeat, _, _ in observations) != [1, 2, 3]:
            raise ValueError(f"Incomplete or duplicated submissions in {key}")
    return cells


def plot_comet(cells, output):
    figure, axes = plt.subplots(1, 2, figsize=(7.0, 2.03))
    figure.subplots_adjust(left=0.086, right=0.99, bottom=0.205, top=0.765, wspace=0.28)
    batches = (1, 32, 128)
    handles = []
    for index, axis in enumerate(axes):
        for policy, (label, color, marker, linestyle) in COMET_POLICIES.items():
            observed = [[values[index + 1] for values in cells[42, policy, batch]] for batch in batches]
            centers = [median(values) for values in observed]
            lo = [center - min(values) for center, values in zip(centers, observed)]
            hi = [max(values) - center for center, values in zip(centers, observed)]
            handle = axis.errorbar((0, 1, 2), centers, yerr=[lo, hi], color=color, marker=marker,
                                   linestyle=linestyle, label=label, linewidth=0.95, markersize=4.3,
                                   markeredgewidth=0.85, markerfacecolor="white",
                                   capsize=1.6, elinewidth=0.6)
            if not index:
                handles.append(handle)
        axis.set_title(("(a) Preparation", "(b) Broadcast to application")[index], loc="left", pad=3.5)
        axis.set_xlabel("Signatures per batch", labelpad=2)
        axis.set_ylabel("Elapsed time (ms)", labelpad=2)
        axis.set_xlim(-0.20, 2.20)
        axis.set_ylim(bottom=0)
        axis.set_xticks((0, 1, 2), batches)
        axis.yaxis.set_major_locator(MaxNLocator(nbins=4, integer=True))
        axis.tick_params(length=2.3, pad=2)
        axis.set_axisbelow(True)
        axis.grid(axis="y", color="#D8D8D8", linewidth=0.55)
    figure.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.52, 0.986), frameon=False,
                  ncols=4, columnspacing=1.55, handlelength=1.65)
    save(figure, output, "tpds_comet_stages.pdf", "CometBFT preparation and broadcast-to-application latency")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, default=ARTIFACT)
    parser.add_argument("--comet-trials", type=Path, default=REVISION / "engine" / "matrix" / "trials.csv")
    parser.add_argument("--output-dir", type=Path, default=REVISION / "manuscript" / "figures")
    parser.add_argument("--extended-deadlines", type=Path,
                        help="The completed extended deadline campaign trials.csv")
    arguments = parser.parse_args()
    plt.rcParams.update({
        "font.family": "serif", "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
        "font.size": 8.4, "axes.titlesize": 8.7, "axes.labelsize": 8.4,
        "xtick.labelsize": 8.2, "ytick.labelsize": 8.2, "legend.fontsize": 8.0,
        "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.65,
        "pdf.fonttype": 42, "pdf.compression": 9,
    })
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    deadline_path = arguments.artifact / "optimistic" / "results_deadlines" / "trials.csv"
    policies = tuple(label for label, _ in DEADLINE_POLICIES)
    deadlines = read_deadlines(deadline_path, ("honest", "mobile"), (*policies, "O-TBC-cache"),
                               WINDOWS_AND_SLOTS, 3)
    comet = read_comet(arguments.comet_trials)
    plot_deadlines(deadlines, arguments.output_dir)
    plot_epochs(arguments.artifact, deadlines, arguments.output_dir)
    plot_comet(comet, arguments.output_dir)
    if arguments.extended_deadlines:
        if not arguments.extended_deadlines.with_name("environment.json").is_file():
            raise ValueError("The extended deadline campaign has not published its environment record")
        conditions = [(window, slots) for window in EXTENDED_WINDOWS for slots in (4, 8)]
        extended = read_deadlines(arguments.extended_deadlines, ("mobile",), policies, conditions, 6)
        plot_extended_deadlines(extended, arguments.output_dir)


if __name__ == "__main__":
    main()
