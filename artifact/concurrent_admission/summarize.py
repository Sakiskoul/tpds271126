import argparse
from collections import defaultdict
import csv
import json
from pathlib import Path
import random
import statistics


def median(rows, field):
    values = [float(r[field]) for r in rows if r[field] != ""]
    return statistics.median(values) if values else None


def percentile(values, fraction):
    points = sorted(values)
    pos = (len(points) - 1) * fraction
    low = int(pos)
    return points[low] + (points[min(low + 1, len(points) - 1)] - points[low]) * (pos - low)


def paired_bootstrap(ratios, seed=2391, samples=20000):
    rng = random.Random(seed)
    distribution = [statistics.median(rng.choices(ratios, k=len(ratios))) for _ in range(samples)]
    return [percentile(distribution, .025), percentile(distribution, .975)]


def table(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def analyze(directory):
    env = json.loads((directory / "environment.json").read_text())
    if env["status"] != "complete":
        raise RuntimeError("campaign has not completed")
    blocks = table(directory / "blocks.csv")
    trials = table(directory / "trials.csv")
    epochs = table(directory / "epochs.csv")
    jobs = table(directory / "jobs.csv")
    if len(blocks) != env["randomized_blocks"]:
        raise ValueError("campaign is missing blocks")
    trial_ids = {r["attempt"] for r in trials}
    assert len(trials) == len(trial_ids) == sum(int(b["attempts"]) for b in blocks)
    assert len(epochs) == sum(int(t["epochs"]) for t in trials)
    assert all(row["attempt"] in trial_ids for row in jobs + epochs)
    assert all(int(row["peak_admitted"]) <= int(row["cap"]) and int(row["incorrect"]) == 0 for row in trials)
    cells = defaultdict(list)
    for row in blocks:
        cells[(row["clients"], row["scenario"], row["case"])].append(row)
    medians = ("goodput", "attempts_s", "median_ms", "p95_ms", "median_jobs", "median_gate_rpc_ms",
               "median_issue_ms", "median_gate_verify_ms", "median_closure_ms", "median_worker_queue_ms")
    result = []
    for (clients, scenario, case), records in sorted(cells.items()):
        row = dict(clients=int(clients), scenario=scenario, case=case, blocks=len(records))
        row.update({field: median(records, field) for field in medians})
        for field in ("correct", "incorrect", "unresolved", "attempts", "rejected", "late"):
            row[field] = sum(int(r[field]) for r in records)
        row.update(max_admitted=max(int(r["max_admitted"]) for r in records),
                   goodput_range=[min(float(r["goodput"]) for r in records), max(float(r["goodput"]) for r in records)],
                   p95_ms_range=[min(float(r["p95_ms"]) for r in records), max(float(r["p95_ms"]) for r in records)],
                   median_block_bytes_per_attempt=statistics.median(int(r["total_bytes"]) / int(r["attempts"]) for r in records),
                   median_authority_core_fraction=statistics.median(float(r["authority_cpu_s"]) / float(r["seconds"]) for r in records),
                   median_workers_cpu_ms_per_attempt=statistics.median(float(r["worker_cpu_s"]) / int(r["attempts"]) * 1000 for r in records),
                   median_scheduler_cpu_ms_per_attempt=statistics.median(float(r["scheduler_cpu_s"]) / int(r["attempts"]) * 1000 for r in records))
        result.append(row)
    contrasts = []
    for clients, scenario, case in sorted(cells):
        if case != "O-TBC":
            continue
        ours = {r["repeat"]: r for r in cells[clients, scenario, case]}
        for other in ["O-TBC-off", "L4", "T2", "DM", "ES-QM", "ES-S"]:
            target = {r["repeat"]: r for r in cells.get((clients, scenario, other), [])}
            paired = sorted(ours.keys() & target.keys())
            ratios = [float(ours[key]["goodput"]) / float(target[key]["goodput"])
                      for key in paired if float(target[key]["goodput"]) > 0]
            goodput_delta = [float(ours[key]["goodput"]) - float(target[key]["goodput"]) for key in paired]
            if paired:
                contrasts.append(dict(clients=int(clients), scenario=scenario, contrast=f"{case}/{other}",
                                      pairs=len(paired), ratio_pairs=len(ratios),
                                      median_goodput_difference=statistics.median(goodput_delta),
                                      median_goodput_ratio=statistics.median(ratios) if ratios else None,
                                      ratio_95_percentile_bootstrap=paired_bootstrap(ratios) if len(ratios) >= 8 else None))
    return dict(environment=env, counts=dict(blocks=len(blocks), attempts=len(trials), epochs=len(epochs), jobs=len(jobs)),
                cells=result, contrasts=contrasts,
                methods="Medians across randomized blocks. Goodput includes unresolved attempts. Contemporaneous policy order was shuffled; contrasts pair equal workload repetition indices. Percentile bootstrap of paired block goodput ratios, 20,000 resamples. Ranges are descriptive. Tail column is median of within-block empirical p95s.")


def plot(report, target, clients):
    import matplotlib.pyplot as plt

    cells = {r["case"]: r for r in report["cells"] if r["clients"] == clients and r["scenario"] == "mobile"}
    labels = [case for case in ["O-TBC", "O-TBC-off", "L4", "T2", "DM", "ES-QM", "ES-S"] if case in cells]
    colors = ["#1456a0" if case == "O-TBC" else "#aaaaaa" if case == "O-TBC-off" else "#68798c" for case in labels]
    fig, axes = plt.subplots(1, 2, figsize=(3.45, 1.39 if len(labels) <= 3 else 2.15),
                             sharey=True, layout="constrained")
    for i, (case, color) in enumerate(zip(labels, colors)):
        row = cells[case]
        for j, (field, range_field) in enumerate([("goodput", "goodput_range"), ("p95_ms", "p95_ms_range")]):
            unit = 1000. if j else 1.
            point = row[field] / unit
            lower, upper = (x / unit for x in row[range_field])
            axes[j].errorbar(point, i, xerr=[[point - lower], [upper - point]], color=color,
                             marker="o", markersize=3.5, capsize=2, lw=.8)
    display = {"O-TBC": "O-TBC on", "O-TBC-off": "O-TBC off"}
    axes[0].set_yticks(range(len(labels)), labels=[display.get(case, case) for case in labels])
    for axis in axes:
        axis.grid(axis="x", alpha=.29, lw=.5)
        axis.tick_params(labelsize=7)
    axes[0].set_ylim(len(labels)-.65, -.50)
    axes[0].set_xlabel("Correct decisions/s", fontsize=7)
    axes[1].set_xlabel("Block p95 latency (s)", fontsize=7)
    fig.savefig(target, metadata={"Creator": None, "CreationDate": None})
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--figure", type=Path)
    parser.add_argument("--clients", type=int, default=4)
    arguments = parser.parse_args()
    report = analyze(arguments.directory)
    (arguments.directory / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    if arguments.figure:
        plot(report, arguments.figure, arguments.clients)
    print(f"{report['counts']['attempts']} attempts; {len(report['cells'])} cells")


if __name__ == "__main__":
    main()
