"""Recompute claim-level summaries from run records."""

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median


def rows(path):
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def grouped(records, *fields):
    groups = defaultdict(list)
    for record in records:
        groups[tuple(record[field] for field in fields)].append(record)
    return groups


def summarize_comet(path, expected):
    trials = rows(path)
    assert len(trials) == expected
    assert len(grouped(trials, "workers", "policy", "batch", "repeat")) == expected
    assert all(int(row["signers"]) >= 3 for row in trials)
    for row in trials:
        name = "-".join(row[field] for field in ("workers", "policy", "batch", "repeat"))
        receipt = json.loads((path.parent / (name + ".json")).read_text())
        assert receipt["record"]["tx_hash"] == row["tx_hash"]
        commits, states = receipt["commits"], receipt["states"]
        assert len(commits) == len(states) == 4
        assert len({c["block_id"]["hash"] for c in commits}) == 1
        assert all(c["power"] * 3 > c["total_power"] * 2 for c in commits)
        assert len({(s["sequence"], s["root"]) for s in states}) == 1
        assert all(c["height"] == int(row["height"]) for c in commits)
    if "aggregate_cpu_ns" in trials[0]:
        for row in trials:
            assert int(row["aggregate_cpu_ns"]) == sum(
                int(row[name + "_cpu_ns"]) for name in ("producer", "observer", "validator", "abci"))
    metrics = [key for key in trials[0] if key.endswith(("_ns", "_bytes")) or key in ("jobs", "epochs")]
    return [{
        "workers": int(n), "batch": int(batch), "policy": policy, "trials": len(cell),
        "median": {m: median(int(row[m]) for row in cell) for m in metrics if cell[0][m]},
        "range": {m: [min(int(row[m]) for row in cell), max(int(row[m]) for row in cell)]
                  for m in metrics if cell[0][m]},
    } for (n, batch, policy), cell in sorted(grouped(trials, "workers", "batch", "policy").items())]


def summarize_certs(path):
    trials = rows(path)
    assert len({(r["n"], r["batch"], r["case"], r["block"]) for r in trials}) == len(trials)
    cells = []
    for (n, b, case), cell in sorted(grouped(trials, "n", "batch", "case").items()):
        assert all(int(r["compact_bytes"]) == 0 for r in cell) == (case == "negative")
        metrics = ("producer_cpu_ns", "producer_wall_ns", "full_cpu_ns", "compact_cpu_ns",
                   "direct_cpu_ns", "full_bytes", "compact_bytes", "direct_bytes", "producer_wire_bytes")
        base = dict(n=int(n), B=int(b), case=case, blocks=len(cell), jobs=median(int(r["jobs"]) for r in cell),
                    epochs=dict(Counter(int(r["epochs"]) for r in cell)))
        for key in metrics:
            values = [int(r[key]) for r in cell if r[key]]
            if values:
                base[key] = dict(median=median(values), minimum=min(values), maximum=max(values))
        for mode in ("full", "compact"):
            paired = [(int(r["producer_cpu_ns"]), int(r["direct_cpu_ns"]), int(r[mode + "_cpu_ns"]))
                      for r in cell if r[mode + "_cpu_ns"]]
            if not paired:
                continue
            thresholds = [math.floor(e / (d - v)) + 1 for e, d, v in paired if d > v]
            base[mode + "_finite_break_even"] = len(thresholds)
            base[mode + "_median_finite_r"] = median(thresholds) if thresholds else None
            base[mode + "_rho"] = {
                r: median((e + r * v) / (r * d) for e, d, v in paired)
                for r in (14, 40, 70)
            }
        cells.append(base)
    return cells


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--certificates", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    archive = args.archive
    result = {
        "comet_matrix": summarize_comet(archive / "engine/matrix/trials.csv", 72),
        "comet_profile": summarize_comet(archive / "review_runs/comet_profile/trials.csv", 36),
        "comet_full_cost": summarize_comet(archive / "scientific_audit/comet_full_cost/trials.csv", 36),
    }
    if args.certificates:
        result["certificates"] = summarize_certs(args.certificates)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
