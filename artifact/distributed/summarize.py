import argparse
import csv
import json
import random
import statistics
from collections import defaultdict
from pathlib import Path


def percentile(values, fraction):
    values = sorted(values)
    index = fraction * (len(values) - 1)
    left = int(index)
    right = min(left + 1, len(values) - 1)
    return values[left] + (index - left) * (values[right] - values[left])


def load_trials(root):
    buckets = defaultdict(list)
    for location in sorted(root.glob("*/trials.csv")):
        with location.open(newline="", encoding="utf-8") as source:
            for row in csv.DictReader(source):
                key = (int(row["n"]), row["placement"], row["scenario"], row["policy"])
                buckets[key].append(row)
    return buckets


def summary_rows(buckets):
    for key, rows in sorted(buckets.items()):
        n, placement, scenario, policy = key
        complete = [row for row in rows if int(row["correct"]) or int(row["wrong"])]
        certified = [row for row in rows if int(row["correct"])]
        times = [float(row["wall_ms"]) for row in certified]
        tails = [float(row["end_to_end_ms"]) for row in certified]
        total_s = sum(float(row["end_to_end_ms"]) for row in rows) / 1000
        yield {
            "n": n,
            "placement": placement,
            "scenario": scenario,
            "policy": policy,
            "blocks": len({row["repeat"] for row in rows}),
            "attempts": len(rows),
            "correct": len(certified),
            "wrong": len(complete) - len(certified),
            "unresolved": len(rows) - len(complete),
            "sequential_goodput": len(certified) / total_s,
            "producer_median_ms": statistics.median(times) if times else None,
            "producer_p95_ms": percentile(times, 0.95) if times else None,
            "end_to_end_median_ms": statistics.median(tails) if tails else None,
            "end_to_end_p95_ms": percentile(tails, 0.95) if tails else None,
            "jobs_median": statistics.median(int(row["jobs"]) for row in rows),
            "epochs_median": statistics.median(int(row["epochs"]) for row in rows),
            "peak_median": statistics.median(int(row["peak"]) for row in rows),
            "worker_verify_cpu_median_ms": statistics.median(int(row["cpu_ns"]) for row in rows) / 1e6,
            "consumer_verify_cpu_median_ms": statistics.median(
                float(row["certified_consumer_cpu_ns"]) for row in certified
            ) / 1e6 if certified else None,
            "application_bytes_median": statistics.median(
                int(row["wire_bytes"]) + int(row["certified_consumer_bytes"]) for row in rows
            ),
        }


def paired_results(buckets):
    groups = sorted({key[:3] for key in buckets})
    comparisons = []
    for n, placement, scenario in groups:
        profile = {key[3]: rows for key, rows in buckets.items() if key[:3] == (n, placement, scenario)}
        if "O-TBC" not in profile:
            continue
        for other in sorted(set(profile) - {"O-TBC"}):
            pairs = {}
            for policy in ["O-TBC", other]:
                by_block = defaultdict(list)
                for row in profile[policy]:
                    by_block[int(row["repeat"])].append(row)
                pairs[policy] = {
                    block: sum(int(row["correct"]) for row in rows)
                    / (sum(float(row["end_to_end_ms"]) for row in rows) / 1000)
                    for block, rows in by_block.items()
                }
            matched = sorted(set(pairs["O-TBC"]) & set(pairs[other]))
            matched = [block for block in matched if pairs[other][block] > 0]
            if not matched:
                continue
            ratios = [pairs["O-TBC"][block] / pairs[other][block] for block in matched]
            rng = random.Random(13817 + n)
            bootstrap = [
                statistics.median(rng.choices(ratios, k=len(ratios))) for _ in range(5000)
            ] if len(matched) >= 8 else None
            comparisons.append(
                {
                    "n": n,
                    "placement": placement,
                    "scenario": scenario,
                    "policy": "O-TBC",
                    "comparison": other,
                    "paired_blocks": len(matched),
                    "median_paired_goodput_ratio": statistics.median(ratios),
                    "range": [min(ratios), max(ratios)],
                    "percentile_block_bootstrap_95": [
                        percentile(bootstrap, 0.025), percentile(bootstrap, 0.975)
                    ] if bootstrap else None,
                }
            )
    return comparisons


def block_rows(buckets):
    for key, rows in sorted(buckets.items()):
        blocks = defaultdict(list)
        for row in rows:
            blocks[int(row["repeat"])].append(row)
        for block, records in sorted(blocks.items()):
            summary = next(summary_rows({key: records}))
            del summary["blocks"]
            yield dict(block=block, **summary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    groups = load_trials(args.results)
    for name, summarizer in (("summary.csv", summary_rows), ("blocks.csv", block_rows)):
        rows = list(summarizer(groups))
        with (args.results / name).open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=tuple(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    (args.results / "paired_goodput.json").write_text(
        json.dumps(paired_results(groups), indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
