"""Validate and summarize the retained four-validator deployment records."""

import csv
import json
import sys
from collections import defaultdict
from itertools import product
from pathlib import Path
from statistics import median

root = Path(sys.argv[1])
policies = {
    "local": (0, 0),
    "direct_majority": (13, 41),
    "adaptive_four_work": (11, 39),
    "O-TBC": (7, 21),
}
expected = set(product((14, 42), policies, (1, 32, 128), (1, 2, 3)))
groups = defaultdict(list)
with (root / "trials.csv").open(newline="") as source:
    for row in csv.DictReader(source):
        key = (int(row["workers"]), row["policy"], int(row["batch"]), int(row["repeat"]))
        if key not in expected:
            raise ValueError(f"Unexpected or duplicated submission {key}")
        expected.remove(key)
        n, policy, batch, repeat = key
        polls = policies[policy][n == 42]
        assert int(row["jobs"]) == polls and int(row["checks"]) == polls * batch
        assert int(row["epochs"]) == {"local": 0, "adaptive_four_work": 2}.get(policy, 1)
        proof = json.loads((root / f"{n}-{policy}-{batch}-{repeat}.json").read_text())
        assert proof["record"]["tx_hash"] == row["tx_hash"]
        commits = proof["commits"]
        states = proof["states"]
        assert len(commits) == len(states) == 4
        assert len({commit["block_id"]["hash"] for commit in commits}) == 1
        assert all(commit["power"] * 3 > commit["total_power"] * 2 for commit in commits)
        assert len({(state["sequence"], state["root"]) for state in states}) == 1
        assert all(commit["height"] == int(row["height"]) for commit in commits)
        assert all(state["height"] >= int(row["height"]) for state in states)
        assert len(proof["raw_evidence_sha256"]) >= 11
        groups[key[:3]].append(row)
if expected:
    raise ValueError(f"Missing {len(expected)} submissions")

metrics = ("request_build_ns", "broadcast_to_all_applied_ns")
with (root / "summary.csv").open("w", newline="") as target:
    writer = csv.writer(target)
    writer.writerow(("workers", "policy", "batch", "jobs", "epochs", "tx_bytes", *(
        f"{metric.removesuffix('_ns')}_{stat}_ms"
        for metric in metrics for stat in ("median", "min", "max")
    )))
    for (n, policy, batch), rows in sorted(groups.items()):
        durations = [[int(row[metric]) / 1e6 for row in rows] for metric in metrics]
        writer.writerow((n, policy, batch, rows[0]["jobs"], rows[0]["epochs"],
                         median(int(row["transaction_bytes"]) for row in rows),
                         *(round(stat(series), 3) for series in durations
                           for stat in (median, min, max))))
print(f"Verified {sum(map(len, groups.values()))} submissions across {len(groups)} cells.")
