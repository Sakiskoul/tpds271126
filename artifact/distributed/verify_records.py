import argparse
import csv
import json
from collections import defaultdict
from itertools import product
from pathlib import Path


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def ids(row, name):
    return {int(value) for value in row[name].split()}


def audit_group(path, environment):
    trials = read_csv(path / "trials.csv")
    epochs = defaultdict(list)
    jobs = defaultdict(list)
    for row in read_csv(path / "epochs.csv"):
        epochs[row["attempt"]].append(row)
    for row in read_csv(path / "jobs.csv"):
        jobs[(row["attempt"], int(row["epoch"]))].append(row)

    expected = set(product(environment["policies"], environment["scenarios"], (0, 1), range(environment["repeats"])))
    observed = {(r["policy"], r["scenario"], int(r["truth"]), int(r["repeat"])) for r in trials}
    assert observed == expected and len(trials) == len(expected), path
    assert len({r["attempt"] for r in trials}) == len(trials), path
    totals = defaultdict(int)
    for trial in trials:
        attempt = trial["attempt"]
        n, f, c, truth = (int(trial[key]) for key in ("n", "f", "c", "truth"))
        placement = trial["placement"]
        result = trial["result"]
        assert path.name == f"n{n}-{placement}"
        assert n == 2 * (f + c)
        outcome = "unresolved" if result == "unresolved" else "correct" if int(result) == truth else "wrong"
        assert int(trial["correct"]) == (outcome == "correct")
        assert int(trial["wrong"]) == (outcome == "wrong")
        totals[outcome] += 1
        cap_by_policy = {"O-TBC": f + c + 1, "L4": f + c + 1, "T2": (4 * f + 2 * c) // 3 + 1}
        cap = cap_by_policy.get(trial["policy"], 2 * f + 1)
        entries = sorted(epochs[attempt], key=lambda row: int(row["epoch"]))
        assert len(entries) == int(trial["epochs"])
        assert [int(entry["epoch"]) for entry in entries] == list(range(1, len(entries) + 1))
        assert max((int(entry["admitted"]) for entry in entries), default=0) == int(trial["peak"]) <= cap
        previous_faults = None
        started = timely = checks = 0
        for entry in entries:
            cohort = ids(entry, "cohort")
            positives = ids(entry, "positive_ids")
            negatives = ids(entry, "negative_ids")
            faults = ids(entry, "faults")
            assert len(faults) <= f and faults <= set(range(n))
            if previous_faults is not None:
                assert len(faults - previous_faults) <= c
            previous_faults = faults
            falsified = positives if truth == 0 else negatives
            assert falsified <= faults
            assert not positives & negatives
            assert (positives | negatives) <= cohort <= set(range(n))
            epoch_jobs = jobs[(attempt, int(entry["epoch"]))]
            actual_started = [j for j in epoch_jobs if int(j["started"])]
            actual_timely = [j for j in epoch_jobs if int(j["timely"])]
            assert len(actual_started) == len(cohort) == int(entry["admitted"])
            assert {int(j["worker"]) for j in actual_started} == cohort
            assert {int(j["worker"]) for j in actual_timely} == (positives | negatives)
            assert len(actual_timely) == int(entry["timely"])
            assert all(int(j["checks"]) == int(trial["batch"]) for j in actual_started)
            for j in epoch_jobs:
                worker_is_remote = placement == "split" and int(j["worker"]) % 2 == 1
                assert (j["site"] == "remote") == worker_is_remote
                totals[j["site"] + "_jobs"] += int(j["started"])
                if worker_is_remote:
                    totals["remote_worker_frame_bytes"] += int(j["wire_bytes"])
            started += len(actual_started)
            timely += len(actual_timely)
            checks += sum(int(j["checks"]) for j in actual_started)
        assert (started, timely, checks) == tuple(int(trial[name]) for name in ("jobs", "timely", "checks"))
        if outcome != "unresolved":
            assert float(trial["certified_consumer_ms"]) > 0
            consumer_bytes = int(trial["certified_consumer_bytes"])
            assert consumer_bytes > 0
            totals["remote_consumer_frame_bytes"] += consumer_bytes
        assert float(trial["wall_ms"]) > 0
        assert float(trial["end_to_end_ms"]) >= float(trial["wall_ms"])
        totals["trials"] += 1
        totals["primitive_checks"] += checks
    counters = (
        "trials", "correct", "wrong", "unresolved", "local_jobs", "remote_jobs", "primitive_checks",
        "remote_worker_frame_bytes", "remote_consumer_frame_bytes",
    )
    return {key: totals[key] for key in counters}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    environment = json.loads((args.results / "environment.json").read_text())
    report = {}
    for group in sorted(args.results.glob("*/trials.csv")):
        report[group.parent.name] = audit_group(group.parent, environment)
    assert report, args.results
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
