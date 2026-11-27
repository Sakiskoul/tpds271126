"""Check one-factor affinity repetitions on the same deadline harness."""

import argparse
import json
from pathlib import Path
from statistics import median

from analyze_final_measurements import grouped, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = []
    baseline = None
    for path in (args.root / label for label in ("2a", "4a", "4b", "2b")):
        environment = json.loads((path / "environment.json").read_text())
        settings = dict(environment)
        settings["args"] = {k: v for k, v in settings["args"].items() if k != "output"}
        del settings["affinity"]
        if baseline is None:
            baseline = settings
        assert settings == baseline, path
        cpus = len(environment["affinity"])
        assert cpus == int(path.name[0])
        epochs = {row["attempt"]: row for row in rows(path / "epochs.csv") if row["epoch"] == "1"}
        trials = rows(path / "trials.csv")
        assert len(trials) == len(epochs) == 36
        for trial in trials:
            assert int(trial["wrong"]) == 0
            first = epochs[trial["attempt"]]
            records.append(
                dict(policy=trial["policy"], D=int(trial["deadline_ms"]), cpus=cpus, rep=path.name,
                     correct=int(trial["correct"]), timely=int(first["timely"]),
                     incomplete=int(first["timely"]) < int(first["planned"]),
                     guard_miss=int(first["guard_miss"])))
    summary = []
    for (cpus, window, policy), cell in sorted(grouped(records, "cpus", "D", "policy").items()):
        assert len(cell) == 12 and len({r["rep"] for r in cell}) == 2
        count = sum(r["correct"] for r in cell)
        summary.append(dict(cpus=cpus, deadline_ms=window, policy=policy, n=len(cell),
                            correct=count, unresolved=len(cell) - count, wrong=0,
                            median_first_timely=median(r["timely"] for r in cell),
                            incomplete_first=sum(r["incomplete"] for r in cell),
                            first_guard_misses=sum(r["guard_miss"] for r in cell)))
    args.output.write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
