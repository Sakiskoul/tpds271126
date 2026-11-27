"""Measure concurrent consumers of one retained positive O-TBC trace."""

import argparse
import csv
import json
from pathlib import Path
from statistics import median

from consumer_fanout import canonical, fanout
from analyze_final_measurements import rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--traces", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True)
    producers = {r["case"]: r for r in rows(args.traces / "paired.csv")
                 if (r["n"], r["batch"], r["block"]) == ("14", "32", "0")}
    raw, costs = [], []
    for case in ("honest", "four"):
        trace = json.loads((args.traces / f"trace-14-{case}.json").read_text())
        producer_cpu = int(producers[case]["producer_cpu_ns"])
        config = {"tx_key": trace["task_key"], "registry": trace["worker_keys"], "seal_key": trace["seal_key"]}
        for count in (14, 40, 70):
            ratios = []
            for block in range(3):
                measurements = {}
                for mode in (("direct", "compact") if block % 2 == 0 else ("compact", "direct")):
                    payload = canonical(trace["batch"] if mode == "direct" else trace["compact"])
                    results = fanout(mode, count, config, payload, trace["context"])
                    for ordinal, (_, cpu) in enumerate(results, 1):
                        raw.append(dict(case=case, consumers=count, block=block, path=mode,
                                        ordinal=ordinal, cpu_ns=cpu))
                    measurements[mode] = sum(cpu for _, cpu in results)
                ratio = (producer_cpu + measurements["compact"]) / measurements["direct"]
                ratios.append(ratio)
                print(case, count, block, round(ratio, 3), flush=True)
            costs.append(dict(case=case, consumers=count, producer_cpu_ns=producer_cpu,
                              ratio_median=median(ratios), ratio_min=min(ratios), ratio_max=max(ratios)))
    for name, measurements in (("consumers.csv", raw), ("summary.csv", costs)):
        with (args.output / name).open("w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=list(measurements[0]))
            writer.writeheader()
            writer.writerows(measurements)


if __name__ == "__main__":
    main()
