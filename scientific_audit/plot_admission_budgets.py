"""Replot the separate local admission-budget sweep from its recorded blocks."""

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from statistics import median

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def csv_rows(file):
    with file.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))

def admission(run, output):
    trials = csv_rows(run / "trials.csv")
    blocks = csv_rows(run / "blocks.csv")
    epoch_rows = csv_rows(run / "epochs.csv")
    assert len(trials) == 216 and len(blocks) == 27
    assert len({r["attempt"] for r in trials}) == len(trials)
    expected = {("O-TBC",22), ("L4",22), ("Direct",41), ("ES-QM",41), ("ES-stream",41)}
    expected |= {("T2",cap) for cap in (28,32,36,40)}
    assert {(x["policy"],int(x["configured_cap"])) for x in blocks} == expected
    groups = defaultdict(list)
    for block in blocks:
        assert int(block["correct"]) == int(block["attempts"]) == 8
        assert int(block["peak_admitted"]) <= int(block["configured_cap"])
        assert int(block["peak_rpc_active"]) <= 4
        groups[block["policy"], int(block["configured_cap"])].append(block)
    assert all(len(rows) == 3 for rows in groups.values())
    assert all(r["correct"] == "1" and r["wrong"] == "0" for r in trials)
    assert all(int(r["admitted"]) <= int(r["configured_cap"]) for r in epoch_rows)
    summary = {}
    for (policy, cap), rows in sorted(groups.items()):
        samples = [float(x["goodput_cert_s"]) for x in rows]
        tail = [float(x["latency_p95_ms"]) for x in rows]
        summary[policy,cap] = [median(samples), min(samples), max(samples), median(tail),
                              max(int(x["peak_admitted"]) for x in rows)]
    plt.rcParams.update({"font.family":"serif", "font.serif":["Times New Roman","DejaVu Serif"],
        "font.size":8, "axes.spines.top":False, "axes.spines.right":False, "pdf.fonttype":42})
    fig, ax = plt.subplots(figsize=(3.48,1.96))
    fig.subplots_adjust(left=.16,bottom=.25,right=.98,top=.72)
    view = {
        "O-TBC":("O-TBC","#0072b2","o",0),
        "L4":("L4","#606060","^",0),
        "T2":("T2","#7452a1","D",0),
        "Direct":("DM","#d55e00","s",-.5),
        "ES-QM":("ES-QM","#008c6b","v",0),
        "ES-stream":("ES-S","#ae8540","P",.5),
    }
    for key,(label,tone,marker,shift) in view.items():
        rows = [(cap, val) for (policy,cap),val in summary.items() if policy == key]
        m = [v[0] for _,v in rows]
        ax.errorbar([cap+shift for cap,_ in rows],m,
            yerr=[[v[0]-v[1] for _,v in rows],[v[2]-v[0] for _,v in rows]],
            label=label,color=tone,marker=marker,markersize=3.8,markerfacecolor="white",
            linewidth=1,ls=":" if key=="T2" else "none",capsize=1.7)
    ax.set_xlim(20.3,43.3)
    ax.set_xticks((22,28,32,36,41))
    ax.set_xlabel("Configured cap (identities per epoch)", labelpad=1.5)
    ax.set_ylabel("Decisions/s", labelpad=1.5)
    ax.grid(axis="y",color="#dfdfdf",linewidth=.55)
    ax.set_axisbelow(True)
    ax.tick_params(length=2.4,pad=1.65)
    fig.legend(loc="upper center",bbox_to_anchor=(.55,.997),frameon=False,ncol=3,columnspacing=1.2)
    fig.savefig(output,
                metadata={"Title":"Admission budget controls","Creator":None,"CreationDate":None})
    print("Validated 216 decisions across all nine policy-cap cells.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    admission(args.run, args.output)
