"""Measure valid application submissions on a four-validator CometBFT testnet."""

import argparse
import os
import time
import csv
import json
import platform
import random
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from itertools import product
from pathlib import Path

from run_valid_cases import (
    ARTIFACT, POLICIES, Cluster, OpenSSLEd25519, Producer, commits, deploy,
    diagnostic, optimistic, sha, state, version,
)
from ledger import canonical


def process_cpu_ticks(processes):
    ticks = 0
    for proc in processes:
        fields = Path(f"/proc/{proc.pid}/stat").read_text().rsplit(")", 1)[1].split()
        ticks += int(fields[11]) + int(fields[12])
    return ticks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.comet.resolve()
    release = subprocess.check_output([str(binary), "version"], text=True).strip()
    if release != "0.38.26":
        raise ValueError(f"Unexpected CometBFT release: {release}")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "environment.json").write_text(json.dumps({
        "engine": release, "executable_sha256": sha(binary),
        "openssl": version(0).decode(), "platform": platform.platform(),
        "source_sha256": {
            p.name: sha(p) for p in (
                Path(__file__), Path(__file__).with_name("run_valid_cases.py"),
                ARTIFACT / "deployment/deploy.py",
                ARTIFACT / "deployment/protocol.py",
                ARTIFACT / "cometbft/abci_socket.py",
                ARTIFACT / "cometbft/ledger.py",
                ARTIFACT / "cometbft/run_comet.py",
                ARTIFACT / "cometbft/commits.py",
                ARTIFACT / "optimistic/scheduler.py",
            )
        },
        "validators": 4, "rpc_slots": 4, "workers": [42],
        "batches": [1, 32, 128], "repetitions": 3,
        "scope": "real local engine of four processes, valid batches, no injected faults",
    }, indent=2) + "\n")
    default_cohort = deploy.cohort

    def select(policy, history, n, f, c):
        if policy == "O-TBC":
            return optimistic(history, n, f, c)
        return default_cohort(policy, history, n, f, c)

    commits.Ed25519PublicKey = OpenSSLEd25519
    deploy.cohort = select
    fields = (
        "policy", "workers", "batch", "repeat", "jobs", "epochs", "checks",
        "transaction_bytes", "request_build_ns", "certificate_build_ns",
        "broadcast_to_all_applied_ns", "end_to_end_ns", "validator_cpu_ns", "abci_cpu_ns", "producer_cpu_ns", "observer_cpu_ns",
        "aggregate_cpu_ns", "certificate_bytes", "height", "round", "signers", "tx_hash",
    )
    try:
        with (output / "trials.csv").open("w", newline="") as trial_file:
            writer = csv.DictWriter(trial_file, fieldnames=fields)
            writer.writeheader()
            for n, (policy, scheduler) in product((42,), POLICIES.items()):
                mode = "direct" if policy == "local" else "certificate"
                cap = n - 1 if policy in {"local", "direct_majority"} else n // 2 + 1
                with tempfile.TemporaryDirectory(prefix="otbc-matrix-") as directory:
                    home = Path(directory)
                    try:
                        with Producer(n, mode, cap, home / "producer") as producer:
                            producer.pool.shutdown()
                            producer.pool = ThreadPoolExecutor(max_workers=4)
                            with Cluster(binary, home / "cluster", 4, producer.config, 45) as cluster:
                                previous = state(cluster.nodes[0]["rpc"])
                                proposal, _ = producer.make(previous, 1, scheduler, "honest")
                                assert cluster.submit(proposal, previous, home / "warmup")["outcome"] == "finalized"
                                trials = list(product((1, 32, 128), range(1, 4)))
                                random.Random(20261126).shuffle(trials)
                                for batch, rep in trials:
                                    validator0 = process_cpu_ticks(cluster.process.values())
                                    abci0 = process_cpu_ticks(cluster.apps.values())
                                    workers0 = process_cpu_ticks(producer.procs)
                                    client0 = time.process_time_ns()
                                    hz = os.sysconf("SC_CLK_TCK")
                                    start = time.perf_counter_ns()
                                    previous = state(cluster.nodes[0]["rpc"])
                                    before_build = time.process_time_ns()
                                    proposal, work = producer.make(previous, batch, scheduler, "honest")
                                    build_cpu = time.process_time_ns() - before_build
                                    pending = home / f"trial-{batch}-{rep}"
                                    result = cluster.submit(proposal, previous, pending)
                                    elapsed = time.perf_counter_ns() - start
                                    client_cpu = time.process_time_ns() - client0
                                    workers_cpu = (process_cpu_ticks(producer.procs) - workers0) * 10**9 // hz
                                    producer_cpu = workers_cpu + build_cpu
                                    observer_cpu = client_cpu - build_cpu
                                    cert = json.loads(proposal)["certificate"]
                                    validator_ns = (process_cpu_ticks(cluster.process.values()) - validator0) * 10**9 // hz
                                    abci_ns = (process_cpu_ticks(cluster.apps.values()) - abci0) * 10**9 // hz
                                    assert result["outcome"] == "finalized" and result["signers"] >= 3
                                    if policy == "O-TBC":
                                        assert (work["jobs"], work["epochs"]) == (n // 2, 1)
                                    record = {
                                        "policy": policy, "workers": n, "batch": batch, "repeat": rep,
                                        "jobs": work["jobs"], "epochs": work["epochs"], "checks": work["checks"],
                                        "transaction_bytes": len(proposal),
                                        "end_to_end_ns": elapsed,
                                        "validator_cpu_ns": validator_ns,
                                        "abci_cpu_ns": abci_ns,
                                        "producer_cpu_ns": producer_cpu,
                                        "observer_cpu_ns": observer_cpu,
                                        "aggregate_cpu_ns": producer_cpu + observer_cpu + validator_ns + abci_ns,
                                        "certificate_bytes": len(canonical(cert)) if cert else 0,
                                        "request_build_ns": work["client_build_ns"],
                                        "certificate_build_ns": work["produce_ns"],
                                        "broadcast_to_all_applied_ns": result["finality_ns"],
                                        **{key: result[key] for key in ("height", "round", "signers", "tx_hash")},
                                    }
                                    writer.writerow(record)
                                    trial_file.flush()
                                    check = json.loads((pending / "verified.json").read_text())
                                    check["record"] = record
                                    check["raw_evidence_sha256"] = {p.name: sha(p) for p in pending.glob("*.json")}
                                    (output / f"{n}-{policy}-{batch}-{rep}.json").write_text(json.dumps(check, indent=2))
                    except Exception:
                        diagnostic(home, output, f"{policy}-{n}")
                        raise
    finally:
        deploy.cohort = default_cohort


if __name__ == "__main__":
    main()
