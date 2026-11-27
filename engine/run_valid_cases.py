"""Run valid O-TBC submissions through a local CometBFT 0.38.26 testnet."""

import argparse
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ARTIFACT = ROOT.parent / "artifact"
sys.path[:0] = [
    str(ARTIFACT / "cometbft"),
    str(ARTIFACT / "deployment"),
    str(ARTIFACT / "optimistic"),
]

import commits
import deploy
from fixture import Producer
from ossl import Key, version
from run_comet import Cluster, sha, state
from scheduler import optimistic

POLICIES = {
    "local": "direct_majority",
    "direct_majority": "direct_majority",
    "adaptive_four_work": "adaptive_four_work",
    "O-TBC": "O-TBC",
}


class OpenSSLEd25519:
    """Load the raw Ed25519 public key through the existing EVP adapter."""

    @staticmethod
    def from_public_bytes(raw):
        if len(raw) != 32:
            raise ValueError("Expected a 32-byte Ed25519 public key")
        prefix = bytes.fromhex("302a300506032b6570032100")
        return Key.from_der(prefix + raw)

def diagnostic(path, output, policy):
    logs = {}
    for log in sorted(path.glob("cluster/node*/*.log")):
        logs[f"{log.parent.name}/{log.name}"] = log.read_text(errors="replace")[-2500:]
    (output / f"{policy}-diagnostic.json").write_text(json.dumps(logs, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = args.comet.resolve()
    comet_version = subprocess.check_output([str(binary), "version"], text=True).strip()
    if comet_version != "0.38.26":
        raise ValueError(f"Unexpected CometBFT version: {comet_version}")
    (output / "environment.json").write_text(json.dumps({
        "cometbft": comet_version,
        "engine_sha256": sha(binary),
        "openssl": version(0).decode(),
        "source": {
            p.name: sha(p) for p in (
                Path(__file__), ARTIFACT / "optimistic/scheduler.py",
                ARTIFACT / "deployment/deploy.py",
                ARTIFACT / "deployment/protocol.py",
                ARTIFACT / "cometbft/run_comet.py",
                ARTIFACT / "cometbft/abci_socket.py",
                ARTIFACT / "cometbft/ledger.py",
            )
        },
        "scope": "one host, four local validators, valid tasks, no faults",
    }, indent=2) + "\n")

    commits.Ed25519PublicKey = OpenSSLEd25519
    default_cohort = deploy.cohort

    def select(policy, history, n, f, c):
        if policy == "O-TBC":
            return optimistic(history, n, f, c)
        return default_cohort(policy, history, n, f, c)

    deploy.cohort = select
    try:
        with (output / "trials.csv").open("w", newline="") as trial_file:
            fields = [
                "policy", "trial", "batch", "jobs", "epochs", "checks",
                "transaction_bytes", "height", "round", "signers", "tx_hash",
            ]
            writer = csv.DictWriter(trial_file, fieldnames=fields)
            writer.writeheader()
            for policy, scheduler in POLICIES.items():
                mode = "direct" if policy == "local" else "certificate"
                cap = 13 if policy in {"local", "direct_majority"} else 8
                with tempfile.TemporaryDirectory(prefix="otbc-engine-") as directory:
                    home = Path(directory)
                    try:
                        with Producer(14, mode, cap, home / "producer") as producer:
                            with Cluster(binary, home / "cluster", 4, producer.config, 35) as cluster:
                                for trial in range(args.repeat):
                                    previous = state(cluster.nodes[0]["rpc"])
                                    proposal, work = producer.make(previous, 32, scheduler, "honest")
                                    if proposal is None:
                                        raise AssertionError(f"{policy} failed to build a valid submission")
                                    if policy == "O-TBC" and (work["jobs"], work["epochs"]) != (7, 1):
                                        raise AssertionError(f"Unexpected O-TBC initial probe: {work}")
                                    result = cluster.submit(proposal, previous, output / f"{policy}-{trial + 1}")
                                    if result["outcome"] != "finalized" or result["signers"] < 3:
                                        raise AssertionError(f"Expected a finalized block: {result}")
                                    writer.writerow({
                                        "policy": policy, "trial": trial + 1, "batch": 32,
                                        "jobs": work["jobs"], "epochs": work["epochs"],
                                        "checks": work["checks"], "transaction_bytes": len(proposal),
                                        **{key: result[key] for key in ("height", "round", "signers", "tx_hash")},
                                    })
                                    trial_file.flush()
                    except Exception:
                        diagnostic(home, output, policy)
                        raise
    finally:
        deploy.cohort = default_cohort


if __name__ == "__main__":
    main()
