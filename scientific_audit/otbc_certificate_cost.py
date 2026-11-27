"""Measure paired full, compact and direct verification on signed O-TBC traces."""

import argparse
import csv
import json
import os
import platform
import random
import tempfile
import time
from pathlib import Path

from consumer_fanout import (
    ARTIFACT, Producer, canonical, expected_context, initial_root, sha, ticks,
    version,
)
import deploy
from ledger import unb64
from protocol import verify_full, verify_positive
from scheduler import optimistic


def options(label, epoch, cohort, n, f, c):
    if label == "two":
        return set(cohort[:f] if epoch == 1 else cohort)
    if label == "four":
        if epoch == 1:
            return set(cohort[:(f + c) // 2])
        if epoch == 2:
            return set(cohort[:(f + c + 1) // 2])
        if epoch == 3:
            return set(cohort[:c])
        return set(cohort)
    raise ValueError(label)


def measure_decoder(action, encoded, repetitions=8):
    samples = []
    for _ in range(repetitions):
        started = time.process_time_ns()
        result = action(json.loads(encoded))
        samples.append(time.process_time_ns() - started)
    return result, sorted(samples)[len(samples) // 2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--blocks", type=int, default=5)
    p.add_argument("--full-size", type=int, nargs="+", default=[1, 32, 128, 256])
    args = p.parse_args()
    args.output.mkdir(parents=True)
    fields = ("n", "batch", "block", "case", "truth", "epochs", "jobs", "peak",
              "producer_cpu_ns",
              "producer_wall_ns", "full_cpu_ns", "compact_cpu_ns", "direct_cpu_ns",
              "full_bytes", "compact_bytes", "direct_bytes", "producer_wire_bytes")
    original_cohort = deploy.cohort
    original_targets = deploy.targeted_positive
    deploy.cohort = lambda policy, h, n, f, c: (
        optimistic(h, n, f, c) if policy == "O-TBC" else original_cohort(policy, h, n, f, c))
    hz = os.sysconf("SC_CLK_TCK")
    try:
        with (args.output / "paired.csv").open("w", newline="") as file:
            writer = csv.DictWriter(file, fields)
            writer.writeheader()
            for n, sizes in ((14, args.full_size), (42, [32])):
                with tempfile.TemporaryDirectory(prefix="otbc-cert-cost-") as temp:
                    with Producer(n, "certificate", n // 2 + 1, temp) as producer:
                        state = {"sequence": 0, "root": initial_root(producer.config)}
                        seal_public = producer.seal.public_key()
                        for block in range(args.blocks):
                            trials = [(b, case) for b in sizes for case in
                                      ("honest", "two", "four", "l4", "negative")]
                            random.Random(1719 + block).shuffle(trials)
                            for b, case in trials:
                                if case in {"two", "four"}:
                                    deploy.targeted_positive = (
                                        lambda policy, epoch, cohort, population, f, c:
                                        options(case, epoch, cohort, population, f, c))
                                else:
                                    deploy.targeted_positive = original_targets
                                negative = case == "negative"
                                policy = "adaptive_four_work" if case == "l4" else "O-TBC"
                                scenario = {"negative": "invalid", "honest": "honest"}.get(case, "targeted")
                                attempt, batch = producer.batch(state, b, invalid=negative)
                                context = expected_context(producer.config, state, attempt, batch)
                                before = ticks(producer.procs)
                                cpu_started = time.process_time_ns()
                                wall_started = time.perf_counter_ns()
                                work, _, (_, compact, entries) = deploy.run_trial(
                                    producer.addrs, producer.sealer, [], producer.registry,
                                    seal_public, context, batch, policy, scenario, attempt,
                                    producer.pool, producer.rng)
                                full_blob = canonical({"format": "full-v1", "epochs": entries})
                                compact_blob = canonical(compact) if compact else None
                                wall = time.perf_counter_ns() - wall_started
                                parent_cpu = time.process_time_ns() - cpu_started
                                total_cpu = parent_cpu + (ticks(producer.procs) - before) * 10**9 // hz
                                expected = 0 if negative else 1
                                epochs = {"honest": 1, "two": 2, "four": 4}
                                assert work["verdict"] == expected
                                assert work["epochs"] == epochs.get(case, work["epochs"])
                                if block == 0 and b == 32:
                                    (args.output / f"trace-{n}-{case}.json").write_bytes(canonical({
                                        "context": context, "policy": policy, "truth": expected,
                                        "worker_keys": producer.config["registry"],
                                        "seal_key": producer.config["seal_key"],
                                        "task_key": producer.config["tx_key"], "batch": batch,
                                        "full": json.loads(full_blob), "compact": compact,
                                    }))
                                direct_blob = canonical(batch)
                                task_public = producer.key.public_key()

                                def direct(decoded):
                                    ok = True
                                    for message, signature in decoded:
                                        try:
                                            task_public.verify(unb64(signature), unb64(message))
                                        except ValueError:
                                            ok = False
                                    return int(ok)

                                result, full_cpu = measure_decoder(
                                    lambda obj: verify_full(obj, producer.registry, seal_public, context),
                                    full_blob)
                                assert result == expected
                                result, direct_cpu = measure_decoder(direct, direct_blob)
                                assert result == expected
                                compact_cpu = None
                                if compact_blob:
                                    result, compact_cpu = measure_decoder(
                                        lambda obj: verify_positive(obj, producer.registry, seal_public, context),
                                        compact_blob)
                                    assert result
                                writer.writerow(dict(
                                    n=n, batch=b, block=block, case=case, truth=expected,
                                    epochs=work["epochs"], jobs=work["jobs"], peak=work["peak"],
                                    producer_cpu_ns=total_cpu,
                                    producer_wall_ns=wall, full_cpu_ns=full_cpu,
                                    compact_cpu_ns=compact_cpu, direct_cpu_ns=direct_cpu,
                                    full_bytes=len(full_blob), compact_bytes=len(compact_blob or b""),
                                    direct_bytes=len(direct_blob), producer_wire_bytes=work["app_wire_bytes"],
                                ))
                                file.flush()
                            print(f"n={n}, block={block + 1}/{args.blocks}", flush=True)
    finally:
        deploy.cohort = original_cohort
        deploy.targeted_positive = original_targets
    (args.output / "environment.json").write_text(json.dumps({
        "platform": platform.platform(), "openssl": version(0).decode(), "cpu_ticks_per_sec": hz,
        "blocks_per_population": args.blocks, "consumer_checks_per_sample": 8,
        "producer_scope": "shared full-and-compact preparation path and both encodings; includes TCP and closure; excludes common input generation",
        "consumer_scope": "paired JSON decode and verification with preloaded keys; no delivery or concurrent consumers",
        "source_sha256": {file.name: sha(file) for file in (
            Path(__file__), Path(__file__).with_name("consumer_fanout.py"),
            ARTIFACT / "deployment/deploy.py", ARTIFACT / "deployment/protocol.py",
            ARTIFACT / "optimistic/scheduler.py",
        )},
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
