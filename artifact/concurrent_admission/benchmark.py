import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import csv
import itertools
import json
import os
from pathlib import Path
import platform
import statistics
import tempfile
import threading
import time

from contract import SNAPSHOT, Control, MAJORITY, launch, rpc
from benchmark_v6 import seeded, signed_history, threshold
from ossl import Key, version
from protocol import b64, canonical, decision, digest, feasible, next_cohort, unb64
from scheduler import optimistic

CASES = {
    "O-TBC": ("O-TBC", True),
    "O-TBC-off": ("O-TBC", False),
    "L4": ("L4", True),
    "T2": ("T2", True),
    "DM": ("DM", True),
    "ES-QM": ("ES-QM", True),
    "ES-S": ("ES-S", True),
    "Authority": ("Authority", True),
}


def cpu(pids):
    ticks = os.sysconf("SC_CLK_TCK")
    fields = [Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split() for pid in pids]
    return sum(int(row[11]) + int(row[12]) for row in fields) / ticks


def quantile(values, fraction):
    if not values:
        return ""
    values = sorted(values)
    pos = (len(values) - 1) * fraction
    low = int(pos)
    return values[low] + (values[min(low + 1, len(values) - 1)] - values[low]) * (pos - low)


def write(path, records):
    if records:
        empty = not path.exists()
        with path.open("a", newline="") as stream:
            writer = csv.DictWriter(stream, records[0].keys())
            if empty:
                writer.writeheader()
            writer.writerows(records)


def plan_for(policy, history, n, f, c, cap, order):
    if policy in MAJORITY:
        return order[:2 * f + 1]
    if policy == "Authority":
        return order[:cap]
    if policy == "O-TBC":
        return optimistic(history, n, f, c)
    if policy == "L4":
        rule = "adaptive_four_work" if f >= c + 5 else "adaptive_four_disjoint"
        return next_cohort(rule, history, n, f, c)
    return next_cohort("adaptive_two", history, n, f, c, admission_cap=cap)


def groups(policy, plan, submit, slots, f):
    if policy not in {"ES-QM", "ES-S"}:
        return [future.result() for future in (list(map(submit, plan)))]
    outcomes = []
    counts = [0, 0]
    remaining = iter(plan)

    def add(future):
        job = future.result()
        outcomes.append(job)
        if job["timely"]:
            counts[job["bit"]] += 1

    if policy == "ES-QM":
        while max(counts) <= f:
            wave = list(itertools.islice(remaining, max(1, f + 1 - max(counts))))
            if not wave:
                break
            for future in list(map(submit, wave)):
                add(future)
    else:
        pending = set(map(submit, itertools.islice(remaining, slots)))
        while pending:
            finished, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                add(future)
            if max(counts) <= f:
                pending.update(map(submit, itertools.islice(remaining, slots - len(pending))))
    return outcomes


def trial(control, addr, registry, seal_public, pool, ctx, batch, case, scenario, truth,
          slots, repeat, task, window_ms):
    policy, gated = CASES[case]
    n, f, c = (ctx[k] for k in ("n", "f", "c"))
    rng = seeded("admission-final", n, repeat, task, scenario)
    order = list(range(n))
    rng.shuffle(order)
    previous = set(rng.sample(order, f)) if scenario == "static" else set()
    start = time.monotonic_ns()
    registered, wire = control.call(op="register", context=ctx, policy=policy)
    cid, cap = registered["cid"], registered["cap"]
    epochs, jobs, entries, history = [], [], [], []
    result, reason = None, "horizon"
    horizon = 1 if policy in MAJORITY or policy == "Authority" else 2 if policy == "T2" else 4
    for epoch in range(1, horizon + 1):
        plan = plan_for(policy, history, n, f, c, cap, order)
        if not plan:
            break
        if scenario == "mobile":
            if epoch == 1:
                selected = set(plan[:f])
                previous = selected | set(rng.sample(sorted(set(order) - selected), f - len(selected)))
            else:
                entrants = [i for i in plan if i not in previous][:c]
                dropped = sorted(previous, key=lambda i: plan.index(i) if i in plan else n, reverse=True)[:len(entrants)]
                previous = (previous - set(dropped)) | set(entrants)
        now = time.monotonic_ns()
        opened, overhead = control.call(op="open", cid=cid, epoch=epoch, plan=sorted(plan))
        wire += overhead

        def run(i, queued):
            running = time.monotonic_ns()
            gate_rpc = issue = ticket_wire = 0
            ticket = None
            task_wire = 0
            row = dict(attempt=ctx["attempt_id"], epoch=epoch, worker=i,
                       queue_ns=running - queued, ticket_rpc_ns=0, ticket_issue_ns=0,
                       ticket_verify_and_replay_ns=0, ticket_wire=0, task_wire=0,
                       task_cpu_ns=0, task_rpc_ns=0, checks=0, started=False, admitted=False,
                       timely=False, bit="", error="")
            try:
                if running >= opened["deadline"]:
                    raise ValueError("work queued past deadline")
                if gated:
                    issued, ticket_wire = control.call(op="admit", cid=cid, epoch=epoch, worker=i)
                    ticket, issue = issued["ticket"], issued["issue_ns"]
                    gate_rpc = time.monotonic_ns() - running
                    row.update(admitted=True, ticket_rpc_ns=gate_rpc,
                               ticket_issue_ns=issue, ticket_wire=ticket_wire)
                before_task = time.monotonic_ns()
                override = (1 - truth if i in previous else None)
                outgoing_batch = batch
                if policy == "Authority":
                    outgoing_batch, override = None, truth
                row.update(started=True)
                reply, task_wire = rpc(addr[i], dict(context=ctx, epoch=epoch,
                                                     batch=outgoing_batch, ticket=ticket, override=override))
                row.update(task_rpc_ns=time.monotonic_ns() - before_task, task_wire=task_wire)
                if not reply["ok"]:
                    raise ValueError(reply["error"])
                if policy != "Authority" and reply["truth"] != truth:
                    raise AssertionError("worker computed wrong underlying result")
                row.update(ticket_verify_and_replay_ns=reply["gate_ns"],
                           task_wire=task_wire + reply["deposit_wire"],
                           task_cpu_ns=reply["task_cpu_ns"], checks=reply["checks"],
                           timely=reply["timely"], bit=reply["bit"])
            except (ValueError, TimeoutError, OSError) as exc:
                row["error"] = str(exc)
            return row

        epoch_jobs = groups(policy, plan, lambda i: pool.submit(run, i, time.monotonic_ns()), slots, f)
        jobs.extend(epoch_jobs)
        selected = sorted(r["worker"] for r in epoch_jobs if r["started"])
        sealed, overhead = control.call(op="finish", cid=cid, epoch=epoch, started=selected)
        wire += overhead
        poll_deadline = time.monotonic_ns() + max(window_ms, 1500) * 1_000_000
        while sealed.get("entry") is None:
            if time.monotonic_ns() >= poll_deadline:
                raise TimeoutError("authority did not seal")
            time.sleep(.005)
            envelope, overhead = control.call(op="get", cid=cid, epoch=epoch)
            sealed = envelope.get("closed") or {}
            wire += overhead
        entry = sealed["entry"]
        entries.append(entry)
        labels = signed_history(entries, registry, seal_public, ctx)
        pair = labels[-1]
        history.append(pair)
        actual_cohort = len(entry["header"]["body"]["cohort"])
        reports = len(entry["reports"])
        assert actual_cohort <= cap and feasible([x[truth] for x in history], f, c)
        epochs.append(dict(attempt=ctx["attempt_id"], epoch=epoch, planned=len(plan),
                           admitted=actual_cohort, reports=reports, deadline=opened["deadline"],
                           close_reason=sealed["reason"], seal_ns=sealed["closure_ns"],
                           window_ns=sealed["window_ns"], epoch_wall_ns=time.monotonic_ns() - now,
                           injected_ids=" ".join(map(str, sorted(previous)))))
        result = threshold(pair, f) if policy in MAJORITY else decision(history, f, c)
        if policy == "Authority":
            result = truth
            reason = "synthetic-control"
            break
        if result is not None:
            reason = "decided"
            break
        if reports != len(plan):
            reason = "incomplete"
            break
    wall = time.monotonic_ns() - start
    metrics = dict(
        attempt=ctx["attempt_id"], case=case, policy=policy, gated=gated, n=n, scenario=scenario,
        repeat=repeat, task=task, correct=int(result == truth and policy != "Authority"),
        incorrect=int(result is not None and result != truth), unresolved=int(result is None),
        synthetic=int(policy == "Authority"), reason=reason, epochs=len(epochs), cap=cap,
        jobs=sum(r["checks"] > 0 for r in jobs), started_rpc=sum(r["started"] for r in jobs),
        completed=sum(r["bit"] != "" for r in jobs), late=sum(r["bit"] != "" and not r["timely"] for r in jobs),
        rejected=sum(bool(r["error"]) for r in jobs), checks=sum(r["checks"] for r in jobs),
        peak_admitted=max([r["admitted"] for r in epochs], default=0), wall_ns=wall,
        wire_bytes=wire + sum(r["ticket_wire"] + r["task_wire"] for r in jobs),
        worker_task_cpu_ns=sum(r["task_cpu_ns"] for r in jobs),
    )
    assert not metrics["incorrect"], metrics
    return metrics, epochs, jobs


def run(args):
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=False)
    n, c = args.population, args.churn
    f = n // 2 - c
    tx = Key.generate("ML-DSA-65")
    workload = seeded("admission-payload", n, args.batch)
    valid = []
    for _ in range(args.batch):
        msg = workload.randbytes(128)
        valid.append([b64(msg), b64(tx.sign(msg))])
    invalid = [entry.copy() for entry in valid]
    bad = bytearray(unb64(invalid[-1][1]))
    bad[-1] ^= 1
    invalid[-1][1] = b64(bad)
    corpora = {0: invalid, 1: valid}
    common_context = dict(chain_id="otbc-integrated", height=1, prestate_root="1" * 64, credential_version=1,
                credential_key_digest=digest(tx.public_bytes()), policy_id="all-ML-DSA-65", policy_version=1,
                component="batch", implementation_id="OpenSSL-EVP", n=n, f=f, c=c)
    cases = list(itertools.product(range(args.repeats), args.clients, args.scenarios, args.cases))
    seeded("admission-block-order", n, args.batch).shuffle(cases)
    sources = [Path(__file__).resolve(), Path(__file__).with_name("contract.py").resolve()]
    sources.extend(sorted(SNAPSHOT.glob("*.py")))
    environment = dict(vars(args), openssl=version(0).decode(), platform=platform.platform(),
                       python=platform.python_version(), cpus=sorted(os.sched_getaffinity(0)),
                       cpu_quota=Path("/sys/fs/cgroup/cpu.max").read_text().strip(),
                       source_sha256={path.name: digest(path.read_bytes()) for path in sources},
                       evidence="One WSL2 host, TCP loopback, per-attempt quota, independently timed closure.",
                       randomized_blocks=len(cases), status="running",
                       initial_state="Fresh registered worker cohort, authority, and database per block; two local warmups per block.")
    (out / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    for repeat, clients, scenario, case in cases:
        block_id = f"{n}-{clients}-{scenario}-{case}-{repeat}"
        gated = CASES[case][1]
        processes = []
        with tempfile.TemporaryDirectory(prefix="otbc-contract-") as tmp:
            try:
                keys = [Key.generate() for _ in range(n)]
                raw_registry = {str(i): b64(key.public_bytes()) for i, key in enumerate(keys)}
                registry = {i: key.public_key() for i, key in enumerate(keys)}
                base = dict(common_context, registry_digest=digest(canonical(raw_registry)))
                secret = os.urandom(32)
                auth_process, authority, seal_der = launch("authority", Path(tmp) / f"authority-{int(gated)}.db",
                                                           raw_registry, secret, args.window_ms, f, c, gated)
                processes.append(auth_process)
                ctl = Control(authority, secret)
                seal_public = Key.from_der(seal_der)
                workers, worker_ids = [], []
                for i, key in enumerate(keys):
                    proc, addr, _ = launch("worker", i, Path(tmp) / f"worker-{int(gated)}-{i}.db",
                                          key, authority, seal_der, tx.public_bytes(), gated)
                    processes.append(proc)
                    workers.append(addr)
                    worker_ids.append(proc.pid)
                with ThreadPoolExecutor(max_workers=args.slots) as pool:
                    for truth, batch in corpora.items():
                        ctx = dict(base, attempt_id=f"warm-{gated}-{truth}", object_digest=digest(canonical(batch)))
                        trial(ctl, workers, registry, seal_public, pool, ctx, batch, "O-TBC" if gated else "O-TBC-off",
                              "honest", truth, args.slots, -1, truth, args.window_ms)


                barrier = threading.Barrier(clients + 1)

                def client(i, pool):
                    barrier.wait()
                    rows = []
                    for task in range(i, args.attempts, clients):
                        truth = (task // clients + i + repeat) % 2
                        batch = corpora[truth]
                        ctx = dict(base, attempt_id=f"{block_id}-{task}", object_digest=digest(canonical(batch)))
                        rows.append(trial(ctl, workers, registry, seal_public, pool, ctx, batch, case,
                                          scenario, truth, args.slots, repeat, task, args.window_ms))
                    return rows

                with ThreadPoolExecutor(max_workers=args.slots) as pool, ThreadPoolExecutor(max_workers=clients) as exec_pool:
                    futures = [exec_pool.submit(client, i, pool) for i in range(clients)]
                    a0, w0, s0 = cpu([auth_process.pid]), cpu(worker_ids), time.process_time_ns()
                    t0 = time.monotonic_ns()
                    barrier.wait()
                    all_trials = [row for future in futures for row in future.result()]
                    elapsed = (time.monotonic_ns() - t0) / 1e9
                    s1, a1, w1 = time.process_time_ns(), cpu([auth_process.pid]), cpu(worker_ids)
                trials = [row[0] for row in all_trials]
                epochs = [epoch for row in all_trials for epoch in row[1]]
                jobs = [job for row in all_trials for job in row[2]]
                successes = sum(r["correct"] for r in trials)
                block = dict(
                    block_id=block_id, case=case, repeat=repeat, clients=clients, n=n, f=f, c=c,
                    scenario=scenario, batch=args.batch, slots=args.slots, gated=gated, attempts=len(trials),
                    correct=successes, incorrect=sum(r["incorrect"] for r in trials),
                    unresolved=sum(r["unresolved"] for r in trials), seconds=elapsed,
                    goodput=successes / elapsed, attempts_s=len(trials) / elapsed,
                    median_ms=statistics.median(r["wall_ns"] for r in trials) / 1e6,
                    p95_ms=quantile([r["wall_ns"] / 1e6 for r in trials], .95),
                    authority_cpu_s=max(0., a1 - a0), worker_cpu_s=max(0., w1 - w0),
                    scheduler_cpu_s=(s1 - s0) / 1e9,
                    median_gate_rpc_ms=quantile([r["ticket_rpc_ns"] / 1e6 for r in jobs if r["admitted"]], .5),
                    median_issue_ms=quantile([r["ticket_issue_ns"] / 1e6 for r in jobs if r["admitted"]], .5),
                    median_gate_verify_ms=quantile([r["ticket_verify_and_replay_ns"] / 1e6
                                                    for r in jobs if r["ticket_verify_and_replay_ns"]], .5),
                    median_closure_ms=quantile([r["seal_ns"] / 1e6 for r in epochs], .5),
                    median_worker_queue_ms=quantile([r["queue_ns"] / 1e6 for r in jobs], .5),
                    median_jobs=statistics.median(r["jobs"] for r in trials),
                    max_admitted=max(r["peak_admitted"] for r in trials),
                    rejected=sum(r["rejected"] for r in trials), late=sum(r["late"] for r in trials),
                    total_bytes=sum(r["wire_bytes"] for r in trials),
                )
                for name, rows in zip(("blocks", "trials", "epochs", "jobs"),
                                      ([block], trials, epochs, jobs)):
                    write(out / f"{name}.csv", rows)
                print(block_id, f"{successes}/{args.attempts}", f"{block['goodput']:.3f}/s",
                      f"p95={block['p95_ms']:.1f} ms", flush=True)
            finally:
                for proc in processes:
                    proc.terminate()
                for proc in processes:
                    proc.join(3)
    environment["status"] = "complete"
    (out / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    p.add_argument("--population", type=int, default=42)
    p.add_argument("--churn", type=int, default=1)
    p.add_argument("--batch", type=int, default=8)
    p.add_argument("--slots", type=int, default=4)
    p.add_argument("--clients", type=int, nargs="+", default=[1, 4, 8, 16])
    p.add_argument("--scenarios", choices=["honest", "static", "mobile"], nargs="+", default=["mobile"])
    p.add_argument("--cases", nargs="+", choices=sorted(CASES), default=list(CASES))
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--attempts", type=int, default=8)
    p.add_argument("--window-ms", type=int, default=4000)
    args = p.parse_args()
    if min(args.population, args.churn, args.batch, args.slots, args.repeats, args.attempts, args.window_ms, *args.clients) < 1:
        p.error("positive arguments are required")
    if args.population % 2 or args.population // 2 - args.churn <= args.churn:
        p.error("require n=2(f+c) and f>c")
    if any(c > args.attempts for c in args.clients):
        p.error("provide at least one attempt per client")
    run(args)


if __name__ == "__main__":
    main()
