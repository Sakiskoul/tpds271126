"""Finite-block concurrent throughput on real TCP/OpenSSL services.

This driver reuses the unmodified V6 authenticated trial and server code in
snapshot/. It adds a shared RPC executor, concurrent clients, timed blocks and
process resource accounting. It is a same-host experiment, with independent
per-attempt injected fault histories. It is not consensus or a saturation test.
"""
import argparse
import concurrent.futures as cf
import copy
import csv
import hashlib
import json
import os
import platform
import random
import resource
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'snapshot'))
from benchmark_v6 import trial, seeded
from deploy import launch, checked, write_csv
from ossl import Key, version
from protocol import canonical, digest, b64, unb64, public_bytes

POLICIES = ['Direct', 'ES-QM', 'ES-stream', 'L4', 'O-TBC']
CHURN = (1, 2, 4, 8, 12)
CONFIGS = [
    dict(n=2 * (20 + c), batch=8, slots=4, clients=4,
         dimension='matched', design_churn=c, realized_churn=c)
    for c in CHURN
] + [
    dict(n=64, batch=8, slots=4, clients=4,
         dimension='fixed', design_churn=12, realized_churn=c)
    for c in CHURN if c < 12
]


def percentile(values, q):
    """Linear interpolation of the finite observed sample."""
    xs = sorted(values)
    pos = (len(xs) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


class SharedRPCPool(cf.ThreadPoolExecutor):
    """Every worker call from every client shares this single bounded pool."""
    def __init__(self, slots):
        super().__init__(max_workers=slots)
        self.lock = threading.Lock()
        self.active = self.outstanding = 0
        self.peak_active = self.peak_outstanding = 0

    def reset_counts(self):
        with self.lock:
            assert self.active == self.outstanding == 0
            self.peak_active = self.peak_outstanding = 0

    def submit(self, fn, /, *args, **kwargs):
        with self.lock:
            self.outstanding += 1
            self.peak_outstanding = max(self.peak_outstanding, self.outstanding)

        def tracked():
            with self.lock:
                self.active += 1
                self.peak_active = max(self.peak_active, self.active)
            try:
                return fn(*args, **kwargs)
            finally:
                with self.lock:
                    self.active -= 1
                    self.outstanding -= 1
        return super().submit(tracked)


def process_cpu(pids):
    ticks = os.sysconf('SC_CLK_TCK')
    total = 0.0
    for pid in pids:

        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        total += (int(fields[11]) + int(fields[12])) / ticks
    return total


def process_rss(pids):
    page_size = os.sysconf('SC_PAGE_SIZE')
    return sum(int(Path(f'/proc/{pid}/statm').read_text().split()[1]) * page_size for pid in pids)


class MemoryProbe:
    def __init__(self, pids):
        self.pids = pids
        self.stop = threading.Event()
        self.peak = process_rss(pids)
        self.samples = 1
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.wait(.05):
            self.peak = max(self.peak, process_rss(self.pids))
            self.samples += 1

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.peak = max(self.peak, process_rss(self.pids))
        self.stop.set()
        self.thread.join()


def run_block(config, policy, scenario, repeat, count, workers, sealer, registry,
              sealer_pub, base, corpora, txpub, pool, service_pids):
    n, B, p, C = (config[k] for k in ('n', 'batch', 'slots', 'clients'))
    block_id = f'n{n}-m{config["realized_churn"]}-{policy}-{scenario}-r{repeat}'


    barrier = threading.Barrier(C + 1)
    assignments = [list(range(client, count, C)) for client in range(C)]
    contexts = dict(base, chain_id='otbc-v8-' + block_id)
    outputs = [[] for _ in range(C)]

    def client_work(client):
        barrier.wait()
        for task in assignments[client]:
            truth = task % 2
            rep_seed = C * 1000000 + repeat * 1000 + task
            row, epochs, jobs = trial(n, B, p, 0, 0, policy, scenario, truth,
                                     rep_seed, corpora[B, truth], workers,
                                     sealer, registry, sealer_pub, contexts,
                                     txpub, pool, config['realized_churn'])

            old = row['attempt']
            unique = block_id + '-task' + str(task)
            row.update(attempt=unique, source_attempt=old, block_id=block_id,
                       clients=C, task_index=task, block_repeat=repeat)
            for r in epochs + jobs:
                r.update(attempt=unique, block_id=block_id)
            outputs[client].append((row, epochs, jobs))

    pool.reset_counts()
    process_ids = [os.getpid()] + service_pids
    with cf.ThreadPoolExecutor(max_workers=C) as clients:
        futures = [clients.submit(client_work, c) for c in range(C)]
        before_cpu = process_cpu(process_ids)
        with MemoryProbe(process_ids) as mem:
            start = time.perf_counter_ns()
            barrier.wait()
            for future in futures:
                future.result()
            end = time.perf_counter_ns()
        after_cpu = process_cpu(process_ids)
    records = sorted((x for client in outputs for x in client), key=lambda x: x[0]['task_index'])
    trials = [x[0] for x in records]
    epochs = [e for x in records for e in x[1]]
    jobs = [j for x in records for j in x[2]]
    assert len(trials) == count
    assert pool.active == pool.outstanding == 0
    assert pool.peak_active <= p
    assert all(r['correct'] and not r['wrong'] for r in trials)
    elapsed = (end - start) / 1e9
    correct = sum(r['correct'] for r in trials)
    latencies = [r['wall_ms'] for r in trials]
    block = dict(block_id=block_id, **config, policy=policy, scenario=scenario,
                 repeat=repeat, attempts=count, correct=correct,
                 wrong=sum(r['wrong'] for r in trials),
                 unresolved=sum(r['result'] == 'unresolved' for r in trials),
                 elapsed_s=elapsed, goodput_cert_s=correct / elapsed,
                 goodput_predicate_checks_s=correct * B / elapsed,
                 latency_median_ms=percentile(latencies, .5),
                 latency_p95_ms=percentile(latencies, .95),
                 latency_max_ms=max(latencies), jobs=sum(r['jobs'] for r in trials),
                 checks=sum(r['checks'] for r in trials),
                 worker_task_cpu_s=sum(r['cpu_ns'] for r in trials) / 1e9,
                 host_process_cpu_s=max(0, after_cpu - before_cpu),
                 wire_bytes=sum(r['wire_bytes'] for r in trials),
                 peak_rpc_active=pool.peak_active,
                 peak_rpc_outstanding=pool.peak_outstanding,
                 sampled_sum_rss_bytes=mem.peak, rss_samples=mem.samples,
                 worker_processes=n, sealer_processes=1, coordinator_processes=1,
                 process_count=n + 2)
    return block, trials, epochs, jobs


def read_optional(path):
    p = Path(path)
    return p.read_text().strip() if p.exists() else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--attempts', type=int, default=16)
    parser.add_argument('--pilot', action='store_true')
    parser.add_argument('--populations', type=int, nargs='+')
    args = parser.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'blocks.csv').exists():
        raise SystemExit('Refusing to overwrite existing measured results')
    configs = CONFIGS[:1] if args.pilot else CONFIGS
    if args.populations:
        configs = [c for c in configs if c['n'] in args.populations]
    if any(args.attempts % c['clients'] for c in configs):
        raise SystemExit('Attempts must be divisible by every client count')
    planned = [dict(c, policy=p, scenario=s, repeat=r)
               for c in configs for p in POLICIES for s in ['mobile']
               for r in range(args.repeats)]
    (out / 'plan.json').write_text(json.dumps(dict(
        created_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        attempts_per_block=args.attempts, blocks=planned,
        total_blocks=len(planned), total_attempts=len(planned) * args.attempts,
        ordering='Deterministic shuffled blocks within each population',
        scope='finite closed-loop blocks; single host; independent per-attempt injected mobile histories'), indent=2) + '\n')
    sources = [Path(__file__)] + sorted((HERE / 'snapshot').glob('*.py'))
    source_hashes = {p.relative_to(HERE).as_posix(): digest(p.read_bytes()) for p in sources}
    blocks, rows, epochs, jobs, topologies, pids_record = [], [], [], [], [], []
    for n in sorted({c['n'] for c in configs}):
        tx = Key.generate('ML-DSA-65')
        txpub = tx.public_key()
        rng = seeded('data-v8', n)
        corpus = []
        for _ in range(max(c['batch'] for c in configs if c['n'] == n)):
            message = rng.randbytes(128)
            corpus.append([b64(message), b64(tx.sign(message))])
        corpora = {}
        for B in {c['batch'] for c in configs if c['n'] == n}:
            corpora[B, 1] = copy.deepcopy(corpus[:B])
            corpora[B, 0] = copy.deepcopy(corpus[:B])
            signature = bytearray(unb64(corpora[B, 0][-1][1]))
            signature[-1] ^= 1
            corpora[B, 0][-1][1] = b64(signature)
        with tempfile.TemporaryDirectory() as directory:
            procs, workers, raw, pools = [], [], {}, {}
            try:
                setup_start = time.perf_counter_ns()
                for i in range(n):
                    proc, x = launch('worker', dict(id=i, tx_key=b64(public_bytes(tx))))
                    procs.append(proc)
                    workers.append(x['addr'])
                    raw[str(i)] = x['public']
                    pids_record.append(dict(n=n, role='worker', worker=i, pid=x['pid']))
                key = Key.generate()
                proc, x = launch('sealer', dict(key=key, registry=raw, db=str(Path(directory) / 'seal.db')))
                procs.append(proc)
                sealer = x['addr']
                pids_record.append(dict(n=n, role='sealer', worker=-1, pid=x['pid']))
                registry = {int(i): Key.from_der(unb64(k)) for i, k in raw.items()}
                base = dict(chain_id='otbc-v8', height=1, prestate_root='1' * 64,
                            credential_version=1, credential_key_digest=digest(public_bytes(tx)),
                            policy_id='all-ML-DSA-65', policy_version=1, component='batch',
                            implementation_id='OpenSSL-EVP', registry_digest=digest(canonical(raw)),
                            n=n, f=20, c=n // 2 - 20)
                pools = {p: SharedRPCPool(p) for p in {c['slots'] for c in configs if c['n'] == n}}
                setup_s = (time.perf_counter_ns() - setup_start) / 1e9
                warm = dict(base, attempt_id='warm', object_digest=digest(canonical(corpus[:1])))
                warm_start = time.perf_counter_ns()
                list(pools[4].map(lambda i: checked(workers[i], dict(op='verify', context=warm,
                     batch=corpus[:1], epoch=1, override=None)), range(n)))
                warmup_s = (time.perf_counter_ns() - warm_start) / 1e9
                topologies.append(dict(n=n, process_count=n+2, setup_s=setup_s,
                                       worker_warmup_s=warmup_s))
                matrix = [c for c in planned if c['n'] == n]
                seeded('order-v8', n).shuffle(matrix)
                for index, case in enumerate(matrix):
                    config = {k: case[k] for k in ('n', 'batch', 'slots', 'clients', 'dimension', 'design_churn', 'realized_churn')}
                    b, rr, ee, jj = run_block(config, case['policy'], case['scenario'], case['repeat'],
                        args.attempts, workers, sealer, registry, key.public_key(), base, corpora,
                        txpub, pools[config['slots']], [p.pid for p in procs])
                    blocks.append(b); rows.extend(rr); epochs.extend(ee); jobs.extend(jj)
                    write_csv(out / 'blocks.csv', blocks)
                    write_csv(out / 'trials.csv', rows)
                    write_csv(out / 'epochs.csv', epochs)
                    write_csv(out / 'jobs.csv', jobs)
                    print(json.dumps(dict(block=len(blocks), planned=len(planned), id=b['block_id'],
                        goodput=round(b['goodput_cert_s'], 3), p95_ms=round(b['latency_p95_ms'], 2),
                        correct=b['correct'], max_active=b['peak_rpc_active'])), flush=True)
            finally:
                for pool in pools.values():
                    pool.shutdown()
                for proc in procs:
                    if proc.is_alive(): proc.terminate()
                for proc in procs: proc.join(timeout=2)
    environment = dict(args=vars(args), openssl=version(0).decode(), python=platform.python_version(),
        platform=platform.platform(), cpu_count=os.cpu_count(), affinity=sorted(os.sched_getaffinity(0)),
        cpu_max=read_optional('/sys/fs/cgroup/cpu.max'), memory_max=read_optional('/sys/fs/cgroup/memory.max'),
        proc_cpuinfo=read_optional('/proc/cpuinfo'), proc_meminfo=read_optional('/proc/meminfo'),
        topologies=topologies, source_sha256=source_hashes,
        notes='Actual loopback TCP services; shared RPC queue; complete signed-report/SQLite closure/transcript authentication for all policies. Same-host shared resources. Independent per-attempt faults. No TLS, real compromises, multi-host, admission gate integration or consensus. Finite closed-loop block rates, no sustainable-load capacity claim. RSS sums double-count shared pages. CPU counters use /proc clock ticks.')
    (out / 'environment.json').write_text(json.dumps(environment, indent=2) + '\n')
    write_csv(out / 'processes.csv', pids_record)
    assert len(blocks) == len(planned)
    print('COMPLETE', len(blocks), len(rows), 'attempts', sum(b['checks'] for b in blocks), 'checks', flush=True)


if __name__ == '__main__':
    main()
