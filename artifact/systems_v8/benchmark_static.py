"""Concurrent controlled report faults with one shared static faulty set.

The immutable primary driver supplies its run_block function and the exact same
TCP/crypto/closure path. Only the fault RNG is fixed across attempts. Selection
RNG calls retain their original per-attempt seeds.
"""
import argparse
import copy
import json
import os
import platform
import random
import tempfile
import time
from pathlib import Path

import benchmark as bench

FAULT_SEED = 2026112608
N, B, P, C = 42, 32, 4, 4


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--attempts', type=int, default=64)
    args = parser.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'blocks.csv').exists():
        raise SystemExit('Refusing to overwrite existing measured results')
    if args.attempts % C:
        raise SystemExit('Attempts must be divisible by four clients')
    fixed_faults = sorted(random.Random(FAULT_SEED).sample(range(N), N // 2 - 1))
    original_seeded = bench.seeded

    def fixed_fault_rng(*xs):
        if xs[0] == 'fault' and xs[5] == 'static':
            return random.Random(FAULT_SEED)
        return original_seeded(*xs)

    bench.trial.__globals__['seeded'] = fixed_fault_rng
    config = dict(n=N, batch=B, slots=P, clients=C, dimension='reference')
    planned = [dict(config, policy=policy, scenario='static', repeat=r)
               for policy in bench.POLICIES for r in range(args.repeats)]
    (out / 'plan.json').write_text(json.dumps(dict(
        created_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        attempts_per_block=args.attempts, blocks=planned,
        total_blocks=len(planned), total_attempts=len(planned) * args.attempts,
        global_fault_seed=FAULT_SEED, global_fault_ids=fixed_faults,
        selection_rng='Original per-attempt selection seeds are unchanged',
        ordering='Deterministically shuffled policy/repetition blocks',
        scope='one same-host process pool with controlled report-fault injection in a single shared static size-f identity set'), indent=2) + '\n')
    sources = [Path(__file__).resolve(), Path(bench.__file__).resolve()] + sorted((bench.HERE / 'snapshot').glob('*.py'))
    hashes = {p.relative_to(bench.HERE).as_posix(): bench.digest(p.read_bytes()) for p in sources}
    tx = bench.Key.generate('ML-DSA-65')
    txpub = tx.public_key()
    rng = original_seeded('data-v8', N)
    corpus = []
    for _ in range(B):
        message = rng.randbytes(128)
        corpus.append([bench.b64(message), bench.b64(tx.sign(message))])
    corpora = {(B, 1): copy.deepcopy(corpus), (B, 0): copy.deepcopy(corpus)}
    sig = bytearray(bench.unb64(corpora[B, 0][-1][1]))
    sig[-1] ^= 1
    corpora[B, 0][-1][1] = bench.b64(sig)
    blocks, trials, epochs, jobs, process_rows = [], [], [], [], []
    with tempfile.TemporaryDirectory() as directory:
        procs, workers, raw, pool = [], [], {}, None
        try:
            setup_start = time.perf_counter_ns()
            for i in range(N):
                proc, x = bench.launch('worker', dict(id=i, tx_key=bench.b64(bench.public_bytes(tx))))
                procs.append(proc); workers.append(x['addr']); raw[str(i)] = x['public']
                process_rows.append(dict(n=N, role='worker', worker=i, pid=x['pid']))
            key = bench.Key.generate()
            proc, x = bench.launch('sealer', dict(key=key, registry=raw, db=str(Path(directory) / 'seal.db')))
            procs.append(proc); sealer = x['addr']
            process_rows.append(dict(n=N, role='sealer', worker=-1, pid=x['pid']))
            registry = {int(i): bench.Key.from_der(bench.unb64(k)) for i, k in raw.items()}
            base = dict(chain_id='otbc-v8-static', height=1, prestate_root='1' * 64,
                credential_version=1, credential_key_digest=bench.digest(bench.public_bytes(tx)),
                policy_id='all-ML-DSA-65', policy_version=1, component='batch',
                implementation_id='OpenSSL-EVP', registry_digest=bench.digest(bench.canonical(raw)),
                n=N, f=N // 2 - 1, c=1)
            pool = bench.SharedRPCPool(P)
            setup_s = (time.perf_counter_ns() - setup_start) / 1e9
            warm = dict(base, attempt_id='warm', object_digest=bench.digest(bench.canonical(corpus[:1])))
            warm_start = time.perf_counter_ns()
            list(pool.map(lambda i: bench.checked(workers[i], dict(op='verify', context=warm,
                batch=corpus[:1], epoch=1, override=None)), range(N)))
            warmup_s = (time.perf_counter_ns() - warm_start) / 1e9
            matrix = planned[:]
            original_seeded('order-static-v8', N).shuffle(matrix)
            for case in matrix:
                block, rr, ee, jj = bench.run_block(config, case['policy'], 'static', case['repeat'],
                    args.attempts, workers, sealer, registry, key.public_key(), base, corpora,
                    txpub, pool, [p.pid for p in procs])
                assert all(sorted(map(int, e['faults'].split())) == fixed_faults for e in ee)
                blocks.append(block); trials.extend(rr); epochs.extend(ee); jobs.extend(jj)
                for name, records in [('blocks', blocks), ('trials', trials), ('epochs', epochs), ('jobs', jobs)]:
                    bench.write_csv(out / (name + '.csv'), records)
                print(json.dumps(dict(block=len(blocks), planned=len(planned), id=block['block_id'],
                    goodput=round(block['goodput_cert_s'], 3), p95_ms=round(block['latency_p95_ms'], 2),
                    correct=block['correct'], global_fault_set_verified=True)), flush=True)
        finally:
            if pool: pool.shutdown()
            for proc in procs:
                if proc.is_alive(): proc.terminate()
            for proc in procs: proc.join(timeout=2)
    env = dict(args=vars(args), openssl=bench.version(0).decode(), python=platform.python_version(),
        platform=platform.platform(), cpu_count=os.cpu_count(), affinity=sorted(os.sched_getaffinity(0)),
        cpu_max=bench.read_optional('/sys/fs/cgroup/cpu.max'), memory_max=bench.read_optional('/sys/fs/cgroup/memory.max'),
        proc_cpuinfo=bench.read_optional('/proc/cpuinfo'), proc_meminfo=bench.read_optional('/proc/meminfo'),
        topologies=[dict(n=N, process_count=N+2, setup_s=setup_s, worker_warmup_s=warmup_s)],
        source_sha256=hashes, global_fault_seed=FAULT_SEED, global_fault_ids=fixed_faults,
        selection_rng='Only fault RNG is replaced. Selection RNG remains per-attempt and deterministic.',
        notes='Actual same-host TCP/ML-DSA/SQLite execution. Globally shared static fault identities inject incorrect signed report bits after real task work. No compromised physical hosts, admission-gate timing, fixed external epochs, TLS, multi-host or consensus. Finite closed-loop blocks.')
    (out / 'environment.json').write_text(json.dumps(env, indent=2) + '\n')
    bench.write_csv(out / 'processes.csv', process_rows)
    assert len(blocks) == len(planned)
    print('COMPLETE', len(blocks), len(trials), 'attempts', sum(b['checks'] for b in blocks), 'checks', flush=True)


if __name__ == '__main__':
    main()
