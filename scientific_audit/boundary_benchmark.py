"""Local cryptographic replay of two-epoch boundary witnesses."""
import argparse
import copy
import csv
import hashlib
import json
import random
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from statistics import median

from audit_two_epochs import ambiguous

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parent / "artifact" / "systems_v8" / "snapshot"
sys.path.insert(0, str(ARTIFACT))
from benchmark_v6 import signed_history
from deploy import launch, checked
from ossl import Key, version
from protocol import canonical, digest, b64, unb64, public_bytes, decision

F, C, BATCH, SLOTS = 20, 1, 8, 4
CAPS = (21, 22, 25, 28, 41)


def extend(population, first, second):
    old = set(first)
    old.update(sorted(second - old)[:F - len(old)])
    old.update(sorted(population - old)[:F - len(old)])
    new = set(second)
    new.update(sorted(old - new)[:F - len(new)])
    assert len(old) == len(new) == F and len(new - old) <= C
    return old, new


def separating_cohort(population, A, B, size):
    outside = sorted(population - A - B)
    for x in range(min(len(A), size) + 1):
        for y in range(max(0, size-x-len(outside)), min(size-x, len(B)) + 1):
            z = size-x-y
            if not ambiguous(F, C, len(A), len(B), x, y, z):
                return set(sorted(A)[:x] + sorted(B)[:y] + outside[:z])
    raise AssertionError("The specified second size contains no separator")


def witness(n, cap, optimum, truth):
    population = set(range(n))
    if optimum and optimum["second_worst"] == 0:
        first = set(range(optimum["first"]))
        return [(first, set(range(F)), set(range(F)))]
    m = cap if optimum is None else optimum["first"]
    first = set(range(m))
    A, B = set(range(m//2)), set(range(m//2, m))
    old_mismatch = (A, B)[truth]
    if optimum:
        second = separating_cohort(population, A, B, optimum["second_worst"])
        old, new = extend(population, old_mismatch, set())
        mismatch = second & new
    else:
        second = set((sorted(population-first) + sorted(first))[:cap])
        k, x, y = len(second), len(second & A), len(second & B)
        p = max(0, k-F, k-(F+C-len(B))-y)
        qa, qb = F+C-len(A), F+C-len(B)
        assert p <= min(k, F, qa+x)
        pos = set(sorted(second & A)[:max(0, p-qa)])
        neg = set(sorted(second & B)[:max(0, k-p-qb)])
        pos.update(sorted(second-pos-neg)[:p-len(pos)])
        neg = second-pos
        assert len(pos) == p and len(pos) <= F and len(neg) <= F
        trajectories = [extend(population, d1, d2) for d1,d2 in ((A,pos),(B,neg))]
        old, new = trajectories[truth]
        mismatch = (pos,neg)[truth]
    return [(first, old, old_mismatch), (second, new, mismatch)]


def run_case(n, cap, truth, rep, plan, batch, base, workers, sealer, registry, seal_key, pool):
    attempt = f"boundary-{n}-{cap}-{truth}-{rep}"
    ctx = dict(base, attempt_id=attempt, object_digest=digest(canonical(batch)))
    entries, counts = [], []
    prev = None
    start = time.monotonic_ns()
    result = None
    for epoch, (cohort, exposed, mismatches) in enumerate(plan,1):
        assert len(cohort) <= cap and mismatches <= cohort & exposed
        assert len(exposed) <= F and (prev is None or len(exposed-prev)<=C)
        prev = exposed
        def poll(i):
            reply, _ = checked(workers[i],dict(op="verify",context=ctx,batch=batch,
                epoch=epoch,override=1-truth if i in mismatches else None))
            assert reply["actual"] == truth and reply["primitive_checks"] == BATCH
            return reply["report"]
        reports = list(pool.map(poll, sorted(cohort)))
        seal, _ = checked(sealer,dict(op="close",context=ctx,epoch=epoch,
                                     cohort=sorted(cohort),reports=reports))
        entries.append(seal["entry"])
        counts.append(len(reports))
        result = decision(signed_history(entries,registry,seal_key,ctx),F,C)
        if result is not None:
            break
    wall_ms = (time.monotonic_ns() - start) / 1e6
    assert result is None or result == truth
    return {"n":n,"cap":cap,"truth":truth,"repeat":rep,"epochs":len(counts),
        "jobs":sum(counts),"decided":int(result is not None),
        "unresolved":int(result is None),"wall_ms":round(wall_ms,6)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    output=parser.parse_args().output.resolve()
    output.mkdir(exist_ok=False)
    cases=json.loads((HERE/"two_epoch_checks.json").read_text())["reference"]
    rows, plans = [], []
    for n in range(40,46):
        tx=Key.generate("ML-DSA-65")
        txpub=tx.public_key()
        r=random.Random(401+n)
        good=[]
        for _ in range(BATCH):
            msg=r.randbytes(64)
            good.append([b64(msg),b64(tx.sign(msg))])
        bad=copy.deepcopy(good)
        sig=bytearray(unb64(bad[-1][1]))
        sig[-1]^=1
        bad[-1][1]=b64(sig)
        inputs={0:bad,1:good}
        with tempfile.TemporaryDirectory(prefix="otbc-boundary-") as d:
            ps, workers, raw = [], [], {}
            try:
                for i in range(n):
                    proc,x=launch("worker",{"id":i,"tx_key":b64(public_bytes(tx))})
                    ps.append(proc)
                    workers.append(x["addr"])
                    raw[str(i)]=x["public"]
                key=Key.generate()
                proc,x=launch("sealer",{"key":key,"registry":raw,"db":str(Path(d)/"seal.db")})
                ps.append(proc)
                registry={int(i):Key.from_der(unb64(v)) for i,v in raw.items()}
                base=dict(chain_id="otbc-boundary",height=1,prestate_root="1"*64,
                    credential_version=1,credential_key_digest=digest(public_bytes(tx)),
                    policy_id="all-ML-DSA-65",policy_version=1,component="batch",
                    implementation_id="OpenSSL-EVP",registry_digest=digest(canonical(raw)),n=n,f=F,c=C)
                queue=[(cap,t,rep) for cap in CAPS if cap<=n for t in (0,1) for rep in range(3)]
                r.shuffle(queue)
                with ThreadPoolExecutor(max_workers=SLOTS) as pool:
                    for cap,t,rep in queue:
                        optimum=cases[str(n)][str(cap)]
                        plan=witness(n,cap,optimum,t)
                        row=run_case(n,cap,t,rep,plan,inputs[t],base,workers,x["addr"],
                                     registry,key.public_key(),pool)
                        assert row["decided"] == int(optimum is not None),(row,optimum)
                        if optimum:
                            assert row["jobs"]==optimum["work"],(row,optimum)
                        rows.append(row)
                        if rep==0:
                            plans.append({"n":n,"cap":cap,"truth":t,"theoretical_guarantee":optimum is not None,
                                "epochs":[dict(cohort=sorted(a),exposed=sorted(b),mismatch=sorted(c)) for a,b,c in plan]})
            finally:
                for proc in ps:
                    if proc.is_alive():
                        proc.terminate()
                for proc in ps:
                    proc.join(timeout=2)
        print(n,len(rows),flush=True)
    with (output/"trials.csv").open("w",newline="") as stream:
        writer=csv.DictWriter(stream,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (output/"witnesses.json").write_text(json.dumps(plans,indent=2)+"\n")
    (output/"environment.json").write_text(json.dumps({
        "scope":"precomputed complete-label witness replay, no online cohort-selection cost",
        "openssl":version(0).decode(),
        "source_sha256":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in
        (Path(__file__),HERE/"audit_two_epochs.py",ARTIFACT/"protocol.py",ARTIFACT/"deploy.py",
         ARTIFACT/"benchmark_v6.py",ARTIFACT/"ossl.py")}},indent=2)+"\n")
    print(len(rows),sum(r["decided"] for r in rows),flush=True)

if __name__=="__main__":
    main()
