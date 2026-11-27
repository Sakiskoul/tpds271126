"""Actual local consumer fan-out using paired input and evidence."""
import argparse
import csv
import json
import multiprocessing as mp
import os
import sys
import tempfile
import time
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/"engine"))
from run_valid_cases import ARTIFACT, Producer, version, sha
from deploy import run_trial
from ledger import canonical, expected_context, initial_root, Key, unb64
from protocol import verify_positive


def ticks(processes):
    n=0
    for p in processes:
        fields=Path(f"/proc/{p.pid}/stat").read_text().rsplit(")",1)[1].split()
        n+=int(fields[11])+int(fields[12])
    return n


def verify(mode, config, blob, ctx, start, connection):
    if mode == "direct":
        key=Key.from_der(unb64(config["tx_key"]))
    else:
        registry={int(i):Key.from_der(unb64(raw)) for i,raw in config["registry"].items()}
        seal=Key.from_der(unb64(config["seal_key"]))
    connection.send("ready")
    if not start.wait(timeout=45):
        raise TimeoutError("Consumer release")
    t=time.process_time_ns()
    payload=json.loads(blob)
    if mode=="direct":
        for message, sig in payload:
            key.verify(unb64(sig),unb64(message))
    else:
        assert verify_positive(payload,registry,seal,ctx)
    connection.send((os.getpid(),time.process_time_ns()-t))
    connection.close()


def fanout(mode, count, config, payload, expected):
    proc_ctx=mp.get_context("fork")
    start=proc_ctx.Event()
    children=[]
    try:
        for _ in range(count):
            recv,send=proc_ctx.Pipe(duplex=False)
            proc=proc_ctx.Process(target=verify,args=(mode,config,payload,expected,start,send))
            proc.start()
            send.close()
            children.append((proc,recv))
        for _,recv in children:
            assert recv.poll(45) and recv.recv()=="ready"
        start.set()
        samples=[]
        for _,recv in children:
            assert recv.poll(45)
            samples.append(recv.recv())
        assert len({pid for pid,_ in samples})==count
        return samples
    finally:
        for proc,recv in children:
            recv.close()
            proc.join(timeout=3)
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=2)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    out=parser.parse_args().output
    out.mkdir(exist_ok=False)
    rows, aggregate=[],[]
    hz=os.sysconf("SC_CLK_TCK")
    with tempfile.TemporaryDirectory(prefix="otbc-consumers-") as temp:
        with Producer(14,"certificate",8,temp) as producer:
            state={"sequence":0,"root":initial_root(producer.config)}
            for B in (32,256):
                for rep in range(3):
                    attempt,batch=producer.batch(state,B)
                    before=ticks(producer.procs)
                    start=time.process_time_ns()
                    ctx=expected_context(producer.config,state,attempt,batch)
                    work,_,(_,certificate,_)=run_trial(
                        producer.addrs,producer.sealer,[],producer.registry,producer.seal.public_key(),
                        ctx,batch,"adaptive_four_work","targeted",attempt,producer.pool,producer.rng)
                    assert certificate and work["verdict"]==1
                    encoded=canonical(certificate)
                    E=time.process_time_ns()-start+(ticks(producer.procs)-before)*10**9//hz
                    raw_batch=canonical(batch)
                    for R in (14,40,70):
                        pair={}
                        for mode in (("direct","compact") if rep%2==0 else ("compact","direct")):
                            cpus=fanout(mode,R,producer.config,raw_batch if mode=="direct" else encoded,ctx)
                            for ordinal,(pid,ns) in enumerate(cpus):
                                rows.append(dict(batch=B,repeat=rep,consumers=R,path=mode,
                                                 ordinal=ordinal,pid=pid,cpu_ns=ns))
                            pair[mode]=sum(ns for _,ns in cpus)
                        aggregate.append(dict(batch=B,repeat=rep,consumers=R,jobs=work["jobs"],
                            epochs=work["epochs"],certificate_bytes=len(encoded),producer_cpu_ns=E,
                            direct_cpu_ns=pair["direct"],compact_cpu_ns=pair["compact"],
                            aggregate_ratio=(E+pair["compact"])/pair["direct"]))
                        print(B,rep,R,round(aggregate[-1]["aggregate_ratio"],3),flush=True)

    for name,values in (("consumers",rows),("paired",aggregate)):
        with (out/(name+".csv")).open("w",newline="") as stream:
            writer=csv.DictWriter(stream,fieldnames=list(values[0]))
            writer.writeheader()
            writer.writerows(values)
    (out/"environment.json").write_text(json.dumps({"openssl":version(0).decode(),
        "source_sha256":{p.name:sha(p) for p in (Path(__file__),ARTIFACT/"deployment/deploy.py",
           ARTIFACT/"deployment/protocol.py",ARTIFACT/"deployment/ossl.py",ARTIFACT/"cometbft/fixture.py")},
        "scope":"local cryptographic CPU of real child processes; worker production includes compact encoding; excludes startup and transport to consumers"
    },indent=2)+"\n")

if __name__=="__main__":
    main()
