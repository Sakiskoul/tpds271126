"""Real wall-clock TCP deadline experiment. No simulated execution times.
A trusted controller timestamps arrivals; only in-window signed replies are sealed.
Worker identities are logical; RPC lanes are not independent physical CPUs.
The fault injector changes labels at fixed epoch boundaries, not actual machines.
"""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'deployment'))
from deploy import launch,checked,write_csv
from ossl import Key,version
from protocol import canonical,digest,b64,unb64,public_bytes,verify_report,verify_headers,verify_positive,compact_positive,decision,feasible,next_cohort,targeted_positive
import argparse, concurrent.futures as cf, csv, hashlib,json,os,platform,random,tempfile,time,copy,math
import numpy as np
from scipy.optimize import milp, Bounds, LinearConstraint

def explicit_path(D,n,f,c):

    T=len(D); k=n*T; rows=[];lo=[];hi=[]
    def add(d,l,u):
        a=np.zeros(k+n*(T-1));
        for i,v in d.items():a[i]=v
        rows.append(a);lo.append(l);hi.append(u)
    for t in range(T):
        add({t*n+i:1 for i in range(n)},f,f)
        for i in D[t]:add({t*n+i:1},1,1)
        if t:
            add({k+(t-1)*n+i:1 for i in range(n)},0,c)
            for i in range(n):add({t*n+i:1,(t-1)*n+i:-1,k+(t-1)*n+i:-1},-np.inf,0)
    r=milp(np.zeros(k+n*(T-1)),integrality=np.ones(k+n*(T-1)),bounds=Bounds(0,1),constraints=LinearConstraint(np.array(rows),lo,hi),options={'time_limit':10})
    assert r.success,r.message
    F=[{i for i in range(n) if r.x[t*n+i]>.5} for t in range(T)]
    assert all(D[t]<=F[t] and len(F[t])==f and (not t or len(F[t]-F[t-1])<=c) for t in range(T))
    return F

def target_trace(n,f,c,truth):
    h=[]; cohorts=[]; D=[]
    for t in range(1,5):
        S=next_cohort('adaptive_four_work',h,n,f,c); S=set(S)
        a=targeted_positive('adaptive_four_work',t,sorted(S),n,f,c)
        if not truth:a=S-a
        pair=(a,S-a); h.append(pair); D.append(pair[truth]);cohorts.append(S)
        if decision(h,f,c) is not None:break
    assert decision(h,f,c)==truth
    return cohorts,D,explicit_path(D,n,f,c)

def epoch_jobs(pool,workers,order,ctx,batch,t,truth,wrong,deadline_ns):
    def run(i):
        start=time.monotonic_ns()
        if start>=deadline_ns:return dict(worker=i,start_ns=start,end_ns=start,started=0,timely=0,checks=0,cpu=0,wire=0,report=None)
        r,nb=checked(workers[i],{'op':'verify','context':ctx,'batch':batch,'epoch':t,'override':1-truth if i in wrong else None})
        end=time.monotonic_ns(); assert r['actual']==truth
        return dict(worker=i,start_ns=start,end_ns=end,started=1,timely=int(end<=deadline_ns),checks=r['primitive_checks'],cpu=r['verify_cpu_ns'],wire=nb,report=r['report'])

    return list(pool.map(run,order))

def trial(n,f,c,B,p,Dms,policy,truth,rep,batch,workers,seal,registry,seal_pub,base,pool,trace,guard_ms):
    attempt=f'deadline-{n}-{f}-{c}-{B}-{p}-{Dms}-{policy}-{truth}-{rep}'
    ctx=dict(base,attempt_id=attempt,object_digest=digest(canonical(batch)),f=f,c=c)
    h=[];entries=[];erows=[];jrows=[];start=time.monotonic_ns(); result=None;reason='horizon'; F=set();prev=None
    for t in range(1,5):
        epoch_start=start+(t-1)*(Dms+guard_ms)*1_000_000; deadline=epoch_start+Dms*1_000_000; transition=deadline+guard_ms*1_000_000
        now=time.monotonic_ns()
        if now<epoch_start:time.sleep((epoch_start-now)/1e9)
        if time.monotonic_ns()>=deadline:reason='epoch_start_miss';break
        if policy=='TBC-L4':
            order=next_cohort('adaptive_four_work',h,n,f,c); S=set(order)
            expected,wrongsets,path=trace;assert S==expected[t-1];F=path[t-1];wrong=wrongsets[t-1]
        else:
            order=list(range(2*f+1)) if policy=='Queued-majority' else [(t*max(1,p)-p+i)%n for i in range(n)]
            S=set(order)
            if t==1:F=set(order[:f])
            else:

                entrants=[i for i in order if i not in F]; leave=sorted(F,key=lambda i:order.index(i) if i in S else n,reverse=True)
                moves=min(c,len(entrants),len(leave));F=(F-set(leave[:moves]))|set(entrants[:moves])
            wrong=F&S
        assert len(F)<=f and (prev is None or len(F-prev)<=c);prev=set(F)
        jobs=epoch_jobs(pool,workers,order,ctx,batch,t,truth,wrong,deadline)
        reports=[j['report'] for j in jobs if j['timely']];


        e,nb=checked(seal,{'op':'close','context':ctx,'epoch':t,'cohort':sorted(S),'reports':reports});entries.append(e['entry'])
        A={r['body']['worker'] for r in reports if r['body']['result']==1}; Z={r['body']['worker'] for r in reports if r['body']['result']==0};h.append((A,Z));assert feasible([pair[truth] for pair in h],f,c)
        if policy=='Queued-majority': result=1 if len(A)>f else 0 if len(Z)>f else None
        else:result=decision(h,f,c)


        if result==1:
            cert=compact_positive({'format':'full-v1','epochs':entries},f,c);assert verify_positive(cert,registry,seal_pub,ctx)
        elif result==0: assert not feasible([pair[1] for pair in h],f,c)
        done=time.monotonic_ns(); guard_miss=done>transition
        if guard_miss:result=None;reason='guard_miss'
        for j in jobs:
            jrows.append(dict(attempt=attempt,epoch=t,worker=j['worker'],start_ms=(j['start_ns']-epoch_start)/1e6,end_ms=(j['end_ns']-epoch_start)/1e6,started=j['started'],timely=j['timely'],checks=j['checks'],cpu_ns=j['cpu'],wire_bytes=j['wire']))
        erows.append(dict(attempt=attempt,epoch=t,requested=len(order),started=sum(j['started'] for j in jobs),timely=len(reports),late=sum(j['started'] and not j['timely'] for j in jobs),positive=len(A),negative=len(Z),faults=' '.join(map(str,sorted(F))),cohort=' '.join(map(str,order)),timely_ids=' '.join(map(str,sorted(A|Z))),positive_ids=' '.join(map(str,sorted(A))),epoch_done_ms=(done-epoch_start)/1e6,guard_miss=int(guard_miss),wire_bytes=nb))
        if guard_miss:break
        if result is not None:reason='decided';break
        if policy=='TBC-L4' and len(reports)!=len(S):reason='incomplete_cohort';break
    assert result is None or result==truth,(attempt,result,truth)
    return dict(attempt=attempt,n=n,f=f,c=c,batch=B,slots=p,deadline_ms=Dms,guard_ms=guard_ms,period_ms=Dms+guard_ms,policy=policy,truth=truth,repeat=rep,result='unresolved' if result is None else result,reason=reason,epochs=len(erows),requested=sum(e['requested'] for e in erows),started=sum(e['started'] for e in erows),timely=sum(e['timely'] for e in erows),late=sum(e['late'] for e in erows),peak_timely=max((e['timely'] for e in erows),default=0),checks=sum(j['checks'] for j in jrows),cpu_ns=sum(j['cpu_ns'] for j in jrows),wire_bytes=sum(e['wire_bytes'] for e in erows)+sum(j['wire_bytes'] for j in jrows),wall_ms=(time.monotonic_ns()-start)/1e6,first_timely=erows[0]['timely'] if erows else 0),erows,jrows

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',default='results');ap.add_argument('--repeats',type=int,default=3);ap.add_argument('--deadlines',nargs='+',type=int,default=[30,100,300]);ap.add_argument('--batches',nargs='+',type=int,default=[8,64]);ap.add_argument('--slots',nargs='+',type=int,default=[8,22]);ap.add_argument('--churn',nargs='+',type=int,default=[1,2]);ap.add_argument('--guard',type=int,default=100);ap.add_argument('--truths',nargs='+',type=int,default=[0,1]);args=ap.parse_args();out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    n=42;tx=Key.generate('ML-DSA-65');rng=random.Random(20261125);corpus=[];procs=[];workers=[];raw={};rows=[];epochs=[];jobs=[]
    for i in range(max(args.batches)):
        msg=rng.randbytes(256);corpus.append([b64(msg),b64(tx.sign(msg))])
    traces={(c,b):target_trace(n,n//2-c,c,b) for c in args.churn for b in args.truths}
    with tempfile.TemporaryDirectory() as td:
        try:
            for i in range(n):
                proc,x=launch('worker',{'id':i,'tx_key':b64(public_bytes(tx))});procs.append(proc);workers.append(x['addr']);raw[str(i)]=x['public']
            key=Key.generate();proc,x=launch('sealer',{'key':key,'registry':raw,'db':str(Path(td)/'seal.db')});procs.append(proc);seal=x['addr'];pub=key.public_key();reg={int(i):Key.from_der(unb64(v)) for i,v in raw.items()}
            base=dict(chain_id='deadline-service',height=1,prestate_root='1'*64,credential_version=1,credential_key_digest=digest(public_bytes(tx)),policy_id='all-ML-DSA-65',policy_version=1,component='batch',implementation_id='OpenSSL-EVP',registry_digest=digest(canonical(raw)),n=n,f=20,c=1)
            with cf.ThreadPoolExecutor(max_workers=22) as pool:
                ctx=dict(base,attempt_id='warm',object_digest=digest(canonical(corpus[:1])))
                list(pool.map(lambda i:checked(workers[i],{'op':'verify','context':ctx,'batch':corpus[:1],'epoch':1,'override':None}),range(n)))
            matrix=[(c,B,p,d,policy,b,r) for c in args.churn for B in args.batches for p in args.slots for d in args.deadlines for policy in ('Queued-majority','Queued-temporal','TBC-L4') for b in args.truths for r in range(args.repeats)]
            rng.shuffle(matrix);pools={p:cf.ThreadPoolExecutor(max_workers=p) for p in args.slots}
            try:
                for k,(c,B,p,d,policy,b,r) in enumerate(matrix):
                    batch=copy.deepcopy(corpus[:B]);f=n//2-c
                    if not b:
                        sig=bytearray(unb64(batch[-1][1]));sig[-1]^=1;batch[-1][1]=b64(sig)
                    row,ee,jj=trial(n,f,c,B,p,d,policy,b,r,batch,workers,seal,reg,pub,base,pools[p],traces[c,b],args.guard);rows.append(row);epochs+=ee;jobs+=jj
                    if (k+1)%24==0 or k+1==len(matrix):
                        write_csv(out/'trials.csv',rows);write_csv(out/'epochs.csv',epochs);write_csv(out/'jobs.csv',jobs);print(k+1,'/',len(matrix),flush=True)
            finally:
                for pool in pools.values():pool.shutdown()
        finally:
            for proc in procs:
                if proc.is_alive():proc.terminate()
            for proc in procs:proc.join(timeout=2)
    (out/'environment.json').write_text(json.dumps(dict(args=vars(args),openssl=version(0).decode(),platform=platform.platform(),affinity=sorted(os.sched_getaffinity(0)),cpu_max=Path('/sys/fs/cgroup/cpu.max').read_text().strip(),source_sha256={str(x.relative_to(Path(__file__).parents[1])):digest(x.read_bytes()) for x in [Path(__file__),*(Path(__file__).parents[1]/'deployment').glob('*.py')]},notes='Wall-clock epoch deadlines and fixed guard; drain in-flight requests before sealing, discard late reports. No overlapping epochs; abort if guard overrun. Logical RPC lanes on shared host, not physical cores. Targeted L4 traces and explicit greedy queue faults; policy-specific adversarial traces, not paired identical faults. Synthetic faults at boundaries, no production exposure measurement. All methods use durable trusted closure. No missing report is treated as a negative. No consensus.'),indent=2)+'\n')
    print('complete',len(rows),sum(r['checks'] for r in rows),flush=True)
if __name__=='__main__':main()
