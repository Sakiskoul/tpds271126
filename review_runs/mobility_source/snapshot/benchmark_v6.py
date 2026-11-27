"""Fresh real TCP/OpenSSL benchmark: O-TBC, early-stop queues and four source-derived policies.
Shared sealed-report transport for ALL rules; external policy rules are specializations,
not full software systems. Deadline starts are anchored, no late or missing report is a bit.
Faults are injected labels, fixed within each window. Timing includes durable closure and
independent verification of the complete sealed signed transcript. No live BFT engine.
"""
import argparse, concurrent.futures as cf, copy, hashlib, json, os, platform, random, tempfile, time
from pathlib import Path
from deploy import launch,checked,write_csv
from ossl import Key,version
from protocol import canonical,digest,b64,unb64,public_bytes,verify_report,verify_headers,merkle_levels,decision,feasible,next_cohort,targeted_positive
from scheduler import optimistic

SAFE={'Direct','ES-QM','ES-stream','QT','O-TBC','O-TBC-cache','L4','RAJ','FAB'}
ALL=['Direct','ES-QM','ES-stream','O-TBC','O-TBC-cache','L4','MBA','FAB','BOINC','RAJ']
DEAD=['Direct','ES-QM','ES-stream','QT','O-TBC','O-TBC-cache','L4']
def seeded(*xs):return random.Random(int.from_bytes(hashlib.sha256(':'.join(map(str,xs)).encode()).digest()[:8],'big'))
def labels(reports):
    return tuple({r['body']['worker'] for r in reports if r['body']['result']==b} for b in (1,0))
def threshold(pair,f):
    return 1 if len(pair[0])>f else 0 if len(pair[1])>f else None

def signed_history(entries,reg,pub,ctx):
    verify_headers([e['header'] for e in entries],pub,ctx,reg)
    hist=[]
    for e in entries:
        b=e['header']['body'];r=e['reports'];ids=[x['body']['worker'] for x in r]
        assert ids==sorted(set(ids)) and len(ids)==b['report_count']
        assert merkle_levels(r)[-1][0].hex()==b['merkle_root']
        for x in r:verify_report(x,reg,ctx,b['epoch'],b['cohort'])
        hist.append(labels(r))
    return hist

def trial(n,B,slots,D,guard,policy,scenario,truth,rep,batch,workers,sealer,reg,pub,base,tx,pool,realized_churn=None):
    f=base['f'];c=base['c'];s=f+c+1;N=set(range(n));attempt=f'v6-{n}-{B}-{slots}-{D}-{policy}-{scenario}-{truth}-{rep}'
    moves_limit = c if realized_churn is None else realized_churn
    assert 0 <= moves_limit <= c and n == 2 * (f + c)
    ctx=dict(base,attempt_id=attempt,object_digest=digest(canonical(batch)))
    fr=seeded('fault',n,B,slots,D,scenario,truth,rep);rr=seeded('selection',n,B,slots,D,scenario,truth,rep)
    order=list(range(n));rr.shuffle(order);F=set(fr.sample(sorted(N),f)) if scenario=='static' else set();prev=None
    history=[];entries=[];queried=set();rows=[];jobrows=[];result=None;reason='horizon';local=0;local_cpu=0;total_wire=0

    trust=rr.random()<.95; counts=[0,0]
    start=time.monotonic_ns()
    for t in range(1,5):
        if D:
            es=start+(t-1)*(D+guard)*10**6;deadline=es+D*10**6;endguard=deadline+guard*10**6
            if time.monotonic_ns()<es:time.sleep((es-time.monotonic_ns())/1e9)
            if time.monotonic_ns()>=deadline:reason='epoch_start_miss';break
        else:es=time.monotonic_ns();deadline=10**30;endguard=10**30
        if policy in ('O-TBC','O-TBC-cache'):plan=optimistic(history,n,f,c)
        elif policy=='L4':plan=next_cohort('adaptive_four_work',history,n,f,c)
        elif policy in ('Direct','ES-QM','ES-stream'):plan=order[:2*f+1]
        elif policy=='QT':plan=[order[(i+(t-1)*s)%n] for i in range(n)]
        elif policy in ('MBA','RAJ'):plan=order[:s] if t==1 else []
        elif policy=='FAB':plan=rr.sample(sorted(N),s)
        elif policy=='BOINC':plan=order[:1 if trust else 2] if t==1 else [order[2]] if t==2 and not trust and max(counts)<2 else []
        else:raise ValueError(policy)
        if not plan:break
        S=set(plan)


        if scenario=='mobile':
            if t==1:
                F=set(plan[:min(f,len(plan))]);F.update(fr.sample(sorted(N-F),f-len(F)))
            else:
                entrants=[i for i in plan if i not in F]; leave=sorted(F,key=lambda i:plan.index(i) if i in S else n,reverse=True)
                moves=min(moves_limit,len(entrants),len(leave));F=(F-set(leave[:moves]))|set(entrants[:moves])
        assert len(F)<=f and (prev is None or len(F-prev)<=moves_limit);prev=set(F)
        jobs=[];reports=[];cache=policy=='O-TBC-cache'
        def run(i):
            begin=time.monotonic_ns()
            if begin>=deadline:return dict(i=i,started=0,timely=0,begin=begin,end=begin,checks=0,cpu=0,wire=0,report=None)
            r,nb=checked(workers[i],{'op':'verify','context':ctx,'batch':None if cache and i in queried else batch,'cache_input':cache,'epoch':t,'override':1-truth if i in F else None})
            end=time.monotonic_ns();assert r['actual']==truth
            return dict(i=i,started=1,timely=int(end<=deadline),begin=begin,end=end,checks=r['primitive_checks'],cpu=r['verify_cpu_ns'],wire=nb,report=r['report'])
        def add(j):
            jobs.append(j)
            if j['timely']:
                verify_report(j['report'],reg,ctx,t,sorted(S));reports.append(j['report'])
        if policy=='ES-QM':


            k=0
            while k<len(plan) and time.monotonic_ns()<deadline:
                pair=labels(reports)
                if threshold(pair,f) is not None:break
                r=max(1,f+1-max(map(len,pair))); wave=plan[k:k+r];k+=len(wave)
                for j in pool.map(run,wave):add(j)
        elif policy=='ES-stream':


            pending={};k=0
            def fill():
                nonlocal k
                while k<len(plan) and len(pending)<slots and time.monotonic_ns()<deadline:
                    p=pool.submit(run,plan[k]);pending[p]=plan[k];k+=1
            fill()
            while pending:
                done,_=cf.wait(pending,return_when=cf.FIRST_COMPLETED)
                for p in done:pending.pop(p);add(p.result())
                if threshold(labels(reports),f) is None:fill()
        else:
            for j in pool.map(run,plan):add(j)
        queried.update(j['i'] for j in jobs if j['started']);cohort=sorted(j['i'] for j in jobs if j['started'])
        entry,nb=checked(sealer,{'op':'close','context':ctx,'epoch':t,'cohort':cohort,'reports':reports});entries.append(entry['entry']);total_wire+=nb
        pair=labels(reports);history.append(pair);counts[0]+=len(pair[1]);counts[1]+=len(pair[0]);assert feasible([x[truth] for x in history],f,c)

        assert signed_history(entries,reg,pub,ctx)==history
        if policy in ('Direct','ES-QM','ES-stream'):result=threshold(pair,f)
        elif policy in ('O-TBC','O-TBC-cache','L4','QT'):result=decision(history,f,c)
        elif policy=='FAB':result=1 if len(pair[0])>f else None
        elif policy=='MBA':result=int(len(pair[0])>len(pair[1])) if len(pair[0])!=len(pair[1]) else rr.randrange(2)
        elif policy=='BOINC':
            if trust and reports:result=int(bool(pair[0]))
            elif max(counts)>=2:result=int(counts[1]>=2)
        elif policy=='RAJ':
            result=threshold(pair,f)
            if result is None:
                t0=time.process_time_ns();result=1
                for msg,sig in batch:
                    try:tx.verify(unb64(sig),unb64(msg))
                    except ValueError:result=0
                local=1;local_cpu=time.process_time_ns()-t0
        done=time.monotonic_ns();overrun=done>endguard
        if overrun:result=None;reason='guard_miss'
        for j in jobs:jobrows.append(dict(attempt=attempt,epoch=t,worker=j['i'],started=j['started'],timely=j['timely'],start_ms=(j['begin']-es)/1e6,end_ms=(j['end']-es)/1e6,checks=j['checks'],cpu_ns=j['cpu'],wire_bytes=j['wire']))
        rows.append(dict(attempt=attempt,epoch=t,planned=len(plan),admitted=len(cohort),timely=len(reports),late=sum(j['started'] and not j['timely'] for j in jobs),positive=len(pair[0]),negative=len(pair[1]),faults=' '.join(map(str,sorted(F))),cohort=' '.join(map(str,cohort)),positive_ids=' '.join(map(str,sorted(pair[0]))),negative_ids=' '.join(map(str,sorted(pair[1]))),elapsed_ms=(done-es)/1e6,guard_miss=int(overrun),seal_wire_bytes=nb))
        if overrun:break
        if result is not None:reason='decided';break
        if policy in ('O-TBC','O-TBC-cache','L4') and len(reports)!=len(plan):reason='incomplete_cohort';break
        if not D and policy in ('Direct','ES-QM','ES-stream','MBA','RAJ'):break
    if policy in SAFE:assert result is None or result==truth,(attempt,result)
    if not D and policy in ('Direct','ES-QM','ES-stream','O-TBC','O-TBC-cache','L4','RAJ'):assert result==truth,(attempt,result)
    return dict(attempt=attempt,n=n,f=f,c=c,batch=B,slots=slots,deadline_ms=D,guard_ms=guard if D else 0,policy=policy,scenario=scenario,truth=truth,repeat=rep,result='unresolved' if result is None else result,correct=int(result==truth),wrong=int(result is not None and result!=truth),reason=reason,epochs=len(rows),jobs=sum(j['started'] for j in jobrows),peak=max((r['admitted'] for r in rows),default=0),timely=sum(j['timely'] for j in jobrows),late=sum(j['started'] and not j['timely'] for j in jobrows),checks=sum(j['checks'] for j in jobrows),cpu_ns=sum(j['cpu_ns'] for j in jobrows),wire_bytes=total_wire+sum(j['wire_bytes'] for j in jobrows),wall_ms=(time.monotonic_ns()-start)/1e6,local_jobs=local,local_checks=B*local,local_cpu_ns=local_cpu),rows,jobrows

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',required=True);p.add_argument('--populations',nargs='+',type=int,default=[14,42]);p.add_argument('--batches',nargs='+',type=int,default=[8]);p.add_argument('--slots',nargs='+',type=int,default=[4]);p.add_argument('--deadlines',nargs='+',type=int,default=[0]);p.add_argument('--guard',type=int,default=100);p.add_argument('--repeats',type=int,default=5);p.add_argument('--scenarios',nargs='+',default=['honest','static','mobile']);p.add_argument('--truths',nargs='+',type=int,default=[0,1]);p.add_argument('--policies',nargs='+',default=ALL);args=p.parse_args()
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True);rows=[];epochs=[];jobs=[]
    for n in args.populations:
        f=n//2-1;c=1;tx=Key.generate('ML-DSA-65');txpub=tx.public_key();rng=seeded('data',n);corpus=[]
        for i in range(max(args.batches)):
            msg=rng.randbytes(128);corpus.append([b64(msg),b64(tx.sign(msg))])
        with tempfile.TemporaryDirectory() as td:
            procs=[];workers=[];raw={};pools={}
            try:
                for i in range(n):
                    pr,x=launch('worker',{'id':i,'tx_key':b64(public_bytes(tx))});procs.append(pr);workers.append(x['addr']);raw[str(i)]=x['public']
                key=Key.generate();pr,x=launch('sealer',{'key':key,'registry':raw,'db':str(Path(td)/'seal.db')});procs.append(pr);seal=x['addr'];pub=key.public_key();reg={int(i):Key.from_der(unb64(v)) for i,v in raw.items()}
                base=dict(chain_id='otbc-v6',height=1,prestate_root='1'*64,credential_version=1,credential_key_digest=digest(public_bytes(tx)),policy_id='all-ML-DSA-65',policy_version=1,component='batch',implementation_id='OpenSSL-EVP',registry_digest=digest(canonical(raw)),n=n,f=f,c=c)
                pools={p:cf.ThreadPoolExecutor(max_workers=p) for p in args.slots};warm=dict(base,attempt_id='warm',object_digest=digest(canonical(corpus[:1])))
                list(pools[args.slots[0]].map(lambda i:checked(workers[i],{'op':'verify','context':warm,'batch':corpus[:1],'epoch':1,'override':None}),range(n)))
                matrix=[(B,p,D,pol,sc,b,r) for B in args.batches for p in args.slots for D in args.deadlines for pol in args.policies for sc in args.scenarios for b in args.truths for r in range(args.repeats)];rng.shuffle(matrix)
                for k,(B,p,D,pol,sc,b,r) in enumerate(matrix):
                    batch=copy.deepcopy(corpus[:B]);
                    if not b:
                        sig=bytearray(unb64(batch[-1][1]));sig[-1]^=1;batch[-1][1]=b64(sig)
                    row,ee,jj=trial(n,B,p,D,args.guard,pol,sc,b,r,batch,workers,seal,reg,pub,base,txpub,pools[p]);rows.append(row);epochs+=ee;jobs+=jj
                    if (k+1)%20==0 or k+1==len(matrix):
                        write_csv(out/'trials.csv',rows);write_csv(out/'epochs.csv',epochs);write_csv(out/'jobs.csv',jobs);print(n,k+1,'/',len(matrix),flush=True)
            finally:
                for pool in pools.values():pool.shutdown()
                for pr in procs:
                    if pr.is_alive():pr.terminate()
                for pr in procs:pr.join(timeout=2)
    (out/'environment.json').write_text(json.dumps(dict(args=vars(args),openssl=version(0).decode(),platform=platform.platform(),affinity=sorted(os.sched_getaffinity(0)),cpu_max=Path('/sys/fs/cgroup/cpu.max').read_text().strip(),source_sha256={x.name:digest(x.read_bytes()) for x in Path(__file__).parent.glob('*.py')},notes='Real loopback TCP; common closure and explicit signed history verification for all policies; same host, injected faults; deadlines exclude late replies; no live consensus.'),indent=2)+'\n');print('complete',len(rows),sum(r['checks']+r['local_checks'] for r in rows),flush=True)
if __name__=='__main__':main()
