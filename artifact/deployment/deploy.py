"""Actual TCP RPC deployment on one host; no simulated clocks or consensus claims.
Control plane is trusted, including epoch closure and injected fault schedules.
All crypto operations invoke OpenSSL EVP. The network is plain TCP with signed
application evidence; use mutually authenticated TLS for external deployments.
"""
import argparse, concurrent.futures as cf, copy, csv, hashlib, json, multiprocessing as mp, os, platform, random, socket, socketserver, sqlite3, struct, tempfile, time, traceback
from pathlib import Path
from ossl import Key, version
from protocol import (canonical,digest,b64,unb64,public_bytes,make_report,verify_report,Sealer,verify_full,verify_positive,compact_positive,observation,decision,feasible,next_cohort,targeted_positive,ZERO_HASH)
LIMIT=32*1024*1024

def recv_exact(s,n):
    out=bytearray()
    while len(out)<n:
        b=s.recv(n-len(out))
        if not b:raise EOFError('short RPC')
        out.extend(b)
    return bytes(out)
def recv(s):
    n=struct.unpack('!I',recv_exact(s,4))[0]
    if n>LIMIT:raise ValueError('frame too large')
    return recv_exact(s,n)
def rpc(addr,request):
    b=canonical(request)
    with socket.create_connection(tuple(addr),timeout=30) as s:
        s.sendall(struct.pack('!I',len(b))+b); r=recv(s)
    reply=json.loads(r)
    return reply,len(b)+len(r)+8

def serve(pipe,role,options):
    key=None; registry=None; tx=None; db=None
    if role=='worker':
        key=Key.generate();tx=Key.from_der(unb64(options['tx_key']))
    else:
        registry={int(i):Key.from_der(unb64(v)) for i,v in options['registry'].items()}
        db=sqlite3.connect(options['db']);db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
        if role=='sealer':
            key=options['key'];db.execute('CREATE TABLE IF NOT EXISTS closures (context TEXT, epoch INTEGER, header TEXT, PRIMARY KEY(context,epoch))')
        else:
            seal=Key.from_der(unb64(options['seal_key']));db.execute('CREATE TABLE IF NOT EXISTS accepted (attempt TEXT PRIMARY KEY, context TEXT, certificate TEXT)')
        db.commit()
    def handle(q):
        op=q['op']
        if op=='ping': return {'role':role,'pid':os.getpid(),'public':b64(public_bytes(key)) if key else None}
        if role=='worker' and op=='verify':
            ctx,corpus=q['context'],q['batch']; i=options['id']; start=time.process_time_ns(); b=1
            if digest(canonical(corpus))!=ctx['object_digest'] or digest(public_bytes(tx))!=ctx['credential_key_digest']:raise ValueError('wrong batch or key')
            for msg,sig in corpus:
                try:tx.verify(unb64(sig),unb64(msg))
                except ValueError:b=0
            elapsed=time.process_time_ns()-start
            val=b if q['override'] is None else q['override']
            return {'report':make_report(key,ctx,q['epoch'],i,val),'primitive_checks':len(corpus),'verify_cpu_ns':elapsed,'actual':b}
        if role=='sealer' and op=='close':
            ctx=q['context']; cid=digest(canonical(ctx)); t=q['epoch']
            db.execute('BEGIN IMMEDIATE')
            try:
                prev=db.execute('SELECT epoch, header FROM closures WHERE context=? ORDER BY epoch DESC LIMIT 1',(cid,)).fetchone()
                sealer=Sealer(key,registry,ctx)
                if prev:sealer.next_epoch=prev[0]+1;sealer.previous=digest(canonical(json.loads(prev[1])))
                entry=sealer.close(t,q['cohort'],q['reports'])
                db.execute('INSERT INTO closures VALUES (?,?,?)',(cid,t,canonical(entry['header']).decode()));db.commit()
                return {'entry':entry}
            except Exception:db.rollback();raise
        if role=='consumer' and op=='accept':


            ctx=q['expected']; cert=q['certificate']; t=time.perf_counter_ns(); cpu=time.process_time_ns()
            if not verify_positive(cert,registry,seal,ctx):raise ValueError('not positive')
            check=time.perf_counter_ns()-t; elapsed=time.process_time_ns()-cpu
            db.execute('INSERT INTO accepted VALUES (?,?,?)',(ctx['attempt_id'],digest(canonical(ctx)),digest(canonical(cert))));db.commit()
            return {'accepted':True,'check_ns':check,'check_cpu_ns':elapsed}
        if role=='consumer' and op=='count':return {'count':db.execute('SELECT count(*) FROM accepted').fetchone()[0]}
        raise ValueError('unsupported op')
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try: response={'ok':True,**handle(json.loads(recv(self.request)))}
            except Exception as e: response={'ok':False,'error':type(e).__name__+': '+str(e)}
            b=canonical(response);self.request.sendall(struct.pack('!I',len(b))+b)
    class Server(socketserver.TCPServer):allow_reuse_address=True
    with Server(('127.0.0.1',0),Handler) as srv:
        pipe.send({'addr':srv.server_address,'pid':os.getpid(),'public':b64(public_bytes(key)) if key else None});pipe.close();srv.serve_forever(poll_interval=.1)

def launch(role,options):
    a,b=mp.Pipe(False);p=mp.Process(target=serve,args=(b,role,options),daemon=True);p.start();b.close()
    if not a.poll(20):p.terminate();raise TimeoutError('service not ready')
    x=a.recv();a.close();return p,x

def checked(addr,q):
    r,b=rpc(addr,q)
    if not r['ok']:raise RuntimeError(r['error'])
    return r,b

def cohort(policy,h,n,f,c):
    if policy=='greedy_exclusion':
        s=f+c+1
        if not h:return list(range(s))
        if len(h)>=f+2:return None
        larger=max(h[-1],key=lambda v:(len(v),tuple(sorted(v))))
        return sorted(set(range(n))-larger)[:s]
    return next_cohort(policy,h,n,f,c)

def run_trial(addrs,sealer,consumers,registry,seal_pub,base,batch,policy,scenario,attempt,pool,rng):
    n,f,c=base['n'],base['f'],base['c'];b=0 if scenario=='invalid' else 1
    ctx=dict(base,attempt_id=attempt,object_digest=digest(canonical(batch)))
    h=[];entries=[];wire=0;worker_cpu=0;checks=0;epochs=[];faults=set();false_history=[];start=time.perf_counter_ns()
    while True:
        S=cohort(policy,h,n,f,c)
        if S is None:break
        t=len(h)+1; target=None
        if scenario=='targeted':
            if policy=='greedy_exclusion':





                if not h: faults=set(S[:len(S)//2]); faults.update(sorted(set(range(n))-set(S))[:f-len(faults)])
                else:
                    eligible=set(S)-faults; unused=faults-set(S); moves=min(c,len(eligible),len(unused)); faults=(faults-set(sorted(unused)[:moves]))|set(sorted(eligible)[:moves])
                target=set(S)-faults
            else: target=targeted_positive(policy,t,S,n,f,c)
        elif scenario in ('mobile','invalid'):
            if t==1:faults=set(rng.sample(range(n),f))
            else:
                leave=rng.sample(sorted(faults),c);enter=rng.sample(sorted(set(range(n))-faults),c);faults=(faults-set(leave))|set(enter)
            target=set(S)-faults if b else set(S)&faults
        if target is not None: false_history.append((set(S)-target) if b else target);assert feasible(false_history,f,c)
        def query(i):return checked(addrs[i],{'op':'verify','context':ctx,'batch':batch,'epoch':t,'override':None if target is None else int(i in target)})
        a=time.perf_counter_ns(); replies=list(pool.map(query,S)); job_wall=time.perf_counter_ns()-a
        reports=[]
        for r,nb in replies:
            assert r['actual']==b;reports.append(r['report']);wire+=nb;worker_cpu+=r['verify_cpu_ns'];checks+=r['primitive_checks']
        a=time.perf_counter_ns(); e,nb=checked(sealer,{'op':'close','context':ctx,'epoch':t,'cohort':S,'reports':reports});seal_wall=time.perf_counter_ns()-a
        wire+=nb; entries.append(e['entry']);h.append(observation(S,reports)); result=decision(h,f,c)
        epochs.append({'attempt':attempt,'epoch':t,'cohort':len(S),'positives':len(h[-1][0]),'worker_rpc_ns':job_wall,'seal_rpc_ns':seal_wall})
        if result is not None:break
    full={'format':'full-v1','epochs':entries}; result=verify_full(full,registry,seal_pub,ctx);assert result is None or result==b
    produce=time.perf_counter_ns()-start; cert=None; check_times=[]; consumer_total=0; consumer_cpu=[]
    if result==1:
        cert=compact_positive(full,f,c);start=time.perf_counter_ns()
        def consume(addr):return checked(addr,{'op':'accept','expected':ctx,'certificate':cert})
        for r,nb in pool.map(consume,consumers):assert r['accepted'];wire+=nb;check_times.append(r['check_ns']);consumer_cpu.append(r['check_cpu_ns'])
        consumer_total=time.perf_counter_ns()-start
    jobs=sum(x['cohort'] for x in epochs)
    return dict(attempt=attempt,n=n,f=f,c=c,batch=len(batch),policy=policy,scenario=scenario,verdict='ambiguous' if result is None else result,epochs=len(h),jobs=jobs,peak=max(x['cohort'] for x in epochs),checks=checks,worker_cpu_ns=worker_cpu,produce_ns=produce,consume_all_ns=consumer_total,consumer_max_check_ns=max(check_times,default=0),consumer_sum_cpu_ns=sum(consumer_cpu),app_wire_bytes=wire,full_bytes=len(canonical(full)),compact_bytes=len(canonical(cert)) if cert else 0,consumers=len(consumers),truth=b),epochs, (ctx,cert,entries)

def write_csv(path,rows):
    with open(path,'w') as f:w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',default='results');ap.add_argument('--repeats',type=int,default=6);ap.add_argument('--populations',type=int,nargs='+',default=[14,22,42]);ap.add_argument('--batches',type=int,nargs='+',default=[1,32,128]);ap.add_argument('--consumers',type=int,default=4);ap.add_argument('--policies',nargs='+',default=['direct_majority','fixed_rotation','adaptive_two','adaptive_four_original','adaptive_four_work','greedy_exclusion']);ap.add_argument('--scenarios',nargs='+',default=['honest','targeted','invalid']);args=ap.parse_args();out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    rng=random.Random(20261125);tx=Key.generate('ML-DSA-65'); tx_key=b64(public_bytes(tx));corpus=[]
    for j in range(max(args.batches)):
        msg=rng.randbytes(256);corpus.append([b64(msg),b64(tx.sign(msg))])
    rows=[];erows=[];regressions=[]; metadata=[]; pid_records=[]
    for n in args.populations:
        f=n//2-1;c=1;assert n==2*f+2*c and f>=6
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);procs=[]
            try:
                start=time.perf_counter_ns();workers=[];registry_raw={}
                for i in range(n):
                    p,x=launch('worker',{'id':i,'tx_key':tx_key});procs.append(p);workers.append(x['addr']);registry_raw[str(i)]=x['public'];pid_records.append({'n':n,'role':'worker','id':i,'pid':x['pid'],'port':x['addr'][1]})
                registry={int(i):Key.from_der(unb64(v)) for i,v in registry_raw.items()};key=Key.generate();seal_raw=b64(public_bytes(key));seal_pub=key.public_key();sealer_opts={'registry':registry_raw,'db':str(path/'seal.db'),'key':key};p,seal=launch('sealer',sealer_opts);procs.append(p);seal_proc=p
                consumer_opts=[];consumers=[];consumer_procs=[]
                for i in range(args.consumers):
                    opt={'registry':registry_raw,'seal_key':seal_raw,'db':str(path/f'consumer{i}.db')};consumer_opts.append(opt);p,x=launch('consumer',opt);procs.append(p);consumer_procs.append(p);consumers.append(x['addr']);pid_records.append({'n':n,'role':'consumer','id':i,'pid':x['pid'],'port':x['addr'][1]})
                pid_records.append({'n':n,'role':'sealer','id':0,'pid':seal['pid'],'port':seal['addr'][1]})
                metadata.append({'n':n,'startup_ns':time.perf_counter_ns()-start,'workers':n,'consumers':args.consumers,'sealers':1})
                base=dict(chain_id='tcp-verification-service',height=1,prestate_root='1'*64,credential_version=1,credential_key_digest=digest(public_bytes(tx)),policy_id='all-ML-DSA-65',policy_version=1,component='batch',implementation_id='OpenSSL-EVP',registry_digest=digest(canonical(registry_raw)),n=n,f=f,c=c)
                with cf.ThreadPoolExecutor(max_workers=max(n,args.consumers)) as pool:

                    warm=dict(base,attempt_id='warm',object_digest=digest(canonical(corpus[:1])))
                    list(pool.map(lambda i:checked(workers[i],{'op':'verify','context':warm,'batch':corpus[:1],'epoch':1,'override':None}),range(n)))
                    matrix=[(B,p,s,r) for B in args.batches for p in args.policies for s in args.scenarios for r in range(args.repeats)];rng.shuffle(matrix)
                    last=None
                    for index,(B,policy,scenario,repeat) in enumerate(matrix):
                        batch=copy.deepcopy(corpus[:B]);
                        if scenario=='invalid':
                            v=bytearray(unb64(batch[-1][1]));v[-1]^=1;batch[-1][1]=b64(v)
                        rr,ee,proof=run_trial(workers,seal['addr'],consumers,registry,seal_pub,base,batch,policy,scenario,f'{n}-{index}',pool,rng)
                        rr['repeat']=repeat;rows.append(rr);erows.extend(ee)
                        if rr['verdict']==1:last=proof
                        if policy!='fixed_rotation':assert rr['verdict']!='ambiguous'
                    assert last is not None
                    ctx,cert,entries=last


                    def reject(addr,q,name):
                        r,_=rpc(addr,q);assert not r['ok'],name;regressions.append({'n':n,'case':name,'rejected':True,'error':r['error']})
                    reject(consumers[0],{'op':'accept','expected':ctx,'certificate':cert},'duplicate attempt')
                    altered=dict(ctx,policy_version=2);reject(consumers[0],{'op':'accept','expected':altered,'certificate':cert},'stale policy')
                    bad=copy.deepcopy(cert);bad['witnesses'][0]['report']['body']['result']=0;reject(consumers[0],{'op':'accept','expected':ctx,'certificate':bad},'tampered witness')
                    before,_=checked(consumers[0],{'op':'count'});consumer_procs[0].terminate();consumer_procs[0].join();p,x=launch('consumer',consumer_opts[0]);procs.append(p);consumers[0]=x['addr'];after,_=checked(consumers[0],{'op':'count'});assert before==after
                    reject(consumers[0],{'op':'accept','expected':ctx,'certificate':cert},'replay after restart')
                    seal_proc.terminate();seal_proc.join();p,x=launch('sealer',sealer_opts);procs.append(p);e=entries[-1];reject(x['addr'],{'op':'close','context':ctx,'epoch':e['header']['body']['epoch'],'cohort':e['header']['body']['cohort'],'reports':e['reports']},'duplicate closure after restart')
                print('completed',n,'trials',len(matrix),flush=True)
                write_csv(out/'trials.csv',rows);write_csv(out/'epochs.csv',erows);write_csv(out/'regressions.csv',regressions);write_csv(out/'processes.csv',pid_records)
            finally:
                for p in procs:
                    if p.is_alive():p.terminate()
                for p in procs:p.join(timeout=2)
    (out/'environment.json').write_text(json.dumps({'args':vars(args),'openssl':version(0).decode(),'platform':platform.platform(),'cpu_count':os.cpu_count(),'affinity':sorted(os.sched_getaffinity(0)),'cpu_max':Path('/sys/fs/cgroup/cpu.max').read_text().strip(),'memory_max':Path('/sys/fs/cgroup/memory.max').read_text().strip(),'topologies':metadata,'source_sha256':{p.name:digest(p.read_bytes()) for p in Path(__file__).parent.glob('*.py')},'notes':'Single shared host, real TCP framed JSON, one process per worker; synthetic signed payloads, no real compromises, no TLS, no BFT engine. App bytes include all RPC requests and responses plus 4-byte framing, exclude TCP/IP headers. Sequential attempts, throughput is achieved sequential batch rate, not saturation.'},indent=2)+'\n')
    print('done',len(rows),'trials',sum(r['checks'] for r in rows),'signature checks',flush=True)
if __name__=='__main__':main()
