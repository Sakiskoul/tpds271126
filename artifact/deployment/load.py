"""Concurrent, closed-loop TCP service throughput experiment (honest batches).
Separate runs after deploy.py. Each client repeatedly certifies one batch; all
clients share the same worker services, sealer and durable consumer endpoints.
The per-attempt fault model is not a global cross-attempt churn guarantee.
"""
import concurrent.futures as cf, json, os, random, tempfile, time, argparse
from pathlib import Path
from deploy import launch, checked, run_trial, write_csv, Key, b64, unb64, public_bytes, canonical,digest,version

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',default='load_results');ap.add_argument('--repeats',type=int,default=3);ap.add_argument('--per-client',type=int,default=3);args=ap.parse_args();out=Path(args.output);out.mkdir(exist_ok=True)
    n,f,c=14,6,1;R=4; rng=random.Random(20261126);tx=Key.generate('ML-DSA-65');pub=b64(public_bytes(tx));corpus=[]
    for j in range(32):
        msg=rng.randbytes(256);corpus.append([b64(msg),b64(tx.sign(msg))])
    procs=[];rows=[];details=[]
    with tempfile.TemporaryDirectory() as d:
        try:
            workers=[];reg={}
            for i in range(n):
                p,x=launch('worker',{'id':i,'tx_key':pub});procs.append(p);workers.append(x['addr']);reg[str(i)]=x['public']
            registry={int(i):Key.from_der(unb64(k)) for i,k in reg.items()};key=Key.generate();seal_pub=key.public_key();seal_raw=b64(public_bytes(key));p,x=launch('sealer',{'registry':reg,'db':d+'/seal.db','key':key});procs.append(p);sealer=x['addr'];consumers=[]
            for i in range(R):
                p,x=launch('consumer',{'registry':reg,'seal_key':seal_raw,'db':d+f'/consumer{i}.db'});procs.append(p);consumers.append(x['addr'])
            base=dict(chain_id='tcp-load',height=1,prestate_root='1'*64,credential_version=1,credential_key_digest=digest(public_bytes(tx)),policy_id='all-ML-DSA-65',policy_version=1,component='batch',implementation_id='OpenSSL-EVP',registry_digest=digest(canonical(reg)),n=n,f=f,c=c)
            warm=dict(base,attempt_id='warm',object_digest=digest(canonical(corpus[:1])))
            for i in range(n):checked(workers[i],{'op':'verify','context':warm,'batch':corpus[:1],'epoch':1,'override':None})
            configs=[(P,L,k) for P in ['direct_majority','adaptive_four_original','adaptive_four_work'] for L in [1,2,4,8] for k in range(args.repeats)];rng.shuffle(configs)


            total=8*args.per_client
            for run,(policy,clients,rep) in enumerate(configs):
                def client(i):
                    ret=[]
                    with cf.ThreadPoolExecutor(max_workers=n) as pool:
                        for j in range(i,total,clients):
                            start=time.perf_counter_ns();r,_,_=run_trial(workers,sealer,consumers,registry,seal_pub,base,corpus,policy,'honest',f'{run}-{j}',pool,random.Random(j));r['end_to_end_ns']=time.perf_counter_ns()-start;r['run']=run;r['clients']=clients;ret.append(r)
                    return ret
                start=time.perf_counter_ns()
                with cf.ThreadPoolExecutor(max_workers=clients) as ex:ret=[r for arr in ex.map(client,range(clients)) for r in arr]
                elapsed=time.perf_counter_ns()-start;assert len(ret)==total and all(r['verdict']==1 for r in ret)
                rows.append(dict(run=run,policy=policy,clients=clients,repeat=rep,batches=total,transactions=total*32,elapsed_ns=elapsed,tx_per_s=total*32*1e9/elapsed,app_wire_bytes=sum(r['app_wire_bytes'] for r in ret)));details.extend(ret)
                print('load',run,policy,clients,round(rows[-1]['tx_per_s'],1),flush=True)
                write_csv(out/'runs.csv',rows);write_csv(out/'attempts.csv',details)
        finally:
            for p in procs:
                if p.is_alive():p.terminate()
            for p in procs:p.join(timeout=2)
    (out/'environment.json').write_text(json.dumps({'openssl':version(0).decode(),'args':vars(args),'notes':'Same shared-host TCP service; all-honest, 32 signatures per batch, 14 workers, 4 consumers; closed-loop clients, fixed 8*per-client batches per run; measured from submission through all durable consumer acknowledgements; no consensus, not WAN.'},indent=2))
if __name__=='__main__':main()
