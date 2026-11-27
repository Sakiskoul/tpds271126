"""Paired real timing control: grant a trusted local process the original batch.
Separate exec-isolated digest-only closure service; test interface rejection.
Does not measure a complete temporal schedule or a trusted hardware mechanism.
"""
import sys,json,os,random,time,tempfile,subprocess,copy,argparse
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'deployment'))
from ossl import Key,version
from deploy import rpc,checked,write_csv
from protocol import canonical,digest,b64,unb64,public_bytes,make_report,verify_headers

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',default='closure_results');ap.add_argument('--repeats',type=int,default=30);args=ap.parse_args();out=Path(args.output);out.mkdir(exist_ok=True,parents=True)
    rng=random.Random(20261125);n=42;f=20;c=1;count=22;tx=Key.generate('ML-DSA-65');txpub=tx.public_key();keys=[Key.generate() for _ in range(n)];reg={i:key.public_key() for i,key in enumerate(keys)};raw={str(i):b64(public_bytes(k)) for i,k in reg.items()};corpus=[]
    for i in range(256):m=rng.randbytes(256);corpus.append((m,tx.sign(m)))
    base=dict(chain_id='closure-ablation',height=1,prestate_root='1'*64,credential_version=1,credential_key_digest=digest(public_bytes(tx)),policy_id='all-ML-DSA-65',policy_version=1,component='batch',implementation_id='OpenSSL-EVP',registry_digest=digest(canonical(raw)),n=n,f=f,c=c)
    results=[];tests=[]
    with tempfile.TemporaryDirectory() as td:
        p=subprocess.Popen([sys.executable,str(Path(__file__).with_name('closure_service.py'))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,close_fds=True)
        try:
            p.stdin.write(json.dumps({'registry':raw,'db':str(Path(td)/'closure.db')})+'\n');p.stdin.flush();ready=json.loads(p.stdout.readline());addr=ready['addr'];sealpub=Key.from_der(unb64(ready['public']));assert ready['pid']!=os.getpid()
            for op in ({'op':'verify','batch':[]},{'op':'close','batch':[]},{'op':'ping','tx_key':b64(public_bytes(tx))}):
                r,_=rpc(addr,op);assert not r['ok'];tests.append(dict(case=op['op']+' unexpected payload/key',rejected=True))
            matrix=[(B,r) for B in (8,64,256) for r in range(args.repeats)];rng.shuffle(matrix)
            for B,r in matrix:
                batch=corpus[:B];ctx=dict(base,attempt_id=f'{B}-{r}',object_digest=digest(canonical([[b64(m),b64(s)] for m,s in batch])));reps=[make_report(keys[i],ctx,1,i,1) for i in range(count)];request={'op':'close','context':ctx,'epoch':1,'cohort':list(range(count)),'reports':reps}
                def local():
                    a=time.perf_counter_ns();cpu=time.process_time_ns()
                    for m,s in batch:txpub.verify(s,m)
                    return (time.perf_counter_ns()-a)/1e6,(time.process_time_ns()-cpu)/1e6
                def closure():
                    a=time.perf_counter_ns();r,wire=checked(addr,request);wall=(time.perf_counter_ns()-a)/1e6;verify_headers([r['entry']['header']],sealpub,ctx,reg);return wall,wire
                if rng.randrange(2):l=local();s=closure()
                else:s=closure();l=local()
                results.append(dict(batch=B,repeat=r,report_count=count,local_wall_ms=l[0],local_cpu_ms=l[1],durable_closure_wall_ms=s[0],closure_wire_bytes=s[1]))
            x,_=rpc(addr,request);assert not x['ok'];tests.append(dict(case='duplicate closure',rejected=True))
        finally:p.terminate();p.wait(timeout=5)
    write_csv(out/'trials.csv',results);(out/'tests.json').write_text(json.dumps(tests,indent=2)+'\n');(out/'environment.json').write_text(json.dumps({'openssl':version(0).decode(),'source_sha256':{x.name:digest(x.read_bytes()) for x in [Path(__file__),Path(__file__).with_name('closure_service.py')]},'notes':'The direct computation is in the controller with original batch and transaction public key. Closure service is a separate exec process with only report registry and DB supplied, freshly generated seal key; strict RPC schema; no enforced OS-level data isolation. The closure timing includes TCP, signature checks, Merkle and SQLite commit; direct timing excludes durable publication and transport. Not a latency comparison of equivalent end-to-end services.'},indent=2)+'\n');print(len(results),'paired controls',len(tests),'interface tests')
if __name__=='__main__':main()
