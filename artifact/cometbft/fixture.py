"""Trusted experimental controller, real TCP workers and sealer."""
import concurrent.futures as cf, random,time,copy
from pathlib import Path
from ledger import canonical,digest,b64,unb64,message,expected_context,Key,public_bytes
from deploy import launch,checked,run_trial

class Producer:
    def __init__(self,n,mode,cap,directory,seed=20261125):
        self.directory=Path(directory);self.directory.mkdir(parents=True,exist_ok=True)
        self.procs=[];self.rng=random.Random(seed);self.key=Key.generate('ML-DSA-65');self.seal=Key.generate();self.addrs=[];reg={}
        try:
            for i in range(n):
                p,w=launch('worker',{'id':i,'tx_key':b64(public_bytes(self.key))});self.procs.append(p);self.addrs.append(w['addr']);reg[str(i)]=w['public']
            p,x=launch('sealer',{'registry':reg,'db':str(self.directory/'seals.db'),'key':self.seal});self.procs.append(p);self.sealer=x['addr']
            self.registry={int(i):Key.from_der(unb64(k)) for i,k in reg.items()};self.pool=cf.ThreadPoolExecutor(max_workers=n)
            self.config=dict(chain_id='tbc-'+mode+'-n'+str(n)+'-cap'+str(cap),n=n,f=n//2-1,c=1,registry=reg,
                seal_key=b64(public_bytes(self.seal)),tx_key=b64(public_bytes(self.key)),max_cohort=cap,mode=mode)
        except BaseException:self.close();raise
    def batch(self,state,B,invalid=False,attempt=None):
        attempt=attempt or self.rng.randbytes(16).hex();data=[]
        for i in range(B):
            msg=message(self.config,state['sequence']+1,state['root'],attempt,i,b64(self.rng.randbytes(128)))
            sig=self.key.sign(msg)
            if invalid and i==B-1:sig=bytes([sig[0]^1])+sig[1:]
            data.append([b64(msg),b64(sig)])
        return attempt,data
    def make(self,state,B,policy,scenario='honest'):
        start=time.perf_counter_ns();attempt,batch=self.batch(state,B,scenario=='invalid');cert=None;row={}
        if self.config['mode']=='certificate':
            base=expected_context(self.config,state,attempt,batch)
            row,epochs,(_,cert,entries)=run_trial(self.addrs,self.sealer,[],self.registry,self.seal.public_key(),base,batch,policy,scenario,attempt,self.pool,self.rng)
            if cert is None:return None,row
        else:row=dict(verdict='unverified',jobs=0,epochs=0,peak=0,checks=0,produce_ns=0)
        raw=canonical(dict(attempt=attempt,batch=batch,certificate=cert));row.update(client_build_ns=time.perf_counter_ns()-start,tx_bytes=len(raw));return raw,row
    def close(self):
        if hasattr(self,'pool'):self.pool.shutdown(wait=True)
        for p in self.procs:
            if p.is_alive():p.terminate()
        for p in self.procs:p.join(timeout=3)
    def __enter__(self):return self
    def __exit__(self,*exc):self.close()
