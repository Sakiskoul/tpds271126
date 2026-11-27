"""Real socket/application regression suite. Client drives lifecycle, NOT BFT."""
import argparse,copy,csv,json,random,socket,subprocess,sys,tempfile,time,hashlib,os
from pathlib import Path
from fixture import Producer
from ledger import canonical,initial_root,expected_context,b64,unb64,advance
from abci_socket import vi,bfield,ifield,fields,one,readframe

class Wire:
    def __init__(self,port):self.port=port
    def call(self,k,p=b'',expected=None):
        with socket.create_connection(('127.0.0.1',self.port),timeout=20) as sock:
            raw=bfield(k,p);sock.sendall(vi(len(raw))+raw)
            with sock.makefile('rb') as f:res=fields(readframe(f))
        r=next(iter(res));assert len(res)==1
        if expected is not None:assert r==expected,(k,r,one(res,r))
        return r,fields(one(res,r))
    def state(self):return json.loads(one(self.call(6,bfield(2,b'/state'),7)[1],7))
    def check(self,raw):return one(self.call(8,bfield(1,raw),9)[1],1,0)
    def propose(self,txs,height):return one(self.call(17,b''.join(bfield(1,x) for x in txs)+ifield(5,height),18)[1],1)
    def prepare(self,txs,height,cap=8*1024*1024):return self.call(16,ifield(1,cap)+b''.join(bfield(2,x) for x in txs)+ifield(5,height),17)[1].get(1,[])
    def finalize(self,txs,height,expected=21):return self.call(20,b''.join(bfield(1,x) for x in txs)+ifield(5,height),expected)[1]
    def commit(self):self.call(11,b'',12)

def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def wait(port,proc):
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        if proc.poll() is not None:raise RuntimeError('app exited '+str(proc.returncode))
        try:Wire(port).call(1,bfield(1,b'hello'),2);return
        except OSError:time.sleep(.05)
    raise TimeoutError('app start')

class Replica:
    def __init__(self,path,config):
        self.path=path;path.mkdir();self.config=config;self.port=free_port();(path/'config.json').write_bytes(canonical(config));self.w=Wire(self.port);self.p=None;self.start()
    def start(self):
        self.log=open(self.path/'app.log','ab');self.p=subprocess.Popen([sys.executable,str(Path(__file__).with_name('abci_socket.py')),'--config',str(self.path/'config.json'),'--db',str(self.path/'ledger.db'),'--port',str(self.port)],stdout=self.log,stderr=self.log);wait(self.port,self.p)
    def stop(self):
        if self.p and self.p.poll() is None:self.p.terminate();self.p.wait(timeout=5)
        if hasattr(self,'log'):self.log.close()
    def restart(self):self.stop();self.start()

def run(out):
    out.mkdir(parents=True,exist_ok=False);checks=[];timings=[]
    def check(name,test):
        if not test:raise AssertionError(name)
        checks.append(name)
    for mode,policy,cap in [('direct','direct_majority',13),('certificate','direct_majority',13),('certificate','adaptive_four_work',8)]:
        case=f'{mode}-{policy}';path=out/case;path.mkdir();rep=[]
        with Producer(14,mode,cap,path/'producer') as prod:
            try:
                for i in range(4):rep.append(Replica(path/f'node{i}',prod.config))
                ws=[r.w for r in rep];root=initial_root(prod.config)
                for w in ws:
                    init=w.call(5,bfield(2,prod.config['chain_id'].encode())+bfield(5,canonical(prod.config))+ifield(6,1),6)
                    check(case+':genesis',one(init[1],3).hex()==root)

                state=ws[0].state();raw,row=prod.make(state,4,policy,'targeted');assert raw
                for w in ws:
                    check(case+':CheckTx',w.check(raw)==0)
                    check(case+':empty proposal',w.propose([],1)==1)
                    check(case+':empty finalize',one(w.finalize([],1),5).hex()==root);w.commit()
                    check(case+':stable empty context',w.check(raw)==0)
                    check(case+':duplicate batch in block',w.propose([raw,raw],2)==2)
                    check(case+':stale block height',w.propose([raw],1)==2)
                    check(case+':byte cap',w.prepare([raw],2,16)==[])
                tx=json.loads(raw);bad=[]
                v=copy.deepcopy(tx);v['attempt']='0'*32;bad.append(('attempt',canonical(v)))
                v=copy.deepcopy(tx);m=bytearray(unb64(v['batch'][0][0]));m[0]^=1;v['batch'][0][0]=b64(m);bad.append(('domain',canonical(v)))
                v=copy.deepcopy(tx);sig=bytearray(unb64(v['batch'][0][1]));sig[-1]^=1;v['batch'][0][1]=b64(sig);bad.append(('signature or object binding',canonical(v)))
                v=copy.deepcopy(tx);v['batch'].reverse();bad.append(('reordered items',canonical(v)))
                bad.append(('noncanonical',raw+b' '));bad.append(('malformed',b'{'))
                if mode=='certificate':
                    v=copy.deepcopy(tx);v['certificate']['witnesses'][0]['proof'].append('0'*64);bad.append(('tampered merkle proof',canonical(v)))
                    v=copy.deepcopy(tx);v['certificate']['witnesses'].append(v['certificate']['witnesses'][0]);bad.append(('duplicate witness',canonical(v)))
                    v=copy.deepcopy(tx);v['certificate']['headers'][0]['body']['context']['f']=0;bad.append(('altered budget',canonical(v)))
                    v=copy.deepcopy(tx);v['certificate']['headers'][0]['body']['context']['chain_id']='wrong';bad.append(('wrong chain',canonical(v)))
                    v=copy.deepcopy(tx);v['certificate']['headers'][0]['body']['context']['registry_digest']='0'*64;bad.append(('wrong registry',canonical(v)))
                    v=copy.deepcopy(tx);v['certificate']['headers'][0]['body']['context']['prestate_root']='0'*64;bad.append(('wrong state',canonical(v)))
                    v=copy.deepcopy(tx);v['certificate']['headers'][0]['body']['cohort']=list(range(14));bad.append(('over-cap',canonical(v)))
                    v=copy.deepcopy(tx);v['certificate']['headers']=v['certificate']['headers']*5;bad.append(('too many epochs',canonical(v)))
                for name,x in bad:
                    for w in ws:
                        check(case+':reject CheckTx '+name,w.check(x)!=0)
                        check(case+':reject proposal '+name,w.propose([x],2)==2)
                for w in ws:check(case+':prepare filters bad',w.prepare([bad[0][1],raw],2)==[raw])

                newroot=advance(ws[0].state(),tx)['root']
                check(case+':pending hash',one(ws[0].finalize([raw],2),5).hex()==newroot)
                check(case+':not persisted before Commit',ws[0].state()['root']==root)
                rep[0].restart();check(case+':precommit crash rollback',ws[0].state()['root']==root)
                for w in ws:
                    check(case+':valid proposal',w.propose([raw],2)==1)
                    check(case+':finalized root',one(w.finalize([raw],2),5).hex()==newroot);w.commit()
                check(case+':four replica roots',all(w.state()==ws[0].state() for w in ws))
                check(case+':accepted sequence',ws[0].state()['sequence']==1)
                rep[1].restart();check(case+':commit restart state',ws[1].state()==ws[0].state())
                for w in ws:check(case+':replay rejected',w.check(raw)!=0 and w.propose([raw],3)==2)
                check(case+':snapshot rejected',one(ws[0].call(13,b'',14)[1],1)==3)


                for B in (1,32,128):
                    for repeat in range(3):
                        s=ws[0].state();height=s['height']+1;start=time.perf_counter_ns();r,row=prod.make(s,B,policy,'honest');assert r
                        produced=time.perf_counter_ns()-start;begin=time.perf_counter_ns()
                        for w in ws:assert w.propose([r],height)==1
                        roots=[one(w.finalize([r],height),5).hex() for w in ws]
                        assert len(set(roots))==1
                        for w in ws:w.commit()
                        elapsed=time.perf_counter_ns()-begin;assert all(w.state()==ws[0].state() for w in ws)
                        timings.append(dict(mode=mode,policy=policy,batch=B,repeat=repeat,client_build_ns=produced,lifecycle_ns=elapsed,tx_bytes=len(r),jobs=row['jobs'],primitive_checks=row['checks'],epochs=row['epochs'],sequence=ws[0].state()['sequence'],root=roots[0]))
                check(case+':final sequence',ws[0].state()['sequence']==10)


                before=ws[2].state();ws[2].finalize([raw],before['height']+1,expected=1)
                rep[2].p.wait(timeout=5);check(case+':invalid adoption fail-stop',rep[2].p.returncode==70)
                rep[2].restart();check(case+':fail-stop preserved state',ws[2].state()==before)
                (path/'final_states.json').write_bytes(canonical([w.state() for w in ws]))
            finally:
                for r in rep:r.stop()
    with (out/'lifecycle.csv').open('w') as f:w=csv.DictWriter(f,fieldnames=list(timings[0]));w.writeheader();w.writerows(timings)
    (out/'checks.json').write_text(json.dumps({'kind':'ABCI wire-client lifecycle tests, NOT consensus','assertions_passed':len(checks),'checks':checks,'lifecycle_trials':len(timings),'source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')}},indent=2))
    print('passed',len(checks),'assertions and',len(timings),'lifecycle trials')
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True);run(Path(ap.parse_args().output))
