"""Real-engine harness. No fallback to mock consensus. Fails if binary unavailable.

Each cell starts fresh CometBFT homes, application DBs and worker keys; one
batch at a time (sequential state dependency). Raw RPC evidence retained.
"""
import argparse,base64,concurrent.futures as cf,csv,hashlib,itertools,json,os,platform,random,re,shutil,socket,subprocess,sys,time,urllib.request,urllib.parse
from pathlib import Path
from fixture import Producer
from ledger import canonical,digest,initial_root,advance
from commits import verify_commit
from test_abci import free_port,wait
VERSION='0.38.26'

def rpc(port,method,params=None,post=False):
    url=f'http://127.0.0.1:{port}'
    if post:
        req=urllib.request.Request(url,canonical(dict(jsonrpc='2.0',id=1,method=method,params=params or {})),{'Content-Type':'application/json'})
    else:req=url+'/'+method+('?' + urllib.parse.urlencode(params) if params else '')
    with urllib.request.urlopen(req,timeout=10) as r:resp=json.load(r)
    if resp.get('error'):raise RuntimeError(str(resp['error']))
    return resp['result']

def state(port):return json.loads(base64.b64decode(rpc(port,'abci_query',{'path':'"/state"'})['response']['value']))
def patch_toml(path,changes):
    section='';out=[];remaining=dict(changes)
    for line in path.read_text().splitlines():
        m=re.match(r'^\s*\[([^]]+)\]\s*$',line)
        if m:section=m[1]
        m=re.match(r'^(\s*)([a-zA-Z_][\w-]*)\s*=',line)
        if m and (section,m[2]) in remaining:
            value=remaining.pop((section,m[2]));line=m[1]+m[2]+' = '+value
        out.append(line)
    if remaining:raise ValueError('missing pinned config keys '+str(list(remaining)))
    path.write_text('\n'.join(out)+'\n')
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def until(fn,timeout,desc):
    end=time.monotonic()+timeout;last=None
    while time.monotonic()<end:
        try:
            v=fn()
            if v:return v
        except Exception as e:last=e
        time.sleep(.1)
    raise TimeoutError(f'{desc}; last exception: {last}')

class Cluster:
    def __init__(self,binary,path,n,config,timeout):
        self.binary=str(binary);self.path=path;self.n=n;self.config=config;self.timeout=timeout;self.process={};self.apps={};self.logs=[];self.nodes=[]
        path.mkdir(parents=True,exist_ok=False);self.ports=set()
        def port():
            while True:
                p=free_port()
                if p not in self.ports:self.ports.add(p);return p
        try:
            for i in range(n):
                home=path/f'node{i}';home.mkdir();r=subprocess.run([self.binary,'init','--home',str(home)],capture_output=True,text=True,check=True);(home/'init.log').write_text(r.stdout+r.stderr)
                key=json.loads((home/'config/priv_validator_key.json').read_text());node_id=subprocess.check_output([self.binary,'show-node-id','--home',str(home)],text=True).strip()
                if not re.fullmatch(r'[a-f0-9]{40}',node_id):raise ValueError('invalid node ID: '+node_id)
                self.nodes.append(dict(home=home,app=port(),rpc=port(),p2p=port(),node_id=node_id,val=dict(address=key['address'],pub_key=key['pub_key'],power='10',name=f'node{i}')))
            gen=json.loads((self.nodes[0]['home']/'config/genesis.json').read_text());gen.update(chain_id=config['chain_id'],validators=[x['val'] for x in self.nodes],app_state=config,app_hash='')
            gen['consensus_params']['block']['max_bytes']=str(16*1024*1024)
            if 'abci' in gen['consensus_params']:gen['consensus_params']['abci']['vote_extensions_enable_height']='0'
            self.genesis=gen;(path/'genesis.json').write_bytes(canonical(gen));self.validators=gen['validators']
            for i,x in enumerate(self.nodes):
                h=x['home'];(h/'config/genesis.json').write_bytes(canonical(gen));(h/'app_config.json').write_bytes(canonical(config))
                peers=','.join(f"{z['node_id']}@127.0.0.1:{z['p2p']}" for j,z in enumerate(self.nodes) if j!=i)
                patch_toml(h/'config/config.toml',{('', 'proxy_app'):json.dumps(f"tcp://127.0.0.1:{x['app']}"),('', 'abci'):'"socket"',('rpc','laddr'):json.dumps(f"tcp://127.0.0.1:{x['rpc']}"),('p2p','laddr'):json.dumps(f"tcp://127.0.0.1:{x['p2p']}"),('p2p','persistent_peers'):json.dumps(peers),('p2p','addr_book_strict'):'false',('p2p','allow_duplicate_ip'):'true',('p2p','pex'):'false',('consensus','create_empty_blocks'):'false',('consensus','timeout_commit'):'"200ms"',('statesync','enable'):'false',('mempool','max_tx_bytes'):str(8*1024*1024)})
            for i in range(n):self.start(i)
            until(lambda:all(int(rpc(x['rpc'],'net_info')['n_peers'])>=n-1 for x in self.nodes),timeout,'peer discovery')
            until(lambda:all(state(x['rpc'])['root']==initial_root(config) for x in self.nodes),timeout,'genesis state')
            (path/'topology.json').write_text(json.dumps(self.nodes,default=str,indent=2))
        except BaseException:self.close();raise
    def start(self,i):
        x=self.nodes[i];h=x['home'];log=open(h/'app.log','ab');self.logs.append(log)
        p=subprocess.Popen([sys.executable,str(Path(__file__).with_name('abci_socket.py')),'--config',str(h/'app_config.json'),'--db',str(h/'ledger.db'),'--port',str(x['app'])],stdout=log,stderr=log);self.apps[i]=p;wait(x['app'],p)
        log=open(h/'engine.log','ab');self.logs.append(log);self.process[i]=subprocess.Popen([self.binary,'start','--home',str(h)],stdout=log,stderr=log)
    def stop(self,i):
        for store in (self.process,self.apps):
            p=store.get(i)
            if p and p.poll() is None:
                p.terminate()
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:p.kill();p.wait()
    def close(self):
        for i in set(self.process)|set(self.apps):self.stop(i)
        for x in self.logs:x.close()
    def __enter__(self):return self
    def __exit__(self,*exc):self.close()
    def submit(self,raw,previous,evidence,online=None):
        online=list(range(self.n)) if online is None else online;ports=[self.nodes[i]['rpc'] for i in online];p=ports[0];txid=digest(raw).upper();t=time.perf_counter_ns();begin=rpc(p,'broadcast_tx_sync',{'tx':base64.b64encode(raw).decode()},True);accepted=int(begin.get('code',0))==0
        evidence.mkdir();(evidence/'broadcast.json').write_bytes(canonical(begin));(evidence/'tx.json').write_bytes(raw)
        if not accepted:return dict(outcome='checktx_rejected',finality_ns='',height='',round='',signers='',tx_hash=txid)
        def indexed():
            r=rpc(p,'tx',{'hash':'0x'+txid,'prove':'true'})
            if r['hash'].upper()!=txid or base64.b64decode(r['tx'])!=raw:raise AssertionError('indexed transaction mismatch')
            if int(r['tx_result'].get('code',0))!=0:raise AssertionError('failed committed transaction')
            return r
        txr=until(indexed,self.timeout,'indexed transaction');indexed_ns=time.perf_counter_ns()-t;h=int(txr['height']);new=advance(previous,json.loads(raw));(evidence/'indexed.json').write_bytes(canonical(txr))

        def all_applied():
            ss=[state(port) for port in ports]
            return ss if all(x['sequence']==new['sequence'] and x['root']==new['root'] and x['height']>=h for x in ss) else None
        ss=until(all_applied,self.timeout,'replicated state');final_ns=time.perf_counter_ns()-t


        facts=[];blockids=[]
        for i,port in zip(online,ports):
            cr=rpc(port,'commit',{'height':str(h)});bl=rpc(port,'block',{'height':str(h)});signed=cr['signed_header'];fact=verify_commit(self.config['chain_id'],signed['commit'],self.validators)
            if fact['block_id']['hash']!=bl['block_id']['hash'] or signed['header']['chain_id']!=self.config['chain_id'] or raw not in [base64.b64decode(x) for x in bl['block']['data']['txs']]:raise AssertionError('block identity or inclusion mismatch')
            facts.append(fact);blockids.append(fact['block_id']['hash']);(evidence/f'commit{i}.json').write_bytes(canonical(cr));(evidence/f'block{i}.json').write_bytes(canonical(bl))
        if len(set(blockids))!=1:raise AssertionError('conflicting committed block IDs')
        (evidence/'verified.json').write_bytes(canonical({'commits':facts,'states':ss}))
        return dict(outcome='finalized',finality_ns=final_ns,indexed_ns=indexed_ns,height=h,round=facts[0]['round'],signers=facts[0]['signers'],tx_hash=txid)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--comet',default='cometbft');ap.add_argument('--output',required=True);ap.add_argument('--nodes',type=int,nargs='+',default=[4]);ap.add_argument('--workers',type=int,nargs='+',default=[14]);ap.add_argument('--batches',type=int,nargs='+',default=[1,32,128]);ap.add_argument('--repeats',type=int,default=3);ap.add_argument('--scenarios',nargs='+',choices=['honest','targeted'],default=['honest','targeted']);ap.add_argument('--policies',nargs='+',choices=['local','direct_majority','adaptive_two','adaptive_four_original','adaptive_four_work','fixed_rotation'],default=['local','direct_majority','adaptive_four_original','adaptive_four_work']);ap.add_argument('--timeout',type=int,default=120);ap.add_argument('--restart',action='store_true');a=ap.parse_args()
    binary=shutil.which(a.comet)
    if not binary:raise SystemExit('BLOCKED: CometBFT v0.38.26 executable not found; no engine run and no fabricated fallback.')
    binary=Path(binary).resolve();ver=subprocess.check_output([str(binary),'version'],text=True).strip()
    if VERSION not in ver:raise SystemExit('Expected pinned v'+VERSION+', got '+ver)
    out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=False)
    (out/'environment.json').write_text(json.dumps(dict(engine_version=ver,engine_sha256=sha(binary),args=vars(a),platform=platform.platform(),python=sys.version,source_sha256={p.name:sha(p) for p in Path(__file__).parent.glob('*.py')},scope='real single-host engine; static Ed25519 voting keys; one batch per block; no claim of quantum-secure consensus or operational mobile compromise'),indent=2))
    rows=[];fields=['nodes','workers','policy','scenario','batch','repeat','outcome','client_build_ns','finality_ns','indexed_ns','tx_bytes','jobs','epochs','checks','height','round','signers','tx_hash','elapsed_ns','error']
    def record(row):
        rows.append(row)
        with (out/'trials.csv').open('w') as f:w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
    for N,n,policy in itertools.product(a.nodes,a.workers,a.policies):
        f=n//2-1;c=1;mode='direct' if policy=='local' else 'certificate';p='direct_majority' if policy=='local' else policy
        cap=2*f+1 if policy in ('local','direct_majority') else ((4*f+2*c)//3+1 if policy=='adaptive_two' else f+c+1)
        cell=out/f'v{N}-w{n}-{policy}';cell.mkdir()
        try:
            with Producer(n,mode,cap,cell/'producer') as prod, Cluster(binary,cell/'cluster',N,prod.config,a.timeout) as cl:

                st=state(cl.nodes[0]['rpc']);raw,_=prod.make(st,1,p,'honest');assert raw;res=cl.submit(raw,st,cell/'warmup');assert res['outcome']=='finalized'
                matrix=list(itertools.product(a.scenarios,a.batches,range(a.repeats)));random.Random(20261125).shuffle(matrix)
                last_raw=None
                for j,(scenario,B,rep) in enumerate(matrix):
                    row=dict(nodes=N,workers=n,policy=policy,scenario=scenario,batch=B,repeat=rep);t=time.perf_counter_ns()
                    try:
                        st=state(cl.nodes[0]['rpc']);raw,r=prod.make(st,B,p,scenario);row.update(r)
                        if raw is None:row['outcome']='no_certificate'
                        else:
                            row.update(cl.submit(raw,st,cell/f'trial{j:04d}'))
                            if row['outcome']=='finalized':last_raw=raw
                        row['elapsed_ns']=time.perf_counter_ns()-t
                    except Exception as e:row.update(outcome='error_or_timeout',error=repr(e),elapsed_ns=time.perf_counter_ns()-t);record(row);raise
                    record(row)
                if last_raw:


                    rr=cl.submit(last_raw,state(cl.nodes[0]['rpc']),cell/'replay');assert rr['outcome']=='checktx_rejected'
                    st=state(cl.nodes[0]['rpc']);attempt,batch=prod.batch(st,1,True);raw=canonical(dict(attempt=attempt,batch=batch,certificate=None));rr=cl.submit(raw,st,cell/'invalid');assert rr['outcome']=='checktx_rejected'
                if a.restart:
                    if N<4:raise ValueError('restart requires at least four validators')
                    cl.stop(N-1);st=state(cl.nodes[0]['rpc']);raw,_=prod.make(st,1,p,'honest');assert raw;rr=cl.submit(raw,st,cell/'offline_commit',online=list(range(N-1)));assert rr['outcome']=='finalized';start=time.perf_counter_ns();cl.start(N-1);target=state(cl.nodes[0]['rpc']);ss=until(lambda:state(cl.nodes[-1]['rpc']) if state(cl.nodes[-1]['rpc'])['root']==target['root'] else None,a.timeout,'node catch-up');(cell/'restart.json').write_bytes(canonical(dict(catchup_ns=time.perf_counter_ns()-start,state=ss,target=target)))
                for i,x in enumerate(cl.nodes):
                    (cell/f'node{i}-metrics.json').write_bytes(canonical(rpc(x['rpc'],'abci_query',{'path':'"/metrics"'})))
        except Exception as e:
            (cell/'failure.txt').write_text(repr(e)+'\n');raise
    print('Actual engine matrix complete:',len(rows),'trials; see',out)
if __name__=='__main__':main()
