"""Deterministic append-only batch ledger for the TBC prototype.

No remote calls in the consensus predicate. 'height' in the TBC context is
application sequence, NOT CometBFT block height. Empty blocks preserve the
application root. One nonempty batch per block; genesis configuration fixed.
"""
import hashlib, json, sqlite3, threading, sys, time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'deployment'))
from protocol import canonical,digest,b64,unb64,public_bytes,verify_positive
from ossl import Key
MAX_TX=8*1024*1024
MAX_BATCH=256
MAX_EPOCHS=4
DOMAIN=b'TBC-ledger-request/v1\0'

def decode(raw):
    if not isinstance(raw,bytes) or len(raw)>MAX_TX: raise ValueError('transaction size')
    o=json.loads(raw)
    if canonical(o)!=raw: raise ValueError('noncanonical transaction')
    return o

def message(config,seq,root,attempt,i,payload):
    return DOMAIN+canonical(dict(chain_id=config['chain_id'],sequence=seq,prestate_root=root,
        attempt_id=attempt,index=i,payload=payload))

def expected_context(config,state,attempt,batch):
    return dict(chain_id=config['chain_id'],height=state['sequence']+1,prestate_root=state['root'],
        credential_version=1,credential_key_digest=digest(unb64(config['tx_key'])),policy_id='all-ML-DSA-65',
        policy_version=1,component='batch',implementation_id='OpenSSL-EVP',registry_digest=digest(canonical(config['registry'])),
        n=config['n'],f=config['f'],c=config['c'],attempt_id=attempt,object_digest=digest(canonical(batch)))

def initial_root(config):return digest(b'TBC-ledger-genesis/v1\0'+canonical(config))

def advance(state,tx):


    record={k:tx[k] for k in ('attempt','batch')}
    return dict(sequence=state['sequence']+1,root=digest(b'TBC-ledger-state/v1\0'+bytes.fromhex(state['root'])+canonical(record)))

class Ledger:
    def __init__(self,config,db_path):
        self.config=config;self.config_hash=digest(canonical(config));self.lock=threading.RLock()
        if set(config)!={'chain_id','n','f','c','registry','seal_key','tx_key','max_cohort','mode'}:raise ValueError('configuration fields')
        n,f,c=config['n'],config['f'],config['c']
        if not (n==2*f+2*c and 1<=c<f and f>=6):raise ValueError('supported population')
        if config['mode'] not in ('direct','certificate'):raise ValueError('mode')
        if not 1<=config['max_cohort']<=n:raise ValueError('cohort cap')
        if set(config['registry'])!=set(map(str,range(n))):raise ValueError('registry identities')
        self.registry={int(i):Key.from_der(unb64(k)) for i,k in config['registry'].items()}
        self.seal=Key.from_der(unb64(config['seal_key']));self.txkey=Key.from_der(unb64(config['tx_key']))
        self.db=sqlite3.connect(db_path,check_same_thread=False,isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1),config TEXT,height INTEGER,sequence INTEGER,root TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS records(sequence INTEGER PRIMARY KEY,attempt TEXT UNIQUE,tx_hash TEXT,body BLOB,block_height INTEGER)')
        self.db.execute('INSERT OR IGNORE INTO state VALUES(1,?,0,0,?)',(self.config_hash,initial_root(config)))
        if self.db.execute('SELECT config FROM state').fetchone()[0]!=self.config_hash:raise ValueError('database genesis mismatch')
        self.pending=None;self.metrics=[]
    def state(self):
        h,s,r=self.db.execute('SELECT height,sequence,root FROM state WHERE id=1').fetchone()
        return dict(height=h,sequence=s,root=r)
    def validate(self,raw,state=None):
        state=self.state() if state is None else state
        tx=decode(raw)
        if set(tx)!={'attempt','batch','certificate'}:raise ValueError('transaction fields')
        attempt=tx['attempt'];batch=tx['batch'];cert=tx['certificate']
        if not isinstance(attempt,str) or len(attempt)!=32 or any(c not in '0123456789abcdef' for c in attempt):raise ValueError('attempt ID')
        if self.db.execute('SELECT 1 FROM records WHERE attempt=?',(attempt,)).fetchone():raise ValueError('replay')
        if not isinstance(batch,list) or not 1<=len(batch)<=MAX_BATCH:raise ValueError('batch size')
        for i,pair in enumerate(batch):
            if not isinstance(pair,list) or len(pair)!=2:raise ValueError('entry fields')
            msg,sig=map(unb64,pair);body=json.loads(msg[len(DOMAIN):]);payload=body['payload']
            if not isinstance(payload,str) or len(unb64(payload))>4096 or len(sig)!=3309:raise ValueError('payload or ML-DSA-65 signature size')
            if msg!=message(self.config,state['sequence']+1,state['root'],attempt,i,payload):raise ValueError('stale or misbound message')
            if self.config['mode']=='direct':self.txkey.verify(sig,msg)
        if self.config['mode']=='direct':
            if cert is not None:raise ValueError('unexpected certificate')
        else:
            if not isinstance(cert,dict) or not 1<=len(cert['headers'])<=MAX_EPOCHS:raise ValueError('epoch limit')
            for head in cert['headers']:
                if len(head['body']['cohort'])>self.config['max_cohort']:raise ValueError('cohort exceeds genesis cap')
            verify_positive(cert,self.registry,self.seal,expected_context(self.config,state,attempt,batch))
        return tx
    def valid(self,raw,state=None):
        try:self.validate(raw,state);return True
        except (ValueError,KeyError,TypeError,IndexError,OverflowError,AttributeError,RecursionError):return False
    def process(self,txs,height):
        return height==self.state()['height']+1 and len(txs)<=1 and all(self.valid(tx) for tx in txs)
    def prepare(self,txs,height,max_bytes):
        if height!=self.state()['height']+1:return []

        return next(([tx] for tx in txs if len(tx)+16<=max_bytes and self.valid(tx)),[])
    def finalize(self,txs,height):
        if self.pending is not None:raise RuntimeError('uncommitted finalization')
        state=self.state()
        if height!=state['height']+1 or len(txs)>1:raise RuntimeError('invalid block height or size')
        tx=self.validate(txs[0],state) if txs else None
        new=advance(state,tx) if tx else dict(sequence=state['sequence'],root=state['root'])
        self.pending=(height,new,tx,txs[0] if tx else None)
        return bytes.fromhex(new['root'])
    def commit(self):
        if self.pending is None:raise RuntimeError('commit without finalize')
        h,new,tx,raw=self.pending
        self.db.execute('BEGIN IMMEDIATE')
        try:
            if tx:self.db.execute('INSERT INTO records VALUES(?,?,?,?,?)',(new['sequence'],tx['attempt'],digest(raw),raw,h))
            self.db.execute('UPDATE state SET height=?,sequence=?,root=? WHERE id=1',(h,new['sequence'],new['root']))
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise
        self.pending=None
    def close(self):self.db.close()
