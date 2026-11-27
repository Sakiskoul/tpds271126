"""Bounded ABCI 2.0 socket adapter; minimal protobuf wire subset.

CometBFT v0.38 field layout (see WIRE_SOURCES.md). Engine interoperability
must be tested against pinned binary; tests in this release use a wire client.
"""
import argparse,json,socketserver,threading,time,os
from pathlib import Path
from ledger import Ledger,canonical,MAX_TX
MAX_FRAME=32*1024*1024

def vi(x):
    if not 0<=x<2**64:raise ValueError('uint64')
    out=bytearray()
    while x>=128:out.append((x&127)|128);x>>=7
    out.append(x);return bytes(out)
def getvi(buf,i):
    x=0
    for j in range(10):
        if i>=len(buf):raise ValueError('short varint')
        b=buf[i];i+=1;x|=(b&127)<<(7*j)
        if b<128:
            if x>=2**64:raise ValueError('varint overflow')
            return x,i
    raise ValueError('varint overflow')
def bfield(k,v):return vi(k*8+2)+vi(len(v))+v
def ifield(k,v):return vi(k*8)+vi(v)
def fields(buf):
    o={};i=0
    while i<len(buf):
        key,i=getvi(buf,i);k,w=key>>3,key&7
        if k==0:raise ValueError('zero field')
        if w==0:v,i=getvi(buf,i)
        elif w==2:
            size,i=getvi(buf,i);end=i+size
            if end>len(buf):raise ValueError('short bytes field')
            v=buf[i:end];i=end
        elif w in (1,5):
            end=i+(8 if w==1 else 4)
            if end>len(buf):raise ValueError('short fixed field')
            v=buf[i:end];i=end
        else:raise ValueError('unsupported wire type')
        o.setdefault(k,[]).append(v)
    return o
def one(d,k,default=None):
    v=d.get(k,[default]);
    if len(v)!=1:raise ValueError('duplicate scalar')
    return v[0]
def readframe(f):
    buf=bytearray()
    for _ in range(10):
        b=f.read(1)
        if not b:
            if not buf:return None
            raise EOFError('short frame length')
        buf+=b
        if b[0]<128:break
    n,_=getvi(buf,0)
    if n>MAX_FRAME:raise ValueError('frame limit')
    d=f.read(n)
    if len(d)!=n:raise EOFError('short frame')
    return d

def answer(app,k,p):

    d=fields(p)
    with app.lock:
        s=app.state()
        if k==1:return 2,bfield(1,one(d,1,b''))
        if k==2:return 3,b''
        if k==3:return 4,bfield(1,b'TBC append-only batch ledger')+bfield(2,b'1')+ifield(3,1)+ifield(4,s['height'])+bfield(5,bytes.fromhex(s['root']) if s['height'] else b'')
        if k==5:
            if s['height']!=0 or one(d,2,b'').decode()!=app.config['chain_id'] or one(d,6,1) not in (0,1):raise RuntimeError('genesis mismatch')

            if json.loads(one(d,5,b'{}'))!=app.config:raise RuntimeError('genesis app_state mismatch')
            return 6,bfield(3,bytes.fromhex(s['root']))
        if k==6:
            path=one(d,2,b'').decode();height=one(d,3,0)
            if path not in ('/state','/metrics') or height not in (0,s['height']) or one(d,4,0):return 7,ifield(1,1)+bfield(3,b'unsupported query')
            value=canonical(s if path=='/state' else app.metrics[-4096:])
            return 7,bfield(7,value)+ifield(9,s['height'])
        if k==8:return 9,ifield(1,0 if app.valid(one(d,1,b'')) else 1)
        if k==11:app.commit();return 12,b''
        if k==12:return 13,b''
        if k==13:return 14,ifield(1,3)
        if k==14:return 15,b''
        if k==15:return 16,ifield(1,2)
        if k==16:return 17,b''.join(bfield(1,x) for x in app.prepare(d.get(2,[]),one(d,5,0),one(d,1,0)))
        if k==17:return 18,ifield(1,1 if app.process(d.get(1,[]),one(d,5,0)) else 2)
        if k==18:return 19,b''
        if k==19:return 20,ifield(1,1)
        if k==20:
            txs=d.get(1,[]);root=app.finalize(txs,one(d,5,0))
            return 21,b''.join(bfield(2,b'') for _ in txs)+bfield(5,root)
        raise ValueError('unsupported ABCI request')

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        app=self.server.app
        while True:
            try:raw=readframe(self.rfile)
            except (ValueError,EOFError):return
            if raw is None:return
            t=time.perf_counter_ns();cpu=time.thread_time_ns();k=0;error=None
            try:
                d=fields(raw)
                if len(d)!=1:raise ValueError('expected exactly one request')
                k=next(iter(d));r,p=answer(app,k,one(d,k))
            except Exception as e:
                error=type(e).__name__+': '+str(e);r,p=1,bfield(1,error.encode()[:4096])
            with app.lock:
                app.metrics.append(dict(method=k,wall_ns=time.perf_counter_ns()-t,cpu_ns=time.thread_time_ns()-cpu,request_bytes=len(raw),error=error))
                if len(app.metrics)>8192:del app.metrics[:4096]
            out=bfield(r,p);self.wfile.write(vi(len(out))+out);self.wfile.flush()
            if error and k in (5,11,20):

                if self.server.fail_stop:os._exit(70)
                return
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True
    def __init__(self,address,app,fail_stop=True):
        self.app=app;self.fail_stop=fail_stop;super().__init__(address,Handler)

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--db',required=True);p.add_argument('--port',type=int,required=True);a=p.parse_args()
    app=Ledger(json.loads(Path(a.config).read_text()),a.db)
    with Server(('127.0.0.1',a.port),app) as s:s.serve_forever()
if __name__=='__main__':main()
