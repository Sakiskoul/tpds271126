"""Exec-isolated, digest-only closure interface (not a hardware sandbox).
No transaction payload or key is supplied via this service's startup or RPC.
The OS/host remains trusted; this does not establish a production trust boundary.
"""
import sys,os,json,socketserver,sqlite3,struct
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'deployment'))
from deploy import recv
from ossl import Key
from protocol import Sealer,canonical,digest,public_bytes,b64,unb64

def main():
    options=json.loads(sys.stdin.readline());assert set(options)=={'registry','db'}
    registry={int(i):Key.from_der(unb64(v)) for i,v in options['registry'].items()};key=Key.generate()
    db=sqlite3.connect(options['db']);db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL');db.execute('CREATE TABLE IF NOT EXISTS closures (context TEXT, epoch INTEGER, header TEXT, PRIMARY KEY(context,epoch))');db.commit()
    def handle(q):
        if set(q)=={'op'} and q['op']=='ping':return {'pid':os.getpid(),'public':b64(public_bytes(key))}
        if set(q)!={'op','context','epoch','cohort','reports'} or q['op']!='close':raise ValueError('digest-only closure interface')
        ctx=q['context'];cid=digest(canonical(ctx));t=q['epoch'];db.execute('BEGIN IMMEDIATE')
        try:
            prev=db.execute('SELECT epoch,header FROM closures WHERE context=? ORDER BY epoch DESC LIMIT 1',(cid,)).fetchone();sealer=Sealer(key,registry,ctx)
            if prev:sealer.next_epoch=prev[0]+1;sealer.previous=digest(canonical(json.loads(prev[1])))
            entry=sealer.close(t,q['cohort'],q['reports']);db.execute('INSERT INTO closures VALUES (?,?,?)',(cid,t,canonical(entry['header']).decode()));db.commit();return {'entry':entry}
        except Exception:db.rollback();raise
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:r={'ok':True,**handle(json.loads(recv(self.request)))}
            except Exception as e:r={'ok':False,'error':str(e)}
            b=canonical(r);self.request.sendall(struct.pack('!I',len(b))+b)
    with socketserver.TCPServer(('127.0.0.1',0),Handler) as srv:
        print(json.dumps({'addr':srv.server_address,'public':b64(public_bytes(key)),'pid':os.getpid()}),flush=True);srv.serve_forever()
if __name__=='__main__':main()
