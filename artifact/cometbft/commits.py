"""Independent verification of static Ed25519 commit signatures.

Checks quorum signed over the RPC block ID. Does not recompute a full header
hash, validate validator-set changes or implement a light client.
"""
import base64,calendar,datetime,hashlib,re,struct
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from abci_socket import vi,ifield,bfield

def timestamp(s):
    m=re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z',s)
    if not m:raise ValueError('expected UTC timestamp')
    sec=calendar.timegm(datetime.datetime.strptime(m[1],'%Y-%m-%dT%H:%M:%S').timetuple());ns=int((m[2] or '').ljust(9,'0'))
    return (ifield(1,sec) if sec else b'')+(ifield(2,ns) if ns else b'')
def vote_bytes(chain,h,r,block_id,ts):
    parts=block_id.get('parts',block_id.get('part_set_header'))
    block=bfield(1,bytes.fromhex(block_id['hash']))+bfield(2,ifield(1,int(parts['total']))+bfield(2,bytes.fromhex(parts['hash'])))
    v=ifield(1,2)+vi(2*8+1)+struct.pack('<q',h)+(vi(3*8+1)+struct.pack('<q',r) if r else b'')+bfield(4,block)+bfield(5,timestamp(ts))+bfield(6,chain.encode())
    return vi(len(v))+v

def verify_commit(chain,commit,validators):
    reg={v['address'].upper():v for v in validators};seen=set();power=0
    h,r=int(commit['height']),int(commit['round']);bid=commit['block_id']
    if h<=0 or r<0 or len(bytes.fromhex(bid['hash']))!=32:raise ValueError('bad commit context')
    for s in commit['signatures']:
        if int(s['block_id_flag'])!=2:continue
        a=s['validator_address'].upper()
        if a in seen or a not in reg:raise ValueError('duplicate or unknown signer')
        v=reg[a];pk=v['pub_key'];raw=base64.b64decode(pk['value'],validate=True)
        if pk['type']!='tendermint/PubKeyEd25519' or hashlib.sha256(raw).digest()[:20].hex().upper()!=a:raise ValueError('unexpected key/address')
        Ed25519PublicKey.from_public_bytes(raw).verify(base64.b64decode(s['signature'],validate=True),vote_bytes(chain,h,r,bid,s['timestamp']))
        seen.add(a);power+=int(v['power'])
    total=sum(int(v['power']) for v in validators)
    if 3*power<=2*total:raise ValueError('insufficient signed power')
    return {'height':h,'round':r,'signers':len(seen),'power':power,'total_power':total,'block_id':bid}
