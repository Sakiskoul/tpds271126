"""Independent protobuf-runtime signing fixture, not an engine-signed commit."""
from google.protobuf import descriptor_pb2,descriptor_pool,message_factory,timestamp_pb2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from commits import verify_commit,vote_bytes
from abci_socket import vi
import hashlib,base64,json,copy
from pathlib import Path
F=descriptor_pb2.FieldDescriptorProto
fd=descriptor_pb2.FileDescriptorProto(name='fixture.proto',package='fixture',syntax='proto3',dependency=['google/protobuf/timestamp.proto'])
def msg(name,defs):
    m=fd.message_type.add(name=name)
    for n,num,t,ref in defs:
        f=m.field.add(name=n,number=num,type=t,label=F.LABEL_OPTIONAL)
        if ref:f.type_name=ref
msg('Parts',[('total',1,F.TYPE_UINT32,None),('hash',2,F.TYPE_BYTES,None)])
msg('Block',[('hash',1,F.TYPE_BYTES,None),('parts',2,F.TYPE_MESSAGE,'.fixture.Parts')])
msg('Vote',[('type',1,F.TYPE_INT32,None),('height',2,F.TYPE_SFIXED64,None),('round',3,F.TYPE_SFIXED64,None),('block',4,F.TYPE_MESSAGE,'.fixture.Block'),('time',5,F.TYPE_MESSAGE,'.google.protobuf.Timestamp'),('chain',6,F.TYPE_STRING,None)])
pool=descriptor_pool.Default();pool.Add(fd);Vote=message_factory.GetMessageClass(pool.FindMessageTypeByName('fixture.Vote'))
def official_shape(chain,h,r,bid,ts):
    v=Vote(type=2,height=h,round=r,chain=chain);v.block.hash=bytes.fromhex(bid['hash']);v.block.parts.total=bid['parts']['total'];v.block.parts.hash=bytes.fromhex(bid['parts']['hash']);v.time.FromJsonString(ts);b=v.SerializeToString(deterministic=True);return vi(len(b))+b
checks=[]
for r in (0,3):
    chain='synthetic-test';bid={'hash':'10'*32,'parts':{'hash':'20'*32,'total':3}};h=9;ts='2026-11-25T12:52:00.123456789Z';vs=[];ss=[]
    data=official_shape(chain,h,r,bid,ts);assert data==vote_bytes(chain,h,r,bid,ts);checks.append('wire parity round '+str(r))
    for i in range(4):
        k=Ed25519PrivateKey.generate();raw=k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw);a=hashlib.sha256(raw).digest()[:20].hex().upper();vs.append(dict(address=a,pub_key=dict(type='tendermint/PubKeyEd25519',value=base64.b64encode(raw).decode()),power='10'));ss.append(dict(block_id_flag=2,validator_address=a,timestamp=ts,signature=base64.b64encode(k.sign(data)).decode()))
    c=dict(height=str(h),round=r,block_id=bid,signatures=ss[:3]);assert verify_commit(chain,c,vs)['power']==30;checks.append('three of four valid')
    for name,bad,ch in [('wrong chain',c,'other'),('insufficient power',dict(c,signatures=ss[:2]),chain),('duplicate signer',dict(c,signatures=[ss[0]]*3),chain),('wrong round',dict(c,round=r+1),chain)]:
        try:verify_commit(ch,bad,vs)
        except Exception:checks.append(name+' rejected')
        else:raise AssertionError(name)
Path('wire_results').mkdir(exist_ok=True)
Path('wire_results/commit_fixture.json').write_text(json.dumps(dict(kind='synthetic protobuf-generated Ed25519 fixture, NOT real engine commit',checks=checks,count=len(checks)),indent=2))
print('commit fixture:',len(checks),'checks passed')
