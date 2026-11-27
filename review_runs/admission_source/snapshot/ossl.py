"""Small OpenSSL 3.5+ ML-DSA adapter. Uses EVP, not a cryptographic implementation."""
import ctypes as C
import ctypes.util
lib=C.CDLL(ctypes.util.find_library('crypto'))
P=C.c_void_p; Z=C.c_size_t; I=C.c_int; B=C.c_char_p

def fn(name,restype,*args):
    f=getattr(lib,name); f.restype=restype; f.argtypes=list(args); return f
version=fn('OpenSSL_version',B,I)
ctx_new=fn('EVP_PKEY_CTX_new_from_name',P,P,B,B)
ctx_free=fn('EVP_PKEY_CTX_free',None,P)
gen_init=fn('EVP_PKEY_keygen_init',I,P)
gen=fn('EVP_PKEY_generate',I,P,C.POINTER(P))
free=fn('EVP_PKEY_free',None,P)
md_new=fn('EVP_MD_CTX_new',P)
md_free=fn('EVP_MD_CTX_free',None,P)
sign_init=fn('EVP_DigestSignInit_ex',I,P,P,B,P,B,P,P)
sign=fn('EVP_DigestSign',I,P,P,C.POINTER(Z),P,Z)
verify_init=fn('EVP_DigestVerifyInit_ex',I,P,P,B,P,B,P,P)
verify=fn('EVP_DigestVerify',I,P,P,Z,P,Z)
encode=fn('i2d_PUBKEY',I,P,C.POINTER(P))
decode=fn('d2i_PUBKEY',P,P,C.POINTER(P),C.c_long)

def ok(v):
    if v!=1: raise ValueError('OpenSSL EVP failure')

class Key:
    def __init__(self,p):
        if not p: raise ValueError('null key')
        self.p=p
    @classmethod
    def generate(cls,alg='ML-DSA-44'):
        ctx=ctx_new(None,alg.encode(),None); p=P()
        if not ctx:raise RuntimeError('ML-DSA requires OpenSSL >=3.5')
        try:ok(gen_init(ctx));ok(gen(ctx,C.byref(p)));return cls(p.value)
        finally:ctx_free(ctx)
    @classmethod
    def from_der(cls,der):
        buf=C.create_string_buffer(der); p=P(C.addressof(buf)); return cls(decode(None,C.byref(p),len(der)))
    def public_bytes(self,*args):
        n=encode(self.p,None); assert n>0
        buf=C.create_string_buffer(n); p=P(C.addressof(buf)); assert encode(self.p,C.byref(p))==n
        return buf.raw
    def public_key(self):return Key.from_der(self.public_bytes())
    def sign(self,msg):
        ctx=md_new(); n=Z()
        try:
            ok(sign_init(ctx,None,None,None,None,self.p,None));ok(sign(ctx,None,C.byref(n),msg,len(msg)))
            buf=C.create_string_buffer(n.value);ok(sign(ctx,buf,C.byref(n),msg,len(msg)));return buf.raw[:n.value]
        finally:md_free(ctx)
    def verify(self,sig,msg):
        ctx=md_new()
        try:ok(verify_init(ctx,None,None,None,None,self.p,None));ok(verify(ctx,sig,len(sig),msg,len(msg)))
        finally:md_free(ctx)
    def __del__(self):
        if getattr(self,'p',None):free(self.p);self.p=None

if __name__=='__main__':
    k=Key.generate('ML-DSA-65'); p=k.public_key(); s=k.sign(b'test');p.verify(s,b'test');print(version(0),len(s),len(p.public_bytes()))
    try:p.verify(s,b'bad')
    except ValueError:print('negative test passed')
    else:raise AssertionError
