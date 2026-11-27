"""O-TBC scheduler. Complete reports required for the four-epoch theorem.
History uses (signed positives, signed negatives); missing is never a bit.
"""
def terminal_cohort(history,n,f,c,s):
    t=len(history); N=set(range(n)); best=None
    suffix=[[(set(),0)] for _ in range(2)]
    for bit in (0,1):
        u=set()
        for j in range(t-1,-1,-1):
            u=u|history[j][bit]; suffix[bit].append((u,c*(t-j)))
    for U,cu in suffix[0]:
        for V,cv in suffix[1]:
            need=2*f+cu+cv-len(U)-len(V)+1
            avail=sorted(N-U-V)
            if 0<need<=min(s,len(avail)) and (best is None or need<len(best)):
                best=avail[:need]
    return best

def optimistic(history,n,f,c):
    assert n==2*(f+c) and 1<=c<f
    h=f+c;s=h+1;t=len(history);N=set(range(n))
    if t==0:return list(range(h))
    terminal=terminal_cohort(history,n,f,c,s)
    if terminal is not None:return terminal
    if t==1:return sorted(N-(history[0][0]|history[0][1]))
    if t==2:
        U=history[0][0]|history[1][0]; V=history[0][1]|history[1][1]
        assert len(U)==len(V)==h and not U&V
        return sorted(N-U)
    if t==3:
        assert len(history[2][1])==f
        return sorted(N-history[2][1])[:s]
    raise AssertionError('unresolved after four epochs')
