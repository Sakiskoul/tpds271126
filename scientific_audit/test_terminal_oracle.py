from audit_temporal import ConcreteWorld, ids, encode
from terminal_oracle import choose
from fractions import Fraction
import json
import random
from pathlib import Path

def run():
    r=random.Random(68320)
    count=0
    for n in range(3,8):
        for f in range(1,n):
            world=ConcreteWorld(n,f)
            for trial in range(100):
                first=second=frozenset(world.states)
                prefix,moves=[],[]
                for _ in range(r.randrange(4)):
                    positive=negative=0
                    labels=[r.randrange(4) for _ in range(n)]
                    for i,lab in enumerate(labels):
                        if lab==1: positive |= 1<<i
                        if lab==2: negative |= 1<<i
                    c=r.randrange(f+1)
                    nxt0=world.advance(world.admit(first,positive),c)
                    nxt1=world.advance(world.admit(second,negative),c)
                    if not nxt0 or not nxt1:
                        break
                    first,second=nxt0,nxt1
                    prefix.append((set(ids(positive)),set(ids(negative))))
                    moves.append(c)
                eligible={i for i in range(n) if r.random()<.84}
                cost=[r.choice((0,1,10,100,1.6e308)) for _ in range(n)]
                cap=r.randrange(1,n+1)
                feasible=[set(ids(x)) for x in world.separators(first,second)
                          if x.bit_count()<=cap and set(ids(x))<=eligible]
                got=choose(n,f,cap,prefix,moves,eligible,cost)
                assert (got is None)==(not feasible)
                if feasible:
                    objective=lambda x:sum(Fraction(cost[i]) for i in x)
                    assert set(got) in feasible and objective(got)==min(map(objective,feasible))
                count+=1
    pos,neg,moves=(0b001010,0b000001,0b100000),(0b010000,0b001000,0),(1,1,1)
    values=(1.6e308,3.2e307,1.5e308,3.2e307,1.2e307,1.1e308)
    extreme=choose(6,2,6,[(set(ids(a)),set(ids(b))) for a,b in zip(pos,neg)],moves,costs=values)
    assert set(extreme)=={1,2,3,4,5}
    (Path(__file__).resolve().parent/"oracle_numeric_checks.json").write_text(
        json.dumps(dict(exact_weighted_finite_cases=count,extreme_cost_regression_sorted=sorted(extreme)),indent=2)+"\n")
    print(f"{count} exact-weighted finite cases and historical numeric regression passed")

if __name__=="__main__":
    run()
