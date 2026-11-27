"""Independent depth-two optimizer using two-set exposure extensions.

The enumeration never calls the production interval test or suffix oracle.
It searches all second cohorts up to their interchangeable identity classes.
A concrete bit-mask exposure-trajectory check validates the compression.
"""
import json
from itertools import combinations
from pathlib import Path

OUT = Path(__file__).resolve().parent


def first_splits(m, f):
    return range(max(0, m - f), min(m, f) + 1)


def ambiguous(f, c, a, b, x, y, z):
    """Whether S with intersections x,y,z admits a common response."""
    k = x + y + z
    low = max(0, k - f, k - (f + c - b) - y)
    high = min(k, f, (f + c - a) + x)
    return low <= high


def minimum_second(n, f, c, a, b):
    other = n - a - b
    for k in range(min(n, 2 * f + 1) + 1):
        for x in range(min(a, k) + 1):
            for y in range(max(0, k - x - other), min(b, k - x) + 1):
                if not ambiguous(f, c, a, b, x, y, k - x - y):
                    return k
    return None


def independent(n, f, c):
    strategies = []
    for m in range(1, n + 1):
        splits = list(first_splits(m, f))
        tails = [minimum_second(n, f, c, a, m-a) for a in splits]
        if any(x is None for x in tails):
            continue
        worst = max(tails, default=0)
        strategies.append({"cap": max(m, worst), "work": m + worst, "first": m, "second_worst": worst})
    return {str(s): min((x for x in strategies if x["cap"] <= s),
                       key=lambda x:(x["work"], x["cap"], x["first"]), default=None)
            for s in range(1, n+1)}


def stated(n, f, c, s):
    if n <= 2*f:
        return None
    if s >= 2*f+1:
        return 2*f+1
    if 2*f+c < n <= 2*f+2*c and s+(s+1)//2 > 2*f+c:
        return 4*f+2*c+1-s
    if n > 2*f+2*c and s >= f+c+1:
        return 2*f+2*c+1
    return None


def validate_compression():
    count = 0
    for n in range(3, 9):
        for f in range(2, min(n, 5)):
            states = [sum(1<<i for i in subset) for subset in combinations(range(n), f)]
            for c in range(1, f):
                nxt = {i: [j for j in states if (j & ~i).bit_count() <= c] for i in states}
                for a in range(f+1):
                    for b in range(min(f,n-a)+1):
                        A = (1<<a)-1
                        B = ((1<<b)-1)<<a
                        live0 = {j for i in states if i&A==A for j in nxt[i]}
                        live1 = {j for i in states if i&B==B for j in nxt[i]}
                        covers = {i|j for i in live0 for j in live1}
                        for S in range(1<<n):
                            x = (A&S).bit_count()
                            y = (B&S).bit_count()
                            z = S.bit_count()-x-y
                            explicit = any(U&S==S for U in covers)
                            assert explicit == ambiguous(f,c,a,b,x,y,z), (n,f,c,A,B,S)
                            count += 1
    return count


def check_group(n, f, c):
    rows=independent(n, f, c)
    for cap, case in rows.items():
        actual = case["work"] if case is not None else None
        expected = stated(n, f, c, int(cap))
        assert actual == expected, (n,f,c,cap,actual,expected)
    return rows


def main():
    concrete = validate_compression()
    checks = 0
    for f in range(2, 9):
        for c in range(1, f):
            for n in range(max(1,2*f-2),2*f+2*c+5):
                check_group(n,f,c)
                checks += n
    reference = {str(n): check_group(n,20,1) for n in range(40,46)}
    checks += sum(map(int, reference))
    (OUT/"two_epoch_checks.json").write_text(json.dumps({"concrete_response_comparisons":concrete,
        "optimized_cap_cases":checks,"reference":reference},indent=2)+"\n",encoding="utf-8")
    print(f"{concrete:,} concrete response checks and {checks:,} optimized cap cases")
    for n, result in reference.items():
        cap=next((s for s, value in result.items() if value is not None), None)
        print(n, cap, result.get(cap))

if __name__=="__main__":
    main()
