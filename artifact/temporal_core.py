"""Exact observation-model utilities for bounded-churn temporal certification.

This module does not implement report authentication or a recovery mechanism.
Worker sets are non-negative integer bitmasks. Churn is the number of NEW
faulty identities allowed between consecutive observation epochs.
"""
from dataclasses import dataclass
from math import inf


def members(mask):
    while mask:
        low = mask & -mask
        yield low.bit_length() - 1
        mask ^= low


def mask_of(items):
    result = 0
    for i in items:
        if i < 0:
            raise ValueError("negative worker identity")
        result |= 1 << i
    return result


def take(mask, count):
    if count < 0 or count > mask.bit_count():
        raise ValueError("insufficient eligible identities")
    result = 0
    for i in members(mask):
        if count == 0:
            break
        result |= 1 << i
        count -= 1
    return result


def transitions(churn, length):
    if isinstance(churn, int):
        if churn < 0:
            raise ValueError("negative churn")
        return [churn] * length
    cs = list(churn)
    if len(cs) != length or any(c < 0 for c in cs):
        raise ValueError("one non-negative churn value per transition required")
    return cs


def interval_feasible(history, f, churn):
    """Whether some allowed fault trajectory covers every required mask."""
    if f < 0 or any(d < 0 for d in history):
        raise ValueError("negative budget or mask")
    cs = transitions(churn, max(0, len(history) - 1))
    for a in range(len(history)):
        union, budget = 0, f
        for b in range(a, len(history)):
            union |= history[b]
            if b > a:
                budget += cs[b - 1]
            if union.bit_count() > budget:
                return False
    return True


def suffixes(history, f, churn_to_next):
    """(required union, accumulated budget), immediately before next epoch.

    A history of length t requires t transition budgets, including the
    transition from its last epoch to the next observation.
    """
    cs = transitions(churn_to_next, len(history))
    union, budget = 0, f
    yield union, budget
    for d, c in zip(reversed(history), reversed(cs)):
        union |= d
        budget += c
        yield union, budget


def belief_rank(history, f, churn_to_next, candidate):
    return candidate.bit_count() - max(
        0, *((candidate | u).bit_count() - b
             for u, b in suffixes(history, f, churn_to_next)))


@dataclass(frozen=True)
class Cohort:
    mask: int
    cost: float
    suffix0: int
    suffix1: int
    required_count: int


def minimum_cost_cohort(n, f, history0, history1, churn_to_next,
                        costs=None, eligible=None, peak=None):
    """Exact cheapest NEXT distinguishing cohort, not a global scheduler.

    Positive/non-negative worker costs are additive. Eligibility and peak
    constraints apply only to this observation. Both histories must still
    be individually feasible. Returns None if no distinguishing cohort fits.
    """
    if len(history0) != len(history1) or not 0 <= f <= n:
        raise ValueError("incompatible histories or population")
    cs = transitions(churn_to_next, len(history0))
    for h in (history0, history1):
        if not interval_feasible(h, f, cs[:-1] if h else []):
            raise ValueError("eliminated hypothesis cannot be revived")
    all_workers = (1 << n) - 1
    if any(d & ~all_workers for d in history0 + history1):
        raise ValueError("worker outside population")
    eligible = all_workers if eligible is None else eligible
    peak = n if peak is None else peak
    costs = [1.0] * n if costs is None else list(costs)
    if eligible < 0 or eligible & ~all_workers or not 0 <= peak <= n:
        raise ValueError("invalid eligibility or peak")
    if len(costs) != n or any(w < 0 or w == inf or w != w for w in costs):
        raise ValueError("finite non-negative worker costs required")
    order = sorted(members(eligible), key=lambda i: (costs[i], i))
    candidates = []
    for j, (u, bu) in enumerate(suffixes(history0, f, cs)):
        for k, (v, bv) in enumerate(suffixes(history1, f, cs)):
            need = bu + bv - u.bit_count() - v.bit_count() + 1
            allowed = eligible & ~(u | v)
            if need <= 0:
                raise ValueError("inconsistent feasible histories")
            if need > min(peak, allowed.bit_count()):
                continue
            selected = [i for i in order if allowed >> i & 1][:need]
            candidates.append(Cohort(mask_of(selected), sum(costs[i] for i in selected), j, k, need))
    return min(candidates, key=lambda z: (z.cost, z.required_count, z.mask)) if candidates else None


def decode(queries, positives, f, churn):
    if len(queries) != len(positives) or any(a & ~s for a, s in zip(positives, queries)):
        raise ValueError("invalid transcript")
    h0 = list(positives)
    h1 = [s ^ a for s, a in zip(queries, positives)]
    zero_possible = interval_feasible(h0, f, churn)
    one_possible = interval_feasible(h1, f, churn)
    if not zero_possible and not one_possible:
        raise ValueError("transcript violates stated model")
    if zero_possible == one_possible:
        return None
    return 0 if zero_possible else 1


@dataclass(frozen=True)
class Witness:
    first: int
    last: int
    reports: tuple
    budget: int


def smallest_positive_witness(positives, f, churn):
    """Minimum report-count interval witness, with distinct worker identities.

    Reports are (zero-based epoch, worker). Authentication and sealed membership
    must be checked separately. Counts ignore seal/Merkle overhead.
    """
    cs = transitions(churn, max(0, len(positives) - 1))
    candidates = []
    for a in range(len(positives)):
        first_report = {}
        budget = f
        for b in range(a, len(positives)):
            if b > a:
                budget += cs[b - 1]
            for i in members(positives[b]):
                first_report.setdefault(i, b)
            if len(first_report) > budget:
                reports = tuple((first_report[i], i) for i in sorted(first_report)[:budget + 1])
                candidates.append(Witness(a, b, reports, budget))
    return min(candidates, key=lambda w: (len(w.reports), w.last - w.first, w.first, w.reports)) if candidates else None


def exact_horizon(f, c, s):
    if not 1 <= c < f:
        raise ValueError("frontier requires 1 <= c < f")
    if s >= 2 * f + 1:
        return 1
    if s <= f + c:
        return None
    d = s - f - c
    return 2 if f < c + 3*d else 3 if f < c + 5*d else 4


def two_epoch_min_work(f, c, s, n=None):
    if not 1 <= c < f:
        raise ValueError("frontier requires 1 <= c < f")
    n = 2*f+2*c if n is None else n
    if n <= 2*f or not 0 < s <= n:
        return None
    if s >= 2*f + 1:
        return 2*f + 1
    if n <= 2*f+c:
        return None
    if n > 2*f+2*c:
        return 2*f+2*c+1 if s >= f+c+1 else None
    if s + (s + 1)//2 <= 2*f + c:
        return None
    return 4*f + 2*c + 1 - s


def certify(n, f, c, observe, policy="saturation", peak=None):
    """Synchronous reference policies. observe(mask, epoch) -> positive mask."""
    all_workers = (1 << n) - 1
    queries, positives = [], []

    def query(s):
        if s & ~all_workers or (peak is not None and s.bit_count() > peak):
            raise ValueError("cohort exceeds population or peak")
        a = observe(s, len(queries))
        if a < 0 or a & ~s:
            raise ValueError("response outside cohort")
        queries.append(s); positives.append(a)
        return decode(queries, positives, f, c)

    if policy == "direct":
        verdict = query(take(all_workers, 2*f + 1))
    elif policy == "two_epoch_work":
        if peak is None or two_epoch_min_work(f, c, peak, n) is None:
            raise ValueError("two epochs cannot guarantee certification")
        if peak >= 2*f + 1:
            verdict = query(take(all_workers, 2*f + 1))
        elif n > 2*f+2*c:
            first = take(all_workers, 2*f+2*c+1-peak)
            verdict = query(first)
            if verdict is None:
                verdict = query(take(all_workers & ~first, peak))
        else:
            a_size = 2*(2*f + c + 1 - peak) - 1
            verdict = query(take(all_workers, a_size))
            if verdict is None:
                a, b = positives[-1], queries[-1] ^ positives[-1]
                excluded = a if a.bit_count() >= b.bit_count() else b
                count = 2*f + c - excluded.bit_count() + 1
                verdict = query(take(all_workers & ~excluded, count))
    elif policy == "four_epoch_work":
        if peak is None or n < 2*f+2*c:
            raise ValueError("four-epoch work policy requires a sufficient pool and peak")
        d = peak-f-c
        if not (1 <= c < f and d >= 1 and f >= c+5*d):
            raise ValueError("work bound is stated in the exact four-epoch regime")
        pool = take(all_workers, 2*f+2*c)
        m = f+c-2*d
        first = take(pool, m)
        verdict = query(first)
        if verdict is None:
            verdict = query(take(pool & ~first, m+1))
        if verdict is None:
            u = positives[0] | positives[1]
            v = (queries[0] ^ positives[0]) | (queries[1] ^ positives[1])
            excluded = u if u.bit_count() >= v.bit_count() else v
            count = min(peak, (pool & ~excluded).bit_count())
            verdict = query(take(pool & ~excluded, count))
        if verdict is None:
            a, b = positives[-1], queries[-1] ^ positives[-1]
            excluded = a if a.bit_count() >= b.bit_count() else b
            count = 2*f+c+1-excluded.bit_count()
            assert count <= peak
            verdict = query(take(pool & ~excluded, count))
        assert sum(s.bit_count() for s in queries) <= 4*(f+c)+1-2*d
    elif policy == "saturation":
        if not (1 <= c < f and n >= 2*f + 2*c):
            raise ValueError("unsupported saturation parameters")
        pool = take(all_workers, 2*f + 2*c)
        first = take(pool, f+c)
        verdict = query(first)
        if verdict is None:
            verdict = query(pool ^ first)
        if verdict is None:
            u = positives[0] | positives[1]
            v = (queries[0] ^ positives[0]) | (queries[1] ^ positives[1])
            assert u.bit_count() == v.bit_count() == f+c and u & v == 0
            verdict = query(v)
        if verdict is None:
            last_negative = queries[-1] ^ positives[-1]
            assert last_negative.bit_count() == f
            verdict = query(take(pool & ~last_negative, f+c+1))
    else:
        raise ValueError("unknown policy")
    if verdict is None:
        raise AssertionError("guaranteed policy did not terminate")
    if verdict == 1 and smallest_positive_witness(positives, f, c) is None:
        raise AssertionError("positive certificate has no witness")
    return verdict, queries, positives
