"""Exact-arithmetic cohort oracle with one canonical identity ordering."""
from fractions import Fraction
from itertools import islice


def choose(n, f, cap, history, churn, eligible=None, costs=None):
    """Separate two still-feasible hypotheses or return None.

    History is a sequence of disjoint observed one/zero identity sets.
    Churn has one transition budget per observed epoch, including the
    transition into the next epoch. The eligibility and cost domains are
    defined over the registry [0,n).
    """
    if len(history) != len(churn) or any(c < 0 for c in churn):
        raise ValueError("Supply a nonnegative bound for each transition")
    allowed = set(range(n)) if eligible is None else set(eligible)
    if not allowed <= set(range(n)):
        raise ValueError("Invalid eligible identity")
    weights = None
    if costs is not None:
        try:
            weights = {i: Fraction(costs[i]) for i in allowed}
        except (ValueError, ZeroDivisionError, OverflowError) as exc:
            raise ValueError("Cohort costs must be finite") from exc
        if any(v < 0 for v in weights.values()):
            raise ValueError("Cohort costs must be nonnegative")
        order = sorted(allowed, key=lambda i: (weights[i], i))
    else:
        order = [i for i in range(n) if i in allowed]

    suffix = [[(set(), 0)], [(set(), 0)]]
    sets = [set(), set()]
    budget = 0
    for pair, new in zip(reversed(history), reversed(churn)):
        budget += new
        for bit in range(2):
            sets[bit] = sets[bit] | pair[bit]
            suffix[bit].append((sets[bit], budget))

    best, best_value = None, None
    for U, a in suffix[0]:
        for V, b in suffix[1]:
            need = 2*f + a+b-len(U)-len(V)+1
            if not 0 < need <= cap:
                continue
            if weights is None and best_value is not None and need >= best_value:
                continue
            cohort = list(islice((i for i in order if i not in U and i not in V),need))
            if len(cohort) != need:
                continue
            value = need if weights is None else sum(weights[i] for i in cohort)
            if best_value is None or value < best_value:
                best, best_value = cohort, value
    return best
