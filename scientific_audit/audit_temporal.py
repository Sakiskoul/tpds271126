"""Independent finite audit of temporal label feasibility and the next-cohort oracle.

Ground truth enumerates concrete exposure sets, bounded set differences, and
complete response partitions. Production formulas are comparison targets only.
Uses finite abstract labels and optionally audits externally supplied saved traces.
"""
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import random
import sys
from collections import Counter
from fractions import Fraction
from functools import lru_cache
from itertools import combinations, product
from pathlib import Path


HERE = Path(__file__).resolve().parent
ARTIFACT = HERE.parent / "artifact"


def import_source(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def ids(mask):
    return tuple(i for i in range(mask.bit_length()) if mask & (1 << i))


def encode(identities):
    return sum(1 << identity for identity in set(identities))


def subsets(mask):
    elements = ids(mask)
    return tuple(encode(choice) for length in range(len(elements) + 1)
                 for choice in combinations(elements, length))


class ConcreteWorld:
    """Finite exposure sets. Reachability uses only explicit admissible edges."""

    def __init__(self, n, f, exact=False):
        self.n = n
        self.universe = (1 << n) - 1
        self.states = tuple(mask for mask in range(1 << n)
                            if (mask.bit_count() == f if exact else mask.bit_count() <= f))
        self.covered = tuple(frozenset(mask for mask in self.states if demand & mask == demand)
                             for demand in range(1 << n))
        self.advance = lru_cache(maxsize=None)(self.advance)
        self.rank_vector = lru_cache(maxsize=None)(self.rank_vector)
        self.separators = lru_cache(maxsize=None)(self.separators)
        self.partition = tuple(tuple((a, cohort ^ a) for a in subsets(cohort))
                               for cohort in range(1 << n))

    def admit(self, reachable, demand):
        return reachable & self.covered[demand]

    def advance(self, reachable, churn):
        return frozenset(future for future in self.states
                         if any((future & ~present).bit_count() <= churn
                                for present in reachable))

    def rank_vector(self, reachable):
        return tuple(max((mask & candidate).bit_count() for mask in reachable)
                     for candidate in range(1 << self.n))

    def separators(self, first, second):
        a_possible = {d for d in range(1 << self.n) if self.covered[d] & first}
        b_possible = {d for d in range(1 << self.n) if self.covered[d] & second}
        return tuple(cohort for cohort, partitions in enumerate(self.partition)
                     if not any(a in a_possible and b in b_possible for a, b in partitions))


def audit_intervals(core):
    scopes = [(n, f, 3 if n <= 3 or f <= 2 else 2)
              for n in range(1, 5) for f in range(n + 1)]
    scopes.append((5, 2, 2))
    results = []
    for n, f, depth in scopes:
        world, exact = ConcreteWorld(n, f), ConcreteWorld(n, f, exact=True)
        churn_options = range(f + 2)
        counts = Counter()
        visited_ranks = set()

        def compare_rank(history, churn, reachable):
            key = (history, churn)
            if key in visited_ranks:
                return
            visited_ranks.add(key)
            ranks = world.rank_vector(reachable)
            for mask, expected in enumerate(ranks):
                assert core.belief_rank(history, f, churn, mask) == expected, (
                    "rank", n, f, history, churn, mask, expected)
                counts["ranks"] += 1

        def observe(history, churn, unrestricted, full):
            for demand in range(1 << n):
                new_history = history + (demand,)
                small_next = world.admit(unrestricted, demand)
                full_next = exact.admit(full, demand)
                expected = bool(small_next)
                assert bool(full_next) == expected, ("padding", n, f, new_history, churn)
                assert core.interval_feasible(new_history, f, churn) == expected, (
                    "interval", n, f, new_history, churn)
                counts["intervals"] += 1
                counts["padding"] += 1
                if not expected:
                    counts["infeasible_prefixes_pruned"] += 1
                    continue
                for c in churn_options:
                    new_churn = churn + (c,)
                    future = world.advance(small_next, c)
                    padded = exact.advance(full_next, c)
                    assert world.rank_vector(future) == exact.rank_vector(padded), (
                        "padding rank", n, f, new_history, new_churn)
                    compare_rank(new_history, new_churn, future)
                    if len(new_history) < depth:
                        observe(new_history, new_churn, future, padded)

        assert core.interval_feasible((), f, ())
        compare_rank((), (), frozenset(world.states))
        observe((), (), frozenset(world.states), frozenset(exact.states))
        row = {"n": n, "f": f, "max_observed_epochs": depth,
               "churn_values": list(churn_options), **counts}
        results.append(row)
        print("interval/rank", row, flush=True)
    return results


def objective(cohort, costs):
    return sum(costs[identity] for identity in ids(cohort)), cohort.bit_count()


def compare_oracle(core, world, f, histories, churn, first, second,
                   eligible, cap, costs, counts):
    separation = tuple(mask for mask in world.separators(first, second)
                       if mask & eligible == mask and mask.bit_count() <= cap)
    ground = min((objective(mask, costs) for mask in separation), default=None)
    answer = core.minimum_cost_cohort(
        world.n, f, *histories, churn, costs=costs, eligible=eligible, peak=cap)
    if ground is None:
        assert answer is None, ("false separation", world.n, f, histories, churn, eligible, cap)
        counts["oracle_no_cohort"] += 1
    else:
        assert answer is not None and answer.mask in separation, (
            "missed/nonseparating answer", world.n, f, histories, churn, eligible, cap)
        assert (answer.cost, answer.required_count) == ground, (
            "nonminimum answer", world.n, f, histories, churn, eligible, cap, costs)
        counts["oracle_feasible"] += 1
        unrestricted = min(mask.bit_count() for mask in separation)
        counts["weighted_larger_than_minimum_cardinality"] += int(answer.required_count > unrestricted)
    counts["oracle_calls"] += 1


def audit_oracle(core, scheduler):
    exhaustive = [(n, f, 2 if n <= 3 and f < n else 1)
                  for n in range(1, 5) for f in range(n + 1)]
    results = []
    for n, f, depth in exhaustive:
        world = ConcreteWorld(n, f)
        counts = Counter()
        initial = frozenset(world.states)
        labels = tuple((a, b) for a, b in product(range(1 << n), repeat=2)
                       if not a & b and a.bit_count() <= f and b.bit_count() <= f)
        uniform = (1,) * n
        short_weights = ((0,) * n, tuple(index + 1 for index in range(n)),
                         tuple((index * 2 + 1) % n for index in range(n)))

        def visit(positive, negative, churn, first, second):
            histories = (positive, negative)
            counts["signed_history_churn_contexts"] += 1
            counts["with_partial_labels"] += int(any(a | b != world.universe
                                                     for a, b in zip(*histories)))
            compare_oracle(core, world, f, histories, churn, first, second,
                           world.universe, n, uniform, counts)
            if n <= 2:
                restrictions = product(range(1 << n), range(n + 1), short_weights)
            else:
                signature = sum(positive) + 3 * sum(negative) + sum(churn)
                restrictions = ((world.universe, signature % (n + 1), short_weights[1]),
                                (signature % (1 << n), n, short_weights[2]))
            for eligible, cap, costs in restrictions:
                compare_oracle(core, world, f, histories, churn, first, second,
                               eligible, cap, costs, counts)
            if not churn or len(set(churn)) == 1:
                constant = churn[0] if churn else 0
                history = [(set(ids(a)), set(ids(b))) for a, b in zip(*histories)]
                for cap in range(n + 1):
                    cohort = scheduler.terminal_cohort(history, n, f, constant, cap)
                    valid = [mask for mask in world.separators(first, second)
                             if mask.bit_count() <= cap]
                    assert (cohort is None) == (not valid), (
                        "scheduler existence", n, f, histories, churn, cap)
                    if cohort is not None:
                        assert encode(cohort) in valid and len(cohort) == min(
                            mask.bit_count() for mask in valid), (
                                "scheduler cardinality", n, f, histories, churn, cap)
                    counts["unweighted_scheduler_calls"] += 1
            if len(positive) == depth:
                return
            for a, b in labels:
                next_a, next_b = world.admit(first, a), world.admit(second, b)
                if next_a and next_b:
                    for c in range(f + 2):
                        visit(positive + (a,), negative + (b,), churn + (c,),
                              world.advance(next_a, c), world.advance(next_b, c))

        visit((), (), (), initial, initial)
        row = {"n": n, "f": f, "max_observed_epochs": depth, **counts}
        results.append(row)
        print("oracle", row, flush=True)

    rng = random.Random(271126)
    sizes = ((4, 1), (5, 1), (5, 2), (6, 2), (6, 3), (7, 2))
    for n, f in sizes:
        world = ConcreteWorld(n, f)
        counts = Counter()
        initial = frozenset(world.states)
        for _ in range(180):
            length = rng.randint(1, 5)
            churn = tuple(rng.randrange(f + 2) for _ in range(length))
            costs = tuple(rng.choice((0, 1, 2, 7, 23, 101)) for _ in range(n))
            first, second = initial, initial
            pos, neg = [], []
            for limit in churn:
                a_state, b_state = rng.choice(sorted(first)), rng.choice(sorted(second))
                a = rng.choice(subsets(a_state))
                b = rng.choice(subsets(b_state & ~a))
                pos.append(a)
                neg.append(b)
                first = world.advance(world.admit(first, a), limit)
                second = world.advance(world.admit(second, b), limit)
            for eligible, cap in ((world.universe, n),
                                  (world.universe, rng.randrange(n + 1)),
                                  (rng.randrange(1 << n), rng.randrange(n + 1))):
                compare_oracle(core, world, f, (tuple(pos), tuple(neg)), churn, first, second,
                               eligible, cap, costs, counts)
        row = {"n": n, "f": f, "seed": 271126, "sampled_histories": 180, **counts}
        results.append(row)
        print("oracle sample", row, flush=True)
    return results


def feasible_trace(n, f, churn, history):
    """Independent filter that avoids constructing all transition edges at large n."""
    states = tuple(mask for mask in range(1 << n) if mask.bit_count() <= f)
    reachable = states
    for i, demands in enumerate(history):
        candidates = tuple(mask for mask in states if mask & demands == demands)
        reachable = candidates if i == 0 else tuple(mask for mask in candidates
                    if any((mask & ~old).bit_count() <= churn[i - 1] for old in reachable))
        if not reachable:
            return False
    return True


def audit_retained(core, source):
    records = {}
    with (source / "trials_raw.csv").open(newline="", encoding="utf-8-sig") as data:
        for row in csv.DictReader(data):
            key = (row["session"], row["repeat"], row["policy"],
                   row["scenario"], row["batch_size"])
            records[key] = tuple(int(row[field]) for field in ("n", "f", "c"))
    figures = json.loads((source / "adversarial_traces.json").read_text())
    counts = Counter()
    for policy, trace in figures.items():
        first_epoch = trace["epochs"][0]
        n, f, c = records[tuple(str(first_epoch[field]) for field in
                                ("session", "repeat", "policy", "scenario", "batch_size"))]
        labels = [tuple(encode(json.loads(epoch[field])) for field in
                       ("positive_ids", "negative_ids")) for epoch in trace["epochs"]]
        for t, (a, b) in enumerate(labels, start=1):
            cohort = encode(json.loads(trace["epochs"][t - 1]["cohort"]))
            assert a | b == cohort and not a & b, ("malformed retained labels", policy, t)
            churn = (c,) * (t - 1)
            candidates = []
            for bit in (0, 1):
                demands = tuple(epoch[bit] for epoch in labels[:t])
                possible = feasible_trace(n, f, churn, demands)
                assert possible == core.interval_feasible(demands, f, churn), (
                    "trace decision", policy, t, bit)
                if possible:
                    candidates.append(bit)
                counts["retained_bit_prefixes"] += 1
            expected = "ambiguous" if len(candidates) == 2 else str(candidates[0])
            assert expected == str(trace["epochs"][t-1]["decision"]), (
                "recorded decision", policy, t, expected)
            counts["retained_epoch_decisions"] += 1
        for bit, path in trace["fault_paths_by_feasible_bit"].items():
            masks = tuple(encode(row) for row in path)
            assert len(masks) == len(labels)
            assert all(mask.bit_count() <= f and labels[i][int(bit)] & mask == labels[i][int(bit)]
                       for i, mask in enumerate(masks))
            assert all((current & ~previous).bit_count() <= c
                       for previous, current in zip(masks, masks[1:]))
            counts["retained_explicit_paths"] += 1
        counts["retained_traces"] += 1
    return counts


def audit_partial_examples(core):

    f = 0
    assert core.interval_feasible((0,), f, ())
    assert not core.interval_feasible((1,), f, ())

    assert not feasible_trace(1, f, (), (1,))

    gap = (0b0011, 0, 0b1100)
    assert core.interval_feasible(gap, 2, (1, 1)) == feasible_trace(4, 2, (1, 1), gap)
    assert core.interval_feasible(gap, 2, (1, 1))
    assert not core.interval_feasible((gap[0], gap[2]), 2, (1,))
    assert core.interval_feasible((gap[0], gap[2]), 2, (2,))
    def separators(positive, negative, churn):
        world = ConcreteWorld(6, 2)
        first = second = frozenset(world.states)
        for a, b, c in zip(positive, negative, churn):
            first = world.advance(world.admit(first, a), c)
            second = world.advance(world.admit(second, b), c)
        return world.separators(first, second)


    pos, neg, churn = (0, 0b000100), (0b000011, 0), (0, 1)
    weights = (40, 40, 0, 90, 10, 40)
    separated = separators(pos, neg, churn)
    size_first = min(separated, key=lambda mask: (mask.bit_count(), objective(mask, weights)))
    cost_first = core.minimum_cost_cohort(6, 2, pos, neg, churn, costs=weights)
    assert cost_first is not None and cost_first.mask in separated
    assert objective(cost_first.mask, weights) == min(objective(s, weights) for s in separated)
    assert (cost_first.cost, cost_first.required_count) == (130, 5)
    assert objective(size_first, weights) == (140, 4)


    pos, neg, churn = (0b001010, 0b000001, 0b100000), (0b010000, 0b001000, 0), (1, 1, 1)
    costs = (1.6e308, 3.2e307, 1.5e308, 3.2e307, 1.2e307, 1.1e308)
    exact = tuple(Fraction.from_float(cost) for cost in costs)
    separated = separators(pos, neg, churn)
    optimum = min(separated, key=lambda mask: objective(mask, exact))
    answer = core.minimum_cost_cohort(6, 2, pos, neg, churn, costs=costs)
    assert answer is not None and answer.cost == float("inf") and answer.mask in separated
    assert objective(answer.mask, exact) > objective(optimum, exact)
    return {
        "partial_and_gap_examples": 2,
        "weighted_example": {
            "cost_optimum": ids(cost_first.mask), "cost": cost_first.cost,
            "cardinality_optimum": ids(size_first), "its_cost": objective(size_first, weights)[0],
        },
        "floating_sum_overflow_reproduced": True,
        "floating_example": {
            "returned_cohort": ids(answer.mask), "exact_optimum": ids(optimum),
            "returned_cost_in_units_of_1e307": float(objective(answer.mask, exact)[0] / 10**307),
            "optimum_cost_in_units_of_1e307": float(objective(optimum, exact)[0] / 10**307),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, default=ARTIFACT)
    parser.add_argument("--retained-traces", type=Path,
                        help="directory containing trials_raw.csv and adversarial_traces.json")
    parser.add_argument("--output", type=Path, default=HERE / "temporal_checks.json")
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    core = import_source(args.artifact / "temporal_core.py", "audited_temporal_core")
    scheduler = import_source(args.artifact / "optimistic" / "scheduler.py", "audited_scheduler")
    summary = {"audit_kind": "abstract exposure-set enumeration",
               "interval_rank": audit_intervals(core), "oracle": audit_oracle(core, scheduler),
               "boundary": audit_partial_examples(core)}
    if args.retained_traces is not None:
        summary["retained"] = dict(audit_retained(core, args.retained_traces))
    for dataset in ("interval_rank", "oracle"):
        keys = ("intervals", "padding", "ranks") if dataset == "interval_rank" else (
            "oracle_calls", "oracle_no_cohort", "oracle_feasible", "unweighted_scheduler_calls",
            "weighted_larger_than_minimum_cardinality")
        summary[dataset + "_totals"] = {key: sum(row.get(key, 0) for row in summary[dataset])
                                        for key in keys}
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in summary.items()
                      if key.endswith("_totals") or key in ("retained", "boundary")}, indent=2))


if __name__ == "__main__":
    main()
