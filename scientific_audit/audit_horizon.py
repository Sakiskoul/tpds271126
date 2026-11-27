"""Independent finite audit for the binary certification game.

The game state uses concrete size-f exposure sets in both hypotheses. Exposure
transitions are enumerated directly. No interval criterion, rank formula, or
scheduling implementation from the manuscript is imported by this solver.
"""

import argparse
import json
from collections import Counter
from functools import lru_cache
from itertools import combinations, product
from pathlib import Path
from time import perf_counter


def bits(mask):
    while mask:
        bit = mask & -mask
        yield bit.bit_length() - 1
        mask ^= bit


def masks(size, available):
    for indices in combinations(available, size):
        yield sum(1 << index for index in indices)


def submasks(mask):
    value = mask
    while True:
        yield value
        if not value:
            return
        value = (value - 1) & mask


def cardinality(mask):
    return bin(mask).count("1")


def column_mask(columns, epoch, label, base=3):
    place = base ** epoch
    return sum(
        1 << index
        for index, code in enumerate(columns)
        if (code // place) % base == label
    )


def append_columns(columns, cohort, positives):
    """Identify histories by their multiset of ordered per-identity labels."""
    return tuple(sorted(
        3 * code + (1 if positives & (1 << index) else 2 if cohort & (1 << index) else 0)
        for index, code in enumerate(columns)
    ))


def groups_of(columns, eligible):
    groups = {}
    for index in bits(eligible):
        groups.setdefault(columns[index], []).append(index)
    return tuple(groups.values())


def prefix_masks(group):
    out = [0]
    for index in group:
        out.append(out[-1] | (1 << index))
    return out


def size_vectors(group_sizes, total):
    if not group_sizes:
        if total == 0:
            yield ()
        return
    first, rest = group_sizes[0], group_sizes[1:]
    for count in range(max(0, total - sum(rest)), min(total, first) + 1):
        for tail in size_vectors(rest, total - count):
            yield (count, *tail)


def cohorts(columns, available, size):
    groups = groups_of(columns, available)
    prefixes = [prefix_masks(group) for group in groups]
    for sizes in size_vectors(tuple(map(len, groups)), size):
        yield sum(prefix[count] for prefix, count in zip(prefixes, sizes))


class ExposureGame:
    def __init__(self, n, f, c):
        self.n, self.f, self.c = n, f, c
        self.initial = (0,) * n
        self.population = (1 << n) - 1
        identities = tuple(range(n))
        self.exposures = tuple(masks(f, identities))
        self.every_exposure = (1 << len(self.exposures)) - 1
        number = {mask: index for index, mask in enumerate(self.exposures)}
        self.adjacent = []
        self.contains = [0] * (1 << n)
        self.stats = Counter()
        for index, current in enumerate(self.exposures):
            identifier = 1 << index
            for required in submasks(current):
                self.contains[required] |= identifier
            successors = identifier
            outside = tuple(bits(self.population ^ current))
            inside = tuple(bits(current))
            for movement in range(1, min(c, f, len(outside)) + 1):
                incoming = tuple(masks(movement, outside))
                for leaving in masks(movement, inside):
                    retained = current ^ leaving
                    for arrived in incoming:
                        successors |= 1 << number[retained | arrived]
            self.adjacent.append(successors)

    @lru_cache(maxsize=65536)
    def advance(self, family):
        self.stats["concrete_family_transitions"] += 1
        result = 0
        for index in bits(family):
            result |= self.adjacent[index]
            if result == self.every_exposure:
                break
        return result

    @lru_cache(maxsize=65536)
    def before(self, columns, elapsed):
        """Two concrete possible-set families immediately before the next observation."""
        zero = one = self.every_exposure
        for epoch in reversed(range(elapsed)):
            positive = column_mask(columns, epoch, 1)
            negative = column_mask(columns, epoch, 2)
            zero = self.advance(zero & self.contains[positive])
            one = self.advance(one & self.contains[negative])
        return zero, one

    def ambiguous_replies(self, columns, elapsed, cohort):
        zero, one = self.before(columns, elapsed)
        prefixes = [prefix_masks(group) for group in groups_of(columns, cohort)]
        for selected in product(*prefixes):
            self.stats["response_patterns_checked"] += 1
            positives = sum(selected)
            if zero & self.contains[positives] and one & self.contains[cohort ^ positives]:
                yield positives

    @lru_cache(maxsize=65536)
    def terminal(self, columns, elapsed, cap):
        self.stats["terminal_states"] += 1
        for size in range(1, cap + 1):
            for cohort in cohorts(columns, self.population, size):
                self.stats["terminal_cohorts"] += 1
                if next(self.ambiguous_replies(columns, elapsed, cohort), None) is None:
                    return cohort
        return None

    def check_unbounded_cover(self, cap):
        """Check the disjoint-pair invariant with literal successors."""
        first = (1 << self.f) - 1
        second = first << self.f
        owner_columns = (0,) * self.f + (1,) * self.f + (2,) * (self.n - 2*self.f)
        left_successors = self.adjacent[self.exposures.index(first)]
        right_successors = self.adjacent[self.exposures.index(second)]
        covers = {
            self.exposures[i] | self.exposures[j]
            for i in bits(left_successors) for j in bits(right_successors)
            if not self.exposures[i] & self.exposures[j]
        }
        branches = 0
        for query in cohorts(owner_columns, self.population, cap):
            branches += 1
            assert any(not query & ~union for union in covers), (cap, query)
        return branches

    @lru_cache(maxsize=65536)
    def can_win(self, columns, elapsed, remaining, cap):
        """Horizon minimax. Padding to cap is valid since replies can be ignored."""
        self.stats["horizon_states"] += 1
        for cohort in cohorts(columns, self.population, cap):
            self.stats["horizon_cohorts"] += 1
            for positives in self.ambiguous_replies(columns, elapsed, cohort):
                if remaining == 1 or not self.can_win(
                    append_columns(columns, cohort, positives), elapsed + 1, remaining - 1, cap
                ):
                    break
            else:
                return True
        return False

    @lru_cache(maxsize=65536)
    def within_work(self, columns, elapsed, remaining, cap, work):
        """A literal-state minimax decision search allowing all cohort sizes."""
        self.stats["work_states"] += 1
        if remaining == 1:
            return work > 0 and self.can_win(columns, elapsed, 1, min(cap, work))
        if work >= cap * remaining:
            return self.can_win(columns, elapsed, remaining, cap)
        if elapsed and not self.can_win(columns, elapsed, remaining, cap):
            return False
        for size in range(1, min(cap, work) + 1):
            for cohort in cohorts(columns, self.population, size):
                for positives in self.ambiguous_replies(columns, elapsed, cohort):
                    if size == work or not self.within_work(
                        append_columns(columns, cohort, positives),
                        elapsed + 1, remaining - 1, cap, work - size
                    ):
                        break
                else:
                    return True
        return False

    @lru_cache(maxsize=65536)
    def fallback_choices(self, columns, elapsed, policy, d):
        h = self.f + self.c
        cap = h + d
        if policy.startswith("optimistic"):
            if policy == "optimistic" and elapsed:

                terminal = self.terminal(columns, elapsed, cap)
                if terminal is not None:
                    return (terminal,)
            if elapsed <= 1:
                available = self.population if elapsed == 0 else column_mask(columns, 0, 0)
                return tuple(cohorts(columns, available, h))
            if elapsed == 2:
                positive_union = column_mask(columns, 1, 1) | column_mask(columns, 0, 1)
                negative_union = column_mask(columns, 1, 2) | column_mask(columns, 0, 2)
                assert cardinality(positive_union) == cardinality(negative_union) == h
                assert not positive_union & negative_union
                return (self.population ^ positive_union,)
            if elapsed == 3:
                negative = column_mask(columns, 0, 2)
                assert cardinality(negative) == self.f
                return tuple(cohorts(columns, self.population ^ negative, cap))
        if elapsed <= 1:
            available = self.population if elapsed == 0 else column_mask(columns, 0, 0)
            return tuple(cohorts(columns, available, h - 2*d + elapsed))
        if elapsed == 2:
            positive = column_mask(columns, 0, 1) | column_mask(columns, 1, 1)
            negative = column_mask(columns, 0, 2) | column_mask(columns, 1, 2)
        else:
            positive = column_mask(columns, 0, 1)
            negative = column_mask(columns, 0, 2)
        largest = max(cardinality(positive), cardinality(negative))
        choices = []
        for excluded in (positive, negative):
            if cardinality(excluded) == largest:
                available = self.population ^ excluded
                size = min(cap, cardinality(available)) if elapsed == 2 else 2*self.f+self.c+1-largest
                assert 1 <= size <= min(cap, cardinality(available))
                choices.extend(cohorts(columns, available, size))
        return tuple(dict.fromkeys(choices))

    @lru_cache(maxsize=65536)
    def check_policy(self, columns, elapsed, policy, d):
        """Verify all tie and reply classes allowed by a paper schedule."""
        self.stats["policy_states"] += 1
        assert elapsed <= 3, (policy, columns, elapsed)
        max_work = max_epochs = max_repeats = 0
        work_witness = ()
        cap = self.f + self.c + d
        for query in self.fallback_choices(columns, elapsed, policy, d):
            self.stats["policy_cohorts"] += 1
            size = cardinality(query)
            assert 1 <= size <= cap
            polled_before = sum(1 << index for index, code in enumerate(columns) if code)
            repeated = cardinality(query & polled_before)

            max_epochs = max(max_epochs, 1)
            max_repeats = max(max_repeats, repeated)
            if size > max_work:
                max_work, work_witness = size, ({"size": size, "last": True},)
            for positives in self.ambiguous_replies(columns, elapsed, query):
                child, epochs, repeats, witness = self.check_policy(
                    append_columns(columns, query, positives), elapsed + 1, policy, d
                )
                max_epochs = max(max_epochs, 1 + epochs)
                max_repeats = max(max_repeats, repeated + repeats)
                if size + child > max_work:
                    max_work = size + child
                    work_witness = ({"size": size, "positives": cardinality(positives)}, *witness)
        assert max_work
        return max_work, max_epochs, max_repeats, work_witness

    def release_caches(self):
        for function in (self.advance, self.before, self.terminal, self.can_win,
                         self.within_work, self.fallback_choices, self.check_policy):
            function.cache_clear()


class FixedSchedules:
    """Concrete ordered fault-set pairs, without a doubled-set reduction."""
    def __init__(self, game):
        self.game = game
        count = len(game.exposures)
        self.cover = [0] * (1 << game.n)
        self.pair_adjacency = []
        for i, first in enumerate(game.exposures):
            first_successors = [row * count for row in bits(game.adjacent[i])]
            for j, second in enumerate(game.exposures):
                next_pair = sum(game.adjacent[j] << offset for offset in first_successors)
                self.pair_adjacency.append(next_pair)
                for query in submasks(first | second):
                    self.cover[query] |= 1 << (i*count + j)
        self.all_pairs = (1 << (count * count)) - 1
        self.transitions = 0

    @lru_cache(maxsize=8192)
    def advance(self, current):
        self.transitions += 1
        result = 0
        for pair in bits(current):
            result |= self.pair_adjacency[pair]
            if result == self.all_pairs:
                break
        return result

    def allowed(self, columns, length):
        initial = self.all_pairs
        for epoch in reversed(range(length)):
            current = initial & self.cover[column_mask(columns, epoch, 1, base=2)]
            if not current:
                return False
            if epoch:
                initial = self.advance(current)
        return True

    def verify(self, cap, horizon):
        schedules = {self.game.initial}
        counts = []
        for length in range(1, horizon + 1):
            schedules = {
                tuple(sorted(2*code + int(bool(cohort & (1 << index)))
                             for index, code in enumerate(prefix)))
                for prefix in schedules
                for cohort in cohorts(prefix, self.game.population, cap)
            }
            for columns in schedules:
                assert self.allowed(columns, length), (cap, length, columns)
            counts.append(len(schedules))
        assert not self.cover[(1 << (2*self.game.f + 1)) - 1]
        return counts


def frontier(f, c):
    return (2*f+1, (4*f+2*c)//3+1, (6*f+4*c)//5+1, f+c+1)


def verify_horizon(game):
    cases = []
    invariant_cap = game.f + game.c
    for horizon, expected in enumerate(frontier(game.f, game.c), start=1):
        for cap in (expected-1, expected):
            if cap == invariant_cap:
                actual, method = False, "concrete disjoint-pair invariant"
            elif horizon == 4 and cap == expected:
                _, epochs, _, _ = game.check_policy(game.initial, 0, "optimistic_fallback", 1)
                actual, method = epochs <= 4, "concrete verification of a constructive policy"
            else:
                actual = game.can_win(game.initial, 0, horizon, cap)
                method = "concrete minimax"
            assert actual == (cap == expected), (game.n, game.f, game.c, horizon, cap, actual)
            cases.append(dict(horizon=horizon, cap=cap, feasible=actual, method=method))
    return cases


def record_scopes(scopes, include_work):
    summary = []
    for f, c in scopes:
        started = perf_counter()
        game = ExposureGame(2*(f+c), f, c)
        result = dict(n=game.n, f=f, c=c, padded_states=len(game.exposures))
        result["unbounded_cover"] = dict(
            cap=f+c, query_orbits=game.check_unbounded_cover(f+c),
            state_orbits=1, state="disjoint size-f exposure sets for the two worlds"
        )
        result["frontier_checks"] = verify_horizon(game)
        calculations = {}
        for policy in ("optimistic", "optimistic_fallback"):
            work, epochs, repeated, witness = game.check_policy(game.initial, 0, policy, 1)
            assert work <= 4*(f+c)+1 and epochs <= 4
            if f >= c+5:
                assert epochs == 4
            calculations[policy] = dict(max_work=work, max_epochs=epochs,
                                        max_repeated_jobs=repeated, work_witness=witness)
        for d in range(1, (f-c)//5 + 1):
            work, epochs, repeated, witness = game.check_policy(game.initial, 0, "L4", d)
            assert work <= 4*(f+c)+1-2*d and epochs == 4
            calculations[f"L4_d{d}"] = dict(max_work=work, max_epochs=epochs,
                                           max_repeated_jobs=repeated, work_witness=witness)
        if include_work and (f, c) == (6, 1):
            cases = {}
            for work in (26, 27):
                possible = game.within_work(game.initial, 0, 4, 8, work)
                assert possible == (work == 27)
                cases[work] = possible
            result["four_round_work_budget"] = cases
        if (f, c) in ((2, 1), (3, 1)):
            fixed = FixedSchedules(game)
            result["fixed_schedule_checks"] = dict(
                cap=2*f, distinct_patterns_by_horizon=fixed.verify(2*f, 4 if f == 2 else 3),
                pair_family_transitions=fixed.transitions
            )
            fixed.advance.cache_clear()
        result["policy_checks"] = calculations
        result["search_counts"] = dict(game.stats)
        result["elapsed_seconds"] = round(perf_counter() - started, 3)
        game.release_caches()
        print(json.dumps(result, sort_keys=True), flush=True)
        summary.append(result)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("horizon_checks.json"))
    parser.add_argument("--full", action="store_true", help="also test n=14, f=6, c=1")
    parser.add_argument("--work", action="store_true", help="also run the n=14 four-epoch work minimax")
    args = parser.parse_args()
    if args.work and not args.full:
        parser.error("--work requires --full")
    scopes = [(2, 1), (3, 1), (3, 2), (4, 1), (4, 2)]
    if args.full:
        scopes += [(5, 1), (6, 1)]
    payload = dict(model="Explicit transitions of concrete size-f exposure sets, binary complete labels",
                   symmetry="Permute identities within identical observed-label history columns",
                   checks=record_scopes(scopes, args.work))
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
