"""Functional temporal-certification prototype; not a consensus engine.

The independent Sealer is a TRUSTED append-only epoch functionality. ML-DSA
worker signatures alone do not freeze history under later key compromise.
Logical identities in this experiment are not isolated security principals.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from itertools import combinations
from typing import Any

from cryptography.hazmat.primitives import serialization


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def public_bytes(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def private_bytes(key) -> bytes:
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


REPORT_DOMAIN = b"temporal-certification-report/v1\x00"
SEAL_DOMAIN = b"temporal-certification-seal/v1\x00"
LEAF_DOMAIN = b"temporal-certification-leaf/v1\x00"
NODE_DOMAIN = b"temporal-certification-node/v1\x00"
ZERO_HASH = "0" * 64
CONTEXT_FIELDS = {
    "chain_id", "height", "object_digest", "prestate_root", "credential_version",
    "credential_key_digest", "policy_id", "policy_version", "component",
    "implementation_id", "attempt_id", "registry_digest", "n", "f", "c",
}


def validate_context(context: dict):
    if set(context) != CONTEXT_FIELDS:
        raise ValueError("noncanonical context fields")
    if not (0 <= context["c"] < context["f"] < context["n"]):
        raise ValueError("invalid budget")


def validate_registry(registry: dict, context: dict):
    if set(registry) != set(range(context["n"])):
        raise ValueError("registry population mismatch")
    export = {str(i): b64(public_bytes(key)) for i, key in registry.items()}
    if digest(canonical(export)) != context["registry_digest"]:
        raise ValueError("registry digest mismatch")


def report_message(body: dict) -> bytes:
    return REPORT_DOMAIN + canonical(body)


def make_report(key, context: dict, epoch: int, worker: int, result: int) -> dict:
    if result not in (0, 1):
        raise ValueError("nonbinary report")
    body = {"context": context, "epoch": epoch, "worker": worker, "result": result}
    return {"body": body, "signature": b64(key.sign(report_message(body)))}


def verify_report(report: dict, registry: dict, context: dict, epoch: int, cohort: list):
    if set(report) != {"body", "signature"}:
        raise ValueError("bad report envelope")
    body = report["body"]
    if set(body) != {"context", "epoch", "worker", "result"}:
        raise ValueError("bad report fields")
    if canonical(body["context"]) != canonical(context) or type(body["epoch"]) is not int or body["epoch"] != epoch:
        raise ValueError("stale or replayed report")
    if body["worker"] not in cohort or body["worker"] not in registry:
        raise ValueError("ineligible reporter")
    if type(body["result"]) is not int or body["result"] not in (0, 1):
        raise ValueError("invalid result")
    registry[body["worker"]].verify(unb64(report["signature"]), report_message(body))


def leaf(report: dict) -> bytes:
    return hashlib.sha256(LEAF_DOMAIN + canonical(report)).digest()


def merkle_levels(reports: list) -> list:
    if not reports:
        return [[hashlib.sha256(LEAF_DOMAIN).digest()]]
    levels = [[leaf(r) for r in reports]]
    while len(levels[-1]) > 1:
        old = levels[-1]
        levels.append([
            hashlib.sha256(NODE_DOMAIN + old[i] + old[min(i + 1, len(old) - 1)]).digest()
            for i in range(0, len(old), 2)
        ])
    return levels


def merkle_proof(reports: list, index: int) -> list[str]:
    if not 0 <= index < len(reports):
        raise ValueError("bad Merkle index")
    levels = merkle_levels(reports)
    proof = []
    for level in levels[:-1]:
        proof.append(level[min(index ^ 1, len(level) - 1)].hex())
        index //= 2
    return proof


def verify_membership(report: dict, index: int, count: int, proof: list, root: str):
    if not 0 <= index < count or count <= 0:
        raise ValueError("invalid Merkle index")
    h, width, position, k = leaf(report), count, index, 0
    while width > 1:
        if k >= len(proof):
            raise ValueError("short Merkle path")
        sibling = bytes.fromhex(proof[k])
        if len(sibling) != 32:
            raise ValueError("bad Merkle sibling")
        if position == width - 1 and width % 2 and sibling != h:
            raise ValueError("bad duplicate Merkle sibling")
        left, right = (sibling, h) if position % 2 else (h, sibling)
        h = hashlib.sha256(NODE_DOMAIN + left + right).digest()
        position //= 2
        width = (width + 1) // 2
        k += 1
    if k != len(proof) or h.hex() != root:
        raise ValueError("Merkle commitment mismatch")


def feasible(history: list[set[int]], f: int, c: int) -> bool:
    for a in range(len(history)):
        union = set()
        for b in range(a, len(history)):
            union.update(history[b])
            if len(union) > f + c * (b - a):
                return False
    return True


def decision(history: list[tuple[set[int], set[int]]], f: int, c: int):
    valid = [bit for bit in (0, 1) if feasible([pair[bit] for pair in history], f, c)]
    if not valid:
        raise ValueError("fault model violated")
    return valid[0] if len(valid) == 1 else None


def observation(cohort: list, reports: list) -> tuple[set[int], set[int]]:


    positive = {r["body"]["worker"] for r in reports if r["body"]["result"] == 1}
    return positive, set(cohort) - positive


class Sealer:
    """Ideal trusted epoch-closure authority, independent of worker keys.

    Refuses alternate closures and late additions; keeps monotonic state in RAM.
    Crash persistence, key protection, BFT implementation and key recovery are
    outside this prototype. This functionality is an ASSUMPTION, not a finding.
    """

    def __init__(self, key, registry: dict, context: dict):
        validate_context(context)
        validate_registry(registry, context)
        self.key, self.registry, self.context = key, registry, context
        self.next_epoch, self.previous = 1, ZERO_HASH

    def close(self, epoch: int, cohort: list, reports: list) -> dict:
        if epoch != self.next_epoch:
            raise ValueError("epoch already closed or out of order")
        if cohort != sorted(set(cohort)) or not set(cohort) <= self.registry.keys():
            raise ValueError("noncanonical cohort")
        ordered = sorted(reports, key=lambda r: r["body"]["worker"])
        seen = set()
        for report in ordered:
            verify_report(report, self.registry, self.context, epoch, cohort)
            worker = report["body"]["worker"]
            if worker in seen:
                raise ValueError("duplicate/equivocating report")
            seen.add(worker)
        body = {
            "context": self.context, "epoch": epoch, "cohort": cohort,
            "report_count": len(ordered), "merkle_root": merkle_levels(ordered)[-1][0].hex(),
            "previous_seal": self.previous,
        }
        header = {"body": body, "signature": b64(self.key.sign(SEAL_DOMAIN + canonical(body)))}
        self.previous = digest(canonical(header))
        self.next_epoch += 1
        return {"header": header, "reports": ordered}


def verify_headers(headers: list, sealer_public, context: dict, registry: dict):
    validate_context(context)
    validate_registry(registry, context)
    if not headers:
        raise ValueError("empty seal chain")
    previous = ZERO_HASH
    for epoch, header in enumerate(headers, 1):
        if set(header) != {"body", "signature"}:
            raise ValueError("bad seal envelope")
        body = header["body"]
        if set(body) != {"context", "epoch", "cohort", "report_count", "merkle_root", "previous_seal"}:
            raise ValueError("bad seal fields")
        if canonical(body["context"]) != canonical(context) or type(body["epoch"]) is not int or body["epoch"] != epoch or body["previous_seal"] != previous:
            raise ValueError("stale context or broken seal chain")
        cohort = body["cohort"]
        if cohort != sorted(set(cohort)) or not set(cohort) <= registry.keys():
            raise ValueError("bad sealed cohort")
        if not 0 <= body["report_count"] <= len(cohort):
            raise ValueError("bad report count")
        sealer_public.verify(unb64(header["signature"]), SEAL_DOMAIN + canonical(body))
        previous = digest(canonical(header))


def verify_full(certificate: dict, registry: dict, sealer_public, context: dict):
    if set(certificate) != {"format", "epochs"} or certificate["format"] != "full-v1":
        raise ValueError("bad full format")
    epochs = certificate["epochs"]
    verify_headers([epoch["header"] for epoch in epochs], sealer_public, context, registry)
    history = []
    for epoch in epochs:
        if set(epoch) != {"header", "reports"}:
            raise ValueError("bad epoch fields")
        body, reports = epoch["header"]["body"], epoch["reports"]
        ids = [r["body"]["worker"] for r in reports]
        if ids != sorted(set(ids)) or len(reports) != body["report_count"]:
            raise ValueError("duplicate, unsorted or missing committed report")
        if merkle_levels(reports)[-1][0].hex() != body["merkle_root"]:
            raise ValueError("modified sealed reports")
        for report in reports:
            verify_report(report, registry, context, body["epoch"], body["cohort"])
        history.append(observation(body["cohort"], reports))
    return decision(history, context["f"], context["c"])


def compact_positive(certificate: dict, f: int, c: int) -> dict:
    epochs = certificate["epochs"]


    for span in range(len(epochs)):
        for start in range(len(epochs) - span):
            end = start + span
            candidates = {}
            for e in range(start, end + 1):
                for index, report in enumerate(epochs[e]["reports"]):
                    if report["body"]["result"] == 1:
                        candidates.setdefault(report["body"]["worker"], (e, index, report))
            q = f + c * span + 1
            if len(candidates) >= q:
                witnesses = []
                for worker in sorted(candidates)[:q]:
                    e, index, report = candidates[worker]
                    witnesses.append({"report": report, "index": index,
                                      "proof": merkle_proof(epochs[e]["reports"], index)})
                return {"format": "positive-merkle-v1", "interval": [start + 1, end + 1],
                        "headers": [e["header"] for e in epochs[:end + 1]], "witnesses": witnesses}
    raise ValueError("no positive certificate")


def verify_positive(certificate: dict, registry: dict, sealer_public, context: dict) -> bool:
    if set(certificate) != {"format", "interval", "headers", "witnesses"} or certificate["format"] != "positive-merkle-v1":
        raise ValueError("bad positive format")
    headers = certificate["headers"]
    verify_headers(headers, sealer_public, context, registry)
    start, end = certificate["interval"]
    if not 1 <= start <= end == len(headers):
        raise ValueError("bad witness interval")
    seen = set()
    for item in certificate["witnesses"]:
        if set(item) != {"report", "index", "proof"}:
            raise ValueError("bad witness fields")
        report, body = item["report"], item["report"]["body"]
        epoch, worker = body["epoch"], body["worker"]
        if not start <= epoch <= end or body["result"] != 1 or worker in seen:
            raise ValueError("nonpositive or repeated witness identity")
        header = headers[epoch - 1]["body"]
        verify_report(report, registry, context, epoch, header["cohort"])
        verify_membership(report, item["index"], header["report_count"], item["proof"], header["merkle_root"])
        seen.add(worker)
    if len(seen) <= context["f"] + context["c"] * (end - start):
        raise ValueError("insufficient distinct positive identities")
    return True


POLICIES = ["direct_majority", "uniform_replication", "one_epoch_budget", "fixed_committee",
            "fixed_rotation", "adaptive_four_original", "adaptive_four_disjoint", "adaptive_two"]


def next_cohort(
    policy: str, history: list, n: int, f: int, c: int, admission_cap: int | None = None
) -> list | None:
    population = set(range(n))
    t, h = len(history), f + c
    capacity = h + 1
    if policy == "direct_majority":
        return list(range(2 * f + 1)) if t == 0 else None
    if policy == "uniform_replication":
        return list(range(n)) if t == 0 else None
    if policy == "one_epoch_budget":
        return list(range(capacity)) if t == 0 else None
    if policy == "fixed_committee":
        return list(range(capacity)) if t < 4 else None
    if policy == "fixed_rotation":
        return sorted((t * capacity + i) % n for i in range(capacity)) if t < 4 else None
    if policy == "adaptive_two":
        minimum_cap = (4 * f + 2 * c) // 3 + 1
        s = minimum_cap if admission_cap is None else admission_cap
        if not (2 * f + c < n <= 2 * f + 2 * c and minimum_cap <= s <= 2 * f):
            raise ValueError("Two-epoch work specialization outside its proven region")
        a = 2 * (2 * f + c + 1 - s) - 1
        assert 1 <= a <= s
        if t == 0:
            return list(range(a))
        if t == 1:
            larger = max(history[0], key=lambda x: (len(x), tuple(sorted(x))))
            k = 2 * f + c - len(larger) + 1
            assert 0 < k <= min(s, n - len(larger))
            return sorted(population - larger)[:k]
        return None
    if policy == "adaptive_four_work":



        assert f >= c + 5
        m, s = f + c - 2, f + c + 1
        if t == 0:
            return list(range(m))
        if t == 1:
            return list(range(m, 2 * m + 1))
        if t == 2:
            unions = [history[0][bit] | history[1][bit] for bit in (0, 1)]
            larger = max(unions, key=lambda x: (len(x), tuple(sorted(x))))
            return sorted(population - larger)[:s]
        if t == 3:
            larger = max(history[-1], key=lambda x: (len(x), tuple(sorted(x))))
            k = 2 * f + c + 1 - len(larger)
            assert k <= s and k <= n - len(larger)
            return sorted(population - larger)[:k]
        return None
    if policy not in ("adaptive_four_original", "adaptive_four_disjoint"):
        raise ValueError(policy)
    first_size = capacity if policy.endswith("original") else h
    if t == 0:
        return list(range(first_size))
    if t == 1:
        return sorted((population - set(range(first_size))) | (set(range(2)) if first_size == capacity else set()))
    if t == 2:
        union = history[0][0] | history[1][0]
        complement = history[0][1] | history[1][1]
        assert len(union) == len(complement) == h and not union & complement
        return sorted(population - union)
    if t == 3:
        assert len(history[2][1]) == f
        return sorted(population - history[2][1])[:capacity]
    return None


def targeted_positive(policy: str, epoch: int, cohort: list, n: int, f: int, c: int) -> set:
    """Policy-specific feasible traces; not one shared adaptive adversary.

    Four-round traces reproduce population saturation. Other bounded policies
    get a stable balanced coloring. One-shot robust policies get f negatives.
    Every realized history is checked and optionally gets a concrete fault path.
    """
    S, h = set(cohort), f + c
    if policy in ("direct_majority", "uniform_replication"):
        return S - set(sorted(S)[:f])
    if policy == "adaptive_four_original":
        s, a = h + 1, (h + 1) // 2
        a1 = {0} | set(range(2, 2 + a - 1))
        union = a1 | set(range(s, s + h - a))
        if epoch <= 2:
            return S & union
        if epoch == 3:
            return set(sorted(S)[:c])
        return S
    if policy == "adaptive_four_disjoint":
        a = h // 2
        union = set(range(a)) | set(range(h, h + h - a))
        if epoch <= 2:
            return S & union
        if epoch == 3:
            return set(sorted(S)[:c])
        return S
    if policy == "adaptive_two":
        if epoch == 1:
            return set(sorted(S)[:len(S) // 2])


        s = (4 * f + 2 * c) // 3 + 1
        a = 2 * (2 * f + c + 1 - s) - 1
        negative_count = f - ((a + 1) // 2) + c
        return S - set(sorted(S)[:negative_count])
    if policy == "adaptive_four_work":
        m = f + c - 2
        a = (m + 1) // 2
        union = set(range(a)) | set(range(m, m + m + 1 - a))
        if epoch <= 2:
            return S & union
        if epoch == 3:
            return S - set(sorted(S)[:f])
        return S
    return S & set(range(0, n, 2))


def concrete_fault_path(mismatches: list[set[int]], n: int, f: int, c: int) -> list[list[int]]:
    """Independent finite-state check, used only at the small measured n.

    Builds actual size-f fault sets containing mismatches, with <=c new IDs.
    Unlike the interval predicate this explicitly explores concrete states.
    """
    states = [frozenset(s) for s in combinations(range(n), f)]
    front = {s: [s] for s in states if mismatches[0] <= s}
    for required in mismatches[1:]:
        new = {}
        for s in states:
            if not required <= s:
                continue
            for previous, path in front.items():
                if len(s - previous) <= c:
                    new[s] = path + [s]
                    break
        front = new
        if not front:
            raise ValueError("no concrete fault path")
    return [sorted(s) for s in next(iter(front.values()))]
