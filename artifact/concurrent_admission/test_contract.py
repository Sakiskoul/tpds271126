from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import tempfile
import time

from contract import Control, launch, rpc
from ossl import Key, version
from protocol import b64, canonical, digest, make_report, unb64, verify_headers


def run(output):
    passes, processes = [], []

    def check(name, result):
        assert result, name
        passes.append(name)

    def start(kind, *args):
        p, addr, pub = launch(kind, *args)
        processes.append(p)
        return p, addr, pub

    def stop(proc):
        proc.terminate()
        proc.join(3)
        assert not proc.is_alive()

    n, f, c = 14, 6, 1
    keys = [Key.generate() for _ in range(n)]
    registry = {str(i): b64(key.public_bytes()) for i, key in enumerate(keys)}
    tx = Key.generate("ML-DSA-65")
    payload = b"concurrent admission regression"
    batch = [[b64(payload), b64(tx.sign(payload))]]
    base = dict(chain_id="test", height=1, prestate_root="1" * 64, credential_version=1,
                credential_key_digest=digest(tx.public_bytes()), policy_id="all-ML-DSA-65", policy_version=1,
                component="batch", implementation_id="OpenSSL-EVP", registry_digest=digest(canonical(registry)),
                n=n, f=f, c=c, object_digest=digest(canonical(batch)))
    secret = os.urandom(32)
    with tempfile.TemporaryDirectory(prefix="otbc-contract-test-") as temp:
        try:
            db = Path(temp)
            auth_args = (db / "authority.db", registry, secret, 1000, f, c, True)
            a_process, address, seal_key = start("authority", *auth_args)
            ctl = Control(address, secret)
            alice, bob = [dict(base, attempt_id=x) for x in ("a", "b")]

            def register(ctx):
                return ctl.send(op="register", context=ctx, policy="O-TBC")[0]

            check("unauthenticated control", not Control(address, os.urandom(32)).send(
                op="register", context=alice, policy="O-TBC")[0]["ok"])
            check("untrusted parameters", not register(dict(alice, f=f-1, c=c+1))["ok"])
            with ThreadPoolExecutor(max_workers=2) as pool:
                a, b = list(pool.map(register, [alice, bob]))
            check("independent concurrent attempts", a["cid"] != b["cid"] and a["cap"] == b["cap"] == 8)
            check("attempt substitution", not register(dict(alice, prestate_root="2" * 64))["ok"])
            ca, cb = a["cid"], b["cid"]
            check("oversized cohort", not ctl.send(op="open", cid=ca, epoch=1, plan=list(range(9)))[0]["ok"])
            with ThreadPoolExecutor(max_workers=2) as pool:
                same = list(pool.map(lambda _: ctl.send(op="open", cid=ca, epoch=1, plan=[0])[0], range(2)))
            check("atomic epoch open", sum(x["ok"] for x in same) == 1)
            opened_b, _ = ctl.call(op="open", cid=cb, epoch=1, plan=list(range(8)))
            check("out-of-cohort authorization", not ctl.send(op="admit", cid=ca, epoch=1, worker=1)[0]["ok"])
            with ThreadPoolExecutor(max_workers=2) as pool:
                same = list(pool.map(lambda _: ctl.send(op="admit", cid=ca, epoch=1, worker=0)[0], range(2)))
            check("atomic ticket issuance", sum(x["ok"] for x in same) == 1)
            ticket = next(x["ticket"] for x in same if x["ok"])
            worker_args = (0, db / "worker.db", keys[0], address, seal_key, tx.public_bytes(), True)
            w_process, worker, _ = start("worker", *worker_args)
            _, other_worker, _ = start("worker", 1, db / "other.db", keys[1], address,
                                        seal_key, tx.public_bytes(), True)
            request = dict(context=alice, epoch=1, batch=batch, ticket=ticket, override=None)
            bad = bytearray(unb64(ticket["signature"]))
            bad[0] ^= 1
            check("invalid ticket authenticator", not rpc(worker, dict(
                request, ticket=dict(ticket, signature=b64(bad))))[0]["ok"])
            check("out-of-cohort execution", not rpc(other_worker, request)[0]["ok"])
            check("cross-attempt ticket reuse", not rpc(worker, dict(request, context=bob))[0]["ok"])
            check("cross-epoch ticket reuse", not rpc(worker, dict(request, epoch=2))[0]["ok"])
            unexpected = dict(op="report", cid=ca, epoch=1, report=make_report(keys[1], alice, 1, 1, 1))
            check("signed report without admission", not rpc(address, unexpected)[0]["ok"])
            executed, _ = rpc(worker, request)
            check("valid gate and task", executed["ok"] and executed["checks"] == 1 and executed["timely"])
            check("replayed worker execution", not rpc(worker, request)[0]["ok"])
            stop(w_process)
            _, worker, _ = start("worker", *worker_args)
            check("durable worker replay prevention", not rpc(worker, request)[0]["ok"])
            closed, _ = ctl.call(op="finish", cid=ca, epoch=1, started=[0])
            ticket_b, _ = ctl.call(op="admit", cid=cb, epoch=1, worker=0)
            stop(a_process)
            _, current, current_key = start("authority", *auth_args)
            ctl = Control(current, secret)
            stored, _ = ctl.call(op="get", cid=ca, epoch=1)
            check("authority key and sealed evidence survive restart",
                  current_key == seal_key and closed["reason"] == "complete" and {k: v for k, v in closed.items() if k != "ok"} == stored["closed"])
            verify_headers([closed["entry"]["header"]], Key.from_der(seal_key), alice,
                           {i: key.public_key() for i, key in enumerate(keys)})
            check("duplicate admission rejected after authority restart", not ctl.send(
                op="admit", cid=cb, epoch=1, worker=0)[0]["ok"])
            time.sleep(max(0, (opened_b["deadline"] - time.monotonic_ns()) / 1e9) + .04)
            stored, _ = ctl.call(op="get", cid=cb, epoch=1)
            check("original cutoff closes disconnected worker epoch", stored["closed"]["reason"] == "deadline"
                  and stored["closed"]["entry"]["reports"] == []
                  and stored["closed"]["entry"]["header"]["body"]["cohort"] == [0])
            check("expired admission", not rpc(worker, dict(request, context=bob, ticket=ticket_b["ticket"]))[0]["ok"])
            late, _ = rpc(current, dict(op="report", cid=cb, epoch=1, report=make_report(keys[0], bob, 1, 0, 1)))
            check("late report excluded", not late.get("timely", False))
        finally:
            for proc in processes:
                if proc.is_alive():
                    stop(proc)
    Path(output).write_text(json.dumps(dict(passed=len(passes), checks=passes,
                                           openssl=version(0).decode()), indent=2) + "\n")
    print(f"{len(passes)} admission checks passed")


if __name__ == "__main__":
    run(sys.argv[1])
