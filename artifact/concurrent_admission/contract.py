import ctypes as ct
import hashlib
import hmac
import json
import multiprocessing as mp
import os
from pathlib import Path
import socketserver
import sqlite3
import struct
import sys
import time

SNAPSHOT = Path(__file__).resolve().parents[2] / "review_runs/admission_source/snapshot"
sys.path.insert(0, str(SNAPSHOT))
from deploy import recv, rpc
from ossl import Key, fn, P, I
from protocol import (
    Sealer, ZERO_HASH, b64, canonical, digest, make_report,
    unb64, validate_context, validate_registry, verify_report,
)

TICKET_DOMAIN = b"otbc-admission/2026\x00"
ENCODE_KEY = fn("i2d_PrivateKey", I, P, ct.POINTER(P))
DECODE_KEY = fn("d2i_AutoPrivateKey", P, P, ct.POINTER(P), ct.c_long)
SCOPES = {
    "O-TBC": lambda f, c: f + c + 1,
    "L4": lambda f, c: f + c + 1,
    "T2": lambda f, c: (4 * f + 2 * c) // 3 + 1,
    "DM": lambda f, c: 2 * f + 1,
    "ES-QM": lambda f, c: 2 * f + 1,
    "ES-S": lambda f, c: 2 * f + 1,
    "Authority": lambda f, c: f + c + 1,
}
MAJORITY = {"DM", "ES-QM", "ES-S"}


def state_store(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db


def encode_private(key):
    length = ENCODE_KEY(key.p, None)
    if length <= 0:
        raise ValueError("key encoding")
    buf = ct.create_string_buffer(length)
    cursor = P(ct.addressof(buf))
    if ENCODE_KEY(key.p, ct.byref(cursor)) != length:
        raise ValueError("key encoding")
    return b64(buf.raw)


def decode_private(text):
    buf = ct.create_string_buffer(unb64(text))
    cursor = P(ct.addressof(buf))
    return Key(DECODE_KEY(None, ct.byref(cursor), len(buf.raw) - 1))


def fields(value, *names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError("unexpected interface fields")


def auth_tag(key, body):
    return hmac.new(key, canonical(body), hashlib.sha256).hexdigest()


class Authority:
    def __init__(self, path, registry, control_key, window_ms, faults, churn, gated):
        self.control_key = control_key
        self.gated = gated
        self.parameters = (len(registry), faults, churn)
        self.window_ns = int(window_ms) * 1_000_000
        self.registry = {int(i): Key.from_der(unb64(v)) for i, v in registry.items()}
        self.db = state_store(path)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta(name TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS attempts(
                attempt TEXT PRIMARY KEY, cid TEXT UNIQUE, context TEXT NOT NULL,
                policy TEXT NOT NULL, cap INTEGER NOT NULL, gated INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS epochs(
                cid TEXT, epoch INTEGER, plan TEXT NOT NULL, opened INTEGER NOT NULL,
                deadline INTEGER NOT NULL, closed TEXT, closed_ns INTEGER,
                PRIMARY KEY(cid, epoch));
            CREATE INDEX IF NOT EXISTS deadlines_to_close ON epochs(deadline) WHERE closed IS NULL;
            CREATE TABLE IF NOT EXISTS admitted(
                cid TEXT, epoch INTEGER, worker INTEGER, PRIMARY KEY(cid, epoch, worker));
            CREATE TABLE IF NOT EXISTS reports(
                cid TEXT, epoch INTEGER, worker INTEGER, report TEXT NOT NULL,
                PRIMARY KEY(cid, epoch, worker));
        """)
        metadata = {
            "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "registry": digest(canonical(registry)),
            "control": digest(control_key),
            "window_ns": str(self.window_ns),
            "mode": str(self.gated),
            "parameters": str(self.parameters),
        }
        old = dict(self.db.execute("SELECT name, value FROM meta").fetchall())
        if old:
            if any(old.get(name) != value for name, value in metadata.items()):
                raise ValueError("changed boot or authority configuration")
            self.key = decode_private(old["private"])
        else:
            self.key = Key.generate("Ed25519")
            with self.db:
                self.db.executemany("INSERT INTO meta VALUES (?, ?)", metadata.items())
                self.db.execute("INSERT INTO meta VALUES ('private', ?)", (encode_private(self.key),))

    def registered(self, cid):
        row = self.db.execute("SELECT * FROM attempts WHERE cid=?", (cid,)).fetchone()
        if row is None:
            raise ValueError("unregistered attempt")
        return row

    def epoch(self, cid, epoch):
        if type(epoch) is not int or not 1 <= epoch <= 4:
            raise ValueError("invalid epoch")
        row = self.db.execute("SELECT * FROM epochs WHERE cid=? AND epoch=?", (cid, epoch)).fetchone()
        if row is None:
            raise ValueError("epoch absent")
        return row

    def ids(self, cid, epoch):
        return [r[0] for r in self.db.execute(
            "SELECT worker FROM admitted WHERE cid=? AND epoch=? ORDER BY worker", (cid, epoch)
        )]

    def reports(self, cid, epoch):
        return [json.loads(r[0]) for r in self.db.execute(
            "SELECT report FROM reports WHERE cid=? AND epoch=? ORDER BY worker", (cid, epoch)
        )]

    def close(self, attempt, epoch, cohort, reports, reason):
        cid, index = attempt["cid"], epoch["epoch"]
        ctx = json.loads(attempt["context"])
        sealer = Sealer(self.key, self.registry, ctx)
        if index > 1:
            previous = json.loads(self.epoch(cid, index - 1)["closed"])["entry"]
            sealer.previous = digest(canonical(previous["header"]))
        sealer.next_epoch = index
        start = time.monotonic_ns()
        entry = sealer.close(index, cohort, reports)
        ended = time.monotonic_ns()
        result = dict(entry=entry, closure_ns=ended - start, reason=reason,
                      window_ns=ended - epoch["opened"])
        with self.db:
            self.db.execute("UPDATE epochs SET closed=?, closed_ns=? WHERE cid=? AND epoch=?",
                            (canonical(result).decode(), ended, cid, index))
        return result

    def tick(self):
        rows = self.db.execute("SELECT * FROM epochs WHERE closed IS NULL AND deadline<=?",
                               (time.monotonic_ns(),)).fetchall()
        for row in rows:
            attempt = self.registered(row["cid"])
            admitted = self.ids(row["cid"], row["epoch"]) if attempt["gated"] else json.loads(row["plan"])
            self.close(attempt, row, admitted, self.reports(row["cid"], row["epoch"]), "deadline")

    def handle(self, q):
        self.tick()
        if q.get("op") == "report":
            return self.accept_report(q)
        fields(q, "control", "tag")
        control = q["control"]
        if not hmac.compare_digest(q["tag"], auth_tag(self.control_key, control)):
            raise ValueError("control authentication")
        op = control["op"]
        if op == "register":
            fields(control, "op", "context", "policy")
            ctx = control["context"]
            validate_context(ctx)
            validate_registry(self.registry, ctx)
            policy = control["policy"]
            if (policy not in SCOPES or tuple(ctx[k] for k in ("n", "f", "c")) != self.parameters
                    or (not self.gated and policy != "O-TBC")):
                raise ValueError("unsupported trusted contract")
            cap = SCOPES[policy](ctx["f"], ctx["c"])
            cid = digest(canonical(ctx))
            with self.db:
                self.db.execute("INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?)",
                                (ctx["attempt_id"], cid, canonical(ctx).decode(), policy, cap, self.gated))
            return dict(cid=cid, cap=cap)
        cid, index = control["cid"], control["epoch"]
        attempt = self.registered(cid)
        if op == "open":
            fields(control, "op", "cid", "epoch", "plan")
            plan = control["plan"]
            if (type(index) is not int or not 1 <= index <= 4 or not isinstance(plan, list)
                    or any(type(i) is not int for i in plan) or plan != sorted(set(plan))
                    or not 1 <= len(plan) <= attempt["cap"] or not set(plan) <= self.registry.keys()):
                raise ValueError("invalid cohort or cap")
            highest = self.db.execute("SELECT max(epoch) FROM epochs WHERE cid=?", (cid,)).fetchone()[0] or 0
            if index != highest + 1 or (highest and self.epoch(cid, highest)["closed"] is None):
                raise ValueError("overlapping or nonconsecutive epoch")
            now = time.monotonic_ns()
            deadline = now + self.window_ns
            with self.db:
                self.db.execute("INSERT INTO epochs VALUES (?, ?, ?, ?, ?, NULL, NULL)",
                                (cid, index, canonical(plan).decode(), now, deadline))
            return dict(deadline=deadline)
        row = self.epoch(cid, index)
        if op == "get":
            fields(control, "op", "cid", "epoch")
            return dict(closed=json.loads(row["closed"]) if row["closed"] else None)
        if row["closed"] and op != "finish":
            raise ValueError("epoch closed")
        plan = json.loads(row["plan"])
        if op == "admit":
            fields(control, "op", "cid", "epoch", "worker")
            worker = control["worker"]
            if not attempt["gated"] or type(worker) is not int or worker not in plan:
                raise ValueError("worker not eligible in this contract")
            start = time.monotonic_ns()
            if start >= row["deadline"]:
                raise ValueError("epoch expired")
            with self.db:
                self.db.execute("INSERT INTO admitted VALUES (?, ?, ?)", (cid, index, worker))
                body = dict(cid=cid, epoch=index, worker=worker, deadline=row["deadline"],
                            synthetic=attempt["policy"] == "Authority")
                ticket = dict(body=body, signature=b64(self.key.sign(TICKET_DOMAIN + canonical(body))))
            return dict(ticket=ticket, issue_ns=time.monotonic_ns() - start)
        if op == "finish":
            fields(control, "op", "cid", "epoch", "started")
            if row["closed"]:
                return json.loads(row["closed"])
            started = control["started"]
            if (not isinstance(started, list) or any(type(i) is not int for i in started)
                    or started != sorted(set(started)) or not set(started) <= set(plan)):
                raise ValueError("invalid started cohort")
            admitted = self.ids(cid, index) if attempt["gated"] else started
            reports = self.reports(cid, index)
            if [r["body"]["worker"] for r in reports] != admitted:
                return dict(entry=None)
            majority = max(sum(r["body"]["result"] == bit for r in reports) for bit in (0, 1))
            authorizes_early = attempt["policy"] in MAJORITY and majority > json.loads(attempt["context"])["f"]
            if admitted != plan and not authorizes_early:
                return dict(entry=None)
            return self.close(attempt, row, admitted, reports, "complete")
        raise ValueError("unknown authority operation")

    def accept_report(self, q):
        fields(q, "op", "cid", "epoch", "report")
        cid, index = q["cid"], q["epoch"]
        attempt, row = self.registered(cid), self.epoch(cid, index)
        if row["closed"] or time.monotonic_ns() >= row["deadline"]:
            return dict(timely=False)
        ctx, report = json.loads(attempt["context"]), q["report"]
        admitted = self.ids(cid, index) if attempt["gated"] else json.loads(row["plan"])
        verify_report(report, self.registry, ctx, index, admitted)
        with self.db:
            self.db.execute("INSERT INTO reports VALUES (?, ?, ?, ?)",
                            (cid, index, report["body"]["worker"], canonical(report).decode()))
        return dict(timely=True)


class Worker:
    def __init__(self, worker_id, path, report_key, authority_addr, authority_key, task_pub, gated):
        self.worker_id = worker_id
        self.report_key = report_key
        self.authority_addr = authority_addr
        self.authority_pub = Key.from_der(authority_key)
        self.task_pub = Key.from_der(task_pub)
        self.task_key_digest = digest(task_pub)
        self.gated = gated
        self.db = state_store(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS consumed(cid TEXT, epoch INTEGER, PRIMARY KEY(cid, epoch))")

    def handle(self, q):
        fields(q, "context", "epoch", "batch", "ticket", "override")
        ctx, epoch, batch = q["context"], q["epoch"], q["batch"]
        cid = digest(canonical(ctx))
        gate_ns = 0
        if self.gated:
            started = time.monotonic_ns()
            ticket = q["ticket"]
            fields(ticket, "body", "signature")
            body = ticket["body"]
            fields(body, "cid", "epoch", "worker", "deadline", "synthetic")
            self.authority_pub.verify(unb64(ticket["signature"]), TICKET_DOMAIN + canonical(body))
            if (body["cid"] != cid or body["epoch"] != epoch or body["worker"] != self.worker_id
                    or body["synthetic"] != (batch is None) or time.monotonic_ns() >= body["deadline"]):
                raise ValueError("invalid worker, context, epoch or window")
            with self.db:
                self.db.execute("INSERT INTO consumed VALUES (?, ?)", (cid, epoch))
            gate_ns = time.monotonic_ns() - started
        if self.gated and time.monotonic_ns() >= body["deadline"]:
            raise ValueError("window elapsed before task execution")
        if batch is None and not self.gated:
            raise ValueError("missing task payload")
        if batch is not None and (digest(canonical(batch)) != ctx["object_digest"]
                                  or self.task_key_digest != ctx["credential_key_digest"]):
            raise ValueError("wrong task or credential")
        if self.gated and time.monotonic_ns() >= body["deadline"]:
            raise ValueError("window elapsed before task execution")
        truth = 1
        cpu_start = time.process_time_ns()
        if batch is not None:
            for msg, sig in batch:
                try:
                    self.task_pub.verify(unb64(sig), unb64(msg))
                except ValueError:
                    truth = 0
        elapsed = time.process_time_ns() - cpu_start
        bit = truth if q["override"] is None else q["override"]
        report = make_report(self.report_key, ctx, epoch, self.worker_id, bit)
        response, wire = rpc(self.authority_addr, dict(op="report", cid=cid, epoch=epoch, report=report))
        if not response["ok"]:
            raise ValueError(response["error"])
        return dict(i=self.worker_id, bit=bit, truth=truth, timely=response["timely"],
                    task_cpu_ns=elapsed, gate_ns=gate_ns, deposit_wire=wire,
                    checks=0 if batch is None else len(batch))


def service(pipe, kind, args):
    os.umask(0o077)
    target = Authority(*args) if kind == "authority" else Worker(*args)

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                result = dict(ok=True, **target.handle(json.loads(recv(self.request))))
            except (ValueError, TypeError, KeyError, sqlite3.IntegrityError, OSError, EOFError) as exc:
                result = dict(ok=False, error=f"{type(exc).__name__}: {exc}")
            body = canonical(result)
            self.request.sendall(struct.pack("!I", len(body)) + body)

    class Server(socketserver.TCPServer):
        allow_reuse_address = True

        def service_actions(self):
            if kind == "authority":
                target.tick()

    with Server(("127.0.0.1", 0), Handler) as server:
        public = target.key.public_bytes() if kind == "authority" else None
        pipe.send((server.server_address, public))
        pipe.close()
        server.serve_forever(poll_interval=0.01)


def launch(kind, *args):
    parent, child = mp.Pipe(False)
    proc = mp.Process(target=service, args=(child, kind, args))
    proc.start()
    child.close()
    try:
        if not parent.poll(15):
            raise TimeoutError(f"{kind} startup timeout")
        addr, public = parent.recv()
    except BaseException:
        proc.terminate()
        proc.join()
        raise
    finally:
        parent.close()
    return proc, addr, public


class Control:
    def __init__(self, addr, secret):
        self.addr, self.secret = addr, secret

    def send(self, **control):
        return rpc(self.addr, dict(control=control, tag=auth_tag(self.secret, control)))

    def call(self, **control):
        response, wire = self.send(**control)
        if not response["ok"]:
            raise ValueError(response["error"])
        return response, wire
