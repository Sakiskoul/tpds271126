import argparse
import concurrent.futures
import copy
import csv
import json
import multiprocessing
import os
import platform
import signal
import socket
import socketserver
import ssl
import statistics
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import benchmark_v6 as benchmark
from deploy import checked, launch, recv
from ossl import Key, version
from protocol import b64, canonical, decision, digest, public_bytes, unb64


def frame(sock, payload):
    encoded = canonical(payload)
    sock.sendall(struct.pack("!I", len(encoded)) + encoded)
    return len(encoded) + 4


def stop_processes(processes):
    for process in processes:
        if process.is_alive():
            process.terminate()
    for process in processes:
        process.join(timeout=5)


def environment():
    cpu = Path("/proc/cpuinfo").read_text().splitlines()
    mem = Path("/proc/meminfo").read_text().splitlines()
    os_release = platform.freedesktop_os_release()["PRETTY_NAME"]
    quota = Path("/sys/fs/cgroup/cpu.max")
    try:
        route = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True, timeout=3
        ).split()
        device = route[route.index("dev") + 1]
        link_speed = Path("/sys/class/net") / device / "speed"
        mbps = int(link_speed.read_text().strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        mbps = None
    return {
        "os": os_release,
        "kernel": platform.release(),
        "cpu": next(s.split(":", 1)[1].strip() for s in cpu if s.startswith("model name")),
        "cpus": len(os.sched_getaffinity(0)),
        "cgroup_cpu_quota": quota.read_text().strip() if quota.exists() else None,
        "memory": mem[0].split(":", 1)[1].strip(),
        "nic_mbps": mbps,
        "python": platform.python_version(),
        "signature_library": version(0).decode(),
        "tls_library": ssl.OPENSSL_VERSION,
    }


class WorkerGateway(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, context, allowed_ips):
        self.context = context
        self.allowed_ips = allowed_ips
        self.workers = {}
        self.processes = []
        self.registry = None
        self.sealer = None
        super().__init__(address, GatewayHandler)

    def verify_request(self, request, address):
        return address[0] in self.allowed_ips

    def reset(self):
        stop_processes(self.processes)
        self.processes.clear()
        self.workers.clear()
        self.registry = None
        self.sealer = None

    def dispatch(self, message):
        operation = message["operation"]
        if operation == "ping":
            return {"ok": True}
        if operation == "profile":
            return {"ok": True, "environment": environment()}
        if operation == "configure":
            identities = message["identities"]
            if len(identities) > 42 or len(set(identities)) != len(identities):
                raise ValueError("invalid worker group")
            if any(type(i) is not int or not 0 <= i < 82 for i in identities):
                raise ValueError("invalid worker identity")
            self.reset()
            try:
                for identity in identities:
                    process, state = launch("worker", {"id": identity, "tx_key": message["tx_key"]})
                    self.processes.append(process)
                    self.workers[identity] = state
            except Exception:
                self.reset()
                raise
            return {
                "ok": True,
                "registry": {str(i): state["public"] for i, state in self.workers.items()},
            }
        if operation == "work":
            request = message["request"]
            if request.get("op") != "verify":
                raise ValueError("unsupported worker operation")
            state = self.workers[message["identity"]]
            result, _ = checked(state["addr"], request)
            return result
        if operation == "configure-consumer":
            self.registry = {
                int(i): Key.from_der(unb64(key)) for i, key in message["registry"].items()
            }
            self.sealer = Key.from_der(unb64(message["seal_key"]))
            return {"ok": True}
        if operation == "observe":
            if self.registry is None:
                raise ValueError("consumer registry is uninitialized")
            ctx = message["context"]
            started = time.thread_time_ns()
            history = benchmark.signed_history(message["entries"], self.registry, self.sealer, ctx)
            result = decision(history, ctx["f"], ctx["c"])
            return {"ok": True, "result": result, "verify_cpu_ns": time.thread_time_ns() - started}
        raise ValueError("unsupported gateway operation")


class GatewayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            secured = self.server.context.wrap_socket(self.request, server_side=True)
        except (OSError, ssl.SSLError):
            return
        with secured:
            try:
                message = json.loads(recv(secured))
                reply = self.server.dispatch(message)
            except Exception as error:
                reply = {"ok": False, "error": f"{type(error).__name__}: {error}"}
            frame(secured, reply)


def tls_context(args, server_side):
    purpose = ssl.Purpose.CLIENT_AUTH if server_side else ssl.Purpose.SERVER_AUTH
    context = ssl.create_default_context(purpose, cafile=str(args.trust))
    context.load_cert_chain(args.cert, args.key)
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


@dataclass(frozen=True)
class Client:
    host: str
    port: int
    peer_name: str
    tls: ssl.SSLContext

    def send(self, message):
        with socket.create_connection((self.host, self.port), timeout=9) as tcp:
            with self.tls.wrap_socket(tcp, server_hostname=self.peer_name) as conn:
                outgoing = frame(conn, message)
                response = recv(conn)
        reply = json.loads(response)
        if not reply.get("ok"):
            raise RuntimeError(reply.get("error", "gateway operation failed"))
        return reply, outgoing + 4 + len(response)


@dataclass(frozen=True)
class RemoteWorker:
    identity: int
    gateway: Client


def routed_checked(address, request):
    if isinstance(address, RemoteWorker):
        return address.gateway.send(
            {"operation": "work", "identity": address.identity, "request": request}
        )
    return checked(address, request)


def probe(client, count, remote_ping_host):
    samples = []
    for _ in range(count):
        start = time.monotonic_ns()
        client.send({"operation": "ping"})
        samples.append((time.monotonic_ns() - start) / 1e6)
    try:
        raw = subprocess.check_output(
            ["ping", "-4", "-q", "-c", "10", "-i", "0.2", "-W", "1", remote_ping_host],
            text=True,
            timeout=15,
        )
        stats = raw.strip().splitlines()[-1].split("=", 1)[1].split()[0]
        icmp = [float(value) for value in stats.split("/")]
    except (IndexError, ValueError, OSError, subprocess.SubprocessError):
        icmp = None
    return {"tls_round_trip_ms": samples, "direct_icmp_min_avg_max_mdev_ms": icmp}


def write_rows(path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=tuple(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def corpus_variants(tx, n, size):
    data = benchmark.seeded("distributed-data", n, size)
    positive = []
    for _ in range(size):
        message = data.randbytes(128)
        positive.append([b64(message), b64(tx.sign(message))])
    negative = copy.deepcopy(positive)
    corrupted = bytearray(unb64(negative[-1][1]))
    corrupted[-1] ^= 1
    negative[-1][1] = b64(corrupted)
    return {1: positive, 0: negative}


def run_group(args, client, n, placement, out):
    f, c = n // 2 - 1, 1
    tx = Key.generate("ML-DSA-65")
    tx_key = b64(public_bytes(tx))
    batches = corpus_variants(tx, n, args.batch)
    remote_ids = list(range(1, n, 2)) if placement == "split" else []
    configured, _ = client.send(
        {"operation": "configure", "identities": remote_ids, "tx_key": tx_key}
    )
    raw_registry = configured["registry"]
    raw_addr = []
    processes = []
    rows, epochs, jobs = [], [], []
    captured = {}
    original_history = benchmark.signed_history
    original_checked = benchmark.checked

    def capture(entries, registry, seal_pub, context):
        captured.clear()
        captured.update(entries=entries, context=context)
        return original_history(entries, registry, seal_pub, context)

    benchmark.checked = routed_checked
    benchmark.signed_history = capture
    try:
        for identity in range(n):
            if identity in remote_ids:
                raw_addr.append(RemoteWorker(identity, client))
            else:
                proc, state = launch("worker", {"id": identity, "tx_key": tx_key})
                processes.append(proc)
                raw_addr.append(state["addr"])
                raw_registry[str(identity)] = state["public"]
        registry = {int(i): Key.from_der(unb64(key)) for i, key in raw_registry.items()}
        seal = Key.generate()
        seal_pub = seal.public_key()
        seal_key = b64(public_bytes(seal))
        client.send({"operation": "configure-consumer", "registry": raw_registry, "seal_key": seal_key})
        ctx = {
            "chain_id": "otbc-multihost",
            "height": 1,
            "prestate_root": "1" * 64,
            "credential_version": 1,
            "credential_key_digest": digest(unb64(tx_key)),
            "policy_id": "all-ML-DSA-65",
            "policy_version": 1,
            "component": "batch",
            "implementation_id": "OpenSSL-EVP",
            "registry_digest": digest(canonical(raw_registry)),
            "n": n,
            "f": f,
            "c": c,
        }
        with tempfile.TemporaryDirectory(dir=out) as temporary:
            proc, sealer = launch(
                "sealer", {"key": seal, "registry": raw_registry, "db": str(Path(temporary) / "seal.db")}
            )
            processes.append(proc)
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.slots) as pool:
                warmup = batches[1][:1]
                warmup_ctx = dict(ctx, attempt_id="warmup", object_digest=digest(canonical(warmup)))

                def warmup_worker(address):
                    return routed_checked(
                        address,
                        {"op": "verify", "context": warmup_ctx, "batch": warmup, "epoch": 1, "override": None},
                    )

                list(pool.map(warmup_worker, raw_addr))
                for repeat in range(args.repeats):
                    conditions = [
                        (policy, scenario, truth)
                        for policy in args.policies
                        for scenario in args.scenarios
                        for truth in (0, 1)
                    ]
                    benchmark.seeded("distributed-order", n, repeat).shuffle(conditions)
                    for policy, scenario, truth in conditions:
                        start = time.monotonic_ns()
                        row, epoch_rows, job_rows = benchmark.trial(
                            n, args.batch, args.slots, args.deadline, args.guard, policy, scenario,
                            truth, repeat, batches[truth], raw_addr, sealer["addr"], registry,
                            seal_pub, ctx, tx.public_key(), pool,
                        )
                        observed_ms, observed_ns, observed_bytes = None, None, 0
                        if row["result"] != "unresolved":
                            t0 = time.monotonic_ns()
                            evidence, observed_bytes = client.send(
                                {
                                    "operation": "observe",
                                    **captured,
                                }
                            )
                            if evidence["result"] != row["result"]:
                                raise RuntimeError("independent consumer disagrees")
                            observed_ms = (time.monotonic_ns() - t0) / 1e6
                            observed_ns = evidence["verify_cpu_ns"]
                        complete_ms = (time.monotonic_ns() - start) / 1e6
                        rows.append(
                            dict(
                                row,
                                placement=placement,
                                remote_workers=len(remote_ids),
                                certified_consumer_ms=observed_ms,
                                certified_consumer_cpu_ns=observed_ns,
                                certified_consumer_bytes=observed_bytes,
                                end_to_end_ms=complete_ms,
                            )
                        )
                        epochs.extend(dict(item, placement=placement) for item in epoch_rows)
                        jobs.extend(
                            dict(item, placement=placement, site="remote" if item["worker"] in remote_ids else "local")
                            for item in job_rows
                        )
                    write_rows(out / "trials.csv", rows)
                    write_rows(out / "epochs.csv", epochs)
                    write_rows(out / "jobs.csv", jobs)
                    print(f"n={n} placement={placement} block={repeat + 1}/{args.repeats}", flush=True)
    finally:
        benchmark.checked = original_checked
        benchmark.signed_history = original_history
        stop_processes(processes)


def credentials(parser):
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--trust", type=Path, required=True)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(required=True, dest="command")
    gateway = commands.add_parser("gateway")
    controller = commands.add_parser("run")
    credentials(gateway)
    credentials(controller)
    gateway.add_argument("--listen", required=True)
    gateway.add_argument("--port", type=int, required=True)
    gateway.add_argument("--peer-ip", nargs="+", required=True)
    controller.add_argument("--host", required=True)
    controller.add_argument("--port", type=int, required=True)
    controller.add_argument("--peer-name", required=True)
    controller.add_argument("--ping-host", required=True)
    controller.add_argument("--output", type=Path, required=True)
    controller.add_argument("--populations", type=int, nargs="+", default=[14, 42])
    controller.add_argument("--batch", type=int, default=32)
    controller.add_argument("--slots", type=int, default=4)
    controller.add_argument("--repeats", type=int, default=10)
    controller.add_argument("--deadline", type=int, default=0)
    controller.add_argument("--guard", type=int, default=100)
    controller.add_argument("--policies", nargs="+", default=["Direct", "L4", "O-TBC", "T2"])
    controller.add_argument("--scenarios", nargs="+", default=["honest", "mobile"])
    controller.add_argument("--placements", nargs="+", default=["local", "split"])
    args = parser.parse_args()

    if args.command == "gateway":
        multiprocessing.set_start_method("spawn")
        context = tls_context(args, server_side=True)
        with WorkerGateway((args.listen, args.port), context, set(args.peer_ip)) as srv:
            signal.signal(signal.SIGTERM, lambda *_: raise_interrupt())
            print("ready", srv.server_address[1], flush=True)
            try:
                srv.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                srv.reset()
        return

    args.output.mkdir(parents=True, exist_ok=False)
    client = Client(args.host, args.port, args.peer_name, tls_context(args, server_side=False))
    remote, _ = client.send({"operation": "profile"})
    network = probe(client, 20, args.ping_host)
    (args.output / "environment.json").write_text(
        json.dumps(
            {
                "controller": environment(),
                "remote": remote["environment"],
                "network": network,
                "n": args.populations,
                "batch": args.batch,
                "slots": args.slots,
                "repeats": args.repeats,
                "policies": args.policies,
                "scenarios": args.scenarios,
                "deadline_ms": args.deadline,
                "guard_ms": args.guard if args.deadline else None,
                "transports": {"local": "loopback TCP", "remote": "one mTLS connection per RPC"},
                "source_sha256": {
                    path.name: digest(path.read_bytes())
                    for path in sorted(Path(__file__).resolve().parent.glob("*.py"))
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("TLS probe median ms", statistics.median(network["tls_round_trip_ms"]), flush=True)
    for n in args.populations:
        for placement in args.placements:
            out = args.output / f"n{n}-{placement}"
            out.mkdir()
            run_group(args, client, n, placement, out)


def raise_interrupt():
    raise KeyboardInterrupt


if __name__ == "__main__":
    main()
