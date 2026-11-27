import argparse
import json
import socket
import struct
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--count", type=int, default=20)
    args = parser.parse_args()
    measurements = []
    for _ in range(args.count):
        start = time.monotonic_ns()
        with socket.create_connection((args.host, args.port), timeout=3) as connection:
            connect_ms = (time.monotonic_ns() - start) / 1e6
            info = connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
            estimated_rtt = struct.unpack_from("=I", info, 68)[0] / 1000
        measurements.append({"tcp_connect_ms": connect_ms, "linux_tcpi_rtt_ms": estimated_rtt})
    print(
        json.dumps(
            {
                "method": "Athens TCP connection to the Strasbourg worker gateway, Linux TCP_INFO initial RTT",
                "measurements": measurements,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
