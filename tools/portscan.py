#!/usr/bin/env python3
"""A small TCP connect scanner for testing the detector on MY OWN instances. Standard library only.

Safety rules built in:
  * it refuses any target outside 10.0.0.0/8 (private addresses of my own lab network);
  * it scans one target and at most 1024 ports, with few threads, so it stays slow and small.

It writes a "ground truth" file: exactly what was scanned and when. tools/validate.py compares
that file with what the detector found.

Usage on the bastion:  python3 portscan.py 10.1.1.192 --ports 1-1024 --out scan_truth.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

ALLOWED = ipaddress.ip_network("10.0.0.0/8")
MAX_PORTS = 1024


def check_target(host: str) -> str:
    """Return the IP if it is inside 10.0.0.0/8, otherwise raise ValueError."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"{host!r} is not an IP address (use a private IP like 10.1.1.20)") from exc
    if ip not in ALLOWED:
        raise ValueError(f"refusing to scan {ip}: only private addresses inside 10.0.0.0/8 are allowed")
    return str(ip)


def parse_ports(text: str) -> list[int]:
    if "-" in text:
        lo, hi = (int(x) for x in text.split("-", 1))
    else:
        lo = hi = int(text)
    if not (1 <= lo <= hi <= 65535):
        raise ValueError("ports must satisfy 1 <= low <= high <= 65535")
    if hi - lo + 1 > MAX_PORTS:
        raise ValueError(f"too many ports: at most {MAX_PORTS} per scan")
    return list(range(lo, hi + 1))


def tcp_connect(host: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def scan(
    host: str, ports: list[int], timeout: float = 0.5, workers: int = 4, connect=tcp_connect
) -> list[int]:
    """Try to connect to each port. Return the ports that accepted the connection (open)."""
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 8))) as pool:
        results = list(pool.map(lambda p: (p, connect(host, p, timeout)), ports))
    return sorted(p for p, is_open in results if is_open)


def local_ip_towards(host: str) -> str:
    """The address this machine would use to reach `host` (no packets are sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, 9))
        return s.getsockname()[0]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="private IP (10.x.x.x) of my own instance")
    ap.add_argument("--ports", default="1-1024")
    ap.add_argument("--timeout", type=float, default=0.5)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", default="scan_truth.json")
    args = ap.parse_args(argv)
    try:
        target = check_target(args.target)
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    scanner = local_ip_towards(target)
    start = time.time()
    open_ports = scan(target, ports, args.timeout, args.workers)
    end = time.time()
    truth = {
        "scanner_ip": scanner,
        "target": target,
        "port_range": [ports[0], ports[-1]],
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "start_epoch": int(start),
        "end_epoch": int(end),
        "start_utc": datetime.fromtimestamp(start, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "end_utc": datetime.fromtimestamp(end, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "timeout": args.timeout,
        "workers": args.workers,
    }
    with open(args.out, "w") as fh:
        json.dump(truth, fh, indent=2)
    print(
        f"scanned {len(ports)} ports on {target} from {scanner} in {end - start:.0f}s; open: {open_ports or 'none'}"
    )
    print(f"ground truth written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
