"""Command line: python -m flowlog_analyzer <fetch|summary|detect|dashboard> [options]"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_REGION = "ap-southeast-2"
DEFAULT_CACHE = Path("data/cache")


def _clients(args):
    import boto3

    session = boto3.Session(region_name=args.region)
    account = args.account or session.client("sts").get_caller_identity()["Account"]
    bucket = args.bucket or f"p1-flowlogs-{account}"
    return session.client("s3"), account, bucket


def load_records(args):
    """Download (or reuse cached) logs for the last --days days and return (records, keys)."""
    from .core import s3_source

    s3, account, bucket = _clients(args)
    days = s3_source.date_range(args.days)
    keys = s3_source.list_log_keys(s3, bucket, account, args.region, days)
    records = list(s3_source.iter_records(s3, bucket, keys, Path(args.cache_dir)))
    return records, keys, bucket


def _fmt(ts: int | None) -> str:
    return "-" if ts is None else datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def cmd_fetch(args) -> int:
    records, keys, bucket = load_records(args)
    print(f"bucket: {bucket}")
    print(f"files found: {len(keys)}")
    print(f"records parsed: {len(records)}")
    if records:
        first = _fmt(min(r.start for r in records if r.start))
        last = _fmt(max(r.end for r in records if r.end))
        print(f"time range: {first} -> {last}")
        print("records per interface:")
        for eni, n in Counter(r.interface_id for r in records).most_common():
            print(f"  {eni}  {n}")
    return 0


def cmd_summary(args) -> int:
    from . import analysis

    records, keys, bucket = load_records(args)
    if not records:
        print("no records found for that period")
        return 1
    df = analysis.to_dataframe(records)
    print(f"{bucket}: {len(keys)} files, last {args.days} day(s)")
    print("KPIs:", analysis.kpis(df))
    for title, table in analysis.summary_tables(df).items():
        if title.startswith("Rejects over time"):
            table = table[table["rejects"] > 0]  # skip the long idle stretches
            title += ", only buckets with rejects"
        print(f"\n=== {title} ===")
        print(table.to_string(index=False) if len(table) else "(none)")
    return 0


def cmd_detect(args) -> int:
    import json

    from .core import detect as det

    records, keys, bucket = load_records(args)
    allow = [ip for chunk in args.allow for ip in chunk.split(",") if ip]
    th = det.Thresholds(
        scan_ports=args.scan_ports,
        scan_window=args.scan_window,
        sweep_hosts=args.sweep_hosts,
        ssh_connections=args.ssh_connections,
    )
    findings = det.detect(records, th, allow)
    print(f"{bucket}: {len(keys)} files, {len(records)} records, last {args.days} day(s)")
    if allow:
        print(f"ignored sources (allowlist): {', '.join(allow)}")
    if not findings:
        print("no findings")
    for f in findings:
        more = " ..." if len(f.targets) > 3 else ""
        print(f"\n[{f.severity.upper()}] {f.type}  {f.source} -> {', '.join(f.targets[:3])}{more}")
        print(f"  ports: {f.ports}")
        seen = f"{det._iso(f.first_seen)} -> {det._iso(f.last_seen)}"
        print(f"  seen:  {seen}   records={f.records} accept={f.accepts} reject={f.rejects}")
        print(f"  {f.detail}")
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "bucket": bucket,
        "days": args.days,
        "records": len(records),
        "thresholds": th.__dict__,
        "allowlist": allow,
        "findings": [f.to_dict() for f in findings],
    }
    out.write_text(json.dumps(payload, indent=2))
    print(f"\nwrote {out} ({len(findings)} findings)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="flowlog_analyzer", description="Analyze VPC Flow Logs from S3.")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("--days", type=int, default=7, help="how many days back to read (default 7)")
        sp.add_argument("--bucket", help="S3 bucket (default p1-flowlogs-<account>)")
        sp.add_argument("--account", help="AWS account id (default: from your credentials)")
        sp.add_argument("--region", default=DEFAULT_REGION)
        sp.add_argument("--cache-dir", default=str(DEFAULT_CACHE))

    def detect_opts(sp):
        sp.add_argument(
            "--allow",
            action="append",
            default=[],
            help="source IP(s) to ignore, comma separated (repeatable)",
        )
        sp.add_argument("--scan-ports", type=int, default=15)
        sp.add_argument("--scan-window", type=int, default=300)
        sp.add_argument("--sweep-hosts", type=int, default=5)
        sp.add_argument("--ssh-connections", type=int, default=20)
        sp.add_argument("--output", default="reports/findings.json")

    for name, helptext in [
        ("fetch", "download logs and print what was found"),
        ("summary", "print top talkers, ports and rejects"),
        ("detect", "run port-scan detection and write reports/findings.json"),
        ("dashboard", "build reports/dashboard.html"),
    ]:
        sp = sub.add_parser(name, help=helptext)
        common(sp)
        if name in ("detect", "dashboard"):
            detect_opts(sp)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "fetch":
        return cmd_fetch(args)
    if args.command == "summary":
        return cmd_summary(args)
    if args.command == "detect":
        return cmd_detect(args)
    print(f"'{args.command}' is not built yet")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
