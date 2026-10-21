#!/usr/bin/env python3
"""Compare what the scanner REALLY did (ground truth) with what the detector FOUND.

Usage:  python tools/validate.py scan_truth.json reports/findings.json
Prints PASS/FAIL with the reason for each check. Exit code 0 only if everything passes.
"""

from __future__ import annotations

import json
import re
import sys


def ports_in(finding: dict) -> int:
    m = re.search(r"\((\d+) ports\)", finding.get("ports", ""))
    return int(m.group(1)) if m else 0


def validate(truth: dict, findings_doc: dict, slack: int = 120, min_ratio: float = 0.8):
    """Return (ok, list of (check, ok, message))."""
    checks = []
    scans = [f for f in findings_doc.get("findings", []) if f["type"] == "port_scan"]
    match = [f for f in scans if f["source"] == truth["scanner_ip"] and truth["target"] in f["targets"]]
    checks.append(
        (
            "detected",
            bool(match),
            f"found a port_scan from {truth['scanner_ip']} to {truth['target']}"
            if match
            else f"no port_scan finding from {truth['scanner_ip']} to {truth['target']} "
            f"(port_scan findings present: {[(f['source'], f['targets']) for f in scans]})",
        )
    )
    if match:
        f = max(match, key=ports_in)
        lo, hi = truth["start_epoch"] - slack, truth["end_epoch"] + slack
        overlap = f["first_seen"] <= hi and f["last_seen"] >= lo
        checks.append(
            (
                "time window",
                overlap,
                f"finding {f['first_seen_utc']} .. {f['last_seen_utc']} vs scan {truth['start_utc']} .. {truth['end_utc']}",
            )
        )
        n, want = ports_in(f), truth["ports_scanned"]
        checks.append(
            (
                "port count",
                n >= min_ratio * want,
                f"finding lists {n} ports; scanner tried {want} (need at least {int(min_ratio * 100)}%)",
            )
        )
        found_open = (
            {int(p) for p in re.findall(r"\b\d+\b", f["detail"].split("Ports that answered (open):")[-1])}
            if "Ports that answered" in f["detail"]
            else set()
        )
        missing = set(truth["open_ports"]) - found_open if truth["open_ports"] else set()
        checks.append(
            (
                "open ports",
                not missing,
                f"scanner found open ports {truth['open_ports']}; detector reports {sorted(found_open) or 'none'}",
            )
        )
    return all(ok for _, ok, _ in checks), checks


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) != 2:
        print(__doc__)
        return 2
    truth = json.load(open(argv[0]))
    doc = json.load(open(argv[1]))
    ok, checks = validate(truth, doc)
    for name, passed, msg in checks:
        print(f"{'PASS' if passed else 'FAIL'}  {name}: {msg}")
    print("\nRESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
