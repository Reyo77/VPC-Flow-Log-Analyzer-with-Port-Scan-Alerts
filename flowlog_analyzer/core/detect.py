"""Scan and sweep detection rules. Pure Python (no pandas) so the Lambda function can use it too.

Three rules, all based on a sliding time window over one source's records:

* vertical port scan : one source touches MANY DIFFERENT PORTS on ONE target, mostly rejected.
* horizontal sweep   : one source touches ONE PORT on MANY DIFFERENT HOSTS, mostly rejected.
* ssh brute force    : one OUTSIDE source makes many connections to port 22.

Why "mostly rejected" for the first two: normal traffic can also look like many ports. Replies to a
big download come back to many different random ports of the downloader, and a server talks to many
hosts on port 443. Those are accepted. A scanner mostly hits closed ports, which are rejected.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .parser import FlowRecord, is_private

TCP, UDP = 6, 17
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Thresholds:
    scan_ports: int = 15  # distinct destination ports on one target ...
    scan_window: int = 300  # ... within this many seconds
    min_reject_ratio: float = 0.5  # share of records in the window that were REJECT
    sweep_hosts: int = 5  # distinct hosts on one port ...
    sweep_window: int = 300
    ssh_connections: int = 20  # connections to port 22 from one outside source ...
    ssh_window: int = 600  # ... within this many seconds


@dataclass
class Finding:
    type: str  # port_scan | port_sweep | ssh_bruteforce
    severity: str  # high | medium | low
    source: str
    targets: list[str]
    ports: str
    first_seen: int
    last_seen: int
    records: int
    accepts: int
    rejects: int
    detail: str = ""
    interfaces: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["first_seen_utc"] = _iso(self.first_seen)
        d["last_seen_utc"] = _iso(self.last_seen)
        return d


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def summarize_ports(ports: Iterable[int], limit: int = 60) -> str:
    """[1,2,3,22,80,81] -> '1-3,22,80-81 (6 ports)'"""
    nums = sorted(set(ports))
    if not nums:
        return "-"
    runs, lo, prev = [], nums[0], nums[0]
    for p in nums[1:]:
        if p == prev + 1:
            prev = p
            continue
        runs.append((lo, prev))
        lo = prev = p
    runs.append((lo, prev))
    text = ",".join(str(a) if a == b else f"{a}-{b}" for a, b in runs)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return f"{text} ({len(nums)} ports)"


def _bursts(events: Sequence[FlowRecord], item, window: int, min_distinct: int, min_reject_ratio: float):
    """Slide a time window over time-sorted records. Wherever the window holds at least `min_distinct`
    different items (and enough rejects), mark it. Return (first, last) index ranges of marked stretches."""
    n = len(events)
    flagged = [False] * n
    seen: Counter = Counter()
    rejects = 0
    i = 0
    for j in range(n):
        seen[item(events[j])] += 1
        rejects += events[j].action == "REJECT"
        while events[j].start - events[i].start > window:
            k = item(events[i])
            seen[k] -= 1
            if seen[k] == 0:
                del seen[k]
            rejects -= events[i].action == "REJECT"
            i += 1
        if len(seen) >= min_distinct and rejects / (j - i + 1) >= min_reject_ratio:
            for x in range(i, j + 1):
                flagged[x] = True
    # Join neighbouring flagged records into one stretch, but start a new stretch after a quiet gap
    ranges, start = [], None
    for idx, flag in enumerate(flagged):
        if start is not None and (not flag or events[idx].start - events[idx - 1].start > window):
            ranges.append((start, idx - 1))
            start = None
        if flag and start is None:
            start = idx
    if start is not None:
        ranges.append((start, n - 1))
    return ranges


def _stats(recs: Sequence[FlowRecord]):
    accepts = sum(r.action == "ACCEPT" for r in recs)
    rejects = sum(r.action == "REJECT" for r in recs)
    return (
        min(r.start for r in recs),
        max(r.end or r.start for r in recs),
        accepts,
        rejects,
        sorted({r.interface_id for r in recs if r.interface_id}),
    )


def _usable(records: Iterable[FlowRecord], allow: set[str]) -> list[FlowRecord]:
    return sorted(
        (
            r
            for r in records
            if r.is_data and r.start is not None and r.srcaddr and r.dstaddr and r.srcaddr not in allow
        ),
        key=lambda r: r.start,
    )


def find_port_scans(records: Iterable[FlowRecord], th: Thresholds, allow: set[str]) -> list[Finding]:
    groups: dict[tuple[str, str], list[FlowRecord]] = defaultdict(list)
    for r in _usable(records, allow):
        if r.protocol in (TCP, UDP) and r.dstport is not None:
            groups[(r.srcaddr, r.dstaddr)].append(r)
    out = []
    for (src, dst), events in groups.items():
        for a, b in _bursts(events, lambda r: r.dstport, th.scan_window, th.scan_ports, th.min_reject_ratio):
            recs = events[a : b + 1]
            first, last, acc, rej, enis = _stats(recs)
            ports = {r.dstport for r in recs}
            open_ports = sorted({r.dstport for r in recs if r.action == "ACCEPT"})
            severity = "high" if len(ports) >= 100 or open_ports else "medium"
            detail = (
                f"{src} probed {len(ports)} different ports on {dst}; "
                f"{rej} of {len(recs)} records were rejected."
            )
            if open_ports:
                detail += f" Ports that answered (open): {summarize_ports(open_ports)}."
            out.append(
                Finding(
                    "port_scan",
                    severity,
                    src,
                    [dst],
                    summarize_ports(ports),
                    first,
                    last,
                    len(recs),
                    acc,
                    rej,
                    detail,
                    enis,
                )
            )
    return out


def find_port_sweeps(records: Iterable[FlowRecord], th: Thresholds, allow: set[str]) -> list[Finding]:
    groups: dict[tuple[str, int, int], list[FlowRecord]] = defaultdict(list)
    for r in _usable(records, allow):
        if r.protocol in (TCP, UDP) and r.dstport is not None:
            groups[(r.srcaddr, r.protocol, r.dstport)].append(r)
    out = []
    for (src, _proto, port), events in groups.items():
        for a, b in _bursts(
            events, lambda r: r.dstaddr, th.sweep_window, th.sweep_hosts, th.min_reject_ratio
        ):
            recs = events[a : b + 1]
            first, last, acc, rej, enis = _stats(recs)
            hosts = sorted({r.dstaddr for r in recs})
            severity = "high" if len(hosts) >= 20 else "medium"
            detail = (
                f"{src} tried port {port} on {len(hosts)} different hosts; "
                f"{rej} of {len(recs)} records were rejected."
            )
            if is_private(src) and not any(is_private(h) for h in hosts):
                # one of OUR hosts is being blocked going out; this is not someone scanning us
                severity = "low"
                detail += " The source is an internal host trying to reach the internet: likely blocked egress, not a scan."
            out.append(
                Finding(
                    "port_sweep",
                    severity,
                    src,
                    hosts,
                    summarize_ports([port]),
                    first,
                    last,
                    len(recs),
                    acc,
                    rej,
                    detail,
                    enis,
                )
            )
    return out


def find_ssh_bruteforce(records: Iterable[FlowRecord], th: Thresholds, allow: set[str]) -> list[Finding]:
    groups: dict[str, list[FlowRecord]] = defaultdict(list)
    for r in _usable(records, allow):
        if r.protocol == TCP and r.dstport == 22 and r.srcport is not None and not is_private(r.srcaddr):
            groups[r.srcaddr].append(r)
    out = []
    for src, events in groups.items():
        # each new connection uses a new source port, so distinct source ports ~ number of connections
        for a, b in _bursts(events, lambda r: r.srcport, th.ssh_window, th.ssh_connections, 0.0):
            recs = events[a : b + 1]
            first, last, acc, rej, enis = _stats(recs)
            targets = sorted({r.dstaddr for r in recs})
            conns = len({r.srcport for r in recs})
            severity = "high" if acc > 0 else "medium"
            detail = f"{src} made {conns} connections to SSH (port 22): {acc} accepted, {rej} rejected."
            if acc:
                detail += " Accepted connections reached the SSH service: check the server's login logs."
            out.append(
                Finding(
                    "ssh_bruteforce",
                    severity,
                    src,
                    targets,
                    "22 (1 ports)",
                    first,
                    last,
                    len(recs),
                    acc,
                    rej,
                    detail,
                    enis,
                )
            )
    return out


def detect(
    records: Iterable[FlowRecord], th: Thresholds | None = None, allow: Iterable[str] = ()
) -> list[Finding]:
    """Run every rule. `allow` is a list of source IPs to ignore (for example your own office IP)."""
    th = th or Thresholds()
    allow_set = set(allow)
    records = list(records)
    findings = (
        find_port_scans(records, th, allow_set)
        + find_port_sweeps(records, th, allow_set)
        + find_ssh_bruteforce(records, th, allow_set)
    )
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.first_seen, f.source))
