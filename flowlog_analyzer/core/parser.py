"""Turn one VPC Flow Log line into a typed record.

A flow log line is 14 values separated by spaces (AWS default format, version 2):
  version account-id interface-id srcaddr dstaddr srcport dstport protocol
  packets bytes start end action log-status
Pure Python on purpose: the Lambda function uses this file too, and must stay small.
"""

from __future__ import annotations

import gzip
import ipaddress
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6"}

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

FIELD_COUNT = 14


@dataclass(frozen=True)
class FlowRecord:
    version: int | None
    account_id: str | None
    interface_id: str | None
    srcaddr: str | None
    dstaddr: str | None
    srcport: int | None
    dstport: int | None
    protocol: int | None
    packets: int | None
    bytes: int | None
    start: int | None  # Unix time (seconds, UTC) of the first packet in the window
    end: int | None
    action: str | None  # ACCEPT or REJECT
    log_status: str  # OK, NODATA (no traffic in the window) or SKIPDATA (records were lost)

    @property
    def protocol_name(self) -> str:
        if self.protocol is None:
            return "-"
        return PROTOCOLS.get(self.protocol, str(self.protocol))

    @property
    def is_data(self) -> bool:
        """True for a real traffic record (not NODATA / SKIPDATA)."""
        return self.log_status == "OK"


def is_private(ip: str | None) -> bool:
    """True if ip is a private (RFC1918) address. Missing or invalid values give False."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETS)


def _int(value: str) -> int | None:
    return None if value == "-" else int(value)


def _str(value: str) -> str | None:
    return None if value == "-" else value


def parse_line(line: str) -> FlowRecord | None:
    """Parse one line. Returns None for the header, blank lines and malformed lines (never raises)."""
    parts = line.split()
    if len(parts) != FIELD_COUNT or parts[0] == "version":
        return None
    try:
        return FlowRecord(
            version=_int(parts[0]),
            account_id=_str(parts[1]),
            interface_id=_str(parts[2]),
            srcaddr=_str(parts[3]),
            dstaddr=_str(parts[4]),
            srcport=_int(parts[5]),
            dstport=_int(parts[6]),
            protocol=_int(parts[7]),
            packets=_int(parts[8]),
            bytes=_int(parts[9]),
            start=_int(parts[10]),
            end=_int(parts[11]),
            action=_str(parts[12]),
            log_status=parts[13],
        )
    except ValueError:
        return None


def parse_lines(lines, include_nodata: bool = False) -> Iterator[FlowRecord]:
    for line in lines:
        rec = parse_line(line)
        if rec is None:
            continue
        if rec.is_data or include_nodata:
            yield rec


def parse_file(path: str | Path, include_nodata: bool = False) -> Iterator[FlowRecord]:
    """Read a .log or .log.gz file and yield records."""
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        yield from parse_lines(fh, include_nodata=include_nodata)
