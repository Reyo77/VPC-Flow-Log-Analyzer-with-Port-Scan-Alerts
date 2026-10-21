"""Find, download and read flow log objects from S3 (read-only: only list and get calls).

AWS stores flow logs under a predictable path, one folder per day:
  AWSLogs/<account-id>/vpcflowlogs/<region>/YYYY/MM/DD/<file>.log.gz
so we can ask S3 for just the days we need instead of listing the whole bucket.
"""

from __future__ import annotations

import gzip
from collections.abc import Iterable, Iterator
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .parser import FlowRecord, parse_file, parse_lines


def day_prefix(account: str, region: str, day: date) -> str:
    return f"AWSLogs/{account}/vpcflowlogs/{region}/{day:%Y/%m/%d}/"


def date_range(days: int, today: date | None = None) -> list[date]:
    """The last `days` calendar days in UTC, oldest first, including today."""
    today = today or datetime.now(timezone.utc).date()
    return [today - timedelta(days=i) for i in range(days - 1, -1, -1)]


def list_log_keys(s3, bucket: str, account: str, region: str, days: Iterable[date]) -> list[str]:
    """List the log object keys for the given days (sorted)."""
    paginator = s3.get_paginator("list_objects_v2")
    keys: list[str] = []
    for day in days:
        for page in paginator.paginate(Bucket=bucket, Prefix=day_prefix(account, region, day)):
            keys.extend(obj["Key"] for obj in page.get("Contents", []))
    return sorted(keys)


def cache_path(cache_dir: Path, key: str) -> Path:
    return Path(cache_dir) / key.replace("/", "__")


def download(s3, bucket: str, key: str, cache_dir: Path) -> Path:
    """Download one object into the local cache. Files already cached are not downloaded again."""
    dest = cache_path(cache_dir, key)
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    s3.download_file(bucket, key, str(tmp))
    tmp.rename(dest)
    return dest


def read_key(
    s3, bucket: str, key: str, cache_dir: Path | None = None, include_nodata: bool = False
) -> Iterator[FlowRecord]:
    """Yield the records in one object. With a cache dir the file is cached on disk; without one
    (for example in Lambda) it is read straight into memory."""
    if cache_dir is not None:
        yield from parse_file(download(s3, bucket, key, cache_dir), include_nodata=include_nodata)
        return
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    if key.endswith(".gz"):
        body = gzip.decompress(body)
    yield from parse_lines(body.decode("utf-8", errors="replace").splitlines(), include_nodata=include_nodata)


def iter_records(
    s3, bucket: str, keys: Iterable[str], cache_dir: Path | None = None, include_nodata: bool = False
) -> Iterator[FlowRecord]:
    for key in keys:
        yield from read_key(s3, bucket, key, cache_dir, include_nodata)


def in_window(records: Iterable[FlowRecord], start: int, end: int) -> Iterator[FlowRecord]:
    """Keep records whose window start falls between two Unix timestamps (inclusive)."""
    for r in records:
        if r.start is not None and start <= r.start <= end:
            yield r
