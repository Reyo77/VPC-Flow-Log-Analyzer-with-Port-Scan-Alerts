import gzip
from datetime import date
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from flowlog_analyzer.core import s3_source

FIX = Path(__file__).parent / "fixtures"
ACCT, REGION, BUCKET = "111122223333", "ap-southeast-2", "p1-flowlogs-test"


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name=REGION)
        client.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
        gz = (FIX / "sample.log.gz").read_bytes()
        for day, name in [("2026/10/19", "a"), ("2026/10/20", "b"), ("2026/10/20", "c"), ("2026/10/21", "d")]:
            client.put_object(
                Bucket=BUCKET, Key=f"AWSLogs/{ACCT}/vpcflowlogs/{REGION}/{day}/{name}.log.gz", Body=gz
            )
        # an object for a different region must never be picked up
        client.put_object(
            Bucket=BUCKET, Key=f"AWSLogs/{ACCT}/vpcflowlogs/us-west-2/2026/10/20/x.log.gz", Body=gz
        )
        yield client


def test_day_prefix():
    assert (
        s3_source.day_prefix(ACCT, REGION, date(2026, 10, 5))
        == f"AWSLogs/{ACCT}/vpcflowlogs/{REGION}/2026/10/05/"
    )


def test_date_range_oldest_first_includes_today():
    assert s3_source.date_range(3, today=date(2026, 10, 21)) == [
        date(2026, 10, 19),
        date(2026, 10, 20),
        date(2026, 10, 21),
    ]


def test_list_keys_filters_by_day_and_region(s3):
    keys = s3_source.list_log_keys(s3, BUCKET, ACCT, REGION, [date(2026, 10, 20)])
    assert [k.rsplit("/", 1)[1] for k in keys] == ["b.log.gz", "c.log.gz"]
    both = s3_source.list_log_keys(s3, BUCKET, ACCT, REGION, [date(2026, 10, 20), date(2026, 10, 21)])
    assert len(both) == 3
    assert s3_source.list_log_keys(s3, BUCKET, ACCT, REGION, [date(2026, 1, 1)]) == []


def test_read_without_cache_gives_records(s3):
    keys = s3_source.list_log_keys(s3, BUCKET, ACCT, REGION, [date(2026, 10, 21)])
    assert len(list(s3_source.iter_records(s3, BUCKET, keys))) == 25


def test_cache_is_used_second_time(s3, tmp_path):
    keys = s3_source.list_log_keys(s3, BUCKET, ACCT, REGION, [date(2026, 10, 21)])
    first = list(s3_source.iter_records(s3, BUCKET, keys, tmp_path))
    assert len(list(tmp_path.iterdir())) == 1
    s3.delete_object(Bucket=BUCKET, Key=keys[0])  # gone from S3, but still cached
    assert list(s3_source.iter_records(s3, BUCKET, keys, tmp_path)) == first


def test_in_window_filters_on_start_time(s3):
    keys = s3_source.list_log_keys(s3, BUCKET, ACCT, REGION, [date(2026, 10, 21)])
    recs = list(s3_source.iter_records(s3, BUCKET, keys))
    inside = list(s3_source.in_window(recs, 1700000000, 1700000100))
    assert inside and all(1700000000 <= r.start <= 1700000100 for r in inside)
    assert len(inside) < len(recs)


def test_plain_log_file_also_readable(s3):
    s3.put_object(
        Bucket=BUCKET, Key="AWSLogs/x/plain.log", Body=gzip.decompress((FIX / "sample.log.gz").read_bytes())
    )
    assert len(list(s3_source.read_key(s3, BUCKET, "AWSLogs/x/plain.log"))) == 25
