from pathlib import Path

import pytest

from flowlog_analyzer import analysis
from flowlog_analyzer.core.parser import parse_file

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def df():
    return analysis.to_dataframe(list(parse_file(FIX / "sample.log")))


def test_dataframe_shape_and_helper_columns(df):
    assert len(df) == 25
    assert {"start_time", "proto", "src_private", "dst_private"} <= set(df.columns)
    assert str(df["start_time"].dt.tz) == "UTC"


def test_most_rejected_port_is_3306_with_4_rejects(df):
    top = analysis.top_rejected_ports(df)
    assert (int(top.loc[0, "dstport"]), int(top.loc[0, "rejects"])) == (3306, 4)
    assert int(top["rejects"].sum()) == 9


def test_top_talker_by_bytes(df):
    top = analysis.top_talkers(df)
    assert (top.loc[0, "srcaddr"], top.loc[0, "dstaddr"], int(top.loc[0, "bytes"])) == (
        "10.0.0.10",
        "198.51.100.7",
        5200,
    )


def test_top_ports_counts_443_twice(df):
    row = analysis.top_ports(df, 20).set_index("dstport").loc[443]
    assert int(row["flows"]) == 2


def test_rejects_over_time_peak_is_the_three_external_scan_records(df):
    t = analysis.rejects_over_time(df)
    assert int(t["rejects"].sum()) == 9
    peak = t.loc[t["rejects"].idxmax()]
    assert int(peak["rejects"]) == 3 and int(peak["bucket"].timestamp()) == 1700000400
    assert (t["rejects"] == 0).any()  # empty buckets are filled in


def test_accept_reject_per_interface(df):
    t = analysis.accept_reject_per_interface(df).set_index("interface_id")
    assert int(t.loc["eni-0000test2", "REJECT"]) == 3
    assert int(t.loc["eni-0000test1", "REJECT"]) == 4


def test_external_sources(df):
    ext = analysis.external_sources(df, 20).set_index("srcaddr")
    assert set(ext.index) == {
        "203.0.113.50",
        "203.0.113.51",
        "198.51.100.7",
        "192.0.2.10",
        "8.8.8.8",
        "172.32.0.1",
    }
    assert int(ext.loc["203.0.113.50", "rejects"]) == 2 and int(ext.loc["203.0.113.50", "ports"]) == 2


def test_internal_vs_external(df):
    t = analysis.internal_vs_external(df).set_index("source")
    assert int(t.loc["internal"].sum()) + int(t.loc["external"].sum()) == 25


def test_kpis(df):
    k = analysis.kpis(df)
    assert k["total_flows"] == 25 and k["rejects"] == 9 and k["reject_pct"] == 36.0


def test_empty_input_does_not_crash():
    empty = analysis.to_dataframe([])
    assert len(analysis.top_talkers(empty)) == 0
    assert len(analysis.rejects_over_time(empty)) == 0
    assert analysis.kpis(empty)["total_flows"] == 0
