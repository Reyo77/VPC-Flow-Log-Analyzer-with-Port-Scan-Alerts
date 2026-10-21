from pathlib import Path

from flowlog_analyzer.core.parser import is_private, parse_file, parse_line

FIX = Path(__file__).parent / "fixtures"


def test_parse_accept_line_types():
    r = parse_line(
        "2 111122223333 eni-0000test1 10.0.0.10 10.1.1.20 40001 22 6 10 1200 1700000000 1700000060 ACCEPT OK"
    )
    assert r.srcaddr == "10.0.0.10" and r.dstaddr == "10.1.1.20"
    assert (r.srcport, r.dstport, r.protocol) == (40001, 22, 6)
    assert (r.packets, r.bytes, r.start, r.end) == (10, 1200, 1700000000, 1700000060)
    assert r.action == "ACCEPT" and r.is_data and r.protocol_name == "TCP"


def test_header_is_skipped():
    header = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"
    assert parse_line(header) is None


def test_dash_becomes_none():
    r = parse_line(
        "2 111122223333 eni-0000test3 10.0.0.10 192.0.2.10 - - 50 7 840 1700000800 1700000860 ACCEPT OK"
    )
    assert r.srcport is None and r.dstport is None and r.protocol_name == "ESP"


def test_nodata_and_skipdata_records():
    r = parse_line("2 111122223333 eni-0000test4 - - - - - - - 1700000900 1700000960 - NODATA")
    assert r.log_status == "NODATA" and not r.is_data and r.srcaddr is None and r.action is None
    assert (
        parse_line("2 111122223333 eni-0000test4 - - - - - - - 1700000960 1700001020 - SKIPDATA").log_status
        == "SKIPDATA"
    )


def test_malformed_lines_return_none():
    assert parse_line("") is None
    assert parse_line("this line is not a flow log record") is None
    assert (
        parse_line(
            "2 111122223333 eni-0000test4 10.0.0.10 10.1.1.20 notaport 22 6 1 60 1700001400 1700001430 ACCEPT OK"
        )
        is None
    )


def test_parse_file_plain_skips_nodata_by_default():
    recs = list(parse_file(FIX / "sample.log"))
    assert len(recs) == 25
    assert all(r.is_data for r in recs)
    assert sum(r.action == "REJECT" for r in recs) == 9


def test_parse_file_can_include_nodata():
    assert len(list(parse_file(FIX / "sample.log", include_nodata=True))) == 27


def test_gzip_matches_plain():
    assert list(parse_file(FIX / "sample.log.gz")) == list(parse_file(FIX / "sample.log"))


def test_is_private():
    for ip in ("10.0.0.1", "172.16.5.5", "172.31.255.255", "192.168.1.5"):
        assert is_private(ip), ip
    for ip in ("8.8.8.8", "172.32.0.1", "203.0.113.50", "", None, "not-an-ip"):
        assert not is_private(ip), ip
