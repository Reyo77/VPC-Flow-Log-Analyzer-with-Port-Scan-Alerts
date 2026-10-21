from pathlib import Path

from flowlog_analyzer.core.detect import Thresholds, detect, summarize_ports
from flowlog_analyzer.core.parser import FlowRecord, parse_file

T0 = 1_700_000_000


def rec(src, dst, dport, start, action="REJECT", sport=40000, proto=6, eni="eni-0000test"):
    return FlowRecord(
        2, "111122223333", eni, src, dst, sport, dport, proto, 1, 60, start, start + 30, action, "OK"
    )


def scan(src="203.0.113.9", dst="10.0.0.10", n=20, spacing=3, first_port=1000, action="REJECT", t0=T0):
    return [rec(src, dst, first_port + i, t0 + i * spacing, action, sport=50000 + i) for i in range(n)]


def kinds(findings):
    return [f.type for f in findings]


# ---- vertical port scan -------------------------------------------------------------------------
def test_scan_20_ports_in_one_minute_is_detected():
    f = detect(scan(n=20, spacing=3))
    assert kinds(f) == ["port_scan"]
    assert f[0].source == "203.0.113.9" and f[0].targets == ["10.0.0.10"]
    assert f[0].ports == "1000-1019 (20 ports)" and f[0].rejects == 20 and f[0].records == 20
    assert f[0].severity == "medium"


def test_scan_boundary_14_ports_not_15_ports_yes():
    assert detect(scan(n=14)) == []
    assert kinds(detect(scan(n=15))) == ["port_scan"]


def test_scan_spread_over_two_hours_is_not_detected():
    assert detect(scan(n=20, spacing=360)) == []


def test_scan_time_boundary_300_seconds_inclusive():
    recs = scan(n=15, spacing=1)
    recs[-1] = rec("203.0.113.9", "10.0.0.10", 1014, T0 + 300, sport=50014)  # exactly 300 s after the first
    assert kinds(detect(recs)) == ["port_scan"]
    recs[-1] = rec("203.0.113.9", "10.0.0.10", 1014, T0 + 301, sport=50014)  # 301 s: one second too late
    assert detect(recs) == []


def test_many_ports_but_mostly_accepted_is_normal_traffic():
    # like the replies of a big download coming back to many random ports
    assert detect(scan(n=40, action="ACCEPT", src="91.189.91.157")) == []


def test_scan_that_finds_open_ports_is_high_severity():
    recs = scan(n=20)
    recs.append(rec("203.0.113.9", "10.0.0.10", 22, T0 + 5, "ACCEPT", sport=51000))
    f = detect(recs)
    assert f[0].severity == "high" and "22" in f[0].detail and f[0].accepts == 1


def test_two_attackers_are_separate_findings():
    f = detect(scan(src="203.0.113.9") + scan(src="198.51.100.77", dst="10.0.0.20"))
    assert sorted(x.source for x in f) == ["198.51.100.77", "203.0.113.9"]


def test_same_attacker_two_bursts_hours_apart_are_two_findings():
    f = detect(scan(t0=T0) + scan(t0=T0 + 7200))
    assert kinds(f) == ["port_scan", "port_scan"]


def test_icmp_and_nodata_are_ignored():
    icmp = [rec("203.0.113.9", "10.0.0.10", 0, T0 + i, proto=1) for i in range(30)]
    assert detect(icmp) == []


def test_allowlisted_source_is_ignored():
    assert detect(scan(), allow=["203.0.113.9"]) == []


def test_thresholds_can_be_changed():
    assert kinds(detect(scan(n=10), Thresholds(scan_ports=10))) == ["port_scan"]


def test_works_with_unsorted_input():
    recs = scan(n=20)
    recs.reverse()
    assert kinds(detect(recs)) == ["port_scan"]


# ---- horizontal sweep ---------------------------------------------------------------------------
def sweep(n, port=22, src="203.0.113.9"):
    return [rec(src, f"10.0.0.{10 + i}", port, T0 + i * 5, sport=52000 + i) for i in range(n)]


def test_sweep_same_port_many_hosts():
    f = detect(sweep(5))
    assert kinds(f) == ["port_sweep"] and f[0].ports == "22 (1 ports)" and len(f[0].targets) == 5


def test_sweep_boundary_4_hosts_not_detected():
    assert detect(sweep(4)) == []


def test_sweep_from_internal_host_to_internet_is_low_severity():
    blocked = [rec("10.0.0.83", f"34.1.1.{i}", 443, T0 + i * 5, sport=55000 + i) for i in range(8)]
    f = detect(blocked)
    assert kinds(f) == ["port_sweep"] and f[0].severity == "low" and "blocked egress" in f[0].detail


def test_sweep_from_internal_host_to_internal_hosts_stays_medium():
    inside = [rec("10.0.0.83", f"10.1.1.{i}", 22, T0 + i * 5, sport=56000 + i) for i in range(8)]
    assert detect(inside)[0].severity == "medium"


def test_sweep_of_accepted_web_traffic_is_normal():
    web = [rec("10.0.0.10", f"34.1.1.{i}", 443, T0 + i, "ACCEPT", sport=53000 + i) for i in range(10)]
    assert detect(web) == []


# ---- ssh brute force ----------------------------------------------------------------------------
def ssh(n, src="203.0.113.9", action="REJECT"):
    return [rec(src, "10.0.0.10", 22, T0 + i * 20, action, sport=54000 + i) for i in range(n)]


def test_ssh_bruteforce_20_connections_detected():
    f = detect(ssh(20))
    assert kinds(f) == ["ssh_bruteforce"] and f[0].severity == "medium"


def test_ssh_bruteforce_boundary_19_not_detected():
    assert detect(ssh(19)) == []


def test_ssh_from_inside_the_network_is_not_flagged():
    assert detect(ssh(30, src="10.0.0.99")) == []


def test_ssh_accepted_connections_are_high_severity():
    assert detect(ssh(20, action="ACCEPT"))[0].severity == "high"


def test_ssh_allowlist():
    assert detect(ssh(30), allow=["203.0.113.9"]) == []


# ---- helpers and the fixture file ---------------------------------------------------------------
def test_summarize_ports():
    assert summarize_ports([22]) == "22 (1 ports)"
    assert summarize_ports([1, 2, 3, 22, 80, 81]) == "1-3,22,80-81 (6 ports)"
    assert summarize_ports(range(1, 1025)) == "1-1024 (1024 ports)"
    assert summarize_ports([]) == "-"


def test_sample_fixture_has_no_findings():
    recs = list(parse_file(Path(__file__).parent / "fixtures" / "sample.log"))
    assert detect(recs) == []


def test_finding_to_dict_has_readable_times():
    d = detect(scan())[0].to_dict()
    assert d["first_seen_utc"].endswith("UTC") and d["type"] == "port_scan"
