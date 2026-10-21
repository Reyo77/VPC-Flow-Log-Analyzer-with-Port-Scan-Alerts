import json

import pytest

from tools import portscan, validate


def test_scanner_refuses_public_and_non_ip_targets():
    for bad in ("8.8.8.8", "203.0.113.5", "172.16.0.5", "192.168.1.1", "example.com", "127.0.0.1"):
        with pytest.raises(ValueError):
            portscan.check_target(bad)
    assert portscan.check_target("10.1.1.192") == "10.1.1.192"


def test_main_refuses_public_ip_with_exit_code_2(tmp_path, capsys):
    assert portscan.main(["8.8.8.8", "--out", str(tmp_path / "x.json")]) == 2
    assert "refusing to scan" in capsys.readouterr().err
    assert not (tmp_path / "x.json").exists()


def test_parse_ports_limits():
    assert portscan.parse_ports("22") == [22]
    assert portscan.parse_ports("1-1024")[-1] == 1024 and len(portscan.parse_ports("1-1024")) == 1024
    for bad in ("1-1025", "0-10", "70000", "50-10"):
        with pytest.raises(ValueError):
            portscan.parse_ports(bad)


def test_scan_returns_open_ports_using_injected_connect():
    open_set = {22, 80}
    found = portscan.scan("10.1.1.1", list(range(1, 101)), connect=lambda h, p, t: p in open_set)
    assert found == [22, 80]


def truth(**kw):
    base = {
        "scanner_ip": "10.0.0.83", "target": "10.1.1.192", "port_range": [1, 1024], "ports_scanned": 1024,
        "open_ports": [22], "start_epoch": 1000, "end_epoch": 1100,
        "start_utc": "t0", "end_utc": "t1",
    }  # fmt: skip
    base.update(kw)
    return base


def finding(**kw):
    base = {
        "type": "port_scan", "source": "10.0.0.83", "targets": ["10.1.1.192"], "ports": "1-1024 (1024 ports)",
        "first_seen": 1005, "last_seen": 1090, "first_seen_utc": "a", "last_seen_utc": "b",
        "detail": "x. Ports that answered (open): 22 (1 ports).",
    }  # fmt: skip
    base.update(kw)
    return base


def test_validate_passes_for_matching_detection():
    ok, checks = validate.validate(truth(), {"findings": [finding()]})
    assert ok and all(c[1] for c in checks)


def test_validate_fails_when_not_detected_or_wrong_source_or_wrong_time_or_few_ports():
    assert not validate.validate(truth(), {"findings": []})[0]
    assert not validate.validate(truth(), {"findings": [finding(source="10.0.0.99")]})[0]
    assert not validate.validate(truth(), {"findings": [finding(first_seen=9000, last_seen=9100)]})[0]
    assert not validate.validate(truth(), {"findings": [finding(ports="1-100 (100 ports)")]})[0]


def test_validate_main_exit_codes(tmp_path):
    t, f = tmp_path / "t.json", tmp_path / "f.json"
    t.write_text(json.dumps(truth()))
    f.write_text(json.dumps({"findings": [finding()]}))
    assert validate.main([str(t), str(f)]) == 0
    f.write_text(json.dumps({"findings": []}))
    assert validate.main([str(t), str(f)]) == 1
