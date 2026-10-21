from pathlib import Path

from flowlog_analyzer import analysis, dashboard
from flowlog_analyzer.core.detect import Finding, detect
from flowlog_analyzer.core.parser import parse_file

FIX = Path(__file__).parent / "fixtures"
SECTIONS = [
    "Findings",
    "Rejects over time",
    "Top talkers",
    "Top rejected ports",
    "Internal vs external sources",
]


def _build(tmp_path, findings=None):
    recs = list(parse_file(FIX / "sample.log"))
    df = analysis.to_dataframe(recs)
    findings = findings if findings is not None else detect(recs)
    return dashboard.write_dashboard(
        df, findings, tmp_path / "d.html", "Test dashboard", "fixture"
    ).read_text()


def test_file_is_big_enough_and_has_every_section(tmp_path):
    text = _build(tmp_path)
    assert (tmp_path / "d.html").stat().st_size > 10_000
    for name in SECTIONS:
        assert name in text, name
    assert "Flow records" in text and "Unique sources" in text


def test_finding_appears_with_severity_class_and_is_escaped(tmp_path):
    f = Finding("port_scan", "high", "203.0.113.9", ["10.0.0.10"], "1-20 (20 ports)", 1_700_000_000, 1_700_000_060,
                20, 0, 20, "probed <script>alert(1)</script> ports")  # fmt: skip
    text = _build(tmp_path, [f])
    assert 'class="sev high"' in text and "203.0.113.9" in text and "port_scan" in text
    assert "<script>alert(1)</script>" not in text and "&lt;script&gt;" in text


def test_no_findings_message(tmp_path):
    assert "No scans or sweeps detected" in _build(tmp_path, [])


def test_empty_data_does_not_crash(tmp_path):
    df = analysis.to_dataframe([])
    text = dashboard.write_dashboard(df, [], tmp_path / "e.html", "Empty", "none").read_text()
    assert "No data." in text
