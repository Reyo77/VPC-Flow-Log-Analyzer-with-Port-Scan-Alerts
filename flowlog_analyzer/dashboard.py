"""Build one self-contained HTML dashboard (charts are embedded, no internet needed to view it)."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go

from . import analysis
from .core.detect import Finding, _iso

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1b2430;--muted:#5c6b7a;--line:#dfe4ea;--accent:#2b6cb0;
--high:#c53030;--medium:#c27c0e;--low:#2f855a}
@media (prefers-color-scheme:dark){:root{--bg:#10151c;--card:#18202a;--ink:#e6ebf1;--muted:#97a6b5;
--line:#2a3542;--accent:#63a4ec;--high:#f56565;--medium:#ecb64b;--low:#68d391}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header,main{max-width:1180px;margin:0 auto;padding:0 20px}header{padding-top:28px}
h1{margin:0;font-size:24px}.sub{color:var(--muted);margin:4px 0 0}
h2{font-size:17px;margin:0 0 10px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.kpi .v{font-size:28px;font-weight:650}.kpi .l{color:var(--muted);font-size:13px}
section{margin:16px 0}.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:12px}
table{border-collapse:collapse;width:100%;font-size:13.5px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}.num{text-align:right;font-variant-numeric:tabular-nums}
.sev{font-weight:700;text-transform:uppercase;font-size:12px}
.sev.high{color:var(--high)}.sev.medium{color:var(--medium)}.sev.low{color:var(--low)}
.empty{color:var(--muted);padding:6px 0}.scroll{overflow-x:auto}
footer{max-width:1180px;margin:20px auto 40px;padding:0 20px;color:var(--muted);font-size:13px}
"""


def _e(x) -> str:
    return html.escape("" if x is None else str(x))


def _table(df: pd.DataFrame, num_cols=()) -> str:
    if df is None or len(df) == 0:
        return '<div class="empty">Nothing to show for this period.</div>'
    head = "".join(f"<th>{_e(c)}</th>" for c in df.columns)
    rows = []
    for _, row in df.iterrows():
        cells = "".join(
            f'<td class="num">{_e(v)}</td>' if c in num_cols else f"<td>{_e(v)}</td>" for c, v in row.items()
        )
        rows.append(f"<tr>{cells}</tr>")
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def _findings_table(findings: list[Finding]) -> str:
    if not findings:
        return '<div class="empty">No scans or sweeps detected in this period.</div>'
    rows = []
    for f in findings:
        targets = ", ".join(f.targets[:3]) + (f" (+{len(f.targets) - 3} more)" if len(f.targets) > 3 else "")
        rows.append(
            f'<tr><td><span class="sev {_e(f.severity)}">{_e(f.severity)}</span></td><td>{_e(f.type)}</td>'
            f"<td>{_e(f.source)}</td><td>{_e(targets)}</td><td>{_e(f.ports)}</td>"
            f"<td>{_e(_iso(f.first_seen))}<br>{_e(_iso(f.last_seen))}</td>"
            f'<td class="num">{f.accepts}/{f.rejects}</td><td>{_e(f.detail)}</td></tr>'
        )
    head = (
        "<th>Severity</th><th>Type</th><th>Source</th><th>Target(s)</th><th>Ports</th>"
        "<th>First / last seen</th><th>Accept/Reject</th><th>What happened</th>"
    )
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def _style(fig: go.Figure, height=340) -> go.Figure:
    fig.update_layout(
        height=height,
        margin=dict(l=10, r=10, t=10, b=10),
        template="plotly_white",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#7c8a99"),
        showlegend=False,
    )
    return fig


def _fig_html(fig: go.Figure, first: bool) -> str:
    return fig.to_html(
        full_html=False, include_plotlyjs=True if first else False, config={"displaylogo": False}
    )


def build_html(df: pd.DataFrame, findings: list[Finding], title: str, period: str) -> str:
    k = analysis.kpis(df) if len(df) else {"total_flows": 0, "reject_pct": 0.0, "unique_sources": 0}
    cards = [
        ("Flow records", f"{k['total_flows']:,}"),
        ("Rejected", f"{k['reject_pct']}%"),
        ("Unique sources", f"{k['unique_sources']:,}"),
        ("Findings", str(len(findings))),
    ]
    kpi_html = "".join(
        f'<div class="card kpi"><div class="v">{v}</div><div class="l">{label}</div></div>'
        for label, v in cards
    )

    over_time = analysis.rejects_over_time(df)
    talkers = analysis.top_talkers(df)
    ports = analysis.top_rejected_ports(df)

    f1 = go.Figure(
        go.Scatter(
            x=over_time["bucket"], y=over_time["rejects"], mode="lines+markers", line=dict(color="#c53030")
        )
    )
    f1.update_yaxes(title="rejected records / 5 min")
    f2 = go.Figure(
        go.Bar(
            x=talkers["bytes"][::-1],
            y=[f"{a} → {b}" for a, b in zip(talkers["srcaddr"], talkers["dstaddr"], strict=True)][::-1],
            orientation="h",
            marker_color="#2b6cb0",
        )
    )
    f2.update_xaxes(title="bytes")
    f3 = go.Figure(
        go.Bar(
            x=ports["rejects"][::-1],
            y=[f"{p}/{pr}" for p, pr in zip(ports["dstport"], ports["proto"], strict=True)][::-1],
            orientation="h",
            marker_color="#c27c0e",
        )
    )
    f3.update_xaxes(title="rejected records")
    charts = [
        (
            "Rejects over time",
            f1,
            "Each point is the number of blocked connection records in a 5-minute window.",
        ),
        ("Top talkers", f2, "Source → destination pairs that moved the most bytes."),
        ("Top rejected ports", f3, "Destination ports that were blocked most often."),
    ]
    chart_html = []
    for i, (name, fig, note) in enumerate(charts):
        body = _fig_html(_style(fig), first=(i == 0)) if len(df) else '<div class="empty">No data.</div>'
        chart_html.append(
            f'<section class="card"><h2>{name}</h2><div class="sub">{note}</div>{body}</section>'
        )

    ext = analysis.external_sources(df) if len(df) else pd.DataFrame()
    io = analysis.internal_vs_external(df) if len(df) else pd.DataFrame()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{_e(title)}</title>
<style>{CSS}</style></head><body>
<header><h1>{_e(title)}</h1><p class="sub">{_e(period)} · generated {generated}</p></header>
<main>
<div class="kpis">{kpi_html}</div>
<section class="card"><h2>Findings</h2>{_findings_table(findings)}</section>
{chart_html[0]}
<div class="grid2">{chart_html[1]}{chart_html[2]}</div>
<div class="grid2">
<section class="card"><h2>Internal vs external sources</h2>
<div class="sub">Records by where the source address is: inside our private ranges, or on the internet.</div>{_table(io)}</section>
<section class="card"><h2>Top external sources</h2>
<div class="sub">Outside addresses that touched us (ports/hosts = how many different ones they used).</div>{_table(ext)}</section>
</div>
</main>
<footer>Built from VPC Flow Logs (default format v2). Flow logs show who talked to whom, not what was said.</footer>
</body></html>"""


def write_dashboard(df, findings, path: str | Path, title: str, period: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_html(df, findings, title, period), encoding="utf-8")
    return path
