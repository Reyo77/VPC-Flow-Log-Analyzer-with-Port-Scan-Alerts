"""Questions we ask the logs, answered with pandas.

A DataFrame is a spreadsheet in Python: one row per flow record, one column per field.
"group by" works like a pivot table: group rows that share a value, then add them up.
"""

from __future__ import annotations

import pandas as pd

from .core.parser import PROTOCOLS, FlowRecord, is_private

COLUMNS = [
    "interface_id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
    "packets", "bytes", "start", "end", "action",
]  # fmt: skip


def to_dataframe(records: list[FlowRecord]) -> pd.DataFrame:
    """Turn parsed records into a table, plus a few helper columns."""
    df = pd.DataFrame([{c: getattr(r, c) for c in COLUMNS} for r in records], columns=COLUMNS)
    df["start_time"] = pd.to_datetime(df["start"], unit="s", utc=True)
    df["proto"] = df["protocol"].map(PROTOCOLS).fillna(df["protocol"].astype("string"))
    df["src_private"] = df["srcaddr"].map(is_private)
    df["dst_private"] = df["dstaddr"].map(is_private)
    return df


def top_talkers(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Source -> destination pairs that moved the most bytes."""
    g = df.groupby(["srcaddr", "dstaddr"], as_index=False).agg(
        bytes=("bytes", "sum"), packets=("packets", "sum"), flows=("bytes", "size")
    )
    return g.sort_values(["bytes", "packets"], ascending=False).head(n).reset_index(drop=True)


def top_ports(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Destination ports that appear in the most flow records (all actions)."""
    d = df.dropna(subset=["dstport"])
    g = d.groupby(["dstport", "proto"], as_index=False).agg(
        flows=("bytes", "size"), packets=("packets", "sum")
    )
    g["dstport"] = g["dstport"].astype(int)
    return g.sort_values(["flows", "packets"], ascending=False).head(n).reset_index(drop=True)


def top_rejected_ports(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Destination ports that were blocked most often, with how many different sources tried."""
    d = df[(df["action"] == "REJECT") & df["dstport"].notna()]
    g = d.groupby(["dstport", "proto"], as_index=False).agg(
        rejects=("bytes", "size"), sources=("srcaddr", "nunique")
    )
    g["dstport"] = g["dstport"].astype(int)
    return g.sort_values(["rejects", "sources"], ascending=False).head(n).reset_index(drop=True)


def rejects_over_time(df: pd.DataFrame, freq: str = "5min") -> pd.DataFrame:
    """Number of REJECT records in each time bucket (empty buckets show as 0)."""
    rej = df[df["action"] == "REJECT"]
    if rej.empty:
        return pd.DataFrame(
            {"bucket": pd.Series(dtype="datetime64[ns, UTC]"), "rejects": pd.Series(dtype="int64")}
        )
    counts = rej.groupby(rej["start_time"].dt.floor(freq)).size()
    full = pd.date_range(counts.index.min(), counts.index.max(), freq=freq, tz="UTC")
    counts = counts.reindex(full, fill_value=0)
    return pd.DataFrame({"bucket": counts.index, "rejects": counts.to_numpy()})


def accept_reject_per_interface(df: pd.DataFrame) -> pd.DataFrame:
    t = pd.crosstab(df["interface_id"], df["action"]).reset_index()
    for col in ("ACCEPT", "REJECT"):
        if col not in t:
            t[col] = 0
    t["reject_pct"] = (100 * t["REJECT"] / (t["ACCEPT"] + t["REJECT"])).round(1)
    return (
        t[["interface_id", "ACCEPT", "REJECT", "reject_pct"]]
        .sort_values("REJECT", ascending=False)
        .reset_index(drop=True)
    )


def internal_vs_external(df: pd.DataFrame) -> pd.DataFrame:
    """Records split by where the source is: inside our private ranges or out on the internet."""
    kind = df["src_private"].map({True: "internal", False: "external"})
    t = pd.crosstab(kind, df["action"]).reset_index().rename(columns={"src_private": "source"})
    t.columns.name = None
    return t


def external_sources(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Outside addresses that touched us: how many records, how many were blocked, how many ports/hosts."""
    ext = df[~df["src_private"] & df["srcaddr"].notna()]
    g = ext.groupby("srcaddr", as_index=False).agg(
        records=("bytes", "size"),
        rejects=("action", lambda a: int((a == "REJECT").sum())),
        ports=("dstport", "nunique"),
        hosts=("dstaddr", "nunique"),
    )
    return g.sort_values(["records", "rejects"], ascending=False).head(n).reset_index(drop=True)


def kpis(df: pd.DataFrame) -> dict:
    total = len(df)
    rejects = int((df["action"] == "REJECT").sum())
    return {
        "total_flows": total,
        "rejects": rejects,
        "reject_pct": round(100 * rejects / total, 1) if total else 0.0,
        "unique_sources": int(df["srcaddr"].nunique()),
        "external_sources": int(df.loc[~df["src_private"], "srcaddr"].nunique()),
    }


def summary_tables(df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    return {
        "Top talkers (by bytes)": top_talkers(df),
        "Top destination ports (all)": top_ports(df),
        "Top rejected ports": top_rejected_ports(df),
        "Rejects over time (5-minute buckets)": rejects_over_time(df),
        "Accept vs reject per interface": accept_reject_per_interface(df),
        "Internal vs external sources": internal_vs_external(df),
        "Top external sources": external_sources(df),
    }
