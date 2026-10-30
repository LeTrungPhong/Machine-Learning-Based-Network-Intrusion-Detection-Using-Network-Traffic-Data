"""Compare flows produced by this project with the published CIC-IDS-2017 flows.

The labelled CSVs (GeneratedLabelledFlows) carry the 5-tuple and a start
timestamp in local time with minute resolution, so flows are matched on the
undirected 5-tuple plus start minute (+/- ``--tolerance-min``). Feature
agreement is measured only on unambiguous pairs (exactly one flow on each
side for that key and minute).

Usage:
    python scripts/compare_flows_with_cic.py --flows <ours.flows.parquet> --cic <labelled.csv> [...]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from preprocessing.cic_csv import parse_cic_timestamp, read_cic_csv  # noqa: E402
from preprocessing.flow_extraction import CIC_COLUMN_MAP  # noqa: E402
from utils.config import load_config  # noqa: E402

COMPARE = ["flow_duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
           "fwd_pkt_len_max", "bwd_pkt_len_max", "flow_iat_mean", "syn_flag_cnt", "fin_flag_cnt",
           "init_win_bytes_fwd", "init_win_bytes_bwd"]


def load_cic(paths: list[str], encoding: str, tz: str) -> pd.DataFrame:
    """Load labelled CIC CSVs with UTC start minute and normalised labels."""
    cols = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp", "Label",
            *[CIC_COLUMN_MAP[c] for c in COMPARE]]
    ds = {"csv_encoding": encoding}
    df = pd.concat([read_cic_csv(p, ds, usecols=cols) for p in paths], ignore_index=True)
    df["minute_utc"] = parse_cic_timestamp(df["Timestamp"], tz).dt.floor("min")
    df = df.rename(columns={"Source IP": "src_ip", "Source Port": "src_port", "Destination IP": "dst_ip",
                            "Destination Port": "dst_port", "Protocol": "protocol"})
    return df.rename(columns={v: f"cic_{k}" for k, v in CIC_COLUMN_MAP.items() if k in COMPARE})


def undirected_key(df: pd.DataFrame) -> pd.Series:
    a = df["src_ip"].astype(str) + ":" + df["src_port"].astype("int64").astype(str)
    b = df["dst_ip"].astype(str) + ":" + df["dst_port"].astype("int64").astype(str)
    lo, hi = np.where(a <= b, a, b), np.where(a <= b, b, a)
    return pd.Series(lo, index=df.index) + "|" + pd.Series(hi, index=df.index) + "|" + df["protocol"].astype("int64").astype(str)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--flows", required=True)
    ap.add_argument("--cic", nargs="+", required=True)
    ap.add_argument("--tolerance-min", type=int, default=1)
    ap.add_argument("--margin-s", type=float, default=150.0,
                    help="ignore flows starting this close to the end of our input (they may be cut)")
    ap.add_argument("--out", default=None, help="write the report as JSON")
    args = ap.parse_args(argv)

    cfg = load_config()
    ccfg = cfg["datasets"]["cicids2017"]
    ours = pd.read_parquet(args.flows)
    cic = load_cic(args.cic, ccfg["csv_encoding"], ccfg["csv_timezone"])

    ours["minute_utc"] = ours["timestamp"].dt.floor("min")
    lo = ours["minute_utc"].min() + pd.Timedelta(minutes=1)          # first minute may be partial
    hi = (ours["timestamp"].max() - pd.Timedelta(seconds=args.margin_s)).floor("min")
    ours_w = ours[(ours["minute_utc"] >= lo) & (ours["minute_utc"] < hi)].copy()
    cic_w = cic[(cic["minute_utc"] >= lo) & (cic["minute_utc"] < hi)].copy()
    ours_w["key"], cic_w["key"] = undirected_key(ours_w), undirected_key(cic_w)

    tol = pd.Timedelta(minutes=args.tolerance_min)
    cand = cic_w[["key", "minute_utc"]].reset_index().merge(
        ours_w[["key", "minute_utc"]].reset_index(), on="key", suffixes=("_cic", "_ours"))
    cand = cand[(cand["minute_utc_cic"] - cand["minute_utc_ours"]).abs() <= tol]
    cic_cov = cic_w.index.isin(cand["index_cic"]).mean() if len(cic_w) else float("nan")
    matched = cic_w.index.isin(cand["index_cic"])
    cov_by_label = {lab: {"cic_flows": int((cic_w["Label"] == lab).sum()),
                          "matched": float(matched[(cic_w["Label"] == lab).to_numpy()].mean())}
                    for lab in cic_w["Label"].value_counts().index}
    ours_cov = ours_w.index.isin(cand["index_ours"]).mean() if len(ours_w) else float("nan")

    # Unambiguous pairs: one flow per side for (key, exact minute)
    c1 = cic_w.groupby(["key", "minute_utc"]).filter(lambda g: len(g) == 1)
    o1 = ours_w.groupby(["key", "minute_utc"]).filter(lambda g: len(g) == 1)
    pairs = c1.merge(o1, on=["key", "minute_utc"], suffixes=("_cic", ""))
    same_dir = ((pairs["src_ip_cic"] == pairs["src_ip"]) & (pairs["src_port_cic"] == pairs["src_port"])).mean()

    agree: dict[str, dict[str, float]] = {}
    for c in COMPARE:
        a, b = pairs[c].astype(float), pairs[f"cic_{c}"].astype(float)
        rel = (a - b).abs() / b.abs().clip(lower=1)
        agree[c] = {"exact": float((a == b).mean()), "within_1pct": float((rel <= 0.01).mean()),
                    "median_abs_diff": float((a - b).abs().median())}
    tot_ours = pairs["fwd_pkts"] + pairs["bwd_pkts"]
    tot_cic = pairs["cic_fwd_pkts"] + pairs["cic_bwd_pkts"]

    report = {
        "window_utc": [str(lo), str(hi)],
        "flows_in_window": {"ours": int(len(ours_w)), "cic": int(len(cic_w))},
        "cic_labels_in_window": cic_w["Label"].value_counts().to_dict(),
        "protocols": {"ours": ours_w["protocol"].value_counts().to_dict(),
                      "cic": cic_w["protocol"].value_counts().to_dict()},
        "coverage": {"cic_flows_with_match": float(cic_cov), "our_flows_with_match": float(ours_cov),
                     "cic_by_label": cov_by_label},
        "unambiguous_pairs": int(len(pairs)),
        "direction_agreement": float(same_dir),
        "total_packets": {"exact": float((tot_ours == tot_cic).mean()),
                          "ours_more": float((tot_ours > tot_cic).mean()),
                          "ours_fewer": float((tot_ours < tot_cic).mean())},
        "feature_agreement": agree,
    }
    text = json.dumps(report, indent=2, default=str)
    print(text)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
