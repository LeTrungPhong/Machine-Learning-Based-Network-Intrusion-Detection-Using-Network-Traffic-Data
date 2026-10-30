"""Host-level behaviour features aggregated from flows.

Flows are grouped by source IP inside sliding time windows
(``window_s`` long, advancing by ``step_s``; a flow belongs to every window
that contains its start time). Separately, :func:`detect_beaconing` looks
for periodic connections from one host to the same destination over the
whole input, since beacon periods can exceed one window.

The ``portscan_suspect`` and ``beaconing_suspect`` columns are heuristic
indicators for analysis and model input. They are not proof of malicious
activity: CDNs, NTP, update checks and monitoring agents can trigger them.

Definitions (per source IP and window):

* ``n_flows``                 flows started by the host
* ``unique_dst_ips/ports``    distinct destinations / destination ports
* ``connection_rate``         ``n_flows / window_s`` (flows per second)
* ``port_entropy``            Shannon entropy (bits) of the destination-port distribution
* ``avg/std_conn_interval_s`` mean / sample std of gaps between consecutive flow starts
* ``syn_ack_ratio``           TCP ``SYN`` flag count / max(``ACK`` flag count, 1) over the host's flows
* ``repeated_conn_count``     ``n_flows`` minus distinct (dst_ip, dst_port) pairs
* ``failed_conn_count``       TCP flows with no reply packet, or reset with no payload in either direction

Usage:
    python -m preprocessing.host_features --flows <file.flows.parquet>
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

REQUIRED_FLOW_COLUMNS = (
    "src_ip", "dst_ip", "dst_port", "protocol", "start_ts_ns",
    "bwd_pkts", "fwd_bytes", "bwd_bytes", "syn_flag_cnt", "ack_flag_cnt", "rst_flag_cnt",
)

HOST_FEATURE_COLUMNS = (
    "n_flows", "unique_dst_ips", "unique_dst_ports", "connection_rate", "port_entropy",
    "avg_conn_interval_s", "std_conn_interval_s", "syn_ack_ratio",
    "repeated_conn_count", "failed_conn_count",
)


def _check_columns(df: pd.DataFrame) -> None:
    missing = [c for c in REQUIRED_FLOW_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Flow table lacks columns: {missing}")


def failed_connections(flows: pd.DataFrame) -> pd.Series:
    """Boolean mask of TCP flows that look like failed connection attempts."""
    tcp = flows["protocol"] == 6
    no_reply = flows["bwd_pkts"] == 0
    reset_no_data = (flows["rst_flag_cnt"] > 0) & (flows["fwd_bytes"] + flows["bwd_bytes"] == 0)
    return tcp & (no_reply | reset_no_data)


def _entropy_bits(counts: pd.Series, group_keys: list[str]) -> pd.Series:
    """Shannon entropy per group from a Series of counts indexed by group keys + value."""
    totals = counts.groupby(level=group_keys).transform("sum")
    p = counts / totals
    return (-(p * np.log2(p))).groupby(level=group_keys).sum()


def compute_host_features(flows: pd.DataFrame, window_s: float = 60.0, step_s: float = 10.0,
                          portscan_cfg: dict[str, Any] | None = None) -> pd.DataFrame:
    """Aggregate flows into per-host sliding-window features.

    Args:
        flows: Flow table from :mod:`preprocessing.flow_extraction`.
        window_s: Window length in seconds.
        step_s: Window step; ``window_s`` must be a multiple of it.
        portscan_cfg: ``{"min_unique_dst_ports": int, "min_unique_dst_ips": int}``.

    Returns:
        One row per (src_ip, window_start) with the columns in
        :data:`HOST_FEATURE_COLUMNS` plus ``window_start``/``window_end`` (UTC)
        and ``portscan_suspect``.
    """
    _check_columns(flows)
    if step_s <= 0 or window_s <= 0:
        raise ValueError("window_s and step_s must be positive")
    n_steps = window_s / step_s
    if abs(n_steps - round(n_steps)) > 1e-9:
        raise ValueError("window_s must be an integer multiple of step_s")
    n_steps = int(round(n_steps))
    cols = list(HOST_FEATURE_COLUMNS) + ["src_ip", "window_start", "window_end", "portscan_suspect"]
    if flows.empty:
        return pd.DataFrame(columns=cols)

    step_ns = int(step_s * 1e9)
    base = flows[list(REQUIRED_FLOW_COLUMNS)].copy()
    base["failed"] = failed_connections(base)
    base["is_tcp"] = base["protocol"] == 6
    k = base["start_ts_ns"].to_numpy() // step_ns
    # Each flow belongs to the n_steps windows whose start index is in (k - n_steps, k].
    rep = base.loc[base.index.repeat(n_steps)].copy()
    rep["win"] = np.repeat(k, n_steps) - np.tile(np.arange(n_steps), len(base))
    rep = rep.reset_index(drop=True)

    g_keys = ["src_ip", "win"]
    g = rep.groupby(g_keys, sort=True)
    out = pd.DataFrame({
        "n_flows": g.size(),
        "unique_dst_ips": g["dst_ip"].nunique(),
        "unique_dst_ports": g["dst_port"].nunique(),
        "failed_conn_count": g["failed"].sum(),
    })
    out["connection_rate"] = out["n_flows"] / window_s
    out["_tcp_flows"] = rep[rep["is_tcp"]].groupby(g_keys).size().reindex(out.index).fillna(0)

    port_counts = rep.groupby(g_keys + ["dst_port"]).size()
    out["port_entropy"] = _entropy_bits(port_counts, g_keys)

    pairs = rep.groupby(g_keys + ["dst_ip", "dst_port"]).size().groupby(level=g_keys).size()
    out["repeated_conn_count"] = out["n_flows"] - pairs

    tcp = rep[rep["is_tcp"]].groupby(g_keys)[["syn_flag_cnt", "ack_flag_cnt"]].sum()
    out["syn_ack_ratio"] = (tcp["syn_flag_cnt"] / tcp["ack_flag_cnt"].clip(lower=1)).reindex(out.index).fillna(0.0)

    rep = rep.sort_values(g_keys + ["start_ts_ns"], kind="stable")
    gaps = rep.groupby(g_keys)["start_ts_ns"].diff() / 1e9
    gstat = gaps.groupby([rep["src_ip"], rep["win"]]).agg(["mean", "std"])
    out["avg_conn_interval_s"] = gstat["mean"].reindex(out.index).fillna(0.0)
    out["std_conn_interval_s"] = gstat["std"].reindex(out.index).fillna(0.0)

    out = out.reset_index()
    out["window_start"] = pd.to_datetime(out["win"] * step_ns, unit="ns", utc=True)
    out["window_end"] = out["window_start"] + pd.Timedelta(seconds=window_s)
    out = out.drop(columns="win")

    # Vertical scan: many ports. Horizontal scan: many hosts *and* mostly failed
    # TCP attempts - many destinations alone is normal browsing (CDNs).
    ps = portscan_cfg or {}
    tcp_flows = out.pop("_tcp_flows").to_numpy(dtype=float)
    failed_ratio = np.divide(out["failed_conn_count"].to_numpy(dtype=float), tcp_flows,
                             out=np.zeros(len(out)), where=tcp_flows > 0)
    out["portscan_suspect"] = (
        (out["unique_dst_ports"] >= int(ps.get("min_unique_dst_ports", 50)))
        | ((out["unique_dst_ips"] >= int(ps.get("min_unique_dst_ips", 20)))
           & (failed_ratio >= float(ps.get("min_failed_ratio", 0.5))))
    )
    for c in ("n_flows", "unique_dst_ips", "unique_dst_ports", "repeated_conn_count", "failed_conn_count"):
        out[c] = out[c].astype("int64")
    return out[["src_ip", "window_start", "window_end", *HOST_FEATURE_COLUMNS, "portscan_suspect"]]


def detect_beaconing(flows: pd.DataFrame, min_connections: int = 6,
                     max_interval_cv: float = 0.2) -> pd.DataFrame:
    """Score periodicity of connections from a host to the same destination.

    For each (src_ip, dst_ip, dst_port, protocol) with at least
    ``min_connections`` flows, the gaps between consecutive flow starts are
    summarised. A low coefficient of variation (std / mean) means regular,
    machine-like timing.

    Returns:
        One row per destination pair with ``n_connections``, ``mean_interval_s``,
        ``std_interval_s``, ``interval_cv``, ``median_interval_s``,
        ``first_seen``/``last_seen`` and ``beaconing_suspect``.
    """
    _check_columns(flows)
    keys = ["src_ip", "dst_ip", "dst_port", "protocol"]
    cols = keys + ["n_connections", "mean_interval_s", "std_interval_s", "interval_cv",
                   "median_interval_s", "first_seen", "last_seen", "beaconing_suspect"]
    if flows.empty:
        return pd.DataFrame(columns=cols)
    df = flows[keys + ["start_ts_ns"]].sort_values(keys + ["start_ts_ns"], kind="stable")
    size = df.groupby(keys)["start_ts_ns"].transform("size")
    df = df[size >= min_connections].copy()
    if df.empty:
        return pd.DataFrame(columns=cols)
    df["gap_s"] = df.groupby(keys)["start_ts_ns"].diff() / 1e9
    g = df.groupby(keys)
    res = pd.DataFrame({
        "n_connections": g.size(),
        "mean_interval_s": g["gap_s"].mean(),
        "std_interval_s": g["gap_s"].std(),
        "median_interval_s": g["gap_s"].median(),
        "first_seen": pd.to_datetime(g["start_ts_ns"].min(), unit="ns", utc=True),
        "last_seen": pd.to_datetime(g["start_ts_ns"].max(), unit="ns", utc=True),
    }).reset_index()
    res["std_interval_s"] = res["std_interval_s"].fillna(0.0)
    res["interval_cv"] = np.where(res["mean_interval_s"] > 0,
                                  res["std_interval_s"] / res["mean_interval_s"], np.inf)
    res["beaconing_suspect"] = res["interval_cv"] <= max_interval_cv
    return res[cols].sort_values(["beaconing_suspect", "n_connections"], ascending=[False, False],
                                 ignore_index=True)


def main(argv: list[str] | None = None) -> int:
    """Compute host features and beaconing scores for a flows Parquet file."""
    from utils.config import get_path, load_config
    from utils.logging_setup import setup_logging
    from utils.storage import ensure_free_space

    ap = argparse.ArgumentParser(description="Host-level sliding-window features")
    ap.add_argument("--flows", required=True)
    ap.add_argument("--out-dir", default=None, help="Default: <processed_dir>/hosts")
    ap.add_argument("--config", default=None)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    setup_logging(cfg)
    hcfg = cfg["host_features"]
    out_dir = Path(args.out_dir) if args.out_dir else get_path(cfg, "processed_dir") / "hosts"
    out_dir.mkdir(parents=True, exist_ok=True)
    ensure_free_space(out_dir, cfg, required_gb=Path(args.flows).stat().st_size * 2 / 1024**3)

    flows = pd.read_parquet(args.flows, columns=list(REQUIRED_FLOW_COLUMNS))
    stem = Path(args.flows).name.split(".flows.")[0]
    hosts = compute_host_features(flows, float(hcfg["window_s"]), float(hcfg["step_s"]), hcfg.get("portscan"))
    bc = hcfg.get("beaconing", {})
    beacons = detect_beaconing(flows, int(bc.get("min_connections", 6)), float(bc.get("max_interval_cv", 0.2)))
    for df, kind in ((hosts, "hosts"), (beacons, "beaconing")):
        df.to_parquet(out_dir / f"{stem}.{kind}.parquet", index=False)
        df.to_csv(out_dir / f"{stem}.{kind}.csv", index=False)
    logger.info("%s flows -> %s host-window rows (%s portscan-suspect), %s destination pairs scored "
                "(%s beaconing-suspect)", f"{len(flows):,}", f"{len(hosts):,}",
                f"{int(hosts['portscan_suspect'].sum()):,}", f"{len(beacons):,}",
                f"{int(beacons['beaconing_suspect'].sum()) if len(beacons) else 0:,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
