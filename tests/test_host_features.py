"""Tests for host-level sliding-window features and beaconing detection."""

from __future__ import annotations

import math

import numpy as np
import pandas as pd
import pytest

from preprocessing.host_features import compute_host_features, detect_beaconing, failed_connections

T0 = 1_499_428_800_000_000_000  # aligned to a 60 s boundary


def flows(rows: list[tuple]) -> pd.DataFrame:
    """rows: (t_s, src, dst, dport[, proto, bwd_pkts, fwd_bytes, bwd_bytes, syn, ack, rst])"""
    full = []
    for r in rows:
        t, src, dst, dport, *rest = r
        proto, bwd_pkts, fwd_b, bwd_b, syn, ack, rst = (rest + [6, 1, 10, 10, 1, 2, 0][len(rest):])
        full.append(dict(start_ts_ns=T0 + round(t * 1e9), src_ip=src, dst_ip=dst, dst_port=dport,
                         protocol=proto, bwd_pkts=bwd_pkts, fwd_bytes=fwd_b, bwd_bytes=bwd_b,
                         syn_flag_cnt=syn, ack_flag_cnt=ack, rst_flag_cnt=rst))
    return pd.DataFrame(full)


def test_each_flow_counted_in_window_over_step_windows() -> None:
    h = compute_host_features(flows([(5.0, "a", "b", 80)]), window_s=60, step_s=10)
    assert len(h) == 6 and (h["n_flows"] == 1).all()
    assert (h["window_start"] <= pd.Timestamp(T0 + 5_000_000_000, tz="UTC")).all()
    assert (h["window_end"] > pd.Timestamp(T0 + 5_000_000_000, tz="UTC")).all()


def test_portscan_host_flagged_benign_not() -> None:
    rows = [(i * 0.1, "10.0.0.1", "10.0.0.2", 1 + i, 6, 0, 0, 0, 1, 0, 0) for i in range(100)]
    rows += [(1.0, "10.0.0.9", "1.1.1.1", 443), (2.0, "10.0.0.9", "1.1.1.1", 443), (3.0, "10.0.0.9", "8.8.8.8", 53)]
    h = compute_host_features(flows(rows), 60, 10, {"min_unique_dst_ports": 50, "min_unique_dst_ips": 20})
    scan = h[h["src_ip"] == "10.0.0.1"]
    assert scan["unique_dst_ports"].max() == 100 and scan["portscan_suspect"].any()
    assert scan["failed_conn_count"].max() == 100            # no reply packets
    assert scan["syn_ack_ratio"].max() == 100                 # 100 SYN, 0 ACK -> 100 / max(0, 1)
    assert scan["port_entropy"].max() == pytest.approx(math.log2(100))
    benign = h[h["src_ip"] == "10.0.0.9"]
    assert not benign["portscan_suspect"].any() and benign["failed_conn_count"].max() == 0


def test_horizontal_scan_needs_failures_browsing_does_not_flag() -> None:
    cfg = {"min_unique_dst_ports": 50, "min_unique_dst_ips": 20, "min_failed_ratio": 0.5}
    browsing = [(i * 0.2, "10.0.0.3", f"93.184.{i}.1", 443, 6, 5, 300, 9000) for i in range(30)]
    sweep = [(i * 0.2, "10.0.0.4", f"10.1.0.{i}", 445, 6, 0, 0, 0, 1, 0, 0) for i in range(30)]
    h = compute_host_features(flows(browsing + sweep), 60, 10, cfg)
    assert not h.loc[h.src_ip == "10.0.0.3", "portscan_suspect"].any()
    assert h.loc[h.src_ip == "10.0.0.4", "portscan_suspect"].any()


def test_entropy_rate_repeats_and_intervals() -> None:
    rows = [(t, "h", "d", 1 + (i % 4)) for i, t in enumerate(range(0, 60, 5))]   # 12 flows, every 5 s
    h = compute_host_features(flows(rows), window_s=60, step_s=60).iloc[0]
    assert h["n_flows"] == 12 and h["connection_rate"] == pytest.approx(0.2)
    assert h["port_entropy"] == pytest.approx(2.0)
    assert h["repeated_conn_count"] == 12 - 4
    assert h["avg_conn_interval_s"] == pytest.approx(5.0) and h["std_conn_interval_s"] == pytest.approx(0.0)


def test_failed_connection_definition() -> None:
    df = flows([(0, "a", "b", 1, 6, 0, 0, 0), (1, "a", "b", 2, 6, 1, 0, 0, 1, 1, 1),
                (2, "a", "b", 3, 6, 3, 50, 900), (3, "a", "b", 4, 17, 0, 10, 0)])
    assert failed_connections(df).tolist() == [True, True, False, False]


def test_invalid_window_rejected() -> None:
    with pytest.raises(ValueError):
        compute_host_features(flows([(0, "a", "b", 1)]), window_s=60, step_s=7)
    with pytest.raises(ValueError):
        compute_host_features(flows([(0, "a", "b", 1)]).drop(columns="rst_flag_cnt"))


def test_empty_input() -> None:
    empty = flows([]).reindex(columns=flows([(0, "a", "b", 1)]).columns)
    assert compute_host_features(empty).empty and detect_beaconing(empty).empty


def test_beaconing_periodic_vs_random() -> None:
    rng = np.random.default_rng(0)
    periodic = [(30.0 * i, "10.0.0.5", "203.0.113.7", 8080) for i in range(10)]
    random_t = np.cumsum(rng.exponential(30.0, size=10))
    noisy = [(float(t), "10.0.0.6", "198.51.100.1", 443) for t in random_t]
    few = [(30.0 * i, "10.0.0.7", "192.0.2.1", 80) for i in range(3)]
    b = detect_beaconing(flows(periodic + noisy + few), min_connections=6, max_interval_cv=0.2)
    assert set(b["src_ip"]) == {"10.0.0.5", "10.0.0.6"}
    p = b[b["src_ip"] == "10.0.0.5"].iloc[0]
    assert p["beaconing_suspect"] and p["mean_interval_s"] == pytest.approx(30.0) and p["interval_cv"] == 0
    assert p["n_connections"] == 10
    n = b[b["src_ip"] == "10.0.0.6"].iloc[0]
    assert not n["beaconing_suspect"] and n["interval_cv"] > 0.2
