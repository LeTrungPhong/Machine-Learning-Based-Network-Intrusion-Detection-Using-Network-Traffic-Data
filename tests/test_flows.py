"""Tests for flow reconstruction and flow features (Phase 1-2).

Expected values are computed by hand from the packet timings below.
"""

from __future__ import annotations

import math
from decimal import Decimal
from pathlib import Path

import pandas as pd
import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

from preprocessing.extract_packets import ACK, FIN, PSH, RST, SYN, PacketRecord, extract_packets
from preprocessing.flow_extraction import (
    CIC_COLUMN_MAP, FlowConfig, FlowManager, RunningStats, extract_flows, iter_flows,
)

T0 = 1_499_428_800_000_000_000  # 2017-07-07 12:00:00 UTC
C, S = "192.168.10.5", "8.8.8.8"


def pkt(t_s: float, src: str, sport: int, dst: str, dport: int, proto: int = 6, flags: int = 0,
        payload: int = 0, win: int = 1000, hdr: int | None = None, ttl: int = 64) -> PacketRecord:
    hdr = hdr if hdr is not None else (20 if proto == 6 else 8)
    return PacketRecord(
        T0 + round(t_s * 1e9), 4, src, dst, sport, dport, proto, 14 + 20 + hdr + payload,
        20 + hdr + payload, 20, hdr, payload, ttl, flags if proto == 6 else 0,
        win if proto == 6 else -1, -1, -1, False, False)


def tcp_session(t: float = 0.0) -> list[PacketRecord]:
    return [
        pkt(t + 0.000, C, 51000, S, 443, flags=SYN, win=29200, hdr=40),
        pkt(t + 0.010, S, 443, C, 51000, flags=SYN | ACK, win=65535, hdr=40),
        pkt(t + 0.020, C, 51000, S, 443, flags=ACK),
        pkt(t + 0.030, C, 51000, S, 443, flags=PSH | ACK, payload=100),
        pkt(t + 0.050, S, 443, C, 51000, flags=PSH | ACK, payload=300),
        pkt(t + 0.060, C, 51000, S, 443, flags=FIN | ACK),
        pkt(t + 0.070, S, 443, C, 51000, flags=FIN | ACK),
        pkt(t + 0.080, C, 51000, S, 443, flags=ACK),   # final ACK, inside close grace
    ]


def flows_of(packets: list[PacketRecord], **kw) -> list[dict]:
    return list(iter_flows(packets, FlowConfig(**kw)))


# ---------------------------------------------------------------- RunningStats

def test_running_stats_matches_pandas() -> None:
    xs = [3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0, 6.0]
    rs = RunningStats()
    for x in xs:
        rs.add(x)
    s = pd.Series(xs)
    assert rs.n == 8 and rs.total == s.sum() and rs.min == 1.0 and rs.max == 9.0
    assert math.isclose(rs.mean, s.mean()) and math.isclose(rs.std, s.std(ddof=1))
    assert RunningStats().summary() == (0.0, 0.0, 0.0, 0.0)


# ---------------------------------------------------------------- TCP session

def test_tcp_session_hand_computed_features() -> None:
    flows = flows_of(tcp_session())
    assert len(flows) == 1
    f = flows[0]
    assert (f["src_ip"], f["src_port"], f["dst_ip"], f["dst_port"], f["protocol"]) == (C, 51000, S, 443, 6)
    assert f["flow_id"] == f"{C}-{S}-51000-443-6"
    assert f["termination"] == "fin" and not f["incomplete"]
    assert f["flow_duration_us"] == 80_000
    assert (f["fwd_pkts"], f["bwd_pkts"], f["fwd_bytes"], f["bwd_bytes"]) == (5, 3, 100, 300)
    # packets at 0,10,20,30,50,60,70,80 ms -> gaps six x 10 ms and one 20 ms
    gaps = pd.Series([10_000] * 3 + [20_000] + [10_000] * 3, dtype=float)
    assert f["flow_iat_mean"] == pytest.approx(gaps.mean()) and f["flow_iat_std"] == pytest.approx(gaps.std())
    assert (f["flow_iat_max"], f["flow_iat_min"]) == (20_000, 10_000)
    # forward packets at 0, 20, 30, 60, 80 ms
    assert f["fwd_iat_total"] == 80_000 and f["fwd_iat_mean"] == 20_000
    assert math.isclose(f["fwd_iat_std"], math.sqrt(2e8 / 3))
    assert (f["fwd_iat_max"], f["fwd_iat_min"]) == (30_000, 10_000)
    # backward packets at 10, 50, 70 ms
    assert f["bwd_iat_total"] == 60_000 and f["bwd_iat_mean"] == 30_000
    assert math.isclose(f["bwd_iat_std"], math.sqrt(2e8))
    assert (f["fwd_pkt_len_max"], f["fwd_pkt_len_min"], f["fwd_pkt_len_mean"]) == (100, 0, 20)
    assert (f["bwd_pkt_len_max"], f["bwd_pkt_len_mean"]) == (300, 100)
    assert f["pkt_len_mean"] == 50 and f["avg_pkt_size"] == 50
    assert f["flow_bytes_per_s"] == pytest.approx(5000.0) and f["flow_pkts_per_s"] == pytest.approx(100.0)
    assert f["fwd_pkts_per_s"] == pytest.approx(62.5) and f["bwd_pkts_per_s"] == pytest.approx(37.5)
    assert (f["syn_flag_cnt"], f["ack_flag_cnt"], f["fin_flag_cnt"], f["psh_flag_cnt"], f["rst_flag_cnt"]) == (2, 7, 2, 2, 0)
    assert (f["fwd_psh_flags"], f["bwd_psh_flags"]) == (1, 1)
    assert (f["init_win_bytes_fwd"], f["init_win_bytes_bwd"]) == (29200, 65535)
    assert f["fwd_header_len"] == 40 + 20 * 4 and f["bwd_header_len"] == 40 + 20 * 2
    assert f["act_data_pkt_fwd"] == 1 and f["min_seg_size_fwd"] == 20
    assert f["down_up_ratio"] == pytest.approx(0.6)
    assert f["active_mean"] == 80_000 and f["idle_mean"] == 0


def test_packets_after_grace_start_new_flow() -> None:
    flows = flows_of(tcp_session() + [pkt(5.0, C, 51000, S, 443, flags=ACK)])
    assert [f["termination"] for f in flows] == ["fin", "end_of_capture"]
    assert flows[1]["fwd_pkts"] == 1 and flows[1]["incomplete"]


def test_new_syn_inside_grace_starts_new_flow() -> None:
    flows = flows_of(tcp_session() + [pkt(0.2, C, 51000, S, 443, flags=SYN)])
    assert len(flows) == 2 and flows[0]["fwd_pkts"] == 5


def test_rst_terminates() -> None:
    flows = flows_of([
        pkt(0.0, C, 40000, S, 22, flags=SYN),
        pkt(0.001, S, 22, C, 40000, flags=RST | ACK),
        pkt(3.0, C, 40000, S, 22, flags=SYN),
    ])
    assert [f["termination"] for f in flows] == ["rst", "end_of_capture"]
    assert flows[0]["bwd_pkts"] == 1 and flows[0]["rst_flag_cnt"] == 1


# ---------------------------------------------------------------- timeouts

def test_flow_timeout_splits_long_flow() -> None:
    pk = [pkt(t, C, 5000, S, 53, proto=17, payload=10) for t in (0, 50, 100, 150, 200, 250)]
    flows = flows_of(pk, flow_timeout_s=120, idle_timeout_s=120)
    assert [f["termination"] for f in flows] == ["flow_timeout", "end_of_capture"]
    assert [f["fwd_pkts"] for f in flows] == [3, 3]
    assert flows[0]["flow_duration_us"] == 100e6


def test_idle_timeout() -> None:
    pk = [pkt(t, C, 5000, S, 53, proto=17) for t in (0, 1, 20)]
    flows = flows_of(pk, idle_timeout_s=10)
    assert [f["termination"] for f in flows] == ["idle_timeout", "end_of_capture"]


def test_sweep_flushes_idle_flows_while_other_traffic_continues() -> None:
    fm = FlowManager(FlowConfig(idle_timeout_s=10, sweep_interval_s=1))
    out = fm.process(pkt(0, C, 1, S, 2, proto=17))
    for i in range(1, 15):
        out += fm.process(pkt(i, "10.0.0.1", 3, "10.0.0.2", 4, proto=17))
    assert len(out) == 1 and out[0]["termination"] == "idle_timeout" and out[0]["src_port"] == 1
    assert len(fm.flows) == 1


def test_direction_follows_first_packet() -> None:
    flows = flows_of([pkt(0, S, 53, C, 5353, proto=17, payload=40), pkt(0.1, C, 5353, S, 53, proto=17, payload=20)])
    f = flows[0]
    assert (f["src_ip"], f["src_port"], f["fwd_bytes"], f["bwd_bytes"]) == (S, 53, 40, 20)


def test_active_idle_periods() -> None:
    pk = [pkt(t, C, 5000, S, 53, proto=17) for t in (0, 1, 2, 10, 11)]
    f = flows_of(pk, activity_timeout_s=5)[0]
    assert f["active_mean"] == pytest.approx(1.5e6) and f["active_max"] == pytest.approx(2e6)
    assert f["active_std"] == pytest.approx(math.sqrt(0.5e12))
    assert f["idle_mean"] == pytest.approx(8e6) and f["idle_min"] == pytest.approx(8e6)


def test_single_packet_flow_has_finite_rates() -> None:
    f = flows_of([pkt(0, C, 1, S, 2, proto=17, payload=5)])[0]
    assert f["flow_duration_us"] == 0 and f["flow_bytes_per_s"] == 0.0 and f["flow_pkts_per_s"] == 0.0
    assert all(math.isfinite(v) for v in f.values() if isinstance(v, float))


# ---------------------------------------------------------------- robustness

def test_dedup_drops_identical_copies_only_when_enabled() -> None:
    pk = [pkt(0, C, 1, S, 2, proto=17, payload=9), pkt(0.000005, C, 1, S, 2, proto=17, payload=9),
          pkt(0.5, C, 1, S, 2, proto=17, payload=9)]
    assert flows_of(pk)[0]["fwd_pkts"] == 3
    f = flows_of(pk, dedup_window_us=10)[0]
    assert f["fwd_pkts"] == 2 and f["dup_pkts_dropped"] == 1


def test_reply_timestamped_before_syn_is_merged_with_correct_direction() -> None:
    attacker, victim = "172.16.0.1", "192.168.10.50"
    pk = [pkt(0.000000, victim, 2003, attacker, 59478, flags=RST | ACK),
          pkt(0.000001, attacker, 59478, victim, 2003, flags=SYN)]
    flows = flows_of(pk)
    assert len(flows) == 1
    f = flows[0]
    assert (f["src_ip"], f["src_port"], f["fwd_pkts"], f["bwd_pkts"]) == (attacker, 59478, 1, 1)
    assert f["termination"] == "rst" and f["syn_flag_cnt"] == 1 and f["rst_flag_cnt"] == 1
    # Outside the window the two packets stay separate flows.
    late = [pk[0], pkt(0.01, attacker, 59478, victim, 2003, flags=SYN)]
    assert len(flows_of(late, reorder_window_us=1000)) == 2
    assert len(flows_of(pk, reorder_window_us=0)) == 2


def test_eviction_respects_max_active_flows() -> None:
    fm = FlowManager(FlowConfig(max_active_flows=2))
    out = []
    for i in range(3):
        out += fm.process(pkt(i * 0.1, C, 1000 + i, S, 80, proto=17))
    assert len(fm.flows) == 2 and len(out) == 1
    assert out[0]["termination"] == "evicted" and out[0]["incomplete"] and out[0]["src_port"] == 1000


def test_out_of_order_packet_gives_no_negative_iat() -> None:
    pk = [pkt(0, C, 1, S, 2, proto=17), pkt(1.0, C, 1, S, 2, proto=17), pkt(0.5, C, 1, S, 2, proto=17)]
    f = flows_of(pk)[0]
    assert f["out_of_order_pkts"] == 1 and f["flow_iat_min"] == 0 and f["flow_duration_us"] == 1e6


def test_cic_column_map_targets_existing_columns() -> None:
    f = flows_of(tcp_session())[0]
    assert set(CIC_COLUMN_MAP) <= set(f)


# ---------------------------------------------------------------- end to end

def _write_pcap(path: Path) -> Path:
    w = PcapWriter(str(path))
    t = Decimal(T0) / Decimal(10**9)
    seq = [
        (0.00, Ether() / IP(src=C, dst=S) / TCP(sport=51000, dport=443, flags="S")),
        (0.01, Ether() / IP(src=S, dst=C) / TCP(sport=443, dport=51000, flags="SA")),
        (0.02, Ether() / IP(src=C, dst=S) / TCP(sport=51000, dport=443, flags="PA") / Raw(b"x" * 50)),
        (0.03, Ether() / IP(src=C, dst=S) / UDP(sport=5353, dport=53) / Raw(b"q" * 20)),
        (0.04, Ether() / IP(src=S, dst=C) / UDP(sport=53, dport=5353) / Raw(b"r" * 60)),
    ]
    for dt, p in seq:
        p.time = t + Decimal(str(dt))
        w.write(p)
    w.close()
    return path


def test_extract_flows_from_pcap_and_packets_parquet_agree(tmp_path: Path) -> None:
    pcap = _write_pcap(tmp_path / "cap.pcap")
    cfg = {"flow": {"export_formats": ["parquet", "csv"]}, "pcap": {"chunk_rows": 10},
           "storage": {"min_free_gb": 0, "warn_free_gb": 0}}
    s1 = extract_flows(tmp_path / "f1", cfg, pcap=pcap)
    a = pd.read_parquet(s1.outputs["parquet"]).sort_values("start_ts_ns", ignore_index=True)
    b_csv = pd.read_csv(s1.outputs["csv"])
    assert len(a) == len(b_csv) == 2
    assert a.loc[0, "fwd_bytes"] == 50 and a.loc[0, "termination"] == "end_of_capture"
    assert a.loc[1, "protocol"] == 17 and (a.loc[1, "fwd_bytes"], a.loc[1, "bwd_bytes"]) == (20, 60)
    assert str(a["timestamp"].dt.tz) == "UTC" and a.loc[0, "start_ts_ns"] == T0

    pk = extract_packets(pcap, tmp_path / "p", cfg, formats=["parquet"])
    s2 = extract_flows(tmp_path / "f2", cfg, packets_parquet=pk.outputs["parquet"])
    b = pd.read_parquet(s2.outputs["parquet"]).sort_values("start_ts_ns", ignore_index=True)
    pd.testing.assert_frame_equal(a, b)


def test_extract_flows_argument_validation(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        extract_flows(tmp_path, {})
