"""Tests for real-time packet monitoring, JSONL alerting, firewall rules, and attack simulation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from models.pipeline import MultiStageNIDSPipeline, generate_multistage_benchmark_data
from realtime.attack_simulator import (
    build_raw_ipv4_tcp_frame,
    generate_raw_portscan_frames,
    run_realtime_simulation,
)
from realtime.monitor import RealtimeNIDSMonitor, build_iptables_block_command


def test_iptables_command_builder_validates_ips() -> None:
    cmd = build_iptables_block_command("10.0.9.99")
    assert cmd == ["iptables", "-I", "INPUT", "-s", "10.0.9.99", "-j", "DROP"]

    with pytest.raises(ValueError, match="loopback"):
        build_iptables_block_command("127.0.0.1")

    with pytest.raises(ValueError):
        build_iptables_block_command("not_an_ip; rm -rf /")


def test_raw_frame_portscan_reconstructed_and_alerted(tmp_path: Path) -> None:
    train_df = generate_multistage_benchmark_data(n_flows=800, include_unseen_attack=False, seed=42)
    pipe = MultiStageNIDSPipeline(seed=42).fit(train_df)

    alert_file = tmp_path / "alerts.jsonl"
    monitor = RealtimeNIDSMonitor(
        pipeline=pipe,
        alert_log_path=alert_file,
        block_ips=True,
        dry_run_firewall=True,
    )

    frames = generate_raw_portscan_frames(scanner_ip="10.0.9.99", target_ip="10.0.0.10", num_ports=60)
    for ts_ns, raw_bytes in frames:
        monitor.ingest_raw_frame(ts_ns, raw_bytes, link_type=1)

    alerts, summary = monitor.flush_and_analyze()
    assert summary["n_flows"] == 60
    assert len(alerts) == 60
    assert "10.0.9.99" in monitor.blocked_ips
    assert alert_file.is_file()

    lines = [json.loads(line) for line in alert_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 60
    assert lines[0]["src_ip"] == "10.0.9.99"
    assert lines[0]["attack_type"] in ("PortScan", "DoS", "Unknown_Anomaly")
    assert "DRY_RUN" in lines[0]["firewall_action"]


def test_multi_scenario_realtime_simulation() -> None:
    rep = run_realtime_simulation(seed=42, block_ips=True, save_report=False)
    sc = rep["scenarios"]
    assert sc["PortScan_Recall"] >= 0.95
    assert sc["DoS_DDoS_Flood_Recall"] >= 0.95
    assert sc["Botnet_C2_Beaconing_Recall"] >= 0.95
    assert sc["ZeroDay_Exploit_Recall"] >= 0.95
    assert sc["Benign_FPR"] <= 0.02
    assert sc["Raw_Packet_Scan_Flows_Reconstructed"] == 65
    assert rep["latency_ms_per_flow"]["mean"] > 0
    assert len(rep["blocked_attacker_ips"]) >= 3

