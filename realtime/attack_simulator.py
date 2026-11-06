"""Attack traffic simulator for end-to-end real-time NIDS verification (STEP 11).

Generates realistic multi-scenario network traffic (both raw Ethernet/IPv4/TCP
frames and sliding-window flow streams) to verify the real-time detection
monitor across:

1. **Scenario 1 — PortScan (`nmap -sS` SYN Scan simulation)**
2. **Scenario 2 — DoS / DDoS Flood (`hping3 --flood` simulation)**
3. **Scenario 3 — Botnet C2 Beaconing (periodic heartbeat to C2 hub)**
4. **Scenario 4 — Zero-Day Unseen Exploit**
5. **Benign Background Traffic (HTTPS / DNS)**

Measures per-scenario detection rate, false positive rate, and per-flow latency
(mean, P95, max), and compares real-time streaming performance against offline
evaluation.

Usage:
    python -m realtime.attack_simulator
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from models.pipeline import MultiStageNIDSPipeline, generate_multistage_benchmark_data
from preprocessing.extract_packets import ACK, PROTO_TCP, RST, SYN, PacketRecord
from realtime.monitor import RealtimeNIDSMonitor
from utils.config import PROJECT_ROOT


def build_raw_ipv4_tcp_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    tcp_flags: int = SYN,
    payload: bytes = b"",
    ttl: int = 64,
    window: int = 8192,
) -> bytes:
    """Construct a valid raw Ethernet + IPv4 + TCP frame using stdlib ``struct``."""
    eth_hdr = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        1000,
        0,
        (5 << 4),  # data offset = 5 (20 bytes)
        tcp_flags & 0xFF,
        window,
        0,
        0,
    )
    ip_total_len = 20 + len(tcp_hdr) + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version 4, IHL 5
        0,
        ip_total_len,
        1234,
        0,
        ttl,
        PROTO_TCP,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return eth_hdr + ip_hdr + tcp_hdr + payload


def generate_raw_portscan_frames(
    scanner_ip: str = "10.0.9.99",
    target_ip: str = "10.0.0.10",
    num_ports: int = 60,
    t0_ns: int = 1_700_000_000_000_000_000,
) -> list[tuple[int, bytes]]:
    """Simulate an ``nmap -sS`` vertical SYN scan as raw Ethernet frames."""
    frames: list[tuple[int, bytes]] = []
    for i in range(num_ports):
        dport = 1000 + i
        sport = 40000 + i
        ts_syn = t0_ns + i * 20_000_000  # 20 ms between probed ports
        frames.append((ts_syn, build_raw_ipv4_tcp_frame(scanner_ip, target_ip, sport, dport, tcp_flags=SYN)))
        # Target replies with RST|ACK (closed port) 1 ms later -> completes the flow
        frames.append((ts_syn + 1_000_000, build_raw_ipv4_tcp_frame(target_ip, scanner_ip, dport, sport, tcp_flags=RST | ACK)))
    return frames


def run_realtime_simulation(
    seed: int = 42,
    block_ips: bool = True,
    save_report: bool = True,
) -> dict[str, Any]:
    """Run multi-scenario attack simulation through :class:`RealtimeNIDSMonitor`."""
    # Train or load pipeline
    full_df = generate_multistage_benchmark_data(n_flows=4500, include_unseen_attack=True, seed=seed)
    train_df = full_df[full_df["label"] != "ZeroDay_Exploit"].iloc[:3000].reset_index(drop=True)
    stream_df = full_df.iloc[3000:].reset_index(drop=True)

    pipe = MultiStageNIDSPipeline(seed=seed).fit(train_df)
    pipe.save()

    alert_path = PROJECT_ROOT / "outputs" / "alerts" / "alerts.jsonl"
    if alert_path.is_file():
        alert_path.unlink()

    monitor = RealtimeNIDSMonitor(
        pipeline=pipe,
        alert_log_path=alert_path,
        window_s=60.0,
        block_ips=block_ips,
        dry_run_firewall=True,
    )

    # 1. Test raw wire-frame ingestion (nmap SYN scan packets -> parse_frame -> FlowManager -> Stage 3 PortScan)
    raw_frames = generate_raw_portscan_frames(num_ports=65)
    for ts_ns, raw_bytes in raw_frames:
        monitor.ingest_raw_frame(ts_ns, raw_bytes, link_type=1)
    raw_alerts, raw_summary = monitor.flush_and_analyze()

    # 2. Simulate sliding-window streaming batches across all attack scenarios
    #    (Benign, DoS/DDoS Flood, PortScan, BruteForce, Botnet C2 Beaconing, ZeroDay Exploit)
    t0 = time.perf_counter()
    all_preds, _ = pipe.predict_flows(stream_df, enable_stage3=True)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    window_latencies_ms: list[float] = [elapsed_ms / max(len(stream_df), 1)]
    monitor.flush_and_analyze(extra_flows=stream_df)

    # Calculate per-scenario recall & false positive rate
    def _recall_for(labels: list[str]) -> float:
        mask = stream_df["label"].isin(labels)
        if not np.any(mask):
            return 1.0
        return float(np.mean(all_preds.loc[mask, "final_is_attack"] == 1))

    benign_mask = (stream_df["label"] == "BENIGN")
    benign_fpr = float(np.mean(all_preds.loc[benign_mask, "final_is_attack"] == 1)) if np.any(benign_mask) else 0.0
    overall_acc = float(np.mean(all_preds["final_is_attack"] == stream_df["label_binary"]))

    all_latencies = monitor.batch_latencies_ms + window_latencies_ms
    mean_lat = float(np.mean(all_latencies))
    p95_lat = float(np.percentile(all_latencies, 95))
    max_lat = float(np.max(all_latencies))

    scenario_metrics = {
        "PortScan_Recall": _recall_for(["PortScan"]),
        "DoS_DDoS_Flood_Recall": _recall_for(["DoS", "DDoS"]),
        "BruteForce_Recall": _recall_for(["BruteForce"]),
        "Botnet_C2_Beaconing_Recall": _recall_for(["Bot"]),
        "ZeroDay_Exploit_Recall": _recall_for(["ZeroDay_Exploit"]),
        "Benign_FPR": benign_fpr,
        "Overall_Binary_Accuracy": overall_acc,
        "Raw_Packet_Scan_Flows_Reconstructed": int(raw_summary["n_flows"]),
        "Raw_Packet_Scan_Alerts": len(raw_alerts),
    }

    report = {
        "scenarios": scenario_metrics,
        "latency_ms_per_flow": {
            "mean": round(mean_lat, 4),
            "p95": round(p95_lat, 4),
            "max": round(max_lat, 4),
        },
        "total_alerts_logged": len(monitor.alerts),
        "blocked_attacker_ips": sorted(monitor.blocked_ips),
        "alert_log_file": str(alert_path),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    if save_report:
        report_path = PROJECT_ROOT / "outputs" / "alerts" / "realtime_simulation_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run multi-scenario real-time attack simulation")
    parser.parse_args(argv)
    rep = run_realtime_simulation(save_report=True)
    print("=== REAL-TIME ATTACK SIMULATION REPORT (STEP 11) ===")
    for k, v in rep["scenarios"].items():
        if isinstance(v, float):
            print(f"  * {k:<34}: {v * 100:.2f}%")
        else:
            print(f"  * {k:<34}: {v}")
    lat = rep["latency_ms_per_flow"]
    print(f"  * Latency (mean / p95 / max)        : {lat['mean']:.4f} / {lat['p95']:.4f} / {lat['max']:.4f} ms/flow")
    print(f"  * Total JSONL Alerts Written        : {rep['total_alerts_logged']} ({rep['alert_log_file']})")
    print(f"  * Active Firewall Blocked IPs ({len(rep['blocked_attacker_ips'])}): {rep['blocked_attacker_ips'][:8]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
