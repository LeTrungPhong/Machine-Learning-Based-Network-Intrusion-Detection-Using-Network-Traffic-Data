"""Real-time packet/flow monitoring, 3-stage AI detection, and JSONL alerting.

Designed for deployment on Kali Linux (or Windows with Npcap) and for
deterministic replay/simulation testing:

1. Captures raw frames via Scapy ``sniff()`` (or ingests a ``PacketRecord`` /
   flow stream).
2. Reconstructs bidirectional flows via :class:`preprocessing.flow_extraction.FlowManager`.
3. Evaluates sliding time windows through :class:`models.pipeline.MultiStageNIDSPipeline`
   (Stage 1 Gaussian -> Stage 2 Random Forest -> Stage 3 Host Beaconing & Botnet Graph).
4. Logs structured alerts to ``outputs/alerts/alerts.jsonl`` and optionally
   generates/executes ``iptables`` active-defense rules when ``block_ips`` is enabled.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd

from models.pipeline import (
    DEFAULT_FLOW_FEATURES,
    MultiStageNIDSPipeline,
    generate_multistage_benchmark_data,
)
from preprocessing.extract_packets import PacketRecord, parse_frame
from preprocessing.flow_extraction import FlowConfig, FlowManager
from utils.config import PROJECT_ROOT, load_config

logger = logging.getLogger(__name__)


def align_flow_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Map :class:`FlowManager` column names onto :data:`DEFAULT_FLOW_FEATURES`."""
    out = df.copy()
    rename_if_missing = {
        "flow_duration": "flow_duration_us",
        "tot_fwd_pkts": "fwd_pkts",
        "tot_bwd_pkts": "bwd_pkts",
        "totlen_fwd_pkts": "fwd_bytes",
        "totlen_bwd_pkts": "bwd_bytes",
        "flow_byts_s": "flow_bytes_per_s",
        "flow_pkts_s": "flow_pkts_per_s",
        "fwd_iat_tot": "fwd_iat_total",
        "bwd_iat_tot": "bwd_iat_total",
        "subflow_fwd_pkts": "fwd_pkts",
        "subflow_bwd_pkts": "bwd_pkts",
    }
    for target_col, src_col in rename_if_missing.items():
        if target_col not in out.columns and src_col in out.columns:
            out[target_col] = out[src_col]

    for col in DEFAULT_FLOW_FEATURES:
        if col not in out.columns:
            out[col] = 0.0

    if "fwd_bytes" not in out.columns and "totlen_fwd_pkts" in out.columns:
        out["fwd_bytes"] = out["totlen_fwd_pkts"].astype(np.int64)
    if "bwd_bytes" not in out.columns and "totlen_bwd_pkts" in out.columns:
        out["bwd_bytes"] = out["totlen_bwd_pkts"].astype(np.int64)
    if "bwd_pkts" not in out.columns and "tot_bwd_pkts" in out.columns:
        out["bwd_pkts"] = out["tot_bwd_pkts"].astype(np.int64)

    return out


def build_iptables_block_command(ip: str) -> list[str]:
    """Validate ``ip`` and build a safe ``iptables`` DROP command."""
    # Validate IP address strictly to prevent command injection
    parsed = ipaddress.ip_address(ip.strip())
    if parsed.is_loopback:
        raise ValueError(f"Refusing to block loopback address: {ip}")
    return ["iptables", "-I", "INPUT", "-s", str(parsed), "-j", "DROP"]


@dataclass
class AlertRecord:
    """Single real-time intrusion alert written to ``alerts.jsonl``."""

    timestamp: str
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    attack_type: str
    severity: str
    confidence: float
    stage1_anomaly_score: float
    stage3_botnet_role: str
    stage3_beaconing: bool
    detection_latency_ms: float
    firewall_action: str = "NONE"


class RealtimeNIDSMonitor:
    """Streaming network monitor integrating FlowManager and MultiStageNIDSPipeline."""

    def __init__(
        self,
        pipeline: MultiStageNIDSPipeline | None = None,
        alert_log_path: str | Path | None = None,
        window_s: float = 60.0,
        block_ips: bool = False,
        dry_run_firewall: bool = True,
        flow_cfg: FlowConfig | None = None,
    ) -> None:
        self.pipeline = pipeline or self._load_or_train_default_pipeline()
        cfg = load_config()
        default_alert_dir = PROJECT_ROOT / cfg["paths"]["alerts_dir"]
        default_alert_file = default_alert_dir / cfg["realtime"]["alert_log"]
        self.alert_log_path = Path(alert_log_path) if alert_log_path is not None else default_alert_file
        self.alert_log_path.parent.mkdir(parents=True, exist_ok=True)

        self.window_s = float(window_s)
        self.block_ips = bool(block_ips)
        self.dry_run_firewall = bool(dry_run_firewall)

        self.flow_manager = FlowManager(flow_cfg or FlowConfig(flow_timeout_s=15.0, idle_timeout_s=5.0))
        self.flow_window: list[dict[str, Any]] = []
        self.alerts: list[AlertRecord] = []
        self.blocked_ips: set[str] = set()
        self.batch_latencies_ms: list[float] = []

    @staticmethod
    def _load_or_train_default_pipeline() -> MultiStageNIDSPipeline:
        saved_path = PROJECT_ROOT / "saved_models" / "multistage_pipeline.joblib"
        if saved_path.is_file():
            try:
                return MultiStageNIDSPipeline.load(saved_path)
            except Exception as exc:
                logger.warning("Could not load %s (%s); training fresh pipeline", saved_path, exc)
        df = generate_multistage_benchmark_data(n_flows=3000, include_unseen_attack=False, seed=42)
        pipe = MultiStageNIDSPipeline(seed=42).fit(df)
        pipe.save(saved_path)
        return pipe

    def _maybe_block_ip(self, src_ip: str, severity: str) -> str:
        if not self.block_ips or severity not in ("MEDIUM", "HIGH", "CRITICAL"):
            return "NONE"
        if src_ip in self.blocked_ips:
            return "ALREADY_BLOCKED"
        try:
            cmd = build_iptables_block_command(src_ip)
        except ValueError:
            return "SKIPPED_INVALID_OR_LOOPBACK"

        self.blocked_ips.add(src_ip)
        if self.dry_run_firewall:
            return f"DRY_RUN ({' '.join(cmd)})"
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=5)
            return "IPTABLES_DROP"
        except Exception as exc:
            logger.error("Failed to execute iptables for %s: %s", src_ip, exc)
            return "IPTABLES_ERROR"

    def ingest_packet(self, pkt: PacketRecord) -> list[dict[str, Any]]:
        """Feed one parsed :class:`PacketRecord` into the flow reconstructor."""
        emitted = self.flow_manager.process(pkt)
        if emitted:
            self.flow_window.extend(emitted)
        return emitted

    def ingest_raw_frame(self, ts_ns: int, raw_bytes: bytes, link_type: int = 1) -> list[dict[str, Any]]:
        """Decode a raw layer-2 frame and feed it into the flow reconstructor."""
        pkt = parse_frame(raw_bytes, linktype=link_type, ts_ns=ts_ns)
        if pkt is None:
            return []
        return self.ingest_packet(pkt)

    def flush_and_analyze(self, extra_flows: pd.DataFrame | None = None) -> tuple[list[AlertRecord], dict[str, Any]]:
        """Flush active flows, run the 3-stage AI pipeline, and write JSONL alerts."""
        self.flow_window.extend(self.flow_manager.flush())

        frames: list[pd.DataFrame] = []
        if self.flow_window:
            frames.append(pd.DataFrame(self.flow_window))
        if extra_flows is not None and not extra_flows.empty:
            frames.append(extra_flows.copy())

        if not frames:
            return [], {"n_flows": 0, "alerts_emitted": 0, "latency_ms": 0.0}

        raw_df = pd.concat(frames, ignore_index=True)
        aligned_df = align_flow_schema(raw_df)

        t0 = time.perf_counter()
        pred_df, summary = self.pipeline.predict_flows(aligned_df, enable_stage3=True)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        per_flow_ms = elapsed_ms / max(len(pred_df), 1)
        self.batch_latencies_ms.append(per_flow_ms)

        new_alerts: list[AlertRecord] = []
        attack_rows = pred_df[pred_df["final_is_attack"] == 1]

        with open(self.alert_log_path, "a", encoding="utf-8") as fh:
            for idx, row in attack_rows.iterrows():
                src_ip = str(row.get("src_ip", "0.0.0.0"))
                dst_ip = str(row.get("dst_ip", "0.0.0.0"))
                src_port = int(row.get("src_port", 0))
                dst_port = int(row.get("dst_port", 0))
                proto = str(row.get("protocol", "TCP"))
                flow_id = str(row.get("flow_id", f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"))
                severity = str(row.get("alert_severity", "HIGH"))
                fw_action = self._maybe_block_ip(src_ip, severity)

                ts_ns = row.get("start_ts_ns", None)
                if ts_ns is not None and pd.notna(ts_ns) and int(ts_ns) > 0:
                    ts_iso = dt.datetime.fromtimestamp(int(ts_ns) / 1e9, tz=dt.timezone.utc).isoformat()
                else:
                    ts_iso = dt.datetime.now(tz=dt.timezone.utc).isoformat()

                alert = AlertRecord(
                    timestamp=ts_iso,
                    flow_id=flow_id,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=proto,
                    attack_type=str(row["final_label"]),
                    severity=severity,
                    confidence=round(float(row.get("stage2_confidence", 1.0)), 4),
                    stage1_anomaly_score=round(float(row.get("stage1_score", 0.0)), 4),
                    stage3_botnet_role=str(row.get("stage3_src_role", "benign")),
                    stage3_beaconing=bool(row.get("stage3_beaconing", 0)),
                    detection_latency_ms=round(float(per_flow_ms), 4),
                    firewall_action=fw_action,
                )
                new_alerts.append(alert)
                fh.write(json.dumps(asdict(alert), ensure_ascii=False) + "\n")

        self.alerts.extend(new_alerts)
        self.flow_window.clear()

        summary["alerts_emitted"] = len(new_alerts)
        summary["blocked_ips_count"] = len(self.blocked_ips)
        return new_alerts, summary

    def run_live_capture(
        self,
        interface: str = "eth0",
        bpf_filter: str = "ip",
        duration_s: float = 30.0,
        packet_count: int = 0,
    ) -> dict[str, Any]:
        """Capture live traffic on a network interface using Scapy ``sniff()``."""
        try:
            from scapy.all import sniff  # type: ignore
        except ImportError as exc:
            raise RuntimeError("Scapy is required for live interface capture (pip install scapy)") from exc

        logger.info("Starting live capture on interface=%s filter='%s' duration=%.1fs", interface, bpf_filter, duration_s)

        def _on_pkt(scapy_pkt: Any) -> None:
            ts_ns = int(float(getattr(scapy_pkt, "time", time.time())) * 1e9)
            self.ingest_raw_frame(ts_ns, bytes(scapy_pkt), link_type=1)

        sniff(
            iface=interface,
            filter=bpf_filter,
            prn=_on_pkt,
            store=False,
            timeout=duration_s if duration_s > 0 else None,
            count=packet_count if packet_count > 0 else 0,
        )
        alerts, summary = self.flush_and_analyze()
        logger.info("Live capture finished: %d flows, %d alerts emitted", summary["n_flows"], len(alerts))
        return summary
