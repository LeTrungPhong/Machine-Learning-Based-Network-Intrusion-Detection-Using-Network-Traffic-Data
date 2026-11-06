"""Multi-stage hybrid Network Intrusion Detection Pipeline.

Combines three complementary detection paradigms into a unified cascading
pipeline:

* **Stage 1 — Gaussian Anomaly Filter (Unsupervised):** Learns the multivariate
  log-likelihood distribution of ``BENIGN`` flows only. Acts as a fast
  first-stage filter and catches unseen / zero-day attacks that deviate
  strongly from normal traffic.
* **Stage 2 — Supervised Attack Classifier (Random Forest):** Classifies
  suspicious flows into specific attack families (``DoS``, ``DDoS``,
  ``PortScan``, ``BruteForce``, ``Bot``, etc.) and vetoes borderline Stage 1
  false positives when benign confidence is high.
* **Stage 3 — Host-Level & Graph Botnet Analyzer:** Aggregates flows across
  hosts and directed communication edges to detect periodic C2 beaconing,
  horizontal/vertical port scans, Centralized C2 servers, and P2P botnet
  meshes that cannot be recognized from a single flow in isolation.

Usage:
    python -m models.pipeline --demo
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_curve
from sklearn.preprocessing import LabelEncoder, RobustScaler

from graph.botnet_graph import build_communication_graph, detect_botnet_topology
from preprocessing.host_features import compute_host_features, detect_beaconing
from utils.config import PROJECT_ROOT, load_config

logger = logging.getLogger(__name__)

DEFAULT_FLOW_FEATURES: tuple[str, ...] = (
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "totlen_fwd_pkts",
    "totlen_bwd_pkts",
    "fwd_pkt_len_max",
    "fwd_pkt_len_min",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "flow_byts_s",
    "flow_pkts_s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "fwd_iat_tot",
    "bwd_iat_tot",
    "fwd_psh_flags",
    "syn_flag_cnt",
    "rst_flag_cnt",
    "ack_flag_cnt",
    "pkt_len_mean",
    "pkt_len_std",
    "subflow_fwd_pkts",
    "subflow_bwd_pkts",
)

META_COLS: set[str] = {
    "flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "timestamp", "start_ts_ns", "day", "source_file", "row_in_file",
    "label", "label_group", "label_binary", "is_botnet",
    "fwd_bytes", "bwd_bytes", "tot_bytes", "bwd_pkts",
}


def _signed_log1p(X: np.ndarray) -> np.ndarray:
    return np.sign(X) * np.log1p(np.abs(X))


@dataclass
class MultiStageNIDSPipeline:
    """Three-stage cascading NIDS pipeline (Gaussian -> Random Forest -> Host/Graph)."""

    feature_columns: list[str] = field(default_factory=lambda: list(DEFAULT_FLOW_FEATURES))
    seed: int = 42
    benign_label: str = "BENIGN"
    # Stage 1 Gaussian parameters
    gaussian_mu: np.ndarray | None = None
    gaussian_var: np.ndarray | None = None
    gaussian_threshold: float = 25.0
    zero_day_multiplier: float = 1.6
    benign_veto_confidence: float = 0.75
    # Stage 2 Supervised Classifier
    scaler: RobustScaler | None = None
    label_encoder: LabelEncoder | None = None
    classifier: RandomForestClassifier | None = None
    # Stage 3 Host & Graph config
    graph_cfg: dict[str, Any] = field(default_factory=dict)
    host_cfg: dict[str, Any] = field(default_factory=dict)
    is_fitted: bool = False

    def _extract_matrix(self, df: pd.DataFrame) -> np.ndarray:
        missing = [c for c in self.feature_columns if c not in df.columns]
        if missing:
            raise ValueError(f"Input DataFrame is missing required flow features: {missing}")
        X = df[self.feature_columns].to_numpy(dtype=np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        return _signed_log1p(X)

    def gaussian_score(self, X_scaled: np.ndarray) -> np.ndarray:
        """Compute negative log-likelihood anomaly score under the fitted Gaussian."""
        if self.gaussian_mu is None or self.gaussian_var is None:
            raise RuntimeError("Stage 1 Gaussian parameters are not fitted")
        return 0.5 * np.sum(
            np.log(2.0 * np.pi * self.gaussian_var) + ((X_scaled - self.gaussian_mu) ** 2) / self.gaussian_var,
            axis=1,
        )

    def fit(
        self,
        df_train: pd.DataFrame,
        label_col: str = "label",
        feature_cols: list[str] | None = None,
    ) -> "MultiStageNIDSPipeline":
        """Fit Stage 1 (Gaussian on BENIGN) and Stage 2 (Random Forest on all classes)."""
        if label_col not in df_train.columns:
            raise ValueError(f"Training DataFrame lacks label column '{label_col}'")

        if feature_cols is not None:
            self.feature_columns = list(feature_cols)
        else:
            inferred = [c for c in df_train.columns if c not in META_COLS]
            if inferred:
                self.feature_columns = inferred

        X_log = self._extract_matrix(df_train)
        y_raw = df_train[label_col].astype(str).to_numpy()
        y_bin = (y_raw != self.benign_label).astype(int)

        self.scaler = RobustScaler()
        X_scaled = self.scaler.fit_transform(X_log).astype(np.float32)

        # Stage 1: Fit Gaussian distribution strictly on BENIGN flows
        benign_mask = (y_bin == 0)
        if not np.any(benign_mask):
            raise ValueError("Training data must contain at least one BENIGN sample for Stage 1 Gaussian")
        X_benign = X_scaled[benign_mask]
        self.gaussian_mu = np.mean(X_benign, axis=0)
        self.gaussian_var = np.var(X_benign, axis=0) + 1e-4

        scores = self.gaussian_score(X_scaled)
        if np.any(y_bin == 1):
            prec, rec, th = precision_recall_curve(y_bin, scores)
            f1 = 2 * prec * rec / np.maximum(prec + rec, 1e-8)
            best_idx = int(np.argmax(f1))
            self.gaussian_threshold = float(th[min(best_idx, max(len(th) - 1, 0))])
        else:
            self.gaussian_threshold = float(np.percentile(scores, 98.0))

        # Stage 2: Fit Supervised Random Forest Classifier
        self.label_encoder = LabelEncoder()
        y_enc = self.label_encoder.fit_transform(y_raw)
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            class_weight="balanced",
            random_state=self.seed,
            n_jobs=-1,
        )
        self.classifier.fit(X_scaled, y_enc)
        self.is_fitted = True
        return self

    def predict_flows(
        self,
        flows_df: pd.DataFrame,
        enable_stage3: bool = True,
    ) -> tuple[pd.DataFrame, dict[str, Any]]:
        """Run the 3-stage detection pipeline on a batch or window of flows.

        Returns:
            ``(annotated_flows_df, summary_metrics_dict)``
        """
        if not self.is_fitted or self.scaler is None or self.classifier is None or self.label_encoder is None:
            raise RuntimeError("Pipeline must be fitted before calling predict_flows()")

        t_start = time.perf_counter()
        out = flows_df.copy().reset_index(drop=True)
        n_rows = len(out)
        if n_rows == 0:
            return out, {"n_flows": 0, "latency_ms": 0.0, "alerts_count": 0}

        # --- Stage 1: Gaussian Anomaly Filter ---
        t_s1 = time.perf_counter()
        X_log = self._extract_matrix(out)
        X_scaled = self.scaler.transform(X_log).astype(np.float32)
        s1_scores = self.gaussian_score(X_scaled)
        s1_flag = (s1_scores >= self.gaussian_threshold).astype(int)
        s1_ms = (time.perf_counter() - t_s1) * 1000.0

        # --- Stage 2: Supervised Multi-Class Classification ---
        t_s2 = time.perf_counter()
        proba = self.classifier.predict_proba(X_scaled)
        pred_idx = np.argmax(proba, axis=1)
        s2_labels = self.label_encoder.inverse_transform(pred_idx)
        s2_conf = np.max(proba, axis=1)

        benign_idx = (
            int(np.where(self.label_encoder.classes_ == self.benign_label)[0][0])
            if self.benign_label in self.label_encoder.classes_
            else -1
        )
        benign_prob = proba[:, benign_idx] if benign_idx >= 0 else np.zeros(n_rows)

        final_labels: list[str] = []
        for i in range(n_rows):
            if s2_labels[i] != self.benign_label and s2_conf[i] >= 0.45:
                # Stage 2 positively identifies a known attack family
                final_labels.append(str(s2_labels[i]))
            elif s1_flag[i] == 1 and s1_scores[i] >= self.gaussian_threshold * self.zero_day_multiplier:
                # Stage 1 detects an extreme statistical anomaly -> Zero-day / Unknown Anomaly even if Stage 2 tree missed it
                final_labels.append("Unknown_Anomaly")
            else:
                final_labels.append(self.benign_label)
        s2_ms = (time.perf_counter() - t_s2) * 1000.0

        # --- Stage 3: Host Beaconing & Graph Botnet Topology Analysis ---
        t_s3 = time.perf_counter()
        host_roles: dict[str, str] = {}
        beaconing_ips: set[str] = set()
        portscan_ips: set[str] = set()
        topology_summary: dict[str, Any] = {"topology_type": "none", "c2_servers": [], "centralized_bots": [], "p2p_bots": []}

        has_network_addrs = ("src_ip" in out.columns and "dst_ip" in out.columns)
        if enable_stage3 and has_network_addrs:
            G = build_communication_graph(out, self.graph_cfg)
            ann_nodes, topology_summary = detect_botnet_topology(G, cfg=self.graph_cfg)
            if not ann_nodes.empty:
                host_roles = dict(zip(ann_nodes["ip"], ann_nodes["predicted_role"]))

            # Check periodic beaconing if timestamps are present
            if "start_ts_ns" in out.columns:
                b_df = detect_beaconing(out, min_connections=5, max_interval_cv=0.25)
                if not b_df.empty:
                    beaconing_ips = set(b_df.loc[b_df["beaconing_suspect"], "src_ip"].astype(str))

            # Check host-level PortScan indicators if required columns exist
            req_host_cols = {"src_ip", "dst_ip", "dst_port", "protocol", "start_ts_ns", "bwd_pkts", "fwd_bytes", "bwd_bytes", "syn_flag_cnt", "ack_flag_cnt", "rst_flag_cnt"}
            if req_host_cols.issubset(out.columns):
                h_df = compute_host_features(out, window_s=60.0, step_s=10.0)
                if not h_df.empty:
                    portscan_ips = set(h_df.loc[h_df["portscan_suspect"], "src_ip"].astype(str))

            # Upgrade flow labels when Stage 3 detects botnet or portscan behavior at host/graph level
            for i in range(n_rows):
                src = str(out.loc[i, "src_ip"])
                dst = str(out.loc[i, "dst_ip"])
                src_role = host_roles.get(src, "benign")
                dst_role = host_roles.get(dst, "benign")
                if src_role in ("c2_server", "centralized_bot", "p2p_bot") or dst_role == "c2_server" or src in beaconing_ips:
                    if final_labels[i] in (self.benign_label, "Unknown_Anomaly"):
                        final_labels[i] = "Bot"
                elif src in portscan_ips and final_labels[i] == self.benign_label:
                    final_labels[i] = "PortScan"

        s3_ms = (time.perf_counter() - t_s3) * 1000.0
        total_ms = (time.perf_counter() - t_start) * 1000.0

        out["stage1_score"] = s1_scores
        out["stage1_flag"] = s1_flag
        out["stage2_label"] = s2_labels
        out["stage2_confidence"] = s2_conf
        if has_network_addrs:
            out["stage3_src_role"] = out["src_ip"].astype(str).map(lambda ip: host_roles.get(ip, "benign"))
            out["stage3_beaconing"] = out["src_ip"].astype(str).isin(beaconing_ips).astype(int)
        else:
            out["stage3_src_role"] = "benign"
            out["stage3_beaconing"] = 0

        out["final_label"] = final_labels
        out["final_is_attack"] = (out["final_label"] != self.benign_label).astype(int)

        severities: list[str] = []
        for i, lbl in enumerate(final_labels):
            if lbl == self.benign_label:
                severities.append("NONE")
            elif lbl in ("Bot", "DDoS") or out.loc[i, "stage3_src_role"] in ("c2_server", "p2p_bot"):
                severities.append("CRITICAL")
            elif lbl in ("DoS", "BruteForce", "Unknown_Anomaly"):
                severities.append("HIGH")
            else:
                severities.append("MEDIUM")
        out["alert_severity"] = severities

        summary = {
            "n_flows": n_rows,
            "stage1_flagged": int(np.sum(s1_flag)),
            "stage2_attacks": int(np.sum(s2_labels != self.benign_label)),
            "stage3_topology": topology_summary.get("topology_type", "none"),
            "stage3_botnet_hosts": len(topology_summary.get("c2_servers", [])) + len(topology_summary.get("centralized_bots", [])) + len(topology_summary.get("p2p_bots", [])),
            "alerts_count": int(out["final_is_attack"].sum()),
            "attack_breakdown": out["final_label"].value_counts().to_dict(),
            "latency_total_ms": float(total_ms),
            "latency_per_flow_ms": float(total_ms / max(n_rows, 1)),
            "stage_latencies_ms": {
                "stage1_gaussian": float(s1_ms),
                "stage2_rf": float(s2_ms),
                "stage3_graph_host": float(s3_ms),
            },
        }
        return out, summary

    def save(self, path: str | Path | None = None) -> Path:
        """Persist the fitted multi-stage pipeline to disk."""
        target = Path(path) if path is not None else (PROJECT_ROOT / "saved_models" / "multistage_pipeline.joblib")
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, target)
        return target

    @classmethod
    def load(cls, path: str | Path | None = None) -> "MultiStageNIDSPipeline":
        """Load a persisted multi-stage pipeline from disk."""
        target = Path(path) if path is not None else (PROJECT_ROOT / "saved_models" / "multistage_pipeline.joblib")
        obj = joblib.load(target)
        if not isinstance(obj, cls):
            raise TypeError(f"Expected MultiStageNIDSPipeline in {target}, got {type(obj)}")
        return obj


# ---------------------------------------------------------------- Synthetic hybrid generator

def generate_multistage_benchmark_data(
    n_flows: int = 6000,
    include_unseen_attack: bool = True,
    seed: int = 42,
) -> pd.DataFrame:
    """Create a multi-class flow dataset with IP addresses, timestamps, and C2 beaconing."""
    rng = np.random.default_rng(seed)
    classes = ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "Bot"]
    weights = [0.65, 0.11, 0.09, 0.08, 0.04, 0.03]
    labels = rng.choice(classes, size=n_flows, p=weights)

    n_feats = len(DEFAULT_FLOW_FEATURES)
    X = np.zeros((n_flows, n_feats), dtype=np.float32)
    src_ips: list[str] = []
    dst_ips: list[str] = []
    dst_ports: list[int] = []
    timestamps_ns: list[int] = []

    t0_ns = 1_700_000_000_000_000_000
    bot_counter = 0

    for i, lbl in enumerate(labels):
        if lbl == "BENIGN":
            X[i] = rng.exponential(scale=8.0, size=n_feats)
            X[i, 17:20] = rng.binomial(1, 0.1, size=3)
            src_ips.append(f"10.0.1.{rng.integers(1, 60)}")
            dst_ips.append(f"198.51.100.{rng.integers(1, 10)}")
            dst_ports.append(int(rng.choice([53, 80, 443])))
            timestamps_ns.append(t0_ns + int(rng.uniform(0, 600) * 1e9))
        elif lbl == "DoS":
            X[i] = rng.normal(loc=45.0, scale=6.0, size=n_feats)
            X[i, 9] = rng.uniform(500, 900)   # flow_byts_s
            X[i, 10] = rng.uniform(300, 600)  # flow_pkts_s
            X[i, 17] = 1
            src_ips.append(f"172.16.0.{rng.integers(1, 5)}")
            dst_ips.append("10.0.0.10")
            dst_ports.append(80)
            timestamps_ns.append(t0_ns + int(rng.uniform(60, 180) * 1e9))
        elif lbl == "DDoS":
            X[i] = rng.normal(loc=85.0, scale=8.0, size=n_feats)
            X[i, 9] = rng.uniform(1500, 3000)
            X[i, 10] = rng.uniform(1000, 2000)
            X[i, 17] = 1
            X[i, 19] = 1
            src_ips.append(f"172.16.1.{rng.integers(1, 30)}")
            dst_ips.append("10.0.0.10")
            dst_ports.append(80)
            timestamps_ns.append(t0_ns + int(rng.uniform(180, 300) * 1e9))
        elif lbl == "PortScan":
            X[i] = rng.exponential(scale=1.5, size=n_feats)
            X[i, 0] = rng.uniform(5, 80)
            X[i, 1] = 1
            X[i, 17] = 1
            X[i, 18] = 1
            src_ips.append("10.0.9.99")
            dst_ips.append("10.0.0.10")
            dst_ports.append(int(1000 + (i % 500)))
            timestamps_ns.append(t0_ns + int((i * 0.05) * 1e9))
        elif lbl == "BruteForce":
            X[i] = rng.normal(loc=25.0, scale=3.0, size=n_feats)
            X[i, 1] = rng.integers(15, 30)
            X[i, 2] = rng.integers(15, 30)
            src_ips.append("10.0.8.88")
            dst_ips.append("10.0.0.22")
            dst_ports.append(22)
            timestamps_ns.append(t0_ns + int(rng.uniform(100, 400) * 1e9))
        else:  # Bot (periodic C2 beaconing; 50% stealthy flows mimicking BENIGN packet stats)
            bot_id = (bot_counter % 6) + 1
            step_k = bot_counter // 6
            bot_counter += 1
            if bot_counter % 2 == 0:
                X[i] = rng.exponential(scale=8.0, size=n_feats)
                X[i, 17:20] = 0
            else:
                X[i] = rng.normal(loc=18.0, scale=2.5, size=n_feats)
            src_ips.append(f"10.0.2.{bot_id}")
            dst_ips.append("203.0.113.200")
            dst_ports.append(8443)
            timestamps_ns.append(t0_ns + int((step_k * 30.0 + rng.normal(0, 0.2)) * 1e9))

    df = pd.DataFrame(np.abs(X), columns=list(DEFAULT_FLOW_FEATURES))
    df["src_ip"] = src_ips
    df["dst_ip"] = dst_ips
    df["dst_port"] = dst_ports
    df["protocol"] = "TCP"
    df["start_ts_ns"] = timestamps_ns
    df["fwd_bytes"] = df["totlen_fwd_pkts"].astype(np.int64)
    df["bwd_bytes"] = df["totlen_bwd_pkts"].astype(np.int64)
    df["bwd_pkts"] = df["tot_bwd_pkts"].astype(np.int64)
    df["syn_flag_cnt"] = df["syn_flag_cnt"].astype(np.int64)
    df["ack_flag_cnt"] = df["ack_flag_cnt"].astype(np.int64)
    df["rst_flag_cnt"] = df["rst_flag_cnt"].astype(np.int64)
    df["label"] = labels
    df["label_binary"] = (df["label"] != "BENIGN").astype(int)

    if include_unseen_attack:
        # Inject 40 flows of an unseen Zero-Day Exploit that mimics BENIGN on primary tree features
        # (columns 0..19) so supervised trees classify it as BENIGN, but has huge anomaly on tail columns (20..23)
        n_zd = 40
        X_zd = rng.exponential(scale=6.0, size=(n_zd, n_feats)).astype(np.float32)
        X_zd[:, 17:20] = 0
        X_zd[:, 20:24] = rng.uniform(5000.0, 9000.0, size=(n_zd, 4))
        zd_df = pd.DataFrame(np.abs(X_zd), columns=list(DEFAULT_FLOW_FEATURES))
        zd_df["src_ip"] = "192.0.2.250"
        zd_df["dst_ip"] = "10.0.0.50"
        zd_df["dst_port"] = 4444
        zd_df["protocol"] = "TCP"
        zd_df["start_ts_ns"] = t0_ns + np.arange(n_zd, dtype=np.int64) * 2_000_000_000
        zd_df["fwd_bytes"] = 50000
        zd_df["bwd_bytes"] = 50000
        zd_df["bwd_pkts"] = 100
        zd_df["syn_flag_cnt"] = 0
        zd_df["ack_flag_cnt"] = 1
        zd_df["rst_flag_cnt"] = 0
        zd_df["label"] = "ZeroDay_Exploit"
        zd_df["label_binary"] = 1
        df = pd.concat([df, zd_df], ignore_index=True)

    return df


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train and test the 3-stage NIDS pipeline")
    parser.add_argument("--demo", action="store_true", help="Run demo training & inference")
    parser.parse_args(argv)

    df = generate_multistage_benchmark_data(n_flows=5000, include_unseen_attack=True, seed=42)
    train_df = df[df["label"] != "ZeroDay_Exploit"].iloc[:3500].reset_index(drop=True)
    test_df = df.iloc[3500:].reset_index(drop=True)

    pipe = MultiStageNIDSPipeline(seed=42)
    pipe.fit(train_df)
    saved_path = pipe.save()

    pred_df, summary = pipe.predict_flows(test_df, enable_stage3=True)
    acc_bin = float(np.mean(pred_df["final_is_attack"] == test_df["label_binary"]))

    print("=== 3-Stage Hybrid NIDS Pipeline Summary ===")
    print(f"  Saved pipeline to : {saved_path}")
    print(f"  Evaluated flows   : {summary['n_flows']} flows ({summary['latency_per_flow_ms']:.4f} ms/flow)")
    print(f"  Stage 1 Flagged   : {summary['stage1_flagged']} anomalous flows")
    print(f"  Stage 2 Classified: {summary['stage2_attacks']} known attack flows")
    print(f"  Stage 3 Topology  : {summary['stage3_topology'].upper()} ({summary['stage3_botnet_hosts']} botnet hosts)")
    print(f"  Binary Accuracy   : {acc_bin * 100:.2f}%")
    print(f"  Attack Breakdown  : {summary['attack_breakdown']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
