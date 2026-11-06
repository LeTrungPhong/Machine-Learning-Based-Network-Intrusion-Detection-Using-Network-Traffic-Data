"""Graph-based botnet topology analysis and node classification.

Constructs a directed host-to-host communication graph ``G = (V, E)`` from
flow records (either the project's Parquet/CSV flow schema or CTU-13
``.binetflow`` captures), extracts structural and temporal graph features for
every host, identifies **Centralized (C2 star/hub-and-spoke)** versus
**Peer-to-Peer (P2P mesh)** botnet topologies, and benchmarks multiple machine
learning algorithms on the extracted graph feature space.

Usage:
    python -m graph.botnet_graph --demo
    python -m graph.botnet_graph --flows processed/flows.parquet
    python -m graph.botnet_graph --binetflow datasets/CTU-13/1/capture20110810.binetflow
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any

import joblib
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier as SklearnMLPClassifier
from sklearn.preprocessing import RobustScaler

from utils.config import PROJECT_ROOT, load_config

logger = logging.getLogger(__name__)

GRAPH_FEATURE_COLUMNS: tuple[str, ...] = (
    "in_degree",
    "out_degree",
    "total_degree",
    "in_out_degree_ratio",
    "weighted_in_degree",
    "weighted_out_degree",
    "bytes_in",
    "bytes_out",
    "bytes_ratio",
    "unique_dst_ports_out",
    "pagerank",
    "in_degree_centrality",
    "out_degree_centrality",
    "clustering_coef",
    "betweenness_centrality",
    "reciprocity_ratio",
    "beacon_out_edges",
    "beacon_in_edges",
    "min_out_interval_cv",
    "neighbor_mean_degree",
)

DEFAULT_GRAPH_CFG: dict[str, Any] = {
    "min_beacon_flows": 5,
    "max_beacon_cv": 0.25,
    "c2_min_beacon_peers": 3,
    "p2p_min_peers": 3,
    "p2p_min_clustering": 0.30,
    "p2p_min_reciprocity": 0.50,
    "pagerank_alpha": 0.85,
}


def _merged_cfg(cfg: dict[str, Any] | None) -> dict[str, Any]:
    out = dict(DEFAULT_GRAPH_CFG)
    if cfg:
        out.update({k: v for k, v in cfg.items() if v is not None})
    return out


# ---------------------------------------------------------------- CTU-13 input

def parse_binetflow(path: str | Path) -> pd.DataFrame:
    """Load a CTU-13 ``.binetflow`` file into the standard flow schema.

    Columns produced:
        ``src_ip``, ``dst_ip``, ``dst_port``, ``protocol``, ``start_ts_ns``,
        ``fwd_bytes``, ``bwd_bytes``, ``tot_bytes``, ``label``, ``is_botnet``.
    """
    df = pd.read_csv(path)
    col_map = {c.strip(): c for c in df.columns}

    def _col(name: str) -> pd.Series:
        if name not in col_map:
            raise ValueError(f"Missing column '{name}' in binetflow file {path}")
        return df[col_map[name]]

    ts = pd.to_datetime(_col("StartTime"), errors="coerce", utc=True)
    start_ts_ns = ts.astype("int64", errors="ignore").fillna(0).astype(np.int64)

    def _parse_port(val: Any) -> int:
        if pd.isna(val):
            return 0
        s = str(val).strip()
        try:
            return int(s, 16) if s.startswith("0x") else int(float(s))
        except ValueError:
            return 0

    dst_port = _col("Dport").map(_parse_port).astype(np.int64) if "Dport" in col_map else pd.Series(0, index=df.index)
    tot_bytes = pd.to_numeric(_col("TotBytes"), errors="coerce").fillna(0).astype(np.int64)
    fwd_bytes = (
        pd.to_numeric(_col("SrcBytes"), errors="coerce").fillna(0).astype(np.int64)
        if "SrcBytes" in col_map
        else tot_bytes
    )
    bwd_bytes = np.maximum(tot_bytes - fwd_bytes, 0)
    raw_label = _col("Label").astype(str) if "Label" in col_map else pd.Series("Background", index=df.index)
    is_botnet = raw_label.str.lower().str.contains("botnet", na=False)

    out = pd.DataFrame({
        "src_ip": _col("SrcAddr").astype(str).str.strip(),
        "dst_ip": _col("DstAddr").astype(str).str.strip(),
        "dst_port": dst_port,
        "protocol": _col("Proto").astype(str).str.strip().str.upper() if "Proto" in col_map else "TCP",
        "start_ts_ns": start_ts_ns,
        "fwd_bytes": fwd_bytes,
        "bwd_bytes": bwd_bytes,
        "tot_bytes": tot_bytes,
        "label": np.where(is_botnet, "Botnet", "BENIGN"),
        "is_botnet": is_botnet.astype(int),
    })
    return out.dropna(subset=["src_ip", "dst_ip"]).reset_index(drop=True)


# ---------------------------------------------------------------- Graph builder

def build_communication_graph(
    flows: pd.DataFrame,
    cfg: dict[str, Any] | None = None,
) -> nx.DiGraph:
    """Build a directed host-to-host communication graph ``G = (V, E)``.

    Each directed edge ``(src_ip, dst_ip)`` aggregates all flows initiated by
    ``src_ip`` towards ``dst_ip`` and computes inter-flow periodicity metrics
    to flag potential C2 beaconing links.
    """
    gcfg = _merged_cfg(cfg)
    min_beacon_flows = int(gcfg["min_beacon_flows"])
    max_beacon_cv = float(gcfg["max_beacon_cv"])

    for req in ("src_ip", "dst_ip"):
        if req not in flows.columns:
            raise ValueError(f"Flow DataFrame is missing required column: '{req}'")

    G = nx.DiGraph()
    if flows.empty:
        return G

    work = flows.copy()
    if "tot_bytes" not in work.columns:
        fwd = pd.to_numeric(work.get("fwd_bytes", 0), errors="coerce").fillna(0)
        bwd = pd.to_numeric(work.get("bwd_bytes", 0), errors="coerce").fillna(0)
        work["tot_bytes"] = fwd + bwd
    if "dst_port" not in work.columns:
        work["dst_port"] = 0
    if "start_ts_ns" not in work.columns:
        if "timestamp" in work.columns:
            ts = pd.to_datetime(work["timestamp"], errors="coerce", utc=True)
            work["start_ts_ns"] = ts.astype("int64").fillna(0).astype(np.int64)
        else:
            work["start_ts_ns"] = np.arange(len(work), dtype=np.int64) * 1_000_000_000

    # Drop self-loops for inter-host topology analysis
    work = work[work["src_ip"] != work["dst_ip"]]
    if work.empty:
        return G

    # Sort by timestamp so inter-arrival intervals are chronological
    work = work.sort_values("start_ts_ns", kind="stable")

    for (src, dst), grp in work.groupby(["src_ip", "dst_ip"], sort=False):
        n_flows = len(grp)
        total_bytes = int(grp["tot_bytes"].sum())
        unique_ports = int(grp["dst_port"].nunique())

        ts_s = grp["start_ts_ns"].to_numpy(dtype=np.float64) / 1e9
        if n_flows >= 2:
            diffs = np.diff(ts_s)
            mean_iv = float(np.mean(diffs))
            std_iv = float(np.std(diffs, ddof=1 if n_flows >= 3 else 0))
            cv = (std_iv / mean_iv) if mean_iv > 1e-9 else float("inf")
        else:
            mean_iv = float("nan")
            std_iv = float("nan")
            cv = float("inf")

        is_beacon = bool(
            n_flows >= min_beacon_flows
            and np.isfinite(mean_iv)
            and mean_iv > 1e-6
            and cv <= max_beacon_cv
        )

        G.add_edge(
            str(src),
            str(dst),
            n_flows=n_flows,
            total_bytes=total_bytes,
            unique_dst_ports=unique_ports,
            mean_interval_s=mean_iv,
            std_interval_s=std_iv,
            interval_cv=cv,
            beaconing_edge=is_beacon,
        )

    return G


# ---------------------------------------------------------------- Node features

def extract_graph_features(
    G: nx.DiGraph,
    cfg: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """Compute structural and temporal graph features for every node in ``G``."""
    gcfg = _merged_cfg(cfg)
    min_beacon_flows = int(gcfg["min_beacon_flows"])
    alpha = float(gcfg["pagerank_alpha"])

    if G.number_of_nodes() == 0:
        return pd.DataFrame(columns=["ip", *GRAPH_FEATURE_COLUMNS])

    nodes = sorted(G.nodes())
    undirected = G.to_undirected()

    try:
        pagerank = nx.pagerank(G, alpha=alpha, weight="n_flows")
    except Exception:
        pagerank = {n: 1.0 / len(nodes) for n in nodes}

    in_cent = nx.in_degree_centrality(G)
    out_cent = nx.out_degree_centrality(G)
    clustering = nx.clustering(undirected)
    k_sample = min(len(nodes), 100)
    betweenness = nx.betweenness_centrality(G, k=k_sample, seed=42)

    rows: list[dict[str, Any]] = []
    for u in nodes:
        in_edges = list(G.in_edges(u, data=True))
        out_edges = list(G.out_edges(u, data=True))

        in_deg = len(in_edges)
        out_deg = len(out_edges)
        tot_deg = in_deg + out_deg
        in_out_ratio = (in_deg + 1.0) / (out_deg + 1.0)

        w_in = sum(int(d.get("n_flows", 1)) for _, _, d in in_edges)
        w_out = sum(int(d.get("n_flows", 1)) for _, _, d in out_edges)

        b_in = sum(int(d.get("total_bytes", 0)) for _, _, d in in_edges)
        b_out = sum(int(d.get("total_bytes", 0)) for _, _, d in out_edges)
        b_ratio = (b_in + 1.0) / (b_out + 1.0)

        u_ports_out = sum(int(d.get("unique_dst_ports", 1)) for _, _, d in out_edges)

        out_peers = {v for _, v, _ in out_edges}
        in_peers = {v for v, _, _ in in_edges}
        all_peers = out_peers | in_peers
        mutual_peers = out_peers & in_peers
        reciprocity_ratio = len(mutual_peers) / max(len(all_peers), 1)

        beacon_out = sum(1 for _, _, d in out_edges if d.get("beaconing_edge", False))
        beacon_in = sum(1 for _, _, d in in_edges if d.get("beaconing_edge", False))

        valid_cvs = [
            float(d["interval_cv"])
            for _, _, d in out_edges
            if int(d.get("n_flows", 0)) >= min_beacon_flows and np.isfinite(d.get("interval_cv", np.inf))
        ]
        min_cv = min(valid_cvs) if valid_cvs else 1.0

        nbrs = list(undirected.neighbors(u))
        nbr_mean_deg = float(np.mean([G.in_degree(v) + G.out_degree(v) for v in nbrs])) if nbrs else 0.0

        rows.append({
            "ip": u,
            "in_degree": float(in_deg),
            "out_degree": float(out_deg),
            "total_degree": float(tot_deg),
            "in_out_degree_ratio": float(in_out_ratio),
            "weighted_in_degree": float(w_in),
            "weighted_out_degree": float(w_out),
            "bytes_in": float(b_in),
            "bytes_out": float(b_out),
            "bytes_ratio": float(b_ratio),
            "unique_dst_ports_out": float(u_ports_out),
            "pagerank": float(pagerank.get(u, 0.0)),
            "in_degree_centrality": float(in_cent.get(u, 0.0)),
            "out_degree_centrality": float(out_cent.get(u, 0.0)),
            "clustering_coef": float(clustering.get(u, 0.0)),
            "betweenness_centrality": float(betweenness.get(u, 0.0)),
            "reciprocity_ratio": float(reciprocity_ratio),
            "beacon_out_edges": float(beacon_out),
            "beacon_in_edges": float(beacon_in),
            "min_out_interval_cv": float(min_cv),
            "neighbor_mean_degree": float(nbr_mean_deg),
        })

    return pd.DataFrame(rows)


# ---------------------------------------------------------------- Topology detection

def detect_botnet_topology(
    G: nx.DiGraph,
    features_df: pd.DataFrame | None = None,
    cfg: dict[str, Any] | None = None,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Classify host roles and overall botnet topology (Centralized vs P2P).

    Roles assigned in ``predicted_role``:
        * ``"c2_server"``        - central Command & Control hub receiving periodic beacons
        * ``"centralized_bot"``  - spoke host periodically beaconing to a C2 server
        * ``"p2p_bot"``          - peer node inside a high-clustering, reciprocal P2P mesh
        * ``"benign"``           - normal background host

    Returns:
        ``(annotated_features_df, topology_summary_dict)``
    """
    gcfg = _merged_cfg(cfg)
    c2_min_peers = int(gcfg["c2_min_beacon_peers"])
    p2p_min_peers = int(gcfg["p2p_min_peers"])
    p2p_min_clust = float(gcfg["p2p_min_clustering"])
    p2p_min_recip = float(gcfg["p2p_min_reciprocity"])

    if features_df is None:
        features_df = extract_graph_features(G, gcfg)
    df = features_df.copy()

    if df.empty:
        return df, {
            "topology_type": "none",
            "n_nodes": 0,
            "n_edges": 0,
            "c2_servers": [],
            "centralized_bots": [],
            "p2p_bots": [],
        }

    feat_by_ip = df.set_index("ip").to_dict(orient="index")

    # 1. Identify P2P Bots first via the mutual-communication subgraph (reciprocal peer mesh)
    # P2P peers initiate connections in both directions (high reciprocity & high clustering),
    # whereas a centralized C2 server is a sink (low reciprocity, high in/out ratio).
    mutual_G = nx.Graph()
    for u, v in G.edges():
        if G.has_edge(v, u):
            mutual_G.add_edge(u, v)

    p2p_bots: set[str] = set()
    for comp in nx.connected_components(mutual_G):
        if len(comp) < p2p_min_peers + 1:
            continue
        sub = mutual_G.subgraph(comp)
        avg_clust = nx.average_clustering(sub) if len(sub) >= 3 else 0.0
        for u in comp:
            f = feat_by_ip[u]
            if (
                sub.degree(u) >= p2p_min_peers
                and (f["clustering_coef"] >= p2p_min_clust or avg_clust >= p2p_min_clust)
                and f["reciprocity_ratio"] >= p2p_min_recip
            ):
                p2p_bots.add(u)

    # 2. Identify Centralized C2 servers: non-P2P hosts receiving periodic beacons from >= c2_min_peers distinct bots
    c2_servers: set[str] = {
        ip for ip, f in feat_by_ip.items()
        if ip not in p2p_bots
        and f["beacon_in_edges"] >= c2_min_peers
        and f["reciprocity_ratio"] < p2p_min_recip
    }

    # 3. Identify Centralized Bots: spoke hosts with a beaconing edge directed into a C2 server
    centralized_bots: set[str] = set()
    for u, v, d in G.edges(data=True):
        if v in c2_servers and u not in c2_servers and u not in p2p_bots and d.get("beaconing_edge", False):
            centralized_bots.add(u)

    roles: list[str] = []
    suspects: list[int] = []
    for ip in df["ip"]:
        if ip in c2_servers:
            roles.append("c2_server")
            suspects.append(1)
        elif ip in centralized_bots:
            roles.append("centralized_bot")
            suspects.append(1)
        elif ip in p2p_bots:
            roles.append("p2p_bot")
            suspects.append(1)
        else:
            roles.append("benign")
            suspects.append(0)

    df["predicted_role"] = roles
    df["is_botnet_suspect"] = suspects

    has_centralized = bool(c2_servers and centralized_bots)
    has_p2p = bool(len(p2p_bots) >= p2p_min_peers)
    if has_centralized and has_p2p:
        topo_type = "hybrid"
    elif has_centralized:
        topo_type = "centralized"
    elif has_p2p:
        topo_type = "p2p"
    else:
        topo_type = "none"

    summary = {
        "topology_type": topo_type,
        "n_nodes": int(G.number_of_nodes()),
        "n_edges": int(G.number_of_edges()),
        "global_reciprocity": float(nx.overall_reciprocity(G)) if G.number_of_edges() > 0 else 0.0,
        "average_clustering": float(nx.average_clustering(G.to_undirected())) if G.number_of_nodes() > 0 else 0.0,
        "c2_servers": sorted(c2_servers),
        "centralized_bots": sorted(centralized_bots),
        "p2p_bots": sorted(p2p_bots),
        "total_suspect_nodes": int(sum(suspects)),
    }
    return df, summary


# ---------------------------------------------------------------- Synthetic benchmark generator

def generate_synthetic_botnet_flows(
    scenario: str = "hybrid",
    n_benign_hosts: int = 60,
    n_centralized_bots: int = 15,
    n_p2p_bots: int = 12,
    seed: int = 42,
) -> tuple[pd.DataFrame, dict[str, str]]:
    """Generate realistic flow traffic with ground-truth host roles.

    Args:
        scenario: ``"centralized"`` | ``"p2p"`` | ``"hybrid"`` | ``"benign"``.
        n_benign_hosts: Number of normal enterprise clients/servers.
        n_centralized_bots: Number of bots beaconing to a central C2 server.
        n_p2p_bots: Number of bots communicating in a dense P2P mesh.
        seed: Random seed.

    Returns:
        ``(flows_df, ground_truth_role_by_ip)``
    """
    if scenario not in ("centralized", "p2p", "hybrid", "benign"):
        raise ValueError(f"Unsupported scenario: {scenario}")

    rng = np.random.default_rng(seed)
    t0_ns = 1_700_000_000_000_000_000
    rows: list[dict[str, Any]] = []
    gt_roles: dict[str, str] = {}

    # 1. Normal background traffic: clients talking to web/DNS/internal servers with exponential inter-arrivals
    servers = [f"198.51.100.{i}" for i in range(1, 9)]
    clients = [f"10.0.1.{i}" for i in range(1, n_benign_hosts + 1)]
    for ip in servers + clients:
        gt_roles[ip] = "benign"

    for client in clients:
        n_targets = int(rng.integers(1, 5))
        chosen_servers = rng.choice(servers, size=n_targets, replace=False)
        for srv in chosen_servers:
            n_conns = int(rng.integers(2, 10))
            # Irregular human-like inter-arrival times (high CV > 0.6)
            gaps = rng.exponential(scale=45.0, size=n_conns)
            times = np.cumsum(gaps)
            for t in times:
                rows.append({
                    "src_ip": client,
                    "dst_ip": str(srv),
                    "dst_port": int(rng.choice([53, 80, 443, 8080])),
                    "protocol": "TCP",
                    "start_ts_ns": t0_ns + int(t * 1e9),
                    "fwd_bytes": int(rng.integers(150, 2000)),
                    "bwd_bytes": int(rng.integers(500, 15000)),
                    "label": "BENIGN",
                })

    # 2. Centralized Botnet (Star topology: Bots -> C2 server with periodic beaconing)
    if scenario in ("centralized", "hybrid") and n_centralized_bots > 0:
        c2_ip = "203.0.113.200"
        gt_roles[c2_ip] = "c2_server"
        for i in range(1, n_centralized_bots + 1):
            bot_ip = f"10.0.2.{i}"
            gt_roles[bot_ip] = "centralized_bot"
            period_s = 30.0
            n_beacons = int(rng.integers(8, 15))
            for k in range(n_beacons):
                jitter = float(rng.normal(0.0, 0.4))  # tiny jitter -> CV ~ 0.02
                t = max(0.1, k * period_s + jitter)
                rows.append({
                    "src_ip": bot_ip,
                    "dst_ip": c2_ip,
                    "dst_port": 8443,
                    "protocol": "TCP",
                    "start_ts_ns": t0_ns + int(t * 1e9),
                    "fwd_bytes": int(rng.integers(120, 160)),
                    "bwd_bytes": int(rng.integers(200, 350)),
                    "label": "Botnet",
                })
            # Bots also make 1-2 normal requests so they aren't trivially isolated
            srv = str(rng.choice(servers))
            rows.append({
                "src_ip": bot_ip,
                "dst_ip": srv,
                "dst_port": 443,
                "protocol": "TCP",
                "start_ts_ns": t0_ns + int(rng.uniform(5, 300) * 1e9),
                "fwd_bytes": 300,
                "bwd_bytes": 1200,
                "label": "Botnet",
            })

    # 3. P2P Botnet (Dense peer mesh with reciprocal connections and high clustering)
    if scenario in ("p2p", "hybrid") and n_p2p_bots > 0:
        p2p_ips = [f"10.0.3.{i}" for i in range(1, n_p2p_bots + 1)]
        for ip in p2p_ips:
            gt_roles[ip] = "p2p_bot"

        # Each P2P bot exchanges state bidirectionally with at least 5 peers in the P2P ring/mesh
        n_peers = len(p2p_ips)
        k_neighbors = min(5, max(1, n_peers - 1))
        for idx, u in enumerate(p2p_ips):
            for offset in range(1, k_neighbors + 1):
                v = p2p_ips[(idx + offset) % n_peers]
                # Both u -> v and v -> u initiate periodic peer-sync flows
                for sender, receiver in ((u, v), (v, u)):
                    for k in range(6):
                        t = k * 25.0 + float(rng.normal(0.0, 0.5))
                        rows.append({
                            "src_ip": sender,
                            "dst_ip": receiver,
                            "dst_port": 16881,
                            "protocol": "UDP",
                            "start_ts_ns": t0_ns + int(max(0.1, t) * 1e9),
                            "fwd_bytes": int(rng.integers(250, 450)),
                            "bwd_bytes": int(rng.integers(250, 450)),
                            "label": "Botnet",
                        })

    df = pd.DataFrame(rows)
    df["tot_bytes"] = df["fwd_bytes"] + df["bwd_bytes"]
    return df, gt_roles


# ---------------------------------------------------------------- ML evaluation on graph features

def train_evaluate_graph_models(
    features_df: pd.DataFrame,
    ground_truth_roles: dict[str, str] | None = None,
    seed: int = 42,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Train and compare ML algorithms for botnet node detection on graph features.

    Evaluates:
        1. Topological Heuristic Rule (Unsupervised Zero-Shot)
        2. Gaussian Anomaly Detector (Unsupervised on Benign nodes)
        3. Isolation Forest (Unsupervised on Benign nodes)
        4. Random Forest Classifier (Supervised)
        5. Gradient Boosting Classifier (Supervised)
        6. MLP Neural Network Classifier (Supervised)
    """
    df = features_df.copy()
    if ground_truth_roles is not None:
        df["true_role"] = df["ip"].map(lambda ip: ground_truth_roles.get(ip, "benign"))
        df["y_true"] = (df["true_role"] != "benign").astype(int)
    elif "is_botnet" in df.columns:
        df["y_true"] = df["is_botnet"].astype(int)
    elif "is_botnet_suspect" in df.columns:
        df["y_true"] = df["is_botnet_suspect"].astype(int)
    else:
        raise ValueError("Cannot evaluate models without ground_truth_roles or 'is_botnet' column")

    X = df[list(GRAPH_FEATURE_COLUMNS)].to_numpy(dtype=np.float32)
    X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
    y = df["y_true"].to_numpy(dtype=int)

    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, np.arange(len(y)), test_size=0.35, random_state=seed, stratify=y
    )

    scaler = RobustScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)
    X_train_benign = X_train_s[y_train == 0]

    results: dict[str, dict[str, Any]] = {}

    def _record(name: str, category: str, y_pred: np.ndarray, scores: np.ndarray | None = None) -> None:
        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        auc = float(roc_auc_score(y_test, scores)) if (scores is not None and len(np.unique(y_test)) > 1) else float("nan")
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        results[name] = {
            "Model": name,
            "Category": category,
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1-Score": f1,
            "ROC-AUC": auc,
            "FPR": fpr,
        }

    # 1. Graph Topology Heuristic
    if "is_botnet_suspect" in df.columns:
        y_pred_topo = df["is_botnet_suspect"].to_numpy(dtype=int)[idx_test]
        _record("Graph Topology Heuristic", "Unsupervised Rule", y_pred_topo, y_pred_topo.astype(float))

    # 2. Gaussian Anomaly Detection (trained on benign graph nodes)
    mu = np.mean(X_train_benign, axis=0)
    var = np.var(X_train_benign, axis=0) + 1e-3
    scores_train_g = 0.5 * np.sum(np.log(2 * np.pi * var) + ((X_train_s - mu) ** 2) / var, axis=1)
    scores_test_g = 0.5 * np.sum(np.log(2 * np.pi * var) + ((X_test_s - mu) ** 2) / var, axis=1)
    p_g, r_g, th_g = precision_recall_curve(y_train, scores_train_g)
    f1_g = 2 * p_g * r_g / np.maximum(p_g + r_g, 1e-8)
    best_th_g = th_g[min(int(np.argmax(f1_g)), max(len(th_g) - 1, 0))]
    _record("Gaussian Anomaly (Graph)", "Unsupervised ML", (scores_test_g >= best_th_g).astype(int), scores_test_g)

    # 3. Isolation Forest
    iso = IsolationForest(n_estimators=100, random_state=seed)
    iso.fit(X_train_benign)
    scores_train_if = -iso.score_samples(X_train_s)
    scores_test_if = -iso.score_samples(X_test_s)
    p_i, r_i, th_i = precision_recall_curve(y_train, scores_train_if)
    f1_i = 2 * p_i * r_i / np.maximum(p_i + r_i, 1e-8)
    best_th_i = th_i[min(int(np.argmax(f1_i)), max(len(th_i) - 1, 0))]
    _record("Isolation Forest (Graph)", "Unsupervised ML", (scores_test_if >= best_th_i).astype(int), scores_test_if)

    # 4. Random Forest Classifier
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, class_weight="balanced", random_state=seed)
    rf.fit(X_train_s, y_train)
    y_pred_rf = rf.predict(X_test_s)
    prob_rf = rf.predict_proba(X_test_s)[:, 1]
    _record("Random Forest (Graph)", "Supervised ML", y_pred_rf, prob_rf)

    # 5. Gradient Boosting Classifier
    gb = HistGradientBoostingClassifier(max_iter=100, max_depth=6, random_state=seed)
    gb.fit(X_train_s, y_train)
    y_pred_gb = gb.predict(X_test_s)
    prob_gb = gb.predict_proba(X_test_s)[:, 1]
    _record("Gradient Boosting (Graph)", "Supervised ML", y_pred_gb, prob_gb)

    # 6. MLP Neural Network Classifier
    mlp = SklearnMLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=seed)
    mlp.fit(X_train_s, y_train)
    y_pred_mlp = mlp.predict(X_test_s)
    prob_mlp = mlp.predict_proba(X_test_s)[:, 1]
    _record("MLP Neural Net (Graph)", "Supervised DL", y_pred_mlp, prob_mlp)

    comparison_df = pd.DataFrame(list(results.values()))
    artifacts = {
        "scaler": scaler,
        "random_forest": rf,
        "gradient_boosting": gb,
        "isolation_forest": iso,
        "feature_columns": list(GRAPH_FEATURE_COLUMNS),
        "metrics": results,
    }
    return comparison_df, artifacts


# ---------------------------------------------------------------- Visualisation

def plot_botnet_graph(
    G: nx.DiGraph,
    annotated_df: pd.DataFrame,
    output_path: str | Path | None = None,
    title: str = "Network Communication Graph & Detected Botnet Topology",
) -> plt.Figure:
    """Render the communication graph with nodes colored by detected botnet role."""
    role_map = dict(zip(annotated_df["ip"], annotated_df["predicted_role"]))
    color_palette = {
        "c2_server": "#d62728",        # Red
        "centralized_bot": "#ff7f0e",  # Orange
        "p2p_bot": "#9467bd",          # Purple
        "benign": "#1f77b4",           # Blue
    }
    size_palette = {
        "c2_server": 420,
        "centralized_bot": 180,
        "p2p_bot": 200,
        "benign": 65,
    }

    fig, ax = plt.subplots(figsize=(11, 7))
    pos = nx.spring_layout(G, k=0.45, iterations=60, seed=42)

    node_colors = [color_palette.get(role_map.get(n, "benign"), "#1f77b4") for n in G.nodes()]
    node_sizes = [size_palette.get(role_map.get(n, "benign"), 65) for n in G.nodes()]

    beacon_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get("beaconing_edge", False)]
    normal_edges = [(u, v) for u, v, d in G.edges(data=True) if not d.get("beaconing_edge", False)]

    nx.draw_networkx_edges(G, pos, edgelist=normal_edges, alpha=0.18, edge_color="#7f7f7f", arrows=True, ax=ax)
    nx.draw_networkx_edges(G, pos, edgelist=beacon_edges, alpha=0.65, edge_color="#d62728", width=1.4, arrows=True, ax=ax)
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.9, edgecolors="white", linewidths=0.8, ax=ax)

    # Label C2 servers and up to a few bots for readability
    labels = {
        n: f"{n}\n({role_map[n]})"
        for n in G.nodes()
        if role_map.get(n) == "c2_server"
    }
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, font_weight="bold", ax=ax)

    for role, col in color_palette.items():
        ax.scatter([], [], c=col, s=120, label=role)
    ax.legend(title="Detected Host Role", loc="upper right", frameon=True)
    ax.set_title(title, fontsize=12, fontweight="bold")
    ax.axis("off")
    plt.tight_layout()

    if output_path is not None:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(out_p, dpi=150, bbox_inches="tight")
    return fig


# ---------------------------------------------------------------- CLI entry point

def run_pipeline(
    flows: pd.DataFrame,
    gt_roles: dict[str, str] | None = None,
    cfg: dict[str, Any] | None = None,
    save_outputs: bool = True,
) -> dict[str, Any]:
    """Run the full botnet graph pipeline: build -> extract -> detect -> ML compare."""
    G = build_communication_graph(flows, cfg)
    feat_df = extract_graph_features(G, cfg)
    annotated_df, summary = detect_botnet_topology(G, feat_df, cfg)
    comparison_df, artifacts = train_evaluate_graph_models(annotated_df, gt_roles)

    if save_outputs:
        saved_dir = PROJECT_ROOT / "saved_models"
        out_dir = PROJECT_ROOT / "outputs" / "botnet_graph"
        saved_dir.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir(parents=True, exist_ok=True)

        joblib.dump(
            {
                "model": artifacts["random_forest"],
                "scaler": artifacts["scaler"],
                "feature_columns": artifacts["feature_columns"],
            },
            saved_dir / "botnet_graph_rf.joblib",
        )
        annotated_df.to_csv(out_dir / "node_features_and_roles.csv", index=False)
        comparison_df.to_csv(out_dir / "ml_botnet_comparison.csv", index=False)

        report_payload = {
            "topology_summary": summary,
            "ml_comparison": artifacts["metrics"],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        (out_dir / "botnet_graph_report.json").write_text(
            json.dumps(report_payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        fig = plot_botnet_graph(G, annotated_df, output_path=out_dir / "botnet_topology_graph.png")
        plt.close(fig)

    return {
        "graph": G,
        "annotated_df": annotated_df,
        "summary": summary,
        "comparison_df": comparison_df,
        "artifacts": artifacts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Graph-based Botnet Topology & ML Detection")
    parser.add_argument("--flows", type=Path, help="Input flow Parquet/CSV file")
    parser.add_argument("--binetflow", type=Path, help="Input CTU-13 .binetflow file")
    parser.add_argument("--demo", action="store_true", help="Run on synthetic hybrid (Centralized + P2P) benchmark")
    args = parser.parse_args(argv)

    cfg = load_config().get("models", {}).get("botnet_graph", {})
    gt_roles = None

    if args.binetflow:
        flows = parse_binetflow(args.binetflow)
    elif args.flows:
        flows = pd.read_parquet(args.flows) if args.flows.suffix == ".parquet" else pd.read_csv(args.flows)
    else:
        # Default to synthetic hybrid benchmark so it can run standalone anytime
        flows, gt_roles = generate_synthetic_botnet_flows(
            scenario="hybrid", n_benign_hosts=80, n_centralized_bots=20, n_p2p_bots=15, seed=42
        )

    res = run_pipeline(flows, gt_roles=gt_roles, cfg=cfg, save_outputs=True)
    summary = res["summary"]
    print("=== Botnet Graph Topology Summary ===")
    print(f"  Detected Topology : {summary['topology_type'].upper()}")
    print(f"  Total Nodes / Edges: {summary['n_nodes']} nodes, {summary['n_edges']} directed edges")
    print(f"  C2 Servers ({len(summary['c2_servers'])})     : {summary['c2_servers']}")
    print(f"  Centralized Bots  : {len(summary['centralized_bots'])} hosts")
    print(f"  P2P Bots          : {len(summary['p2p_bots'])} hosts")
    print("\n=== ML Model Comparison on Graph Features ===")
    print(res["comparison_df"].to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
