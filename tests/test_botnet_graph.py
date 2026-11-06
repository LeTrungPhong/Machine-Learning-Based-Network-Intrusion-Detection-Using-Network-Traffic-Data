"""Comprehensive tests for graph-based botnet topology & ML detection."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pytest

from graph.botnet_graph import (
    GRAPH_FEATURE_COLUMNS,
    build_communication_graph,
    detect_botnet_topology,
    extract_graph_features,
    generate_synthetic_botnet_flows,
    parse_binetflow,
    plot_botnet_graph,
    train_evaluate_graph_models,
)


def test_empty_and_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="missing required column"):
        build_communication_graph(pd.DataFrame({"src_ip": ["10.0.0.1"]}))

    empty_df = pd.DataFrame(columns=["src_ip", "dst_ip", "dst_port", "start_ts_ns", "fwd_bytes", "bwd_bytes"])
    G = build_communication_graph(empty_df)
    assert G.number_of_nodes() == 0 and G.number_of_edges() == 0

    feat = extract_graph_features(G)
    assert feat.empty and list(feat.columns) == ["ip", *GRAPH_FEATURE_COLUMNS]

    ann, summary = detect_botnet_topology(G, feat)
    assert ann.empty and summary["topology_type"] == "none"


def test_self_loops_ignored_and_edge_beaconing_computed() -> None:
    t0 = 1_700_000_000_000_000_000
    rows = [
        # Self-loop should be ignored
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.1", "dst_port": 80, "start_ts_ns": t0, "fwd_bytes": 100, "bwd_bytes": 100},
    ]
    # Periodic edge 10.0.0.2 -> 203.0.113.5 every 10 seconds (6 flows -> 5 intervals of 10s, CV = 0.0)
    for k in range(6):
        rows.append({
            "src_ip": "10.0.0.2",
            "dst_ip": "203.0.113.5",
            "dst_port": 8080,
            "start_ts_ns": t0 + k * 10 * 1_000_000_000,
            "fwd_bytes": 50,
            "bwd_bytes": 150,
        })
    # Irregular edge 10.0.0.3 -> 203.0.113.5
    for t_s in (0, 2, 45, 46, 200, 500):
        rows.append({
            "src_ip": "10.0.0.3",
            "dst_ip": "203.0.113.5",
            "dst_port": 443,
            "start_ts_ns": t0 + t_s * 1_000_000_000,
            "fwd_bytes": 100,
            "bwd_bytes": 200,
        })

    G = build_communication_graph(pd.DataFrame(rows), {"min_beacon_flows": 5, "max_beacon_cv": 0.2})
    assert "10.0.0.1" not in G
    assert G.has_edge("10.0.0.2", "203.0.113.5")

    e_periodic = G.edges["10.0.0.2", "203.0.113.5"]
    assert e_periodic["n_flows"] == 6
    assert e_periodic["total_bytes"] == 6 * 200
    assert e_periodic["mean_interval_s"] == pytest.approx(10.0)
    assert e_periodic["interval_cv"] == pytest.approx(0.0)
    assert e_periodic["beaconing_edge"] is True

    e_irreg = G.edges["10.0.0.3", "203.0.113.5"]
    assert e_irreg["beaconing_edge"] is False and e_irreg["interval_cv"] > 0.5


def test_centralized_botnet_topology_detection() -> None:
    flows, gt = generate_synthetic_botnet_flows(
        scenario="centralized", n_benign_hosts=30, n_centralized_bots=8, n_p2p_bots=0, seed=7
    )
    G = build_communication_graph(flows)
    ann, summary = detect_botnet_topology(G)

    assert summary["topology_type"] == "centralized"
    assert summary["c2_servers"] == ["203.0.113.200"]
    assert len(summary["centralized_bots"]) == 8
    assert summary["p2p_bots"] == []

    # Check 100% role agreement with ground truth
    pred_by_ip = dict(zip(ann["ip"], ann["predicted_role"]))
    for ip, true_role in gt.items():
        if ip in pred_by_ip:
            assert pred_by_ip[ip] == true_role


def test_p2p_botnet_topology_detection() -> None:
    flows, gt = generate_synthetic_botnet_flows(
        scenario="p2p", n_benign_hosts=30, n_centralized_bots=0, n_p2p_bots=10, seed=11
    )
    G = build_communication_graph(flows)
    ann, summary = detect_botnet_topology(G)

    assert summary["topology_type"] == "p2p"
    assert summary["c2_servers"] == []
    assert summary["centralized_bots"] == []
    assert len(summary["p2p_bots"]) == 10

    pred_by_ip = dict(zip(ann["ip"], ann["predicted_role"]))
    for ip, true_role in gt.items():
        if ip in pred_by_ip:
            assert pred_by_ip[ip] == true_role


def test_hybrid_botnet_topology_and_ml_comparison() -> None:
    flows, gt = generate_synthetic_botnet_flows(
        scenario="hybrid", n_benign_hosts=50, n_centralized_bots=12, n_p2p_bots=10, seed=42
    )
    G = build_communication_graph(flows)
    feat = extract_graph_features(G)
    ann, summary = detect_botnet_topology(G, feat)

    assert summary["topology_type"] == "hybrid"
    assert summary["c2_servers"] == ["203.0.113.200"]
    assert len(summary["centralized_bots"]) == 12
    assert len(summary["p2p_bots"]) == 10

    comp_df, artifacts = train_evaluate_graph_models(ann, gt, seed=42)
    assert len(comp_df) == 6
    assert set(comp_df["Model"]) >= {
        "Graph Topology Heuristic",
        "Gaussian Anomaly (Graph)",
        "Isolation Forest (Graph)",
        "Random Forest (Graph)",
        "Gradient Boosting (Graph)",
        "MLP Neural Net (Graph)",
    }
    # Supervised & heuristic models should achieve high F1 on clean structural features
    rf_f1 = comp_df.loc[comp_df["Model"] == "Random Forest (Graph)", "F1-Score"].iloc[0]
    topo_f1 = comp_df.loc[comp_df["Model"] == "Graph Topology Heuristic", "F1-Score"].iloc[0]
    assert rf_f1 >= 0.90
    assert topo_f1 >= 0.95
    assert "random_forest" in artifacts and "scaler" in artifacts


def test_benign_only_traffic_triggers_no_botnet_alert() -> None:
    flows, _ = generate_synthetic_botnet_flows(
        scenario="benign", n_benign_hosts=35, n_centralized_bots=0, n_p2p_bots=0, seed=99
    )
    G = build_communication_graph(flows)
    ann, summary = detect_botnet_topology(G)
    assert summary["topology_type"] == "none"
    assert summary["total_suspect_nodes"] == 0
    assert (ann["predicted_role"] == "benign").all()


def test_ctu13_binetflow_parser(tmp_path: Path) -> None:
    sample = tmp_path / "sample.binetflow"
    sample.write_text(
        "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n"
        "2011/08/10 09:46:53.047277,1.0,tcp,147.32.84.165,1025,->,203.0.113.9,0x0050,S_RA,0,0,4,240,120,flow=From-Botnet-V42-TCP-CC\n"
        "2011/08/10 09:47:03.047277,0.5,udp,147.32.84.170,53211,<->,8.8.8.8,53,CON,0,0,2,140,60,flow=From-Normal-V42-Stripped\n",
        encoding="utf-8",
    )
    df = parse_binetflow(sample)
    assert len(df) == 2
    assert df.loc[0, "dst_port"] == 80  # 0x0050 parsed as 80
    assert df.loc[0, "label"] == "Botnet" and df.loc[0, "is_botnet"] == 1
    assert df.loc[0, "fwd_bytes"] == 120 and df.loc[0, "bwd_bytes"] == 120
    assert df.loc[1, "label"] == "BENIGN" and df.loc[1, "is_botnet"] == 0


def test_plot_botnet_graph_saves_figure(tmp_path: Path) -> None:
    flows, _ = generate_synthetic_botnet_flows(
        scenario="centralized", n_benign_hosts=10, n_centralized_bots=4, n_p2p_bots=0, seed=1
    )
    G = build_communication_graph(flows)
    ann, _ = detect_botnet_topology(G)
    out_img = tmp_path / "graph.png"
    fig = plot_botnet_graph(G, ann, output_path=out_img)
    plt.close(fig)
    assert out_img.is_file() and out_img.stat().st_size > 1000

