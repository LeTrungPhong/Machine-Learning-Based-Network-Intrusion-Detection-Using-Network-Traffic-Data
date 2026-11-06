"""Tests for the 3-stage hybrid NIDS pipeline and full evaluation suite."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from evaluation.evaluate_pipeline import evaluate_all_approaches
from models.pipeline import (
    DEFAULT_FLOW_FEATURES,
    MultiStageNIDSPipeline,
    generate_multistage_benchmark_data,
)


def test_pipeline_error_handling() -> None:
    pipe = MultiStageNIDSPipeline()
    df = generate_multistage_benchmark_data(n_flows=200, include_unseen_attack=False, seed=1)

    with pytest.raises(RuntimeError, match="must be fitted"):
        pipe.predict_flows(df)

    with pytest.raises(ValueError, match="lacks label column"):
        pipe.fit(df.drop(columns=["label"]))

    only_attack = df[df["label"] != "BENIGN"].reset_index(drop=True)
    with pytest.raises(ValueError, match="at least one BENIGN"):
        pipe.fit(only_attack)

    pipe.fit(df)
    with pytest.raises(ValueError, match="missing required flow features"):
        pipe.predict_flows(df.drop(columns=[DEFAULT_FLOW_FEATURES[0]]))


def test_three_stage_pipeline_detects_known_and_zeroday_attacks(tmp_path: Path) -> None:
    df = generate_multistage_benchmark_data(n_flows=1500, include_unseen_attack=True, seed=42)
    train_df = df[df["label"] != "ZeroDay_Exploit"].iloc[:1000].reset_index(drop=True)
    test_df = df.iloc[1000:].reset_index(drop=True)

    pipe = MultiStageNIDSPipeline(seed=42)
    pipe.fit(train_df)

    # Test save/load round-trip
    saved_file = pipe.save(tmp_path / "pipe.joblib")
    loaded_pipe = MultiStageNIDSPipeline.load(saved_file)

    pred_df, summary = loaded_pipe.predict_flows(test_df, enable_stage3=True)
    assert len(pred_df) == len(test_df)
    assert summary["n_flows"] == len(test_df)
    assert summary["latency_per_flow_ms"] > 0

    # Binary accuracy should be > 95%
    acc = float(np.mean(pred_df["final_is_attack"] == test_df["label_binary"]))
    assert acc >= 0.95

    # Unseen ZeroDay_Exploit rows in test_df should be caught as attacks
    zd_mask = (test_df["label"] == "ZeroDay_Exploit")
    assert zd_mask.sum() > 0
    assert (pred_df.loc[zd_mask, "final_is_attack"] == 1).mean() >= 0.95


def test_stage3_upgrades_stealthy_beaconing_to_bot() -> None:
    df = generate_multistage_benchmark_data(n_flows=800, include_unseen_attack=False, seed=7)
    pipe = MultiStageNIDSPipeline(seed=7)
    pipe.fit(df)

    # Craft 6 flows that look completely BENIGN at the flow feature level,
    # but exhibit periodic beaconing every 20.0s from 3 bots to a C2 server 203.0.113.99
    benign_template = df[df["label"] == "BENIGN"].iloc[0].to_dict()
    stealth_rows = []
    t0 = 1_700_000_000_000_000_000
    for bot_idx in range(1, 4):
        for k in range(6):
            row = dict(benign_template)
            row["src_ip"] = f"10.99.0.{bot_idx}"
            row["dst_ip"] = "203.0.113.99"
            row["dst_port"] = 8443
            row["start_ts_ns"] = t0 + k * 20 * 1_000_000_000
            stealth_rows.append(row)

    stealth_df = pd.DataFrame(stealth_rows)

    # Without Stage 3, flow features look benign -> not flagged as Bot
    pred_no_s3, _ = pipe.predict_flows(stealth_df, enable_stage3=False)
    assert (pred_no_s3["final_label"] == "BENIGN").all()

    # With Stage 3 enabled, host beaconing & C2 graph topology upgrades them to 'Bot'
    pred_with_s3, sum_s3 = pipe.predict_flows(stealth_df, enable_stage3=True)
    assert (pred_with_s3["final_label"] == "Bot").all()
    assert (pred_with_s3["final_is_attack"] == 1).all()
    assert sum_s3["stage3_topology"] == "centralized"


def test_evaluate_all_approaches_and_ablation() -> None:
    df = generate_multistage_benchmark_data(n_flows=3000, include_unseen_attack=True, seed=123)
    res = evaluate_all_approaches(df=df, seed=123, save_outputs=False)

    comp_df = res["comparison_df"]
    ablation_df = res["ablation_df"]
    assert len(comp_df) == 7
    assert len(ablation_df) == 4

    full_row = comp_df[comp_df["Approach"] == "3-Stage Hybrid Pipeline (Full)"].iloc[0]
    assert full_row["F1-Score"] >= 0.94
    assert full_row["ZeroDay_Recall"] >= 0.95
    assert full_row["Botnet_Recall"] >= 0.95
