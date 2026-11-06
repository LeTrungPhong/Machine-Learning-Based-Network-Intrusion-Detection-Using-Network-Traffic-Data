"""Comprehensive evaluation, model comparison, and ablation study (STEP 10).

Compares standalone anomaly detectors (Gaussian, Isolation Forest), standalone
supervised classifiers (Random Forest, Gradient Boosting, MLP), and the full
3-Stage Cascading NIDS Pipeline across:

* Overall Binary Detection (Accuracy, Precision, Recall, F1-Score, FPR)
* Known Attack Classification (Macro-F1)
* Unseen / Zero-Day Attack Recall (``ZeroDay_Exploit`` detection rate)
* Botnet C2 / Beaconing Recall (``Bot`` detection rate)
* Per-flow Inference Latency (ms/flow)

Usage:
    python -m evaluation.evaluate_pipeline
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
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
)
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelEncoder, RobustScaler

from models.pipeline import (
    DEFAULT_FLOW_FEATURES,
    MultiStageNIDSPipeline,
    generate_multistage_benchmark_data,
)
from utils.config import PROJECT_ROOT


def evaluate_all_approaches(
    df: pd.DataFrame | None = None,
    seed: int = 42,
    save_outputs: bool = True,
) -> dict[str, Any]:
    """Compare standalone models and the 3-stage pipeline, plus ablation study."""
    if df is None:
        df = generate_multistage_benchmark_data(n_flows=6000, include_unseen_attack=True, seed=seed)

    # Separate unseen Zero-Day flows so they appear ONLY in the test split
    known_df = df[df["label"] != "ZeroDay_Exploit"].reset_index(drop=True)
    zd_df = df[df["label"] == "ZeroDay_Exploit"].reset_index(drop=True)

    n_train = int(len(known_df) * 0.65)
    train_df = known_df.iloc[:n_train].reset_index(drop=True)
    test_df = pd.concat([known_df.iloc[n_train:], zd_df], ignore_index=True)

    feat_cols = list(DEFAULT_FLOW_FEATURES)
    X_train_raw = np.sign(train_df[feat_cols].to_numpy(dtype=np.float32)) * np.log1p(
        np.abs(train_df[feat_cols].to_numpy(dtype=np.float32))
    )
    X_test_raw = np.sign(test_df[feat_cols].to_numpy(dtype=np.float32)) * np.log1p(
        np.abs(test_df[feat_cols].to_numpy(dtype=np.float32))
    )

    scaler = RobustScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    y_bin_train = train_df["label_binary"].to_numpy(dtype=int)
    y_bin_test = test_df["label_binary"].to_numpy(dtype=int)
    y_lbl_train = train_df["label"].astype(str).to_numpy()
    y_lbl_test = test_df["label"].astype(str).to_numpy()

    zd_mask = (y_lbl_test == "ZeroDay_Exploit")
    bot_mask = (y_lbl_test == "Bot")

    comparison_rows: list[dict[str, Any]] = []

    def _score_binary(
        name: str,
        paradigm: str,
        y_pred_bin: np.ndarray,
        latency_ms: float,
    ) -> dict[str, Any]:
        acc = float(accuracy_score(y_bin_test, y_pred_bin))
        prec = float(precision_score(y_bin_test, y_pred_bin, zero_division=0))
        rec = float(recall_score(y_bin_test, y_pred_bin, zero_division=0))
        f1 = float(f1_score(y_bin_test, y_pred_bin, zero_division=0))
        tn, fp, fn, tp = confusion_matrix(y_bin_test, y_pred_bin, labels=[0, 1]).ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        zd_rec = float(np.mean(y_pred_bin[zd_mask] == 1)) if np.any(zd_mask) else float("nan")
        bot_rec = float(np.mean(y_pred_bin[bot_mask] == 1)) if np.any(bot_mask) else float("nan")
        row = {
            "Approach": name,
            "Paradigm": paradigm,
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1-Score": f1,
            "FPR": fpr,
            "ZeroDay_Recall": zd_rec,
            "Botnet_Recall": bot_rec,
            "Latency_ms_per_flow": float(latency_ms / max(len(y_bin_test), 1)),
        }
        comparison_rows.append(row)
        return row

    # 1. Gaussian Anomaly Detector (Unsupervised)
    X_benign = X_train[y_bin_train == 0]
    mu = np.mean(X_benign, axis=0)
    var = np.var(X_benign, axis=0) + 1e-4
    scores_tr = 0.5 * np.sum(np.log(2 * np.pi * var) + ((X_train - mu) ** 2) / var, axis=1)
    p, r, th = precision_recall_curve(y_bin_train, scores_tr)
    best_th = th[min(int(np.argmax(2 * p * r / np.maximum(p + r, 1e-8))), max(len(th) - 1, 0))]

    t0 = time.perf_counter()
    scores_te = 0.5 * np.sum(np.log(2 * np.pi * var) + ((X_test - mu) ** 2) / var, axis=1)
    y_pred_gauss = (scores_te >= best_th).astype(int)
    t_gauss = (time.perf_counter() - t0) * 1000.0
    _score_binary("Gaussian Anomaly (Stage 1 Only)", "Unsupervised", y_pred_gauss, t_gauss)

    # 2. Isolation Forest (Unsupervised)
    iso = IsolationForest(n_estimators=100, random_state=seed, n_jobs=-1)
    iso.fit(X_benign)
    s_tr_if = -iso.score_samples(X_train)
    p_i, r_i, th_i = precision_recall_curve(y_bin_train, s_tr_if)
    best_th_i = th_i[min(int(np.argmax(2 * p_i * r_i / np.maximum(p_i + r_i, 1e-8))), max(len(th_i) - 1, 0))]

    t0 = time.perf_counter()
    s_te_if = -iso.score_samples(X_test)
    y_pred_if = (s_te_if >= best_th_i).astype(int)
    t_if = (time.perf_counter() - t0) * 1000.0
    _score_binary("Isolation Forest", "Unsupervised", y_pred_if, t_if)

    # 3. Random Forest Classifier (Supervised Stage 2 Only)
    le = LabelEncoder()
    y_enc_tr = le.fit_transform(y_lbl_train)
    rf = RandomForestClassifier(n_estimators=100, max_depth=16, class_weight="balanced", random_state=seed, n_jobs=-1)
    rf.fit(X_train, y_enc_tr)

    t0 = time.perf_counter()
    y_pred_rf_lbl = le.inverse_transform(rf.predict(X_test))
    y_pred_rf_bin = (y_pred_rf_lbl != "BENIGN").astype(int)
    t_rf = (time.perf_counter() - t0) * 1000.0
    _score_binary("Random Forest (Stage 2 Only)", "Supervised Multi-class", y_pred_rf_bin, t_rf)

    # 4. Gradient Boosting Classifier (Supervised)
    gb = HistGradientBoostingClassifier(max_iter=100, max_depth=8, random_state=seed)
    gb.fit(X_train, y_enc_tr)
    t0 = time.perf_counter()
    y_pred_gb_lbl = le.inverse_transform(gb.predict(X_test))
    y_pred_gb_bin = (y_pred_gb_lbl != "BENIGN").astype(int)
    t_gb = (time.perf_counter() - t0) * 1000.0
    _score_binary("Gradient Boosting", "Supervised Multi-class", y_pred_gb_bin, t_gb)

    # 5. Deep MLP Classifier (Supervised DL)
    mlp = MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=80, random_state=seed)
    mlp.fit(X_train, y_enc_tr)
    t0 = time.perf_counter()
    y_pred_mlp_lbl = le.inverse_transform(mlp.predict(X_test))
    y_pred_mlp_bin = (y_pred_mlp_lbl != "BENIGN").astype(int)
    t_mlp = (time.perf_counter() - t0) * 1000.0
    _score_binary("Deep MLP Classifier", "Supervised DL", y_pred_mlp_bin, t_mlp)

    # 6. Multi-Stage Pipeline without Stage 3 (Stage 1 + Stage 2 only)
    pipe = MultiStageNIDSPipeline(seed=seed)
    pipe.fit(train_df)
    pred_s12, sum_s12 = pipe.predict_flows(test_df, enable_stage3=False)
    _score_binary(
        "2-Stage Pipeline (Gaussian + RF)",
        "Hybrid (Stage 1+2)",
        pred_s12["final_is_attack"].to_numpy(dtype=int),
        sum_s12["latency_total_ms"],
    )

    # 7. Full 3-Stage Hybrid Pipeline (Gaussian + RF + Host/Graph Botnet)
    pred_full, sum_full = pipe.predict_flows(test_df, enable_stage3=True)
    _score_binary(
        "3-Stage Hybrid Pipeline (Full)",
        "Cascading (Stage 1+2+3)",
        pred_full["final_is_attack"].to_numpy(dtype=int),
        sum_full["latency_total_ms"],
    )

    comp_df = pd.DataFrame(comparison_rows)

    # Ablation table focusing on the 3 stages
    ablation_df = comp_df[
        comp_df["Approach"].isin([
            "Gaussian Anomaly (Stage 1 Only)",
            "Random Forest (Stage 2 Only)",
            "2-Stage Pipeline (Gaussian + RF)",
            "3-Stage Hybrid Pipeline (Full)",
        ])
    ].reset_index(drop=True)

    if save_outputs:
        out_dir = PROJECT_ROOT / "outputs" / "evaluation"
        out_dir.mkdir(parents=True, exist_ok=True)
        pipe.save(PROJECT_ROOT / "saved_models" / "multistage_pipeline.joblib")

        comp_df.to_csv(out_dir / "full_pipeline_comparison.csv", index=False)
        ablation_df.to_csv(out_dir / "ablation_study.csv", index=False)

        report_data = {
            "comparison": comp_df.to_dict(orient="records"),
            "ablation": ablation_df.to_dict(orient="records"),
            "pipeline_summary": sum_full,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        (out_dir / "evaluation_report.json").write_text(
            json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        # Plot visual comparison
        fig, ax = plt.subplots(figsize=(11, 5))
        x = np.arange(len(comp_df))
        w = 0.26
        ax.bar(x - w, comp_df["F1-Score"] * 100, width=w, label="Overall F1-Score (%)", color="#1f77b4")
        ax.bar(x, comp_df["ZeroDay_Recall"] * 100, width=w, label="Unseen Zero-Day Recall (%)", color="#ff7f0e")
        ax.bar(x + w, comp_df["Botnet_Recall"] * 100, width=w, label="Botnet C2 Recall (%)", color="#2ca02c")
        ax.set_xticks(x)
        ax.set_xticklabels(comp_df["Approach"], rotation=20, ha="right")
        ax.set_ylabel("Percentage (%)")
        ax.set_ylim(0, 110)
        ax.set_title("Comparison of Standalone ML Models vs 3-Stage Hybrid NIDS Pipeline")
        ax.legend(loc="lower right")
        plt.tight_layout()
        fig.savefig(out_dir / "pipeline_comparison.png", dpi=150)
        plt.close(fig)

    return {
        "comparison_df": comp_df,
        "ablation_df": ablation_df,
        "pipeline": pipe,
        "pipeline_summary": sum_full,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate and compare all NIDS models & 3-stage pipeline")
    parser.parse_args(argv)
    res = evaluate_all_approaches(save_outputs=True)
    print("=== FULL PIPELINE COMPARISON (STEP 10) ===")
    print(res["comparison_df"].to_string(index=False))
    print("\n=== ABLATION STUDY (STAGE 1 vs STAGE 2 vs STAGE 1+2 vs STAGE 1+2+3) ===")
    print(res["ablation_df"].to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

