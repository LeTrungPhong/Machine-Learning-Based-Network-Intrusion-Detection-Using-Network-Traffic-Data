"""STEP 6: train and evaluate anomaly detectors on CIC-IDS-2017 (day split).

Setup (all from ``configs/config.yaml`` -> ``models.anomaly``):

* split ``by_day``: train Mon-Wed, validation = latest part of Wednesday,
  test Thu-Fri. Every attack type in the test days is absent from training.
* features: the ``by_day`` preprocessor fitted on *benign* training flows.
  Transformed matrices are cached as ``.npy`` memmaps so they can be scored in
  chunks without holding everything in RAM (and reused by later steps).
* thresholds are calibrated on validation data only:
  ``fpr@X`` uses benign validation scores (no attack labels needed);
  ``best_f1_val`` maximises F1 on validation, whose attacks are Wednesday DoS
  variants and Heartbleed, i.e. *not* the test attack types.

Usage:
    python -m models.train_anomaly
    python -m models.train_anomaly --rebuild-features
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from evaluation.metrics import (
    binary_metrics,
    curve_points,
    per_label_detection,
    ranking_metrics,
    threshold_at_fpr,
    threshold_best_f1,
)
from models.anomaly import build_detector
from models.feature_cache import build_feature_cache, load_part
from utils.config import resolve_path

logger = logging.getLogger(__name__)

def anomaly_parts(acfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Cached parts for STEP 6: benign training rows, an unlabelled training sample, val and test."""
    return {
        "train_benign": {"split": "train", "benign_only": True},
        "train_sample": {"split": "train", "sample_rows": int(acfg["unsupervised_sample_rows"])},
        "val": {"split": "val"},
        "test": {"split": "test"},
    }


def build_anomaly_cache(cfg: dict[str, Any], rebuild: bool = False) -> Path:
    acfg = cfg["models"]["anomaly"]
    return build_feature_cache(cfg, acfg["split"], acfg["preprocessor"], acfg["features_dir"],
                               anomaly_parts(acfg), rebuild=rebuild)


# ---------------------------------------------------------------- experiment

def _variant_params(cfg: dict[str, Any], variant: dict[str, Any]) -> dict[str, Any]:
    base = dict(cfg["models"].get(variant["kind"], {}) or {})
    base.update(variant.get("params") or {})
    return base


def evaluate_scores(y_val: np.ndarray, s_val: np.ndarray, y_test: np.ndarray, s_test: np.ndarray,
                    labels_test: np.ndarray, target_fprs: list[float]) -> dict[str, Any]:
    """Calibrate thresholds on validation scores and evaluate them on the test scores."""
    thresholds = {f"fpr@{t:g}": threshold_at_fpr(s_val[y_val == 0], t) for t in target_fprs}
    if y_val.min() != y_val.max():
        thresholds["best_f1_val"] = threshold_best_f1(y_val, s_val)
    out: dict[str, Any] = {"ranking_test": ranking_metrics(y_test, s_test),
                           "ranking_val": ranking_metrics(y_val, s_val), "policies": {}}
    for name, th in thresholds.items():
        out["policies"][name] = {
            "val": binary_metrics(y_val, s_val, th),
            "test": binary_metrics(y_test, s_test, th),
            "test_per_label": per_label_detection(labels_test, s_test, th).reset_index().to_dict(orient="records"),
        }
    return out


def run(cfg: dict[str, Any], rebuild_features: bool = False) -> dict[str, Any]:
    acfg = cfg["models"]["anomaly"]
    seed = int(cfg["project"].get("random_seed", 42))
    target_fprs = [float(t) for t in acfg["target_fpr"]]
    features_dir = build_anomaly_cache(cfg, rebuild=rebuild_features)
    models_dir = resolve_path(acfg["models_dir"])
    out_dir = resolve_path(acfg["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)

    X_val, lab_val = load_part(features_dir, "val")
    X_test, lab_test = load_part(features_dir, "test")
    y_val = lab_val["label_binary"].to_numpy(dtype=int)
    y_test = lab_test["label_binary"].to_numpy(dtype=int)
    results: dict[str, Any] = {
        "setup": {
            "split": acfg["split"], "preprocessor": acfg["preprocessor"], "features": int(X_test.shape[1]),
            "val_rows": int(len(y_val)), "val_attack_rows": int(y_val.sum()),
            "val_labels": lab_val["label"].value_counts().to_dict(),
            "test_rows": int(len(y_test)), "test_attack_rows": int(y_test.sum()),
            "test_labels": lab_test["label"].value_counts().to_dict(),
            "target_fpr": target_fprs, "seed": seed,
        },
        "models": {},
    }
    curves: dict[str, dict[str, pd.DataFrame]] = {}
    test_scores: dict[str, np.ndarray] = {}

    for variant in acfg["variants"]:
        name, kind, fit_on = variant["name"], variant["kind"], variant.get("fit_on", "benign")
        part = {"benign": "train_benign", "all": "train_sample"}[fit_on]
        X_tr, lab_tr = load_part(features_dir, part)
        params = _variant_params(cfg, variant)
        det = build_detector(kind, params, seed)
        logger.info("[%s] fitting %s on %s (%s rows, %.2f%% attack)", name, kind, part, f"{len(X_tr):,}",
                    100 * lab_tr["label_binary"].mean())
        t0 = time.perf_counter()
        det.fit(X_tr)
        fit_s = time.perf_counter() - t0
        det.save(models_dir / f"{name}.joblib")

        s_val = det.score(X_val)
        t0 = time.perf_counter()
        s_test = det.score(X_test)
        score_s = time.perf_counter() - t0
        if not (np.isfinite(s_val).all() and np.isfinite(s_test).all()):
            raise ValueError(f"[{name}] produced non-finite scores")

        ev = evaluate_scores(y_val, s_val, y_test, s_test, lab_test["label"].to_numpy(), target_fprs)
        ev.update({"kind": kind, "fit_on": fit_on, "train_part": part, "train_rows": int(len(X_tr)),
                   "train_attack_share": float(lab_tr["label_binary"].mean()), "params": params,
                   "fit_seconds": fit_s, "score_seconds_test": score_s,
                   "score_us_per_flow": 1e6 * score_s / len(X_test)})
        results["models"][name] = ev
        curves[name] = curve_points(y_test, s_test)
        test_scores[name] = s_test.astype(np.float32)
        prim = ev["policies"][f"fpr@{target_fprs[0]:g}"]["test"]
        logger.info("[%s] test ROC-AUC %.4f PR-AUC %.4f | fpr@%g: P %.3f R %.3f F1 %.3f FPR %.4f | fit %.1fs, %.2f us/flow",
                    name, ev["ranking_test"]["roc_auc"], ev["ranking_test"]["pr_auc"], target_fprs[0],
                    prim["precision"], prim["recall"], prim["f1"], prim["fpr"], fit_s, ev["score_us_per_flow"])

    write_outputs(results, curves, out_dir, target_fprs[0])
    pd.DataFrame(test_scores).assign(label=lab_test["label"].to_numpy(), row_id=lab_test["row_id"].to_numpy()) \
        .to_parquet(resolve_path(cfg["paths"]["processed_dir"]) / "anomaly_test_scores.parquet", index=False)
    return results


# ---------------------------------------------------------------- outputs

def summary_table(results: dict[str, Any]) -> pd.DataFrame:
    rows = []
    for name, ev in results["models"].items():
        for pol, m in ev["policies"].items():
            t = m["test"]
            rows.append({"model": name, "policy": pol, "threshold": t["threshold"],
                         "val_fpr": m["val"]["fpr"], "val_recall": m["val"]["recall"],
                         "test_precision": t["precision"], "test_recall": t["recall"], "test_f1": t["f1"],
                         "test_fpr": t["fpr"], "test_roc_auc": ev["ranking_test"]["roc_auc"],
                         "test_pr_auc": ev["ranking_test"]["pr_auc"], "fit_s": ev["fit_seconds"],
                         "score_us_per_flow": ev["score_us_per_flow"]})
    return pd.DataFrame(rows)


def per_label_table(results: dict[str, Any], policy: str) -> pd.DataFrame:
    frames = []
    for name, ev in results["models"].items():
        d = pd.DataFrame(ev["policies"][policy]["test_per_label"]).set_index("label")["rate"].rename(name)
        frames.append(d)
    n = pd.DataFrame(next(iter(results["models"].values()))["policies"][policy]["test_per_label"]).set_index("label")["n"]
    return pd.concat([n] + frames, axis=1).sort_values("n", ascending=False)


def write_outputs(results: dict[str, Any], curves: dict[str, dict[str, pd.DataFrame]], out_dir: Path,
                  primary_fpr: float) -> None:
    (out_dir / "anomaly_results.json").write_text(json.dumps(results, indent=2, default=float), encoding="utf-8")
    summary_table(results).to_csv(out_dir / "anomaly_summary.csv", index=False)
    policy = f"fpr@{primary_fpr:g}"
    per_label_table(results, policy).to_csv(out_dir / f"anomaly_per_label_{policy.replace('@', '_')}.csv")
    plot_curves(curves, out_dir)
    plot_per_label(per_label_table(results, policy), out_dir / "anomaly_per_label_detection.png", policy)
    logger.info("Wrote STEP 6 outputs to %s", out_dir)


def _style_for(name: str) -> dict[str, Any]:
    from eda.visualization import BLUE, ORANGE
    color = BLUE if name.startswith("gaussian") else ORANGE
    return {"color": color, "linestyle": "-" if name.endswith(("diag", "benign")) else "--", "linewidth": 2}


def plot_curves(curves: dict[str, dict[str, pd.DataFrame]], out_dir: Path) -> None:
    import matplotlib.pyplot as plt

    from eda.visualization import _save, chart_style

    with chart_style():
        fig, ax = plt.subplots(figsize=(6.4, 4.4))
        for name, c in curves.items():
            roc = c["roc"][c["roc"]["fpr"] > 0]
            ax.plot(roc["fpr"], roc["tpr"], label=name, **_style_for(name))
        ax.set_xscale("log")
        ax.set_xlim(1e-4, 1)
        ax.set_ylim(0, 1.01)
        ax.set_xlabel("false positive rate (log scale)")
        ax.set_ylabel("true positive rate (recall)")
        ax.set_title("ROC on Thu-Fri test (unseen attack types)")
        ax.legend(loc="upper left")
    _save(fig, out_dir / "anomaly_roc.png",
          pd.concat({k: v["roc"] for k, v in curves.items()}, names=["model", "i"]))
    with chart_style():
        fig, ax = plt.subplots(figsize=(6.4, 4.4))
        for name, c in curves.items():
            ax.plot(c["pr"]["recall"], c["pr"]["precision"], label=name, **_style_for(name))
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1.01)
        ax.set_xlabel("recall")
        ax.set_ylabel("precision")
        ax.set_title("Precision-recall on Thu-Fri test")
        ax.legend(loc="upper right")
    _save(fig, out_dir / "anomaly_pr.png",
          pd.concat({k: v["pr"] for k, v in curves.items()}, names=["model", "i"]))


def plot_per_label(table: pd.DataFrame, path: Path, policy: str) -> None:
    """Small multiples: detection rate per test label, one panel per model."""
    import matplotlib.pyplot as plt

    from eda.visualization import BLUE, INK_2, _save, chart_style

    models = [c for c in table.columns if c != "n"]
    labels = [f"{l} (n={int(n):,})" for l, n in zip(table.index, table["n"])]
    ncol = min(2, len(models))
    nrow = int(np.ceil(len(models) / ncol))
    with chart_style():
        fig, axes = plt.subplots(nrow, ncol, figsize=(4.2 * ncol + 2.4, (0.3 * len(table) + 0.9) * nrow + 0.6),
                                 sharey=True, squeeze=False)
        for ax in axes.flat[len(models):]:
            ax.set_visible(False)
        for ax, m in zip(axes.flat, models):
            v = table[m].to_numpy()[::-1]
            ax.barh(labels[::-1], v, color=BLUE, height=0.62)
            for i, x in enumerate(v):
                ax.annotate(f"{100 * x:.1f}%", (x, i), xytext=(3, 0), textcoords="offset points",
                            va="center", fontsize=7, color=INK_2)
            ax.set_xlim(0, 1.25)
            ax.set_xticks([0, 0.5, 1.0], ["0", "50%", "100%"])
            ax.grid(axis="y", visible=False)
            ax.set_title(m, fontsize=10)
        fig.suptitle(f"Share of test flows flagged per label\n({policy} on benign validation; BENIGN row = FPR)",
                     x=0.01, ha="left", fontsize=11, fontweight="semibold")
        fig.tight_layout()
    _save(fig, path, table)


def main(argv: list[str] | None = None) -> int:
    from utils.config import load_config
    from utils.logging_setup import setup_logging

    ap = argparse.ArgumentParser(description="STEP 6: Gaussian and Isolation Forest anomaly detection")
    ap.add_argument("--config", default=None)
    ap.add_argument("--rebuild-features", action="store_true")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    setup_logging(cfg)
    res = run(cfg, rebuild_features=args.rebuild_features)
    print(summary_table(res).to_string(index=False, float_format=lambda x: f"{x:.4f}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
