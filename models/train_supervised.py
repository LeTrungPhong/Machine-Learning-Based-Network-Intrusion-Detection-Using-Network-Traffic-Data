"""STEP 7: supervised multi-class classification on CIC-IDS-2017.

Setup (``configs/config.yaml`` -> ``models.supervised``):

* split ``temporal_per_class``: for every label the earliest 65% of flows are
  training data, the next 15% validation and the latest 20% test, so each
  class is evaluated on flows recorded after the ones it was trained on.
  All 15 labels occur in every split (the rarest have 2-7 test flows).
* features: the ``temporal_per_class`` preprocessor (fitted on training rows).
* imbalance: per-row class weights *or* SMOTE on the training split.
* model selection uses validation macro-F1 only; the test split is touched
  once per model for the reported numbers.

Usage:
    python -m models.train_supervised
    python -m models.train_supervised --only rf_weighted xgb_weighted
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

from evaluation.metrics import grouped_labels, multiclass_metrics
from models.feature_cache import build_feature_cache, load_part, output_features
from models.supervised import FlowClassifier, class_sample_weights, smote_augment
from utils.config import resolve_path

logger = logging.getLogger(__name__)

PARTS = {"train": {"split": "train"}, "val": {"split": "val"}, "test": {"split": "test"}}


def _params(cfg: dict[str, Any], variant: dict[str, Any]) -> dict[str, Any]:
    p = dict(cfg["models"].get(variant["kind"], {}) or {})
    p.update(variant.get("params") or {})
    return p


def evaluate_predictions(y_true: np.ndarray, y_pred: np.ndarray, labels: list[str],
                         groups: dict[str, str], benign: str) -> dict[str, Any]:
    """Fine-label metrics plus the same metrics after mapping labels to attack families."""
    fine = multiclass_metrics(y_true, y_pred, labels, benign)
    group_order = list(dict.fromkeys(grouped_labels(np.asarray(labels), groups)))
    fam = multiclass_metrics(grouped_labels(y_true, groups), grouped_labels(y_pred, groups), group_order, benign)
    return {"fine": fine, "group": fam}


def run(cfg: dict[str, Any], only: list[str] | None = None, rebuild_features: bool = False) -> dict[str, Any]:
    scfg = cfg["models"]["supervised"]
    ds = cfg["datasets"]["cicids2017"]
    benign = ds.get("benign_label", "BENIGN")
    groups = ds.get("label_groups", {})
    seed = int(cfg["project"].get("random_seed", 42))
    features_dir = build_feature_cache(cfg, scfg["split"], scfg["preprocessor"], scfg["features_dir"], PARTS,
                                       rebuild=rebuild_features)
    names = output_features(features_dir)
    models_dir = resolve_path(scfg["models_dir"])
    out_dir = resolve_path(scfg["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)

    X_tr, lab_tr = load_part(features_dir, "train")
    X_val, lab_val = load_part(features_dir, "val")
    X_te, lab_te = load_part(features_dir, "test")
    y_tr, y_val, y_te = (lab["label"].astype(str).to_numpy() for lab in (lab_tr, lab_val, lab_te))
    labels = pd.Series(y_tr).value_counts().index.tolist()  # by training support, largest first
    power = float(scfg.get("class_weight_power", 1.0))
    w_tr, class_w = class_sample_weights(y_tr, power)
    w_val = pd.Series(y_val).map(class_w).to_numpy(dtype=np.float32)

    results: dict[str, Any] = {
        "setup": {"split": scfg["split"], "preprocessor": scfg["preprocessor"], "features": len(names),
                  "rows": {"train": int(len(y_tr)), "val": int(len(y_val)), "test": int(len(y_te))},
                  "test_support": pd.Series(y_te).value_counts().to_dict(), "labels": labels,
                  "class_weight_power": power, "class_weights": class_w, "seed": seed},
        "models": {},
    }
    smote: tuple[np.ndarray, np.ndarray, dict[str, int]] | None = None
    preds: dict[str, np.ndarray] = {}
    importances: dict[str, pd.Series] = {}

    variants = [v for v in scfg["variants"] if not only or v["name"] in only]
    for v in variants:
        name, kind, imb = v["name"], v["kind"], v.get("imbalance", "class_weight")
        if imb == "smote":
            if smote is None:
                t0 = time.perf_counter()
                smote = smote_augment(X_tr, y_tr, features_dir / "train_smote.npy",
                                      int(scfg["smote_max_per_class"]), seed)
                logger.info("SMOTE added %s synthetic training rows (%.1f s): %s", f"{sum(smote[2].values()):,}",
                            time.perf_counter() - t0, smote[2])
            X_fit, y_fit, w_fit, wv = smote[0], smote[1], None, None
        elif imb == "class_weight":
            X_fit, y_fit, w_fit, wv = X_tr, y_tr, w_tr, w_val
        else:
            raise ValueError(f"[{name}] unknown imbalance handling: {imb}")

        params = _params(cfg, v)
        clf = FlowClassifier(kind, params, seed)
        logger.info("[%s] fitting %s on %s rows (%s)", name, kind, f"{len(y_fit):,}", imb)
        t0 = time.perf_counter()
        clf.fit(X_fit, y_fit, w_fit, X_val, y_val, wv)
        fit_s = time.perf_counter() - t0
        clf.save(models_dir / f"{name}.joblib")

        p_val = clf.predict(X_val)
        t0 = time.perf_counter()
        p_te = clf.predict(X_te)
        pred_s = time.perf_counter() - t0
        ev_val = evaluate_predictions(y_val, p_val, labels, groups, benign)
        ev_te = evaluate_predictions(y_te, p_te, labels, groups, benign)
        imp = clf.feature_importance(names)
        results["models"][name] = {
            "kind": kind, "imbalance": imb, "params": params, "train_rows": int(len(y_fit)),
            "smote_synthetic": smote[2] if imb == "smote" else {}, "best_iteration": clf.best_iteration_,
            "fit_seconds": fit_s, "predict_us_per_flow": 1e6 * pred_s / len(y_te),
            "val": ev_val, "test": ev_te, "top_features": imp.head(30).to_dict(),
        }
        preds[name] = p_te
        importances[name] = imp
        f, g = ev_te["fine"], ev_te["group"]
        logger.info("[%s] val macro-F1 %.4f | test macro-F1 %.4f (families %.4f), acc %.4f, attack recall %.4f, "
                    "FPR %.5f | fit %.0fs, %.1f us/flow", name, ev_val["fine"]["macro_f1"], f["macro_f1"],
                    g["macro_f1"], f["accuracy"], f["binary"]["recall"], f["binary"]["fpr"], fit_s,
                    results["models"][name]["predict_us_per_flow"])

    if not results["models"]:
        raise ValueError("No variant selected")
    best = max(results["models"], key=lambda n: results["models"][n]["val"]["fine"]["macro_f1"])
    results["best_by_val_macro_f1"] = best
    write_outputs(results, importances, out_dir)
    pd.DataFrame(preds).assign(label=y_te, row_id=lab_te["row_id"].to_numpy()).to_parquet(
        resolve_path(cfg["paths"]["processed_dir"]) / "supervised_test_predictions.parquet", index=False)
    return results


# ---------------------------------------------------------------- outputs

def summary_table(results: dict[str, Any]) -> pd.DataFrame:
    rows = []
    for name, m in results["models"].items():
        f, g = m["test"]["fine"], m["test"]["group"]
        rows.append({"model": name, "val_macro_f1": m["val"]["fine"]["macro_f1"], "test_macro_f1": f["macro_f1"],
                     "test_group_macro_f1": g["macro_f1"], "test_weighted_f1": f["weighted_f1"],
                     "test_accuracy": f["accuracy"], "test_balanced_accuracy": f["balanced_accuracy"],
                     "attack_precision": f["binary"]["precision"], "attack_recall": f["binary"]["recall"],
                     "benign_fpr": f["binary"]["fpr"], "fit_s": m["fit_seconds"],
                     "predict_us_per_flow": m["predict_us_per_flow"], "best_iteration": m["best_iteration"]})
    return pd.DataFrame(rows)


def per_class_table(results: dict[str, Any], level: str = "fine", metric: str = "f1") -> pd.DataFrame:
    cols = {}
    support = None
    for name, m in results["models"].items():
        pc = pd.DataFrame(m["test"][level]["per_class"]).set_index("label")
        cols[name] = pc[metric]
        support = pc["support"]
    return pd.concat([support.rename("test_support")] + [s.rename(n) for n, s in cols.items()], axis=1)


def write_outputs(results: dict[str, Any], importances: dict[str, pd.Series], out_dir: Path) -> None:
    (out_dir / "supervised_results.json").write_text(json.dumps(results, indent=2, default=float), encoding="utf-8")
    summary_table(results).to_csv(out_dir / "supervised_summary.csv", index=False)
    for level in ("fine", "group"):
        for metric in ("f1", "precision", "recall"):
            per_class_table(results, level, metric).to_csv(out_dir / f"supervised_{level}_{metric}.csv")
    pd.DataFrame(importances).to_csv(out_dir / "supervised_feature_importance.csv")
    best = results["best_by_val_macro_f1"]
    plot_f1_heatmap(per_class_table(results, "fine", "f1"), out_dir / "supervised_per_class_f1.png")
    plot_confusion(results["models"][best]["test"]["fine"], best, out_dir / f"supervised_confusion_{best}.png")
    from eda.visualization import bar_counts

    bar_counts(importances[best].head(20), f"{best}: top-20 feature importance (training data)",
               "importance (normalised)", out_dir / f"supervised_importance_{best}.png", log=False)
    logger.info("Wrote STEP 7 outputs to %s (best by validation macro-F1: %s)", out_dir, best)


def _seq_cmap():
    from matplotlib.colors import LinearSegmentedColormap

    return LinearSegmentedColormap.from_list("blue_seq", ["#f4f8fd", "#9cc2ee", "#2a78d6", "#104281"])


def plot_f1_heatmap(table: pd.DataFrame, path: Path) -> None:
    """Per-class test F1, classes x models, sequential blue."""
    import matplotlib.pyplot as plt

    from eda.visualization import INK, _save, chart_style

    models = [c for c in table.columns if c != "test_support"]
    vals = table[models].to_numpy(dtype=float)
    ylabels = [f"{l} (n={int(n):,})" for l, n in zip(table.index, table["test_support"])]
    with chart_style():
        fig, ax = plt.subplots(figsize=(1.5 * len(models) + 3.6, 0.36 * len(table) + 1.4))
        im = ax.imshow(vals, cmap=_seq_cmap(), vmin=0, vmax=1, aspect="auto")
        ax.grid(False)
        ax.set_xticks(range(len(models)), models, rotation=0, fontsize=8)
        ax.set_yticks(range(len(ylabels)), ylabels, fontsize=8)
        for i in range(vals.shape[0]):
            for j in range(vals.shape[1]):
                ax.text(j, i, f"{vals[i, j]:.3f}", ha="center", va="center", fontsize=7,
                        color="white" if vals[i, j] > 0.6 else INK)
        ax.set_title("Per-class F1 on the temporal test split")
        cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
        cb.outline.set_visible(False)
    _save(fig, path, table)


def plot_confusion(fine: dict[str, Any], name: str, path: Path) -> None:
    """Row-normalised confusion matrix (share of each true class), sequential blue."""
    import matplotlib.pyplot as plt

    from eda.visualization import INK, _save, chart_style

    labels = fine["labels"]
    cm = np.asarray(fine["confusion"], dtype=float)
    norm = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    with chart_style():
        fig, ax = plt.subplots(figsize=(9, 8))
        im = ax.imshow(norm, cmap=_seq_cmap(), vmin=0, vmax=1)
        ax.grid(False)
        ax.set_xticks(range(len(labels)), labels, rotation=60, ha="right", fontsize=7)
        ax.set_yticks(range(len(labels)), [f"{l} ({int(n):,})" for l, n in zip(labels, cm.sum(axis=1))], fontsize=7)
        for i in range(len(labels)):
            for j in range(len(labels)):
                if norm[i, j] >= 0.005:
                    ax.text(j, i, f"{100 * norm[i, j]:.0f}" if norm[i, j] >= 0.995 or norm[i, j] < 0.1
                            else f"{100 * norm[i, j]:.1f}", ha="center", va="center", fontsize=6,
                            color="white" if norm[i, j] > 0.6 else INK)
        ax.set_xlabel("predicted")
        ax.set_ylabel("true (test flows)")
        ax.set_title(f"{name}: confusion matrix, % of each true class")
        cb = fig.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
        cb.outline.set_visible(False)
    _save(fig, path, pd.DataFrame(cm.astype(int), index=labels, columns=labels))


def main(argv: list[str] | None = None) -> int:
    from utils.config import load_config
    from utils.logging_setup import setup_logging

    ap = argparse.ArgumentParser(description="STEP 7: Random Forest and XGBoost multi-class classification")
    ap.add_argument("--config", default=None)
    ap.add_argument("--only", nargs="+", default=None, help="Variant names to run (default: all)")
    ap.add_argument("--rebuild-features", action="store_true")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    setup_logging(cfg)
    res = run(cfg, only=args.only, rebuild_features=args.rebuild_features)
    print(summary_table(res).to_string(index=False, float_format=lambda x: f"{x:.4f}"))
    return 0


if __name__ == "__main__":
    # Re-enter through the package module so saved classifiers pickle as models.supervised.*.
    from models.train_supervised import main as _main

    sys.exit(_main())
