"""Threshold selection and detection metrics for anomaly scores.

Conventions: ``y`` is 1 for attack and 0 for benign; scores are anomaly
scores (higher = more anomalous); a flow is flagged when ``score >= threshold``.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve


def threshold_at_fpr(benign_scores: np.ndarray, target_fpr: float) -> float:
    """Smallest threshold whose false-positive rate on ``benign_scores`` is <= ``target_fpr``.

    Only benign scores are used, so the threshold needs no attack labels.
    """
    s = np.sort(np.asarray(benign_scores, dtype=np.float64))
    if s.size == 0:
        raise ValueError("No benign scores to calibrate on")
    if not 0.0 < target_fpr < 1.0:
        raise ValueError("target_fpr must be in (0, 1)")
    k = int(np.floor(target_fpr * s.size))  # at most k benign rows may be flagged
    if k == 0:
        return float(np.nextafter(s[-1], np.inf))
    # Flag the k highest: threshold just above the (k+1)-th highest score. Ties can only
    # lower the realised FPR, never raise it.
    return float(np.nextafter(s[s.size - k - 1], np.inf))


def threshold_best_f1(y: np.ndarray, scores: np.ndarray) -> float:
    """Threshold that maximises F1 on labelled data (requires both classes)."""
    y = np.asarray(y)
    if y.min() == y.max():
        raise ValueError("Best-F1 threshold needs both benign and attack rows")
    p, r, th = precision_recall_curve(y, scores)
    f1 = 2 * p[:-1] * r[:-1] / np.maximum(p[:-1] + r[:-1], 1e-12)
    return float(th[int(np.argmax(f1))])


def binary_metrics(y: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, Any]:
    """Confusion counts and rates at ``threshold``."""
    y = np.asarray(y).astype(bool)
    pred = np.asarray(scores) >= threshold
    tp = int(np.sum(pred & y))
    fp = int(np.sum(pred & ~y))
    fn = int(np.sum(~pred & y))
    tn = int(np.sum(~pred & ~y))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {
        "threshold": float(threshold), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": prec, "recall": rec, "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0, "accuracy": (tp + tn) / max(len(y), 1),
    }


def ranking_metrics(y: np.ndarray, scores: np.ndarray) -> dict[str, float]:
    """Threshold-free metrics: ROC-AUC and PR-AUC (average precision)."""
    y = np.asarray(y)
    if y.min() == y.max():
        return {"roc_auc": float("nan"), "pr_auc": float("nan"), "attack_prevalence": float(y.mean())}
    return {"roc_auc": float(roc_auc_score(y, scores)), "pr_auc": float(average_precision_score(y, scores)),
            "attack_prevalence": float(y.mean())}


def per_label_detection(labels: np.ndarray, scores: np.ndarray, threshold: float) -> pd.DataFrame:
    """Share of flows flagged per original label (detection rate; FPR for BENIGN)."""
    df = pd.DataFrame({"label": np.asarray(labels).astype(str), "flagged": np.asarray(scores) >= threshold})
    g = df.groupby("label")["flagged"].agg(n="size", flagged="sum")
    g["rate"] = g["flagged"] / g["n"]
    return g.sort_values("n", ascending=False)


def curve_points(y: np.ndarray, scores: np.ndarray, max_points: int = 400) -> dict[str, pd.DataFrame]:
    """Down-sampled ROC and PR curves for plotting and table views."""
    fpr, tpr, _ = roc_curve(y, scores)
    p, r, _ = precision_recall_curve(y, scores)

    def thin(a: np.ndarray, b: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        if len(a) <= max_points:
            return a, b
        idx = np.unique(np.linspace(0, len(a) - 1, max_points).astype(int))
        return a[idx], b[idx]

    fpr, tpr = thin(fpr, tpr)
    r, p = thin(r[::-1], p[::-1])
    return {"roc": pd.DataFrame({"fpr": fpr, "tpr": tpr}), "pr": pd.DataFrame({"recall": r, "precision": p})}


# ---------------------------------------------------------------- multi-class

def multiclass_metrics(y_true: np.ndarray, y_pred: np.ndarray, labels: list[str],
                       benign: str = "BENIGN") -> dict[str, Any]:
    """Overall, per-class and attack-vs-benign metrics for label predictions.

    ``labels`` fixes the class order of the per-class table and the confusion
    matrix (rows = true, columns = predicted).
    """
    from sklearn.metrics import (accuracy_score, balanced_accuracy_score, confusion_matrix,
                                 precision_recall_fscore_support)

    y_true = np.asarray(y_true).astype(str)
    y_pred = np.asarray(y_pred).astype(str)
    present = [c for c in labels if c in set(y_true)]
    p, r, f, n = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    per_class = pd.DataFrame({"precision": p, "recall": r, "f1": f, "support": n}, index=pd.Index(labels, name="label"))
    pc = per_class.loc[present]
    is_att_t, is_att_p = y_true != benign, y_pred != benign
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        # macro over classes present in y_true, so a class absent from this split does not count as F1 = 0
        "macro_f1": float(pc["f1"].mean()),
        "weighted_f1": float(np.average(pc["f1"], weights=pc["support"])),
        "per_class": per_class.reset_index().to_dict(orient="records"),
        "confusion": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "labels": list(labels),
        "binary": binary_metrics(is_att_t.astype(int), is_att_p.astype(float), 0.5),
        "attack_misclassified_as_other_attack": int(np.sum(is_att_t & is_att_p & (y_true != y_pred))),
    }


def grouped_labels(y: np.ndarray, groups: dict[str, str]) -> np.ndarray:
    """Map fine labels to their family (e.g. ``DoS Hulk`` -> ``DoS``); unknown labels map to themselves."""
    s = pd.Series(np.asarray(y).astype(str))
    return s.map(groups).fillna(s).to_numpy()
