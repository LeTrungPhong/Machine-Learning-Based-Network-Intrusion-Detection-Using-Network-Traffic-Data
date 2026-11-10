"""Tests for STEP 6 anomaly detectors and threshold/metric helpers."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from scipy.stats import multivariate_normal

from evaluation.metrics import (
    binary_metrics,
    per_label_detection,
    ranking_metrics,
    threshold_at_fpr,
    threshold_best_f1,
)
from models.anomaly import GaussianAnomalyDetector, IsolationForestDetector, build_detector
from models.train_anomaly import evaluate_scores


@pytest.fixture()
def blobs() -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(0)
    benign = rng.normal(0, 1, size=(4000, 5)).astype(np.float32)
    attack = rng.normal(4, 1, size=(200, 5)).astype(np.float32)
    return benign, attack


# ---------------------------------------------------------------- Gaussian

def test_gaussian_diag_matches_scipy_nll(blobs):
    benign, _ = blobs
    det = GaussianAnomalyDetector(covariance="diag", min_variance=0.0).fit(benign)
    var = benign.astype(np.float64).var(axis=0, ddof=1)
    ref = -multivariate_normal(benign.mean(axis=0, dtype=np.float64), np.diag(var)).logpdf(benign[:50])
    np.testing.assert_allclose(det.score(benign[:50]), ref, rtol=1e-6)


def test_gaussian_full_matches_scipy_nll(blobs):
    benign, _ = blobs
    mixed = benign.copy()
    mixed[:, 1] = mixed[:, 0] * 0.8 + mixed[:, 1] * 0.2  # correlated pair
    det = GaussianAnomalyDetector(covariance="full", min_variance=0.0).fit(mixed)
    cov = np.cov(mixed.astype(np.float64), rowvar=False)
    ref = -multivariate_normal(mixed.mean(axis=0, dtype=np.float64), cov).logpdf(mixed[:50])
    np.testing.assert_allclose(det.score(mixed[:50]), ref, rtol=1e-6)


def test_gaussian_chunked_scoring_is_identical(blobs):
    benign, attack = blobs
    X = np.vstack([benign, attack])
    a = GaussianAnomalyDetector(covariance="full", chunk_rows=10_000).fit(benign).score(X)
    b = GaussianAnomalyDetector(covariance="full", chunk_rows=97).fit(benign).score(X)
    np.testing.assert_allclose(a, b, rtol=1e-10)


def test_gaussian_constant_feature_is_finite_with_variance_floor(blobs):
    benign, attack = blobs
    benign = benign.copy()
    benign[:, 2] = 0.0  # e.g. a one-hot port never seen in benign training data
    det = GaussianAnomalyDetector(covariance="diag", min_variance=1e-3).fit(benign)
    s = det.score(attack)
    assert np.isfinite(s).all()


def test_gaussian_separates_attacks(blobs):
    benign, attack = blobs
    for cov in ("diag", "full"):
        det = GaussianAnomalyDetector(covariance=cov).fit(benign)
        assert det.score(attack).min() > np.median(det.score(benign))


def test_gaussian_rejects_bad_input(blobs):
    benign, _ = blobs
    with pytest.raises(ValueError):
        GaussianAnomalyDetector(covariance="spherical").fit(benign)
    bad = benign.copy()
    bad[0, 0] = np.nan
    with pytest.raises(ValueError):
        GaussianAnomalyDetector().fit(bad)
    det = GaussianAnomalyDetector().fit(benign)
    with pytest.raises(ValueError):
        det.score(benign[:, :3])
    with pytest.raises(RuntimeError):
        GaussianAnomalyDetector().score(benign)


# ---------------------------------------------------------------- Isolation Forest

def test_isolation_forest_scores_attacks_higher_and_is_deterministic(blobs):
    benign, attack = blobs
    a = IsolationForestDetector(n_estimators=50, random_state=1, chunk_rows=500).fit(benign)
    b = IsolationForestDetector(n_estimators=50, random_state=1).fit(benign)
    np.testing.assert_allclose(a.score(attack), b.score(attack))
    assert np.median(a.score(attack)) > np.quantile(a.score(benign), 0.99)


def test_detector_save_load_roundtrip(tmp_path: Path, blobs):
    benign, attack = blobs
    for kind in ("gaussian", "isolation_forest"):
        det = build_detector(kind, {"n_estimators": 20} if kind == "isolation_forest" else {}).fit(benign)
        p = det.save(tmp_path / f"{kind}.joblib")
        again = type(det).load(p)
        np.testing.assert_allclose(det.score(attack), again.score(attack))
    with pytest.raises(TypeError):
        GaussianAnomalyDetector.load(tmp_path / "isolation_forest.joblib")
    with pytest.raises(ValueError):
        build_detector("svm")


# ---------------------------------------------------------------- metrics

def test_threshold_at_fpr_never_exceeds_target():
    rng = np.random.default_rng(3)
    s = rng.normal(size=10_001)
    for t in (0.1, 0.01, 0.001):
        th = threshold_at_fpr(s, t)
        realised = np.mean(s >= th)
        assert realised <= t
        assert realised >= t - 2 / len(s)  # as close as the sample allows


def test_threshold_at_fpr_with_ties_and_tiny_target():
    s = np.array([1.0] * 95 + [5.0] * 5)
    assert np.mean(s >= threshold_at_fpr(s, 0.05)) == pytest.approx(0.05)
    assert np.mean(s >= threshold_at_fpr(s, 0.03)) == 0.0  # a tie block of 5 cannot be split
    assert np.mean(s >= threshold_at_fpr(s, 0.001)) == 0.0
    with pytest.raises(ValueError):
        threshold_at_fpr(s, 0.0)
    with pytest.raises(ValueError):
        threshold_at_fpr(np.array([]), 0.1)


def test_binary_metrics_counts():
    y = np.array([0, 0, 0, 1, 1])
    s = np.array([0.1, 0.6, 0.2, 0.9, 0.3])
    m = binary_metrics(y, s, 0.5)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 1, 1, 2)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["fpr"] == pytest.approx(1 / 3)


def test_best_f1_and_ranking():
    y = np.array([0, 0, 0, 1, 1])
    s = np.array([0.1, 0.2, 0.3, 0.8, 0.9])
    th = threshold_best_f1(y, s)
    assert binary_metrics(y, s, th)["f1"] == 1.0
    r = ranking_metrics(y, s)
    assert r["roc_auc"] == 1.0 and r["pr_auc"] == 1.0
    assert np.isnan(ranking_metrics(np.zeros(3), s[:3])["roc_auc"])
    with pytest.raises(ValueError):
        threshold_best_f1(np.zeros(3), s[:3])


def test_per_label_detection_and_evaluate_scores():
    labels = np.array(["BENIGN"] * 4 + ["DDoS"] * 2)
    y = (labels != "BENIGN").astype(int)
    s = np.array([0.1, 0.2, 0.3, 0.9, 0.95, 0.4])
    t = per_label_detection(labels, s, 0.5)
    assert t.loc["BENIGN", "rate"] == 0.25 and t.loc["DDoS", "rate"] == 0.5

    ev = evaluate_scores(y, s, y, s, labels, [0.25])
    assert set(ev["policies"]) == {"fpr@0.25", "best_f1_val"}
    assert ev["policies"]["fpr@0.25"]["val"]["fpr"] <= 0.25
