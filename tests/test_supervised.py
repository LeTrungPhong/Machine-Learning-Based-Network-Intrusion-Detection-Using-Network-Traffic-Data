"""Tests for STEP 7 classifiers, imbalance handling and multi-class metrics."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from evaluation.metrics import grouped_labels, multiclass_metrics
from models.supervised import FlowClassifier, class_sample_weights, smote_augment
from models.train_supervised import evaluate_predictions


@pytest.fixture()
def data() -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(0)
    centers = {"BENIGN": 0.0, "DoS": 4.0, "PortScan": -4.0, "Rare": 8.0}
    sizes = {"BENIGN": 2000, "DoS": 300, "PortScan": 200, "Rare": 12}
    X = np.vstack([rng.normal(centers[c], 1.0, size=(n, 4)) for c, n in sizes.items()]).astype(np.float32)
    y = np.concatenate([[c] * n for c, n in sizes.items()]).astype(object)
    return X, y


def test_class_sample_weights_balanced_and_power():
    y = np.array(["a"] * 90 + ["b"] * 10)
    w, table = class_sample_weights(y, power=1.0)
    assert table == pytest.approx({"a": 100 / (2 * 90), "b": 100 / (2 * 10)})
    # balanced weights give every class the same total weight
    assert w[y == "a"].sum() == pytest.approx(w[y == "b"].sum())
    _, t_half = class_sample_weights(y, power=0.5)
    assert t_half["b"] == pytest.approx(np.sqrt(table["b"]))


def test_smote_augment_only_grows_small_classes(tmp_path: Path, data):
    X, y = data
    X_aug, y_aug, added = smote_augment(X, y, tmp_path / "aug.npy", max_per_class=300, seed=1)
    counts = pd.Series(y_aug).value_counts()
    assert counts["BENIGN"] == 2000 and counts["DoS"] == 300  # at/above the target: untouched
    assert counts["PortScan"] == 300 and counts["Rare"] == 300
    assert added == {"PortScan": 100, "Rare": 288}
    np.testing.assert_array_equal(X_aug[: len(X)], X)  # originals first, unchanged
    # synthetic Rare rows lie between Rare samples (interpolation within the class)
    rare_syn = X_aug[len(X):][y_aug[len(X):] == "Rare"]
    rare = X[y == "Rare"]
    assert (rare_syn.min(axis=0) >= rare.min(axis=0) - 1e-5).all()
    assert (rare_syn.max(axis=0) <= rare.max(axis=0) + 1e-5).all()


@pytest.mark.parametrize("kind,params", [
    ("random_forest", {"n_estimators": 20}),
    ("xgboost", {"n_estimators": 50, "early_stopping_rounds": 5, "max_depth": 3}),
])
def test_classifier_fit_predict_roundtrip(tmp_path: Path, data, kind, params):
    X, y = data
    w, _ = class_sample_weights(y)
    clf = FlowClassifier(kind, params, seed=0, chunk_rows=500).fit(X, y, w, X[::3], y[::3], w[::3])
    pred = clf.predict(X)
    assert set(pred) <= set(y)
    assert np.mean(pred == y) > 0.95
    proba = clf.predict_proba(X)
    np.testing.assert_allclose(proba.sum(axis=1), 1.0, rtol=1e-4)
    again = FlowClassifier.load(clf.save(tmp_path / "m.joblib"))
    np.testing.assert_array_equal(again.predict(X), pred)
    imp = clf.feature_importance(["a", "b", "c", "d"])
    assert list(imp.index) != [] and imp.sum() == pytest.approx(1.0, rel=1e-5)
    if kind == "xgboost":
        assert clf.best_iteration_ is not None


def test_classifier_rejects_unknown_validation_label(data):
    X, y = data
    with pytest.raises(ValueError):
        FlowClassifier("xgboost", {"n_estimators": 5}).fit(X, y, None, X[:3], np.array(["Nope"] * 3))
    with pytest.raises(ValueError):
        FlowClassifier("svm").fit(X, y)


def test_multiclass_metrics_and_groups():
    labels = ["BENIGN", "DoS Hulk", "DoS slowloris", "PortScan"]
    y_true = np.array(["BENIGN", "BENIGN", "DoS Hulk", "DoS slowloris", "PortScan", "PortScan"])
    y_pred = np.array(["BENIGN", "PortScan", "DoS slowloris", "DoS slowloris", "PortScan", "BENIGN"])
    m = multiclass_metrics(y_true, y_pred, labels)
    pc = pd.DataFrame(m["per_class"]).set_index("label")
    assert pc.loc["DoS Hulk", "recall"] == 0.0 and pc.loc["DoS slowloris", "precision"] == 0.5
    assert m["confusion"][1][2] == 1  # DoS Hulk predicted as slowloris
    b = m["binary"]
    assert (b["tp"], b["fp"], b["fn"], b["tn"]) == (3, 1, 1, 1)
    assert m["attack_misclassified_as_other_attack"] == 1

    groups = {"BENIGN": "BENIGN", "DoS Hulk": "DoS", "DoS slowloris": "DoS", "PortScan": "PortScan"}
    np.testing.assert_array_equal(grouped_labels(np.array(["DoS Hulk", "X"]), groups), ["DoS", "X"])
    ev = evaluate_predictions(y_true, y_pred, labels, groups, "BENIGN")
    g = pd.DataFrame(ev["group"]["per_class"]).set_index("label")
    assert g.loc["DoS", "recall"] == 1.0  # Hulk -> slowloris is correct at family level
    assert ev["group"]["labels"] == ["BENIGN", "DoS", "PortScan"]


def test_macro_f1_ignores_classes_absent_from_truth():
    m = multiclass_metrics(np.array(["A", "A", "B"]), np.array(["A", "A", "B"]), ["A", "B", "C"])
    assert m["macro_f1"] == 1.0
