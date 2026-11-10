"""Supervised multi-class flow classifiers (STEP 7): Random Forest and XGBoost.

Both are wrapped behind one interface - ``fit(X, y, sample_weight, X_val,
y_val, w_val)``, ``predict_proba(X)``, ``predict(X)`` - with labels kept as
strings outside and integer codes inside. Class imbalance is handled either
with per-row sample weights (:func:`class_sample_weights`) or by SMOTE
oversampling of the training split (:func:`smote_augment`), never both.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


def class_sample_weights(y: np.ndarray, power: float = 1.0) -> tuple[np.ndarray, dict[str, float]]:
    """Per-row weights ``(n / (k * n_c)) ** power`` (``power=1`` is scikit-learn's "balanced").

    Returns the row weights and the per-class weight table.
    """
    y = np.asarray(y).astype(str)
    counts = pd.Series(y).value_counts()
    w = (len(y) / (len(counts) * counts)) ** float(power)
    return pd.Series(y).map(w).to_numpy(dtype=np.float32), {str(k): float(v) for k, v in w.items()}


def smote_augment(X: np.ndarray, y: np.ndarray, out_path: str | Path, max_per_class: int,
                  seed: int = 42) -> tuple[np.ndarray, np.ndarray, dict[str, int]]:
    """Write ``X`` plus SMOTE samples to ``out_path`` (memmap) and return it with labels.

    SMOTE interpolates only between neighbours of the same class, so it is fit
    on the rows of the classes to oversample (every class below
    ``max_per_class``); large classes and the full matrix never enter memory.
    Returns ``(X_aug, y_aug, synthetic_counts_by_class)``.
    """
    from preprocessing.preprocess import resample_training

    y = np.asarray(y).astype(str)
    counts = pd.Series(y).value_counts()
    small = counts.index[(counts >= 2) & (counts < max_per_class)]
    idx = np.flatnonzero(np.isin(y, small))
    if len(idx) == 0:
        return X, y, {}
    X_small = np.asarray(X[idx])
    Xr, yr = resample_training(X_small, y[idx], "smote", max_per_class=max_per_class, seed=seed)
    X_syn, y_syn = Xr[len(idx):], np.asarray(yr[len(idx):]).astype(str)

    out = np.lib.format.open_memmap(Path(out_path), mode="w+", dtype=np.float32,
                                    shape=(len(X) + len(X_syn), X.shape[1]))
    step = 200_000
    for s in range(0, len(X), step):
        chunk = X[s:s + step]
        out[s:s + len(chunk)] = chunk
    out[len(X):] = X_syn
    out.flush()
    del out
    X_aug = np.load(out_path, mmap_mode="r")
    return X_aug, np.concatenate([y, y_syn]), pd.Series(y_syn).value_counts().astype(int).to_dict()


@dataclass
class FlowClassifier:
    """Random Forest (``kind="random_forest"``) or XGBoost (``kind="xgboost"``) over string labels.

    Args:
        kind: Model family.
        params: Hyper-parameters for the underlying estimator. For XGBoost,
            ``early_stopping_rounds`` uses the validation set passed to ``fit``.
        seed: Random seed.
        chunk_rows: Rows per ``predict_proba`` batch.
    """

    kind: str
    params: dict[str, Any] = field(default_factory=dict)
    seed: int = 42
    chunk_rows: int = 200_000
    classes_: list[str] | None = None
    model_: Any = field(default=None, repr=False)
    best_iteration_: int | None = None

    def _encode(self, y: np.ndarray) -> np.ndarray:
        lookup = {c: i for i, c in enumerate(self.classes_)}
        try:
            return np.fromiter((lookup[v] for v in np.asarray(y).astype(str)), dtype=np.int32, count=len(y))
        except KeyError as exc:
            raise ValueError(f"Label {exc} not seen in training") from None

    def fit(self, X: np.ndarray, y: np.ndarray, sample_weight: np.ndarray | None = None,
            X_val: np.ndarray | None = None, y_val: np.ndarray | None = None,
            w_val: np.ndarray | None = None) -> "FlowClassifier":
        self.classes_ = sorted(pd.unique(np.asarray(y).astype(str)))
        yi = self._encode(y)
        p = dict(self.params)
        if self.kind == "random_forest":
            from sklearn.ensemble import RandomForestClassifier

            p.setdefault("n_jobs", -1)
            self.model_ = RandomForestClassifier(random_state=self.seed, **p)
            self.model_.fit(X, yi, sample_weight=sample_weight)
        elif self.kind == "xgboost":
            import xgboost as xgb

            esr = p.pop("early_stopping_rounds", None)
            p.setdefault("n_jobs", -1)
            self.model_ = xgb.XGBClassifier(objective="multi:softprob", num_class=len(self.classes_),
                                            eval_metric="mlogloss", random_state=self.seed,
                                            early_stopping_rounds=esr if X_val is not None else None, **p)
            eval_set, eval_w = None, None
            if X_val is not None:
                eval_set = [(X_val, self._encode(y_val))]
                eval_w = [w_val] if w_val is not None else None
            self.model_.fit(X, yi, sample_weight=sample_weight, eval_set=eval_set,
                            sample_weight_eval_set=eval_w, verbose=False)
            self.best_iteration_ = int(getattr(self.model_, "best_iteration", p.get("n_estimators", 0)) or 0)
        else:
            raise ValueError(f"Unknown classifier kind: {self.kind}")
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if self.model_ is None:
            raise RuntimeError("Classifier is not fitted")
        out = np.empty((len(X), len(self.classes_)), dtype=np.float32)
        for s in range(0, len(X), self.chunk_rows):
            part = np.asarray(X[s:s + self.chunk_rows])
            out[s:s + len(part)] = self.model_.predict_proba(part)
        return out

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.asarray(self.classes_, dtype=object)[self.predict_proba(X).argmax(axis=1)]

    def feature_importance(self, names: list[str]) -> pd.Series:
        """Impurity importance (Random Forest) or total gain normalised to 1 (XGBoost)."""
        if self.kind == "random_forest":
            imp = pd.Series(self.model_.feature_importances_, index=names)
        else:
            gain = self.model_.get_booster().get_score(importance_type="total_gain")
            imp = pd.Series({names[int(k[1:])]: v for k, v in gain.items()}).reindex(names, fill_value=0.0)
            imp = imp / imp.sum() if imp.sum() > 0 else imp
        return imp.sort_values(ascending=False)

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @staticmethod
    def load(path: str | Path) -> "FlowClassifier":
        obj = joblib.load(path)
        if not isinstance(obj, FlowClassifier):
            raise TypeError(f"{path} does not contain a FlowClassifier")
        return obj
