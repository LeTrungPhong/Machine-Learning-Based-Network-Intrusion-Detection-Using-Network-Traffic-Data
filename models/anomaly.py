"""Anomaly detectors trained on (mostly) benign traffic (STEP 6).

Both detectors expose the same interface: ``fit(X)``, ``score(X)`` and
``save`` / ``load``. ``score`` returns an *anomaly score* where higher means
more anomalous, so thresholds and metrics are model-agnostic.

* :class:`GaussianAnomalyDetector` - multivariate Gaussian density of the
  training data; the score is the negative log-likelihood. ``covariance="diag"``
  treats features as independent (per-feature mean and variance);
  ``covariance="full"`` uses the full covariance matrix (Mahalanobis distance).
* :class:`IsolationForestDetector` - scikit-learn Isolation Forest; the score
  is ``-score_samples(X)``.

Inputs are expected to be preprocessed (imputed, log-transformed, scaled),
e.g. with the ``by_day`` preprocessor fitted on benign training flows.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

_LOG_2PI = float(np.log(2.0 * np.pi))


def _chunks(n: int, size: int) -> range:
    return range(0, n, max(int(size), 1))


@dataclass
class GaussianAnomalyDetector:
    """Gaussian density model; ``score`` is the negative log-likelihood.

    Args:
        covariance: ``"diag"`` (independent features) or ``"full"``.
        min_variance: Floor added to variances (``diag``) or to the covariance
            diagonal (``full``). Prevents infinite scores on features that are
            constant in training, such as rare one-hot port columns.
        chunk_rows: Rows scored per batch, to bound memory.
    """

    covariance: str = "diag"
    min_variance: float = 1e-3
    chunk_rows: int = 200_000
    mean_: np.ndarray | None = field(default=None, repr=False)
    var_: np.ndarray | None = field(default=None, repr=False)
    chol_: np.ndarray | None = field(default=None, repr=False)
    log_det_: float | None = None
    n_features_: int | None = None
    n_train_: int | None = None

    def fit(self, X: np.ndarray) -> "GaussianAnomalyDetector":
        if self.covariance not in ("diag", "full"):
            raise ValueError(f"covariance must be 'diag' or 'full', got {self.covariance!r}")
        X = np.asarray(X)
        if X.ndim != 2 or len(X) < 2:
            raise ValueError("Need a 2-D array with at least 2 rows")
        if not np.isfinite(X).all():
            raise ValueError("Training data contains NaN or infinite values")
        self.n_train_, self.n_features_ = X.shape
        # Two-pass mean/variance in float64 avoids float32 accumulation error on ~1M rows.
        self.mean_ = X.mean(axis=0, dtype=np.float64)
        if self.covariance == "diag":
            var = np.zeros(self.n_features_)
            for s in _chunks(len(X), self.chunk_rows):
                d = X[s:s + self.chunk_rows].astype(np.float64) - self.mean_
                var += (d * d).sum(axis=0)
            self.var_ = var / (len(X) - 1) + self.min_variance
            self.log_det_ = float(np.log(self.var_).sum())
        else:
            cov = np.zeros((self.n_features_, self.n_features_))
            for s in _chunks(len(X), self.chunk_rows):
                d = X[s:s + self.chunk_rows].astype(np.float64) - self.mean_
                cov += d.T @ d
            cov = cov / (len(X) - 1) + self.min_variance * np.eye(self.n_features_)
            self.chol_ = np.linalg.cholesky(cov)
            self.log_det_ = float(2.0 * np.log(np.diag(self.chol_)).sum())
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """Negative log-likelihood per row (higher = more anomalous)."""
        if self.mean_ is None:
            raise RuntimeError("Detector is not fitted")
        X = np.asarray(X)
        if X.ndim != 2 or X.shape[1] != self.n_features_:
            raise ValueError(f"Expected {self.n_features_} features, got shape {X.shape}")
        out = np.empty(len(X), dtype=np.float64)
        const = 0.5 * (self.n_features_ * _LOG_2PI + self.log_det_)
        for s in _chunks(len(X), self.chunk_rows):
            d = X[s:s + self.chunk_rows].astype(np.float64) - self.mean_
            if self.covariance == "diag":
                maha = (d * d / self.var_).sum(axis=1)
            else:
                z = np.linalg.solve(self.chol_, d.T)  # L z = d^T  ->  |z|^2 = Mahalanobis distance^2
                maha = (z * z).sum(axis=0)
            out[s:s + len(d)] = 0.5 * maha + const
        return out

    def save(self, path: str | Path) -> Path:
        return _save(self, path)

    @staticmethod
    def load(path: str | Path) -> "GaussianAnomalyDetector":
        return _load(path, GaussianAnomalyDetector)


@dataclass
class IsolationForestDetector:
    """Isolation Forest wrapper; ``score`` is ``-score_samples`` (higher = more anomalous).

    Args:
        n_estimators, max_samples, max_features: Passed to :class:`sklearn.ensemble.IsolationForest`.
        random_state: Seed.
        n_jobs: Parallel jobs for fitting and scoring.
        chunk_rows: Rows scored per batch, to bound memory.
    """

    n_estimators: int = 200
    max_samples: int | float | str = 256
    max_features: float = 1.0
    random_state: int = 42
    n_jobs: int = -1
    chunk_rows: int = 200_000
    model_: IsolationForest | None = field(default=None, repr=False)
    n_train_: int | None = None

    def fit(self, X: np.ndarray) -> "IsolationForestDetector":
        X = np.asarray(X)
        if not np.isfinite(X).all():
            raise ValueError("Training data contains NaN or infinite values")
        self.model_ = IsolationForest(n_estimators=self.n_estimators, max_samples=self.max_samples,
                                      max_features=self.max_features, contamination="auto",
                                      random_state=self.random_state, n_jobs=self.n_jobs)
        self.model_.fit(X)
        self.n_train_ = len(X)
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        if self.model_ is None:
            raise RuntimeError("Detector is not fitted")
        X = np.asarray(X)
        out = np.empty(len(X), dtype=np.float64)
        for s in _chunks(len(X), self.chunk_rows):
            part = X[s:s + self.chunk_rows]
            out[s:s + len(part)] = -self.model_.score_samples(part)
        return out

    def save(self, path: str | Path) -> Path:
        return _save(self, path)

    @staticmethod
    def load(path: str | Path) -> "IsolationForestDetector":
        return _load(path, IsolationForestDetector)


def build_detector(kind: str, params: dict[str, Any] | None = None, seed: int = 42) -> Any:
    """Create a detector from its config name (``gaussian``, ``isolation_forest``, ``autoencoder``, ``vae``)."""
    params = dict(params or {})
    if kind == "gaussian":
        return GaussianAnomalyDetector(**params)
    if kind == "isolation_forest":
        params.setdefault("random_state", seed)
        return IsolationForestDetector(**params)
    if kind in ("autoencoder", "vae"):
        from models.deep_anomaly import AutoencoderDetector, VAEDetector  # torch only when needed

        params.setdefault("random_state", seed)
        return (AutoencoderDetector if kind == "autoencoder" else VAEDetector)(**params)
    raise ValueError(f"Unknown detector kind: {kind}")


def _save(obj: Any, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(obj, path)
    return path


def _load(path: str | Path, cls: type) -> Any:
    obj = joblib.load(path)
    if not isinstance(obj, cls):
        raise TypeError(f"{path} does not contain a {cls.__name__}")
    return obj
