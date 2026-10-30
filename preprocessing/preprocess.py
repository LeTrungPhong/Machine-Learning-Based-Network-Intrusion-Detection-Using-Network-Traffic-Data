"""Train/validation/test splits and the feature preprocessing pipeline.

Leakage rules enforced here:

* split assignment never looks at feature values;
* imputation medians, scaler statistics, one-hot port vocabulary and the
  correlated-feature filter are all fitted on training rows only;
* resampling (SMOTE) is only ever applied to training data.

The fitted pipeline and its input/output schema are saved together so that
inference (offline or real time) applies exactly the same transformation.

Usage:
    python -m preprocessing.preprocess --strategy temporal_per_class
    python -m preprocessing.preprocess --strategy by_day --fit-on benign
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, RobustScaler, StandardScaler
from sklearn.utils.class_weight import compute_class_weight

from preprocessing.data_cleaning import CATEGORICAL_INPUTS
from utils.config import resolve_path

logger = logging.getLogger(__name__)

SPLITS = ("train", "val", "test")
META_COLUMNS = ("flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "timestamp",
                "day", "source_file", "row_in_file", "label", "label_group", "label_binary")


# ---------------------------------------------------------------- data access

def load_clean(cfg: dict[str, Any], columns: Iterable[str] | None = None) -> pd.DataFrame:
    """Load the cleaned CIC-IDS-2017 table (row order defines ``row_id``)."""
    path = resolve_path(cfg["datasets"]["cicids2017"]["clean_output"])
    if not path.is_file():
        raise FileNotFoundError(f"{path} not found - run python -m preprocessing.data_cleaning first")
    return pd.read_parquet(path, columns=list(columns) if columns is not None else None)


def feature_columns(df: pd.DataFrame) -> list[str]:
    """Numeric model inputs: every column that is not metadata."""
    return [c for c in df.columns if c not in META_COLUMNS]


# ---------------------------------------------------------------- splits

def _temporal_cut(n: int, val_fraction: float, test_fraction: float) -> tuple[int, int]:
    """Return ``(n_train, n_val)`` for one class; each split gets >= 1 row when ``n >= 3``."""
    n_test = int(round(n * test_fraction))
    n_val = int(round(n * val_fraction))
    if n >= 3:
        n_test, n_val = max(n_test, 1), max(n_val, 1)
    n_train = max(n - n_val - n_test, 0)
    return n_train, n_val


def split_rows(meta: pd.DataFrame, strategy: str, pcfg: dict[str, Any], seed: int = 42) -> pd.Series:
    """Assign each row to ``train`` / ``val`` / ``test``.

    Args:
        meta: Needs ``label``, ``timestamp``, ``day``, ``row_in_file`` and ``source_file``.
        strategy: ``temporal_per_class`` | ``by_day`` | ``stratified_random``.
        pcfg: ``preprocessing`` config section.
        seed: Random seed (``stratified_random`` only).

    Returns:
        Categorical Series aligned with ``meta.index``.
    """
    val_f, test_f = float(pcfg.get("val_fraction", 0.15)), float(pcfg.get("test_fraction", 0.2))
    split = pd.Series("train", index=meta.index, dtype=object)
    if strategy == "temporal_per_class":
        order = meta.sort_values(["timestamp", "source_file", "row_in_file"], kind="stable").index
        ordered = meta.loc[order]
        for _, idx in ordered.groupby("label", sort=False).groups.items():
            idx = ordered.loc[idx].index  # keep time order within the class
            n_train, n_val = _temporal_cut(len(idx), val_f, test_f)
            split.loc[idx[n_train:n_train + n_val]] = "val"
            split.loc[idx[n_train + n_val:]] = "test"
    elif strategy == "by_day":
        train_days, test_days = set(pcfg["train_days"]), set(pcfg["test_days"])
        unknown = set(meta["day"].unique()) - train_days - test_days
        if unknown:
            raise ValueError(f"Days not assigned to train or test: {sorted(unknown)}")
        split[meta["day"].isin(test_days)] = "test"
        tr = meta[~meta["day"].isin(test_days)].sort_values(["timestamp", "source_file", "row_in_file"], kind="stable")
        n_val = int(round(len(tr) * val_f / (1 - test_f))) if len(tr) else 0
        # validation = the latest part of the training days (still before the test days)
        split.loc[tr.index[len(tr) - n_val:]] = "val"
    elif strategy == "stratified_random":
        idx = meta.index.to_numpy()
        y = meta["label"].to_numpy()
        rare = pd.Series(y).map(pd.Series(y).value_counts()) < 3
        strat = np.where(rare, "__rare__", y)
        tr_val, te = train_test_split(idx, test_size=test_f, stratify=strat, random_state=seed)
        strat_tv = pd.Series(strat, index=idx).loc[tr_val]
        tr, va = train_test_split(tr_val, test_size=val_f / (1 - test_f), stratify=strat_tv, random_state=seed)
        split.loc[va], split.loc[te] = "val", "test"
    else:
        raise ValueError(f"Unknown split strategy: {strategy}")
    return split.astype(pd.CategoricalDtype(list(SPLITS)))


def split_summary(meta: pd.DataFrame, split: pd.Series) -> dict[str, Any]:
    """Per-split row counts by label and time range."""
    out: dict[str, Any] = {}
    for s in SPLITS:
        m = meta[split == s]
        out[s] = {"rows": int(len(m)), "labels": m["label"].value_counts().to_dict(),
                  "time_utc": [str(m["timestamp"].min()), str(m["timestamp"].max())] if len(m) else None,
                  "days": sorted(m["day"].unique().tolist())}
    return out


# ---------------------------------------------------------------- pipeline

def signed_log1p(x: np.ndarray) -> np.ndarray:
    """``sign(x) * log1p(|x|)``; keeps the -1 sentinel distinguishable from 0."""
    return np.sign(x) * np.log1p(np.abs(x))


def correlated_features(X: pd.DataFrame, threshold: float, sample_rows: int | None = None,
                        seed: int = 42) -> list[str]:
    """Greedy filter: for every pair with ``|r| > threshold`` drop the later column.

    Computed on (a sample of) the training data after the signed log transform.
    """
    if sample_rows and len(X) > sample_rows:
        X = X.sample(sample_rows, random_state=seed)
    Z = pd.DataFrame(signed_log1p(X.to_numpy(dtype="float64")), columns=X.columns)
    corr = Z.corr().abs().to_numpy()
    cols = list(X.columns)
    drop: set[str] = set()
    for i in range(len(cols)):
        if cols[i] in drop:
            continue
        for j in range(i + 1, len(cols)):
            if cols[j] not in drop and corr[i, j] > threshold:
                drop.add(cols[j])
    return [c for c in cols if c in drop]


def build_preprocessor(numeric: list[str], categorical: list[str], pcfg: dict[str, Any]) -> ColumnTransformer:
    """Median imputation -> optional signed log -> scaler for numeric; one-hot for categorical."""
    scaler = {"robust": RobustScaler(), "standard": StandardScaler()}[pcfg.get("scaler", "robust")]
    steps: list[tuple[str, Any]] = [("impute", SimpleImputer(strategy="median"))]
    if pcfg.get("log_transform", True):
        steps.append(("log", FunctionTransformer(signed_log1p, feature_names_out="one-to-one")))
    steps.append(("scale", scaler))
    transformers: list[tuple[str, Any, list[str]]] = [("num", Pipeline(steps), numeric)]
    if categorical:
        top_k = int(pcfg.get("top_k_ports", 32))
        transformers.append(("cat", OneHotEncoder(handle_unknown="infrequent_if_exist", max_categories=top_k + 1,
                                                  sparse_output=False, dtype=np.float32), categorical))
    return ColumnTransformer(transformers, remainder="drop", verbose_feature_names_out=True)


def class_weights(y: np.ndarray) -> dict[str, float]:
    """Balanced class weights computed from training labels."""
    classes = np.unique(y)
    w = compute_class_weight("balanced", classes=classes, y=y)
    return {str(c): float(v) for c, v in zip(classes, w)}


def resample_training(X: np.ndarray, y: np.ndarray, method: str, max_per_class: int = 50_000,
                      seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Oversample minority classes of the *training* split.

    ``smote`` raises every class below ``max_per_class`` up to that size (or
    leaves it if larger); ``k_neighbors`` adapts to the smallest class.
    Classes with fewer than 2 samples are left unchanged.
    """
    if method in (None, "none", "class_weight"):
        return X, y
    if method != "smote":
        raise ValueError(f"Unknown resampling method: {method}")
    from imblearn.over_sampling import SMOTE

    counts = pd.Series(y).value_counts()
    targets = {c: max(int(n), max_per_class) for c, n in counts.items() if 2 <= n < max_per_class}
    if not targets:
        return X, y
    k = max(1, min(5, int(counts[list(targets)].min()) - 1))
    sm = SMOTE(sampling_strategy=targets, k_neighbors=k, random_state=seed)
    Xr, yr = sm.fit_resample(X, y)
    return Xr.astype(X.dtype, copy=False), yr


@dataclass
class FittedPreprocessor:
    """A fitted transformer plus the schema needed to apply it at inference time."""

    transformer: ColumnTransformer
    numeric: list[str]
    categorical: list[str]
    dropped_correlated: list[str]
    output_features: list[str]
    meta: dict[str, Any]

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        missing = [c for c in self.numeric + self.categorical if c not in df.columns]
        if missing:
            raise ValueError(f"Input lacks columns required by the preprocessor: {missing}")
        return self.transformer.transform(df[self.numeric + self.categorical]).astype(np.float32, copy=False)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        schema = {k: getattr(self, k) for k in ("numeric", "categorical", "dropped_correlated", "output_features")}
        schema["meta"] = self.meta
        path.with_suffix(".schema.json").write_text(json.dumps(schema, indent=2, default=str), encoding="utf-8")

    @staticmethod
    def load(path: str | Path) -> "FittedPreprocessor":
        obj = joblib.load(path)
        if not isinstance(obj, FittedPreprocessor):
            raise TypeError(f"{path} does not contain a FittedPreprocessor")
        return obj


def fit_preprocessor(train: pd.DataFrame, pcfg: dict[str, Any], numeric: list[str],
                     categorical: list[str] | None = None, seed: int = 42,
                     meta: dict[str, Any] | None = None) -> FittedPreprocessor:
    """Fit the full preprocessing on training rows only."""
    categorical = list(CATEGORICAL_INPUTS if categorical is None else categorical)
    thr = pcfg.get("correlation_threshold")
    dropped = correlated_features(train[numeric], float(thr), pcfg.get("correlation_sample_rows"), seed) if thr else []
    kept = [c for c in numeric if c not in dropped]
    ct = build_preprocessor(kept, categorical, pcfg)
    ct.fit(train[kept + categorical])
    info = {"sklearn": sklearn.__version__, "train_rows": int(len(train)), "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
            **(meta or {})}
    return FittedPreprocessor(ct, kept, categorical, dropped, list(ct.get_feature_names_out()), info)


# ---------------------------------------------------------------- CLI

def run(cfg: dict[str, Any], strategy: str, fit_on: str = "all") -> dict[str, Any]:
    """Compute a split, fit the preprocessor on its training rows and save both."""
    pcfg = cfg["preprocessing"]
    seed = int(cfg["project"].get("random_seed", 42))
    df = load_clean(cfg)
    split = split_rows(df, strategy, pcfg, seed)
    splits_dir = resolve_path(pcfg["splits_dir"])
    splits_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame({"row_id": np.arange(len(df), dtype=np.int64), "split": split.to_numpy()}).to_parquet(
        splits_dir / f"cicids2017_{strategy}.parquet", index=False)
    summary = split_summary(df, split)

    train = df[split.to_numpy() == "train"]
    if fit_on == "benign":
        train = train[train["label_binary"] == 0]
    elif fit_on != "all":
        raise ValueError("fit_on must be 'all' or 'benign'")
    numeric = [c for c in feature_columns(df)]
    fp = fit_preprocessor(train, pcfg, numeric, seed=seed, meta={"strategy": strategy, "fit_on": fit_on})
    out = resolve_path(pcfg["preprocessors_dir"]) / f"cicids2017_{strategy}_{fit_on}.joblib"
    fp.save(out)
    weights = class_weights(df.loc[split.to_numpy() == "train", "label"].to_numpy())
    result = {"strategy": strategy, "fit_on": fit_on, "split_file": str(splits_dir / f"cicids2017_{strategy}.parquet"),
              "preprocessor": str(out), "n_numeric_in": len(numeric), "dropped_correlated": fp.dropped_correlated,
              "n_output_features": len(fp.output_features), "class_weights_train": weights, "splits": summary}
    rep = resolve_path(cfg["paths"]["eda_dir"]) / f"split_{strategy}.json"
    rep.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    logger.info("%s: train %s / val %s / test %s rows; %d numeric (-%d correlated) + %d categorical -> %d features; saved %s",
                strategy, f"{summary['train']['rows']:,}", f"{summary['val']['rows']:,}", f"{summary['test']['rows']:,}",
                len(fp.numeric), len(fp.dropped_correlated), len(fp.categorical), len(fp.output_features), out.name)
    return result


def main(argv: list[str] | None = None) -> int:
    from utils.config import load_config
    from utils.logging_setup import setup_logging

    ap = argparse.ArgumentParser(description="Create splits and fit the preprocessing pipeline")
    ap.add_argument("--strategy", choices=["temporal_per_class", "by_day", "stratified_random"], required=True)
    ap.add_argument("--fit-on", choices=["all", "benign"], default="all")
    ap.add_argument("--config", default=None)
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    setup_logging(cfg)
    run(cfg, args.strategy, args.fit_on)
    return 0


if __name__ == "__main__":
    sys.exit(main())
