"""Cache preprocessed feature matrices of one split on disk (``.npy`` memmaps).

The cleaned CIC table is transformed once with a fitted preprocessor and the
result is written part by part, so training and scoring can read the
matrices in chunks without holding the whole split in RAM. A part is a subset
of one split value, optionally benign-only or randomly sampled.

Files per part: ``<part>.npy`` (float32) and ``<part>.labels.parquet``
(``row_id``, ``label``, ``label_binary``, ``label_group``), plus
``cache_meta.json``. The cache is rebuilt when the preprocessor, the split
file or the part specification changes.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from preprocessing.preprocess import FittedPreprocessor
from utils.config import resolve_path
from utils.storage import ensure_free_space

logger = logging.getLogger(__name__)

LABEL_COLUMNS = ["label", "label_binary", "label_group"]


def build_feature_cache(cfg: dict[str, Any], split: str, preprocessor: str, features_dir: str | Path,
                        parts: dict[str, dict[str, Any]], rebuild: bool = False,
                        chunk_rows: int = 200_000) -> Path:
    """Transform the selected rows of ``split`` and cache them under ``features_dir``.

    Args:
        cfg: Loaded configuration.
        split: Split strategy name (``processed/splits/cicids2017_<split>.parquet``).
        preprocessor: File name in ``preprocessing.preprocessors_dir``.
        features_dir: Output directory.
        parts: ``{name: {"split": "train"|"val"|"test", "benign_only": bool,
            "sample_rows": int | None}}``. Parts are built in the given order;
            sampled parts draw from one RNG seeded with ``project.random_seed``.
        rebuild: Ignore an up-to-date cache.
        chunk_rows: Rows transformed per batch.
    """
    pcfg = cfg["preprocessing"]
    seed = int(cfg["project"].get("random_seed", 42))
    features_dir = resolve_path(features_dir)
    meta_path = features_dir / "cache_meta.json"
    pre_path = resolve_path(pcfg["preprocessors_dir"]) / preprocessor
    split_path = resolve_path(pcfg["splits_dir"]) / f"cicids2017_{split}.parquet"
    stamp = {"preprocessor": str(pre_path), "preprocessor_mtime": pre_path.stat().st_mtime,
             "split_file": str(split_path), "split_mtime": split_path.stat().st_mtime,
             "parts": parts, "seed": seed}
    files_ok = all((features_dir / f"{p}.npy").is_file() and (features_dir / f"{p}.labels.parquet").is_file()
                   for p in parts)
    if not rebuild and meta_path.is_file() and files_ok:
        old = json.loads(meta_path.read_text(encoding="utf-8"))
        if all(old.get(k) == v for k, v in stamp.items()):
            logger.info("Using cached features in %s", features_dir)
            return features_dir
        logger.info("Feature cache in %s is stale; rebuilding", features_dir)

    fp = FittedPreprocessor.load(pre_path)
    split_df = pd.read_parquet(split_path)
    clean_path = resolve_path(cfg["datasets"]["cicids2017"]["clean_output"])
    table = pq.read_table(clean_path, columns=fp.numeric + fp.categorical + LABEL_COLUMNS)
    if table.num_rows != len(split_df):
        raise ValueError(f"Split file has {len(split_df)} rows but {clean_path.name} has {table.num_rows}")
    if not (split_df["row_id"].to_numpy() == np.arange(len(split_df))).all():
        raise ValueError("Split file row_id must be 0..n-1 in order")

    s = split_df["split"].astype(str).to_numpy()
    benign = table.column("label_binary").to_numpy() == 0
    rng = np.random.default_rng(seed)
    rows: dict[str, np.ndarray] = {}
    for name, spec in parts.items():
        mask = s == spec["split"]
        if spec.get("benign_only"):
            mask &= benign
        idx = np.flatnonzero(mask)
        n = spec.get("sample_rows")
        if n is not None and int(n) < len(idx):
            idx = np.sort(rng.choice(idx, size=int(n), replace=False))
        rows[name] = idx

    n_out = len(fp.output_features)
    features_dir.mkdir(parents=True, exist_ok=True)
    ensure_free_space(features_dir, cfg, required_gb=sum(len(r) for r in rows.values()) * n_out * 4 / 2**30)

    for name, idx in rows.items():
        t0 = time.perf_counter()
        mm = np.lib.format.open_memmap(features_dir / f"{name}.npy", mode="w+", dtype=np.float32,
                                       shape=(len(idx), n_out))
        for start in range(0, len(idx), chunk_rows):
            X = fp.transform(table.take(idx[start:start + chunk_rows]).to_pandas())
            if not np.isfinite(X).all():
                raise ValueError(f"Non-finite values after preprocessing in part {name}")
            mm[start:start + len(X)] = X
        mm.flush()
        del mm
        lab = table.select(LABEL_COLUMNS).take(idx).to_pandas()
        lab.insert(0, "row_id", idx.astype(np.int64))
        lab.to_parquet(features_dir / f"{name}.labels.parquet", index=False)
        logger.info("Cached %s: %s rows x %d features (%.1f s)", name, f"{len(idx):,}", n_out, time.perf_counter() - t0)

    stamp["output_features"] = fp.output_features
    stamp["rows"] = {k: int(len(v)) for k, v in rows.items()}
    meta_path.write_text(json.dumps(stamp, indent=2), encoding="utf-8")
    return features_dir


def load_part(features_dir: str | Path, part: str) -> tuple[np.ndarray, pd.DataFrame]:
    """Memory-mapped feature matrix and labels of one cached part."""
    features_dir = Path(features_dir)
    X = np.load(features_dir / f"{part}.npy", mmap_mode="r")
    lab = pd.read_parquet(features_dir / f"{part}.labels.parquet")
    if len(lab) != len(X):
        raise ValueError(f"{part}: {len(X)} feature rows but {len(lab)} label rows")
    return X, lab


def output_features(features_dir: str | Path) -> list[str]:
    """Feature names stored with the cache."""
    meta = json.loads((Path(features_dir) / "cache_meta.json").read_text(encoding="utf-8"))
    return list(meta["output_features"])
