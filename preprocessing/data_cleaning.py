"""Clean the published CIC-IDS-2017 flow CSVs into one Parquet table.

Source: ``GeneratedLabelledFlows/TrafficLabelling`` (85 columns). Its 79
feature columns are numerically identical, row by row, to
``MachineLearningCVE`` (verified on all 8 files), and it adds the flow
identifiers and timestamps needed for time-based splits.

Steps (every count is written to the cleaning report):

1. strip column names, drop all-empty rows, normalise labels;
2. parse timestamps to UTC (12-hour clock without AM/PM, see :mod:`cic_csv`);
3. coerce features to numbers, count NaN / +-Inf / negative values per column,
   replace +-Inf and impossible negatives (all except the -1 "no packet" sentinel
   of ``Init_Win_bytes_*``) by NaN; imputation happens later, fitted on training data only;
4. drop ``Fwd Header Length.1`` if it duplicates ``Fwd Header Length``;
5. drop columns that are constant over the whole dataset;
6. drop exact duplicate rows (features + label), keeping the first in time order,
   and count *conflicting* duplicates (same features, different labels);
7. write features as float32 with snake_case names, plus ``label``,
   ``label_group``, ``label_binary``, ``day`` and flow identifiers.

Usage:
    python -m preprocessing.data_cleaning
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from preprocessing.cic_csv import parse_cic_timestamp, read_cic_csv
from utils.config import resolve_path
from utils.storage import ensure_free_space

logger = logging.getLogger(__name__)

META_COLUMNS: dict[str, str] = {
    "Flow ID": "flow_id", "Source IP": "src_ip", "Source Port": "src_port",
    "Destination IP": "dst_ip", "Destination Port": "dst_port", "Protocol": "protocol",
}
DUPLICATE_COLUMN = ("Fwd Header Length.1", "Fwd Header Length")
#: Columns where -1 is a legitimate "not observed" value.
SENTINEL_NEGATIVE = ("Init_Win_bytes_forward", "Init_Win_bytes_backward")
#: Columns that are both identifiers and model inputs; kept as int metadata and
#: encoded as categories by the preprocessing pipeline.
CATEGORICAL_INPUTS = ("dst_port", "protocol")


def snake(name: str) -> str:
    """``'Flow Bytes/s'`` -> ``'flow_bytes_s'``."""
    return re.sub(r"[^0-9a-zA-Z]+", "_", name).strip("_").lower()


def ordered_files(cfg_ds: dict[str, Any]) -> list[tuple[str, str]]:
    """Return ``(day, file_stem)`` in capture order from ``datasets.cicids2017.days``."""
    return [(day, stem) for day, stems in cfg_ds["days"].items() for stem in stems]


def _clean_one(path: Path, day: str, cfg_ds: dict[str, Any]) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Pass 1 for one file: parse, coerce, count problems. Rows are not dropped here."""
    df = read_cic_csv(path, cfg_ds)
    st: dict[str, Any] = {"rows": int(len(df))}
    label_col = cfg_ds.get("label_column", "Label")
    feature_src = [c for c in df.columns if c not in META_COLUMNS and c not in ("Timestamp", label_col)]

    num = df[feature_src].apply(pd.to_numeric, errors="coerce")
    raw_na = df[feature_src].isna()
    st["non_numeric"] = {c: int(v) for c, v in (num.isna() & ~raw_na).sum().items() if v}
    st["nan"] = {c: int(v) for c, v in num.isna().sum().items() if v}
    inf = np.isinf(num)
    st["inf"] = {c: int(v) for c, v in inf.sum().items() if v}
    neg = num < 0
    st["negative"] = {c: int(v) for c, v in neg.sum().items() if v}
    num = num.mask(inf)
    # -1 initial window means "no packet in that direction" (valid sentinel); any
    # other negative duration / IAT / length / rate is impossible -> NaN, imputed later.
    invalid = neg.drop(columns=[c for c in SENTINEL_NEGATIVE if c in neg.columns])
    st["negative_set_nan"] = {c: int(v) for c, v in invalid.sum().items() if v}
    num[invalid.columns] = num[invalid.columns].mask(invalid)

    dup_src, dup_ref = DUPLICATE_COLUMN
    if dup_src in num.columns:
        same = bool(num[dup_src].equals(num[dup_ref]))
        st["fwd_header_length_1_identical"] = same
        if same:
            num = num.drop(columns=dup_src)

    out = pd.DataFrame({new: df[old] for old, new in META_COLUMNS.items()})
    for c in ("src_port", "dst_port", "protocol"):
        out[c] = pd.to_numeric(out[c], errors="coerce").astype("int32")
    out["timestamp"] = parse_cic_timestamp(df["Timestamp"], cfg_ds.get("csv_timezone", "America/Moncton"))
    st["timestamp_unparsed"] = int(out["timestamp"].isna().sum())
    out["day"] = day
    out["source_file"] = path.stem.replace(".pcap_ISCX", "")
    out["row_in_file"] = np.arange(len(df), dtype=np.int64)
    out["label"] = df[label_col].astype(str)
    feats = num.astype("float32")
    feats.columns = [snake(c) for c in feats.columns]
    if feats.columns.duplicated().any():
        raise ValueError(f"Feature names collide after snake_case in {path.name}")
    out = pd.concat([out.reset_index(drop=True), feats.reset_index(drop=True)], axis=1)
    out = out.sort_values(["timestamp", "row_in_file"], kind="stable", ignore_index=True)
    st["labels"] = out["label"].value_counts().to_dict()
    return out, st


def clean_cicids2017(cfg: dict[str, Any], drop_conflicting: bool = True) -> dict[str, Any]:
    """Run both cleaning passes and write the cleaned Parquet file and report.

    Args:
        cfg: Loaded configuration.
        drop_conflicting: Also drop rows whose features appear with more than one label.

    Returns:
        The cleaning report (also written as JSON).
    """
    t0 = time.perf_counter()
    cfg_ds = cfg["datasets"]["cicids2017"]
    root = resolve_path(cfg_ds["root"])
    src_dir = root / cfg_ds["csv_labelled_dir"]
    out_path = resolve_path(cfg_ds["clean_output"])
    tmp_dir = out_path.parent / "_tmp_clean"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    ensure_free_space(out_path.parent, cfg, required_gb=1.5)
    groups: dict[str, str] = cfg_ds.get("label_groups", {})
    benign = cfg_ds.get("benign_label", "BENIGN")

    per_file: dict[str, Any] = {}
    hashes, label_codes, feat_hashes = [], [], []
    col_min: pd.Series | None = None
    col_max: pd.Series | None = None
    feature_cols: list[str] | None = None
    parts: list[Path] = []
    for day, stem in ordered_files(cfg_ds):
        path = src_dir / f"{stem}.pcap_ISCX.csv"
        logger.info("Pass 1: %s", path.name)
        df, st = _clean_one(path, day, cfg_ds)
        per_file[stem] = st
        meta = set(META_COLUMNS.values()) | {"timestamp", "day", "source_file", "row_in_file", "label"}
        fc = [c for c in df.columns if c not in meta]
        if feature_cols is None:
            feature_cols = fc
        elif fc != feature_cols:
            raise ValueError(f"{stem}: feature columns differ from the first file")
        model_inputs = df[[*CATEGORICAL_INPUTS, *feature_cols]]
        feat_hashes.append(pd.util.hash_pandas_object(model_inputs, index=False).to_numpy())
        hashes.append(pd.util.hash_pandas_object(pd.concat([model_inputs, df["label"]], axis=1), index=False).to_numpy())
        label_codes.append(df["label"].to_numpy())
        mn, mx = df[feature_cols].min(), df[feature_cols].max()
        col_min = mn if col_min is None else np.fmin(col_min, mn)
        col_max = mx if col_max is None else np.fmax(col_max, mx)
        p = tmp_dir / f"{stem}.parquet"
        df.to_parquet(p, index=False)
        parts.append(p)
        del df, model_inputs

    assert feature_cols is not None and col_min is not None and col_max is not None
    h = np.concatenate(hashes)
    fh = np.concatenate(feat_hashes)
    labels = np.concatenate(label_codes)
    n_total = len(h)
    dup_mask = pd.Series(h).duplicated(keep="first").to_numpy()
    lab_per_feat = pd.DataFrame({"fh": fh, "label": labels}).groupby("fh")["label"].nunique()
    conflicting_fh = set(lab_per_feat[lab_per_feat > 1].index)
    conflict_mask = pd.Series(fh).isin(conflicting_fh).to_numpy()
    conflict_labels = pd.Series(labels[conflict_mask]).value_counts().to_dict()
    drop_mask = dup_mask | (conflict_mask if drop_conflicting else False)
    constant = sorted(c for c in feature_cols
                      if not (np.isfinite(col_min[c]) and np.isfinite(col_max[c])) or col_min[c] == col_max[c])
    kept_features = [c for c in feature_cols if c not in constant]

    logger.info("Pass 2: writing %s", out_path)
    writer: pq.ParquetWriter | None = None
    offset = 0
    kept_labels: dict[str, int] = {}
    try:
        for p in parts:
            df = pd.read_parquet(p)
            keep = ~drop_mask[offset: offset + len(df)]
            offset += len(df)
            df = df.loc[keep].drop(columns=constant)
            df.insert(df.columns.get_loc("label") + 1, "label_group",
                      df["label"].map(groups).fillna(df["label"]))
            df.insert(df.columns.get_loc("label_group") + 1, "label_binary",
                      (df["label"] != benign).astype("int8"))
            for k, v in df["label"].value_counts().items():
                kept_labels[k] = kept_labels.get(k, 0) + int(v)
            table = pa.Table.from_pandas(df, preserve_index=False)
            if writer is None:
                writer = pq.ParquetWriter(out_path, table.schema, compression="zstd")
            writer.write_table(table.cast(writer.schema))
            p.unlink()
    finally:
        if writer is not None:
            writer.close()
    tmp_dir.rmdir()

    def total(key: str) -> dict[str, int]:
        acc: dict[str, int] = {}
        for st in per_file.values():
            for k, v in st.get(key, {}).items():
                acc[k] = acc.get(k, 0) + v
        return dict(sorted(acc.items(), key=lambda kv: -kv[1]))

    report = {
        "source": str(src_dir),
        "output": str(out_path),
        "rows_read": n_total,
        "exact_duplicates_dropped": int(dup_mask.sum()),
        "conflicting_duplicate_rows": int(conflict_mask.sum()),
        "conflicting_rows_by_label": {k: int(v) for k, v in conflict_labels.items()},
        "conflicting_dropped": bool(drop_conflicting),
        "rows_written": int(n_total - drop_mask.sum()),
        "constant_features_dropped": constant,
        "features_kept": kept_features,
        "categorical_inputs": list(CATEGORICAL_INPUTS),
        "nan_by_feature": total("nan"),
        "inf_by_feature": total("inf"),
        "negative_by_feature": total("negative"),
        "negative_set_nan_by_feature": total("negative_set_nan"),
        "non_numeric_by_feature": total("non_numeric"),
        "labels_before": total("labels"),
        "labels_after": dict(sorted(kept_labels.items(), key=lambda kv: -kv[1])),
        "per_file": per_file,
        "seconds": round(time.perf_counter() - t0, 1),
    }
    rep_path = resolve_path(cfg_ds["cleaning_report"])
    rep_path.parent.mkdir(parents=True, exist_ok=True)
    rep_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    logger.info("Cleaned %s -> %s rows (%s exact duplicates, %s conflicting), %d features (%d constant dropped) in %.0fs",
                f"{n_total:,}", f"{report['rows_written']:,}", f"{report['exact_duplicates_dropped']:,}",
                f"{report['conflicting_duplicate_rows']:,}", len(kept_features), len(constant), report["seconds"])
    return report


def main(argv: list[str] | None = None) -> int:
    import argparse

    from utils.config import load_config
    from utils.logging_setup import setup_logging

    ap = argparse.ArgumentParser(description="Clean CIC-IDS-2017 CSVs into Parquet")
    ap.add_argument("--config", default=None)
    ap.add_argument("--keep-conflicting", action="store_true")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    setup_logging(cfg)
    clean_cicids2017(cfg, drop_conflicting=not args.keep_conflicting)
    return 0


if __name__ == "__main__":
    sys.exit(main())
