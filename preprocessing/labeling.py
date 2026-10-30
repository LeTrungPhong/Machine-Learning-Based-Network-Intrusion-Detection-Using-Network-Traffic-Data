"""Transfer CIC-IDS-2017 labels onto flows extracted by this project.

The published CSVs give each flow's 5-tuple and start time (minute
resolution, local time). Our flows are matched on the *undirected* 5-tuple
and start minute within +/- ``tolerance_min``. For each of our flows:

* ``matched``                 - all candidate CIC flows carry the same label
* ``conflict_benign_attack``  - candidates are BENIGN plus exactly one attack label;
                                the attack label is used (e.g. a TCP connection CIC split in two)
* ``ambiguous``               - candidates carry two or more different attack labels; no label
* ``unmatched``               - no candidate; no label

Flows without a label must not be used for supervised training. CIC's own
labels are inherited as published, including their known errors.

Usage:
    python -m preprocessing.labeling --flows processed/flows/Friday-WorkingHours.flows.parquet
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from preprocessing.cic_csv import parse_cic_timestamp, read_cic_csv
from utils.config import resolve_path

logger = logging.getLogger(__name__)

STATUSES = ("matched", "conflict_benign_attack", "ambiguous", "unmatched")


def undirected_key(src_ip: pd.Series, src_port: pd.Series, dst_ip: pd.Series, dst_port: pd.Series,
                   protocol: pd.Series) -> pd.Series:
    """Direction-independent 5-tuple key ``"ipA:portA|ipB:portB|proto"``."""
    a = src_ip.astype(str) + ":" + src_port.astype("int64").astype(str)
    b = dst_ip.astype(str) + ":" + dst_port.astype("int64").astype(str)
    swap = (a > b).to_numpy()
    lo = np.where(swap, b, a)
    hi = np.where(swap, a, b)
    return pd.Series(lo, index=src_ip.index) + "|" + pd.Series(hi, index=src_ip.index) + "|" + protocol.astype("int64").astype(str)


def load_cic_labels(paths: list[Path], cfg_ds: dict[str, Any]) -> pd.DataFrame:
    """Key, UTC start minute and label of every flow in the given labelled CSVs."""
    cols = ["Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp",
            cfg_ds.get("label_column", "Label")]
    df = pd.concat([read_cic_csv(p, cfg_ds, cols) for p in paths], ignore_index=True)
    out = pd.DataFrame({
        "key": undirected_key(df["Source IP"], df["Source Port"], df["Destination IP"], df["Destination Port"],
                              df["Protocol"]),
        "minute": parse_cic_timestamp(df["Timestamp"], cfg_ds.get("csv_timezone", "America/Moncton")).dt.floor("min"),
        "label": df[cfg_ds.get("label_column", "Label")].astype(str),
    })
    return out.dropna(subset=["minute"])


def assign_labels(flows: pd.DataFrame, cic: pd.DataFrame, benign: str = "BENIGN",
                  tolerance_min: int = 1) -> pd.DataFrame:
    """Return ``label`` and ``label_status`` for every row of ``flows`` (index preserved).

    Args:
        flows: Our flows with ``src_ip, src_port, dst_ip, dst_port, protocol, timestamp``.
        cic: Output of :func:`load_cic_labels`.
        benign: Name of the benign label.
        tolerance_min: Allowed difference in start minute.
    """
    ours = pd.DataFrame({
        "key": undirected_key(flows["src_ip"], flows["src_port"], flows["dst_ip"], flows["dst_port"], flows["protocol"]),
        "minute": flows["timestamp"].dt.floor("min"),
    }, index=flows.index)
    # Unique labels per (key, minute) on the CIC side keeps the merges small.
    cic_u = cic.drop_duplicates(["key", "minute", "label"])
    hits = []
    for shift in range(-tolerance_min, tolerance_min + 1):
        probe = ours.assign(minute=ours["minute"] + pd.Timedelta(minutes=shift)).reset_index(names="row")
        hits.append(probe.merge(cic_u, on=["key", "minute"], how="inner")[["row", "label"]])
    cand = pd.concat(hits, ignore_index=True).drop_duplicates()

    g = cand.groupby("row")["label"]
    n_labels, any_label = g.nunique(), g.first()
    att = cand[cand["label"] != benign].groupby("row")["label"]
    n_att = att.nunique().reindex(n_labels.index, fill_value=0)
    att_label = att.first().reindex(n_labels.index)

    status = pd.Series("unmatched", index=flows.index, dtype=object)
    label = pd.Series(pd.NA, index=flows.index, dtype="string")
    single = n_labels.index[n_labels == 1]
    conflict = n_labels.index[(n_labels > 1) & (n_att == 1)]
    ambiguous = n_labels.index[n_att >= 2]
    status.loc[single], label.loc[single] = "matched", any_label.loc[single].to_numpy()
    status.loc[conflict], label.loc[conflict] = "conflict_benign_attack", att_label.loc[conflict].to_numpy()
    status.loc[ambiguous] = "ambiguous"
    return pd.DataFrame({"label": label, "label_status": status})


def label_flow_file(flows_path: str | Path, cfg: dict[str, Any], out_dir: str | Path | None = None,
                    tolerance_min: int = 1) -> dict[str, Any]:
    """Label one ``*.flows.parquet`` file using the CIC CSVs of the same capture day."""
    cfg_ds = cfg["datasets"]["cicids2017"]
    flows_path = Path(flows_path)
    stem = flows_path.name.split(".flows.")[0]
    day = stem.split("-")[0]
    if day not in cfg_ds["days"]:
        raise ValueError(f"Cannot infer capture day from {flows_path.name}")
    csv_dir = resolve_path(cfg_ds["root"]) / cfg_ds["csv_labelled_dir"]
    csvs = [csv_dir / f"{s}.pcap_ISCX.csv" for s in cfg_ds["days"][day]]
    flows = pd.read_parquet(flows_path)
    cic = load_cic_labels(csvs, cfg_ds)
    lab = assign_labels(flows, cic, cfg_ds.get("benign_label", "BENIGN"), tolerance_min)
    groups = cfg_ds.get("label_groups", {})
    flows["day"] = day
    flows["label"] = lab["label"]
    flows["label_status"] = lab["label_status"]
    flows["label_group"] = flows["label"].map(groups).astype("string")
    benign = cfg_ds.get("benign_label", "BENIGN")
    is_attack = (flows["label"].fillna(benign) != benign).to_numpy(dtype=bool)
    flows["label_binary"] = np.where(flows["label"].isna().to_numpy(), -1, is_attack.astype(int)).astype("int8")

    out_dir = Path(out_dir) if out_dir else resolve_path(cfg["paths"]["processed_dir"]) / "labelled"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{stem}.flows.labelled.parquet"
    flows.to_parquet(out, index=False)

    cic_counts = cic["label"].value_counts()
    ours_counts = flows["label"].value_counts()
    report = {
        "flows_file": str(flows_path), "output": str(out), "day": day, "cic_files": [str(p) for p in csvs],
        "flows": int(len(flows)), "status": flows["label_status"].value_counts().to_dict(),
        "labels_ours_vs_cic": {k: {"ours": int(ours_counts.get(k, 0)), "cic_rows": int(cic_counts.get(k, 0))}
                               for k in sorted(set(cic_counts.index) | set(ours_counts.index))},
        "tolerance_min": tolerance_min,
    }
    out.with_suffix(".report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    logger.info("%s: %s flows, status %s", stem, f"{len(flows):,}", report["status"])
    return report


def main(argv: list[str] | None = None) -> int:
    from utils.config import load_config
    from utils.logging_setup import setup_logging

    ap = argparse.ArgumentParser(description="Assign CIC-IDS-2017 labels to extracted flows")
    ap.add_argument("--flows", nargs="+", required=True)
    ap.add_argument("--tolerance-min", type=int, default=1)
    ap.add_argument("--config", default=None)
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    setup_logging(cfg)
    for f in args.flows:
        label_flow_file(f, cfg, tolerance_min=args.tolerance_min)
    return 0


if __name__ == "__main__":
    sys.exit(main())
