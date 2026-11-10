"""Where do STEP 6 false positives on the Thu-Fri test come from?

Splits benign test flows flagged at each model's ``fpr@<primary>`` threshold by
capture day and by the Friday DDoS window. Inside that window CIC labels the
DDoS fragments whose source is the victim (192.168.10.50) as BENIGN (see
STEP 5), so part of the measured FPR is label noise rather than model error.

Usage:
    python scripts/anomaly_fp_diagnostic.py
    python scripts/anomaly_fp_diagnostic.py --section deep_anomaly
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.metrics import binary_metrics  # noqa: E402
from models.train_anomaly import scores_path, section_cfg  # noqa: E402
from utils.config import load_config, resolve_path  # noqa: E402

VICTIM = "192.168.10.50"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--section", default="anomaly")
    section = ap.parse_args().section
    cfg = load_config()
    acfg = section_cfg(cfg, section)
    out_dir = resolve_path(acfg["output_dir"])
    res = json.loads((out_dir / f"{section}_results.json").read_text(encoding="utf-8"))
    policy = f"fpr@{float(acfg['target_fpr'][0]):g}"
    scores = pd.read_parquet(scores_path(cfg, section))
    meta = pd.read_parquet(resolve_path(cfg["datasets"]["cicids2017"]["clean_output"]),
                           columns=["day", "src_ip", "timestamp"])
    s = scores.join(meta, on="row_id")
    ddos = s[s["label"] == "DDoS"]["timestamp"]
    t0, t1 = ddos.min(), ddos.max()
    b = s[s["label"] == "BENIGN"]
    window = (b["day"] == "Friday") & b["timestamp"].between(t0, t1)
    victim_src = window & (b["src_ip"] == VICTIM)

    report: dict = {"policy": policy, "ddos_window_utc": [str(t0), str(t1)],
                    "benign_test_rows": int(len(b)), "benign_in_ddos_window": int(window.sum()),
                    "benign_in_window_victim_as_source": int(victim_src.sum()), "models": {}}
    # Sensitivity analysis only (headline metrics keep CIC's labels): treat the victim-as-source
    # BENIGN rows inside the DDoS window as DDoS and recompute the binary metrics.
    y_orig = (s["label"] != "BENIGN").to_numpy()
    y_alt = y_orig.copy()
    y_alt[s.index.get_indexer(victim_src[victim_src].index)] = True
    for name, ev in res["models"].items():
        th = ev["policies"][policy]["test"]["threshold"]
        flag = b[name] >= th
        report["models"][name] = {
            "fpr_overall": float(flag.mean()),
            "fpr_by_day": {k: float(v) for k, v in flag.groupby(b["day"]).mean().items()},
            "fpr_in_ddos_window": float(flag[window].mean()),
            "fpr_victim_as_source": float(flag[victim_src].mean()),
            "fpr_outside_window": float(flag[~window].mean()),
            "share_of_false_positives_in_window": float(flag[window].sum() / max(flag.sum(), 1)),
            "sensitivity_victim_source_as_ddos": binary_metrics(y_alt.astype(int), s[name].to_numpy(), th),
        }
    path = out_dir / f"{section}_fp_diagnostic.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
