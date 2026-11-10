"""Explain the two largest STEP 7 error sources on the temporal test split.

1. BENIGN flows predicted as DDoS: share whose source is the DDoS victim
   (192.168.10.50), i.e. the DDoS fragments CIC labels BENIGN (STEP 5).
2. Bot: test Bot flows all go to the C2 205.174.165.73:8080. Compares them
   with BENIGN-labelled test flows to the same address and port, and with Bot
   training flows, on a few flow features.

Usage:
    python scripts/supervised_error_diagnostic.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils.config import load_config, resolve_path  # noqa: E402

VICTIM = "192.168.10.50"
C2 = ("205.174.165.73", 8080)
FEATURES = ["flow_duration", "total_fwd_packets", "total_backward_packets", "total_length_of_fwd_packets",
            "total_length_of_bwd_packets", "init_win_bytes_backward", "flow_iat_mean"]


def main() -> int:
    cfg = load_config()
    scfg = cfg["models"]["supervised"]
    pred = pd.read_parquet(resolve_path(cfg["paths"]["processed_dir"]) / "supervised_test_predictions.parquet")
    models = [c for c in pred.columns if c not in ("label", "row_id")]
    clean = pd.read_parquet(resolve_path(cfg["datasets"]["cicids2017"]["clean_output"]),
                            columns=["src_ip", "dst_ip", "dst_port"] + FEATURES)
    split = pd.read_parquet(resolve_path(cfg["preprocessing"]["splits_dir"]) / f"cicids2017_{scfg['split']}.parquet")
    clean["split"] = split["split"].astype(str).to_numpy()
    p = pred.join(clean, on="row_id")

    report: dict = {"benign_predicted_ddos": {}, "bot": {}}
    for m in models:
        x = p[(p["label"] == "BENIGN") & (p[m] == "DDoS")]
        report["benign_predicted_ddos"][m] = {"n": int(len(x)),
                                             "share_src_is_victim": float((x["src_ip"] == VICTIM).mean()) if len(x) else None}

    to_c2 = p[(p["dst_ip"] == C2[0]) & (p["dst_port"] == C2[1])]
    bot_test = p[p["label"] == "Bot"]
    report["bot"]["test_bot_flows"] = int(len(bot_test))
    report["bot"]["test_bot_flows_to_c2_8080"] = int(((bot_test["dst_ip"] == C2[0]) & (bot_test["dst_port"] == C2[1])).sum())
    report["bot"]["test_flows_to_c2_8080_by_label"] = to_c2["label"].value_counts().to_dict()
    report["bot"]["predictions_on_test_bot"] = {m: bot_test[m].value_counts().to_dict() for m in models}
    train_bot = clean[(clean["split"] == "train")]
    train_bot = train_bot.loc[pd.read_parquet(resolve_path(cfg["datasets"]["cicids2017"]["clean_output"]),
                                              columns=["label"]).loc[train_bot.index, "label"] == "Bot"]
    medians = pd.DataFrame({
        "test Bot -> C2:8080": to_c2[to_c2["label"] == "Bot"][FEATURES].median(),
        "test BENIGN -> C2:8080": to_c2[to_c2["label"] == "BENIGN"][FEATURES].median(),
        "train Bot (all)": train_bot[FEATURES].median(),
    })
    report["bot"]["feature_medians"] = medians.to_dict()
    out = resolve_path(scfg["output_dir"]) / "supervised_error_diagnostic.json"
    out.write_text(json.dumps(report, indent=2, default=float), encoding="utf-8")
    print(json.dumps(report, indent=2, default=float))
    return 0


if __name__ == "__main__":
    sys.exit(main())
