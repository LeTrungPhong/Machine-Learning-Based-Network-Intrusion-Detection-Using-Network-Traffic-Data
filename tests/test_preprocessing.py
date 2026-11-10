"""Tests for CIC cleaning, splits, the preprocessing pipeline and label transfer (Phase 4)."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from preprocessing.data_cleaning import clean_cicids2017, snake
from preprocessing.labeling import assign_labels, undirected_key
from preprocessing.preprocess import (
    FittedPreprocessor, class_weights, correlated_features, fit_preprocessor, resample_training,
    signed_log1p, split_rows,
)

HEADER = ("Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp,"
          " Flow Duration, Flow Bytes/s, Init_Win_bytes_forward, Fwd Header Length, Fwd Header Length.1,"
          " Constant Col, Label\n")


def _row(i: int, dur: float, rate: str, win: int, hdr: int, label: str, ts: str = "7/7/2017 1:00") -> str:
    return f"f{i},10.0.0.{i % 5},{1000 + i},192.168.10.50,80,6,{ts},{dur},{rate},{win},{hdr},{hdr},7,{label}\n"


@pytest.fixture()
def tiny_cic(tmp_path: Path) -> dict:
    d = tmp_path / "CIC" / "csvs" / "TL"
    d.mkdir(parents=True)
    mon = HEADER + "".join(_row(i, 100 + i, "5.0", 8192, 20, "BENIGN", "03/07/2017 08:55:58") for i in range(6))
    mon += _row(0, 100, "5.0", 8192, 20, "BENIGN", "03/07/2017 08:56:00")          # exact duplicate of row 0
    fri = HEADER + _row(1, -5, "Infinity", -1, 20, "BENIGN")                       # negative duration, inf
    fri += _row(2, 50, "NaN", -1, -3, "DDoS") + _row(3, 60, "1.0", 64, 20, "DDoS")
    fri += _row(9, 70, "2.0", 64, 20, "Web Attack \x96 XSS")
    fri += _row(8, 71, "2.0", 64, 20, "BENIGN")
    fri += ",,,,,,,,,,,,,\n"
    (d / "Monday-X.pcap_ISCX.csv").write_bytes(mon.encode("latin-1"))
    (d / "Friday-X.pcap_ISCX.csv").write_bytes(fri.encode("latin-1"))
    return {
        "datasets": {"cicids2017": {
            "root": str(tmp_path / "CIC"), "csv_labelled_dir": "csvs/TL", "csv_encoding": "latin-1",
            "csv_timezone": "America/Moncton", "label_column": "Label", "benign_label": "BENIGN",
            "days": {"Monday": ["Monday-X"], "Friday": ["Friday-X"]},
            "label_groups": {"Web Attack - XSS": "WebAttack", "DDoS": "DDoS", "BENIGN": "BENIGN"},
            "clean_output": str(tmp_path / "out" / "clean.parquet"),
            "cleaning_report": str(tmp_path / "out" / "report.json")}},
        "storage": {"min_free_gb": 0, "warn_free_gb": 0},
    }


def test_snake_names() -> None:
    assert snake(" Flow Bytes/s") == "flow_bytes_s" and snake("Init_Win_bytes_forward") == "init_win_bytes_forward"


def test_clean_cicids2017_on_tiny_files(tiny_cic: dict) -> None:
    rep = clean_cicids2017(tiny_cic)
    df = pd.read_parquet(tiny_cic["datasets"]["cicids2017"]["clean_output"])
    assert rep["rows_read"] == 7 + 5                      # empty row dropped
    assert rep["exact_duplicates_dropped"] == 1
    assert rep["conflicting_duplicate_rows"] == 0
    assert "constant_col" in rep["constant_features_dropped"]
    assert "fwd_header_length_1" not in df.columns
    assert rep["per_file"]["Friday-X"]["inf"] == {"Flow Bytes/s": 1}
    # counted before the duplicate column is dropped
    assert rep["negative_set_nan_by_feature"] == {"Flow Duration": 1, "Fwd Header Length": 1, "Fwd Header Length.1": 1}
    assert len(df) == 11
    fri = df[df.day == "Friday"].set_index("flow_id")
    assert np.isnan(fri.loc["f1", "flow_duration"]) and np.isnan(fri.loc["f1", "flow_bytes_s"])
    assert fri.loc["f1", "init_win_bytes_forward"] == -1                      # sentinel kept
    assert fri.loc["f9", "label"] == "Web Attack - XSS" and fri.loc["f9", "label_group"] == "WebAttack"
    assert fri.loc["f9", "label_binary"] == 1 and fri.loc["f8", "label_binary"] == 0
    assert str(fri.loc["f2", "timestamp"]) == "2017-07-07 16:00:00+00:00"   # "1:00" = 13:00 local
    assert df["flow_duration"].dtype == np.float32


def test_conflicting_duplicates_are_detected(tiny_cic: dict, tmp_path: Path) -> None:
    d = Path(tiny_cic["datasets"]["cicids2017"]["root"]) / "csvs" / "TL"
    fri = HEADER + _row(3, 60, "1.0", 64, 20, "DDoS") + _row(3, 60, "1.0", 64, 20, "BENIGN")
    (d / "Friday-X.pcap_ISCX.csv").write_bytes(fri.encode("latin-1"))
    rep = clean_cicids2017(tiny_cic)
    assert rep["conflicting_duplicate_rows"] == 2 and rep["conflicting_rows_by_label"] == {"DDoS": 1, "BENIGN": 1}


# ---------------------------------------------------------------- splits

def _meta(n_per: dict[str, int]) -> pd.DataFrame:
    rows = []
    t0 = pd.Timestamp("2017-07-03 12:00", tz="UTC")
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    for li, (lab, n) in enumerate(n_per.items()):
        for i in range(n):
            rows.append({"label": lab, "timestamp": t0 + pd.Timedelta(minutes=i * 7 + li),
                         "day": days[min(i * 5 // max(n, 1), 4)], "row_in_file": i, "source_file": "x"})
    return pd.DataFrame(rows)


def test_temporal_per_class_split_is_time_ordered_and_covers_all_classes() -> None:
    meta = _meta({"BENIGN": 100, "Heartbleed": 11, "Rare": 3})
    s = split_rows(meta, "temporal_per_class", {"val_fraction": 0.15, "test_fraction": 0.2})
    for lab, g in meta.groupby("label"):
        sp = s.loc[g.index]
        assert set(sp) == {"train", "val", "test"}
        assert g.loc[sp == "train", "timestamp"].max() < g.loc[sp == "val", "timestamp"].min()
        assert g.loc[sp == "val", "timestamp"].max() < g.loc[sp == "test", "timestamp"].min()
    assert (s[meta.label == "BENIGN"] == "test").sum() == 20


def test_by_day_split_separates_days() -> None:
    meta = _meta({"BENIGN": 50})
    s = split_rows(meta, "by_day", {"train_days": ["Monday", "Tuesday", "Wednesday"],
                                    "test_days": ["Thursday", "Friday"], "val_fraction": 0.15, "test_fraction": 0.2})
    assert set(meta.loc[s == "test", "day"]) == {"Thursday", "Friday"}
    assert not set(meta.loc[s != "test", "day"]) & {"Thursday", "Friday"}
    assert meta.loc[s == "val", "timestamp"].min() > meta.loc[s == "train", "timestamp"].max()
    with pytest.raises(ValueError):
        split_rows(meta, "by_day", {"train_days": ["Monday"], "test_days": ["Friday"]})


def test_stratified_random_split_and_unknown_strategy() -> None:
    meta = _meta({"A": 200, "B": 40, "C": 2})
    s = split_rows(meta, "stratified_random", {"val_fraction": 0.15, "test_fraction": 0.2}, seed=1)
    assert abs((s == "test").mean() - 0.2) < 0.02
    with pytest.raises(ValueError):
        split_rows(meta, "bogus", {})


# ---------------------------------------------------------------- pipeline

def test_preprocessor_fits_on_train_only_and_roundtrips(tmp_path: Path) -> None:
    rng = np.random.default_rng(0)
    train = pd.DataFrame({"a": rng.normal(10, 1, 500), "b": rng.exponential(5, 500), "dst_port": rng.choice([80, 443, 53], 500),
                          "protocol": rng.choice([6, 17], 500)})
    train.loc[:9, "a"] = np.nan
    train["a_copy"] = train["a"] * 2.0                       # perfectly correlated -> dropped
    test = pd.DataFrame({"a": [np.nan, 1e6], "b": [1.0, 2.0], "a_copy": [0.0, 0.0], "dst_port": [80, 9999], "protocol": [6, 1]})
    fp = fit_preprocessor(train, {"scaler": "robust", "log_transform": True, "correlation_threshold": 0.99,
                                  "top_k_ports": 2}, ["a", "b", "a_copy"])
    assert fp.dropped_correlated == ["a_copy"] and fp.numeric == ["a", "b"]
    imputer = fp.transformer.named_transformers_["num"].named_steps["impute"]
    assert imputer.statistics_[0] == pytest.approx(np.nanmedian(train["a"]))      # train statistics only
    Xt = fp.transform(test)
    assert Xt.dtype == np.float32 and np.isfinite(Xt).all() and Xt.shape[1] == len(fp.output_features)
    path = tmp_path / "p.joblib"
    fp.save(path)
    again = FittedPreprocessor.load(path)
    np.testing.assert_array_equal(again.transform(test), Xt)
    schema = json.loads(path.with_suffix(".schema.json").read_text())
    assert schema["numeric"] == ["a", "b"] and schema["categorical"] == ["dst_port", "protocol"]
    with pytest.raises(ValueError):
        fp.transform(test.drop(columns="b"))


def test_signed_log_and_correlation_filter() -> None:
    np.testing.assert_allclose(signed_log1p(np.array([-1.0, 0.0, np.e - 1])), [-np.log(2), 0.0, 1.0])
    x = pd.DataFrame({"a": np.arange(100.0), "b": np.arange(100.0) * 3, "c": np.sin(np.arange(100.0))})
    assert correlated_features(x, 0.99) == ["b"]


def test_class_weights_and_smote_only_raise_minorities() -> None:
    y = np.array(["A"] * 90 + ["B"] * 10)
    w = class_weights(y)
    assert w["B"] > w["A"]
    rng = np.random.default_rng(0)
    X = rng.normal(size=(100, 3)).astype(np.float32)
    Xr, yr = resample_training(X, y, "smote", max_per_class=50)
    counts = pd.Series(yr).value_counts()
    assert counts["A"] == 90 and counts["B"] == 50 and Xr.dtype == np.float32
    assert resample_training(X, y, "class_weight")[0] is X


# ---------------------------------------------------------------- label transfer

def test_assign_labels_rules() -> None:
    t = pd.Timestamp("2017-07-07 18:56:30", tz="UTC")
    flows = pd.DataFrame({
        "src_ip": ["172.16.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
        "src_port": [49670, 1, 2, 3, 4], "dst_ip": ["192.168.10.50"] * 5, "dst_port": [80] * 5,
        "protocol": [6] * 5, "timestamp": [t] * 5})
    m = t.floor("min")
    cic = pd.DataFrame({
        "key": [*undirected_key(pd.Series(["192.168.10.50"] * 2), pd.Series([80, 80]), pd.Series(["172.16.0.1"] * 2),
                                pd.Series([49670, 49670]), pd.Series([6, 6])),
                *undirected_key(pd.Series(["10.0.0.1", "10.0.0.2", "10.0.0.2"]), pd.Series([1, 2, 2]),
                                pd.Series(["192.168.10.50"] * 3), pd.Series([80] * 3), pd.Series([6] * 3))],
        "minute": [m, m, m + pd.Timedelta(minutes=1), m, m],
        "label": ["BENIGN", "DDoS", "BENIGN", "DDoS", "PortScan"]})
    out = assign_labels(flows, cic)
    assert out["label_status"].tolist() == ["conflict_benign_attack", "matched", "ambiguous", "unmatched", "unmatched"]
    assert out["label"].tolist()[:2] == ["DDoS", "BENIGN"] and out["label"].isna().tolist()[2:] == [True, True, True]
    # outside the tolerance -> unmatched
    late = flows.iloc[[1]].assign(timestamp=t + pd.Timedelta(minutes=5))
    assert assign_labels(late, cic)["label_status"].iloc[0] == "unmatched"


def test_log_transform_pickles_by_importable_module_name():
    # Regression: defined in preprocess.py and saved via `python -m preprocessing.preprocess`,
    # the function was pickled as __main__.signed_log1p and could not be loaded elsewhere.
    from preprocessing.preprocess import build_preprocessor

    ct = build_preprocessor(["a"], [], {"log_transform": True})
    fn = ct.transformers[0][1].named_steps["log"].func
    assert fn.__module__ == "preprocessing.transforms"


def test_save_refuses_class_defined_in_main(tmp_path: Path):
    # Regression: running `python -m preprocessing.preprocess` pickled the class as
    # __main__.FittedPreprocessor, loadable only by scripts that happened to import it.
    class Fake(FittedPreprocessor):
        pass

    Fake.__module__ = "__main__"
    with pytest.raises(RuntimeError):
        Fake(None, [], [], [], [], {}).save(tmp_path / "p.joblib")
