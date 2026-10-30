"""Tests for CIC-IDS-2017 CSV quirks."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from preprocessing.cic_csv import normalize_label, parse_cic_timestamp, read_cic_csv


def test_timestamp_morning_afternoon_and_seconds_format() -> None:
    s = pd.Series(["7/7/2017 8:59", "7/7/2017 12:59", "7/7/2017 1:00", "7/7/2017 5:02", "03/07/2017 08:55:58", "bad"])
    utc = parse_cic_timestamp(s)
    expect = ["2017-07-07 11:59", "2017-07-07 15:59", "2017-07-07 16:00", "2017-07-07 20:02", "2017-07-03 11:55:58"]
    assert list(utc[:5]) == [pd.Timestamp(e, tz="UTC") for e in expect]
    assert pd.isna(utc.iloc[5])


def test_labels_normalised() -> None:
    s = pd.Series([" BENIGN", "Web Attack \x96 XSS", "Web Attack � Brute Force", "Web Attack ï¿½ XSS"])
    assert normalize_label(s).tolist() == ["BENIGN", "Web Attack - XSS", "Web Attack - Brute Force", "Web Attack - XSS"]
    assert normalize_label(s, {"Web Attack - XSS": "WebAttack"}).tolist()[1] == "WebAttack"


def test_read_cic_csv_strips_columns_and_drops_empty_rows(tmp_path: Path) -> None:
    p = tmp_path / "x.csv"
    p.write_bytes(b" Source IP, Timestamp, Label\n1.1.1.1,7/7/2017 1:00,Web Attack \x96 XSS\n,,\n")
    df = read_cic_csv(p, {"csv_encoding": "latin-1"}, usecols=["Source IP", "Label"])
    assert list(df.columns) == ["Source IP", "Label"] and len(df) == 1
    assert df["Label"].iloc[0] == "Web Attack - XSS"
