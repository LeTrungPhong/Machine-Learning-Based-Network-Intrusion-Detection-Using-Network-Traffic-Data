"""Helpers for the published CIC-IDS-2017 CSV files.

Quirks handled here (measured on the downloaded files):

* Column names carry leading spaces.
* Web Attack labels contain byte 0x96 (cp1252 en dash); files are read as latin-1.
* ``TrafficLabelling/Thursday-...-WebAttacks`` has 288,602 all-empty rows.
* ``Timestamp`` is local time (UTC-3) on a 12-hour clock *without* AM/PM:
  ``7/7/2017 1:00`` means 13:00. Capture ran ~08:40-17:10, so hours below
  ``afternoon_below_hour`` are shifted by 12 h. Monday uses
  ``dd/mm/YYYY HH:MM:SS``; the other days ``d/m/YYYY H:MM``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

LABEL_DASH = "\x96"


def normalize_label(s: pd.Series, aliases: dict[str, str] | None = None) -> pd.Series:
    """Strip labels, replace the cp1252 dash by '-', then apply ``aliases``."""
    out = s.astype("string")
    # 0x96 (cp1252 dash); U+FFFD; and U+FFFD's UTF-8 bytes decoded as latin-1 (MachineLearningCVE files)
    for bad in (LABEL_DASH, "�", "ï¿½"):
        out = out.str.replace(bad, "-", regex=False)
    out = out.str.strip()
    return out.replace(aliases) if aliases else out


def parse_cic_timestamp(s: pd.Series, tz: str = "America/Moncton", afternoon_below_hour: int = 8) -> pd.Series:
    """Parse CIC ``Timestamp`` strings to UTC, resolving the missing AM/PM.

    Args:
        s: Raw strings such as ``"7/7/2017 1:00"`` or ``"03/07/2017 08:55:58"``.
        tz: Time zone of the capture site.
        afternoon_below_hour: Hours ``1..afternoon_below_hour-1`` are PM.

    Returns:
        tz-aware UTC timestamps (NaT where unparsable).
    """
    parts = s.astype("string").str.strip().str.extract(r"^(\d{1,2})/(\d{1,2})/(\d{4}) (\d{1,2}):(\d{2})(?::(\d{2}))?$")
    day, month, year, hour, minute = (pd.to_numeric(parts[i]).astype("float64") for i in range(5))
    sec = pd.to_numeric(parts[5]).astype("float64").fillna(0.0)
    hour = hour.where(~((hour >= 1) & (hour < afternoon_below_hour)), hour + 12)
    local = pd.to_datetime(pd.DataFrame({"year": year, "month": month, "day": day,
                                         "hour": hour, "minute": minute, "second": sec}), errors="coerce")
    return local.dt.tz_localize(tz, ambiguous="NaT", nonexistent="NaT").dt.tz_convert("UTC")


def read_cic_csv(path: str | Path, cfg_ds: dict[str, Any], usecols: list[str] | None = None) -> pd.DataFrame:
    """Read one CIC CSV with stripped column names, empty rows dropped and labels normalised.

    Args:
        path: CSV file.
        cfg_ds: ``cfg["datasets"]["cicids2017"]``.
        usecols: Optional subset of (stripped) column names.
    """
    header = pd.read_csv(path, nrows=0, encoding=cfg_ds.get("csv_encoding", "latin-1")).columns
    stripped = {c: c.strip() for c in header}
    raw_cols = None if usecols is None else [c for c in header if stripped[c] in set(usecols)]
    df = pd.read_csv(path, encoding=cfg_ds.get("csv_encoding", "latin-1"), usecols=raw_cols, low_memory=False)
    df = df.rename(columns=stripped).dropna(how="all")
    label = cfg_ds.get("label_column", "Label")
    if label in df.columns:
        df[label] = normalize_label(df[label], cfg_ds.get("label_aliases") or None)
    return df
