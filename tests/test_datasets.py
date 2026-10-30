"""Tests for dataset verification using small synthetic files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from utils.datasets import capture_format, location_hint, verify_dataset

PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")


def _cfg(root: Path, expected: dict[str, int]) -> dict[str, Any]:
    return {"datasets": {"demo": {"root": str(root), "expected_files": expected}}}


def test_verify_reports_ok_missing_size_and_format(tmp_path: Path) -> None:
    root = tmp_path / "datasets" / "demo"
    (root / "pcaps").mkdir(parents=True)
    good = PCAPNG_MAGIC + b"\x00" * 12
    (root / "pcaps" / "good.pcap").write_bytes(good)
    (root / "pcaps" / "bad.pcap").write_bytes(b"\x00" * 16)
    (root / "a.csv").write_bytes(b"x,y\n1,2\n")

    results = {r.relpath: r for r in verify_dataset(_cfg(root, {
        "pcaps/good.pcap": len(good),
        "pcaps/bad.pcap": 16,
        "a.csv": 999,
        "missing.csv": 1,
    }), "demo")}

    assert results["pcaps/good.pcap"].ok and results["pcaps/good.pcap"].detail == "pcapng"
    assert results["pcaps/bad.pcap"].status == "bad_format"
    assert results["a.csv"].status == "size_mismatch" and results["a.csv"].actual_size == 8
    assert results["missing.csv"].status == "missing"


def test_capture_format_classic_pcap(tmp_path: Path) -> None:
    p = tmp_path / "x.pcap"
    p.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 20)
    assert capture_format(p) == "pcap (LE, us)"


def test_location_hint_detects_singular_dataset_folder(tmp_path: Path) -> None:
    (tmp_path / "dataset" / "demo").mkdir(parents=True)
    hint = location_hint(_cfg(tmp_path / "datasets" / "demo", {}), "demo")
    assert hint is not None and "dataset" in hint and "exists" in hint


def test_location_hint_none_when_root_exists(tmp_path: Path) -> None:
    root = tmp_path / "datasets" / "demo"
    root.mkdir(parents=True)
    assert location_hint(_cfg(root, {}), "demo") is None
