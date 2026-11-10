"""Dataset presence and integrity checks driven by ``config.yaml``.

The checks are read-only: they verify that each expected file exists, has
the recorded byte size and, for captures, starts with a pcap/pcapng magic
number. Nothing is downloaded or modified.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from utils.config import ConfigError, resolve_path

logger = logging.getLogger(__name__)

PCAP_MAGICS: dict[bytes, str] = {
    bytes.fromhex("d4c3b2a1"): "pcap (LE, us)",
    bytes.fromhex("a1b2c3d4"): "pcap (BE, us)",
    bytes.fromhex("4d3cb2a1"): "pcap (LE, ns)",
    bytes.fromhex("a1b23c4d"): "pcap (BE, ns)",
    bytes.fromhex("0a0d0d0a"): "pcapng",
}


@dataclass(frozen=True)
class FileCheck:
    """Result of checking one expected dataset file."""

    relpath: str
    status: str  # "ok" | "missing" | "size_mismatch" | "bad_format"
    expected_size: int
    actual_size: int | None = None
    detail: str = ""
    required: bool = True  # False for paths under datasets.<name>.optional_paths

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def capture_format(path: str | Path) -> str | None:
    """Return the capture format from the file's magic number, or ``None``."""
    with open(path, "rb") as fh:
        return PCAP_MAGICS.get(fh.read(4))


def dataset_root(cfg: dict[str, Any], name: str) -> Path:
    """Return the absolute root directory of dataset ``name``."""
    try:
        return resolve_path(cfg["datasets"][name]["root"])
    except KeyError as exc:
        raise ConfigError(f"datasets.{name}.root is not defined") from exc


def verify_dataset(cfg: dict[str, Any], name: str) -> list[FileCheck]:
    """Check every file listed in ``datasets.<name>.expected_files``.

    Args:
        cfg: Loaded configuration.
        name: Dataset key, e.g. ``"cicids2017"``.

    Returns:
        One :class:`FileCheck` per expected file, in configuration order.
    """
    root = dataset_root(cfg, name)
    expected: dict[str, int] = cfg["datasets"][name].get("expected_files") or {}
    optional = tuple(cfg["datasets"][name].get("optional_paths") or ())
    results: list[FileCheck] = []
    for rel, size in expected.items():
        path = root / rel
        req = not rel.startswith(optional) if optional else True
        if not path.is_file():
            results.append(FileCheck(rel, "missing", int(size), required=req))
            continue
        actual = path.stat().st_size
        if actual != int(size):
            results.append(FileCheck(rel, "size_mismatch", int(size), actual, required=req))
            continue
        if path.suffix.lower() in {".pcap", ".pcapng"}:
            fmt = capture_format(path)
            if fmt is None:
                results.append(FileCheck(rel, "bad_format", int(size), actual, "unknown magic", required=req))
                continue
            results.append(FileCheck(rel, "ok", int(size), actual, fmt, required=req))
            continue
        results.append(FileCheck(rel, "ok", int(size), actual, required=req))
    return results


def location_hint(cfg: dict[str, Any], name: str) -> str | None:
    """Suggest a likely misplaced dataset folder when the configured root is absent."""
    root = dataset_root(cfg, name)
    if root.is_dir():
        return None
    parent = root.parent
    for candidate in (parent.parent / "dataset" / root.name, parent.parent / root.name):
        if candidate.is_dir():
            return f"{root} not found, but {candidate} exists - move it or update datasets.{name}.root"
    return f"{root} not found - see README for download instructions"
