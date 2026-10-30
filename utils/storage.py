"""Disk-space and memory guards for long-running jobs.

Extracting flows from multi-GB captures can fill a drive; these checks make
jobs fail early with a clear message instead of crashing half-way.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

import psutil

logger = logging.getLogger(__name__)

GB = 1024**3


class InsufficientStorageError(RuntimeError):
    """Raised when a write would leave less free space than configured."""


def free_gb(path: str | Path) -> float:
    """Return free space in GiB on the drive that holds ``path``.

    The nearest existing parent is used, so the path itself need not exist.
    """
    p = Path(path).resolve()
    while not p.exists() and p != p.parent:
        p = p.parent
    return shutil.disk_usage(p).free / GB


def ensure_free_space(
    path: str | Path,
    cfg: dict[str, Any],
    required_gb: float = 0.0,
) -> float:
    """Check that writing ``required_gb`` under ``path`` keeps the reserve.

    Args:
        path: Directory that will receive the output.
        cfg: Loaded configuration (uses ``storage.min_free_gb`` / ``warn_free_gb``).
        required_gb: Estimated size of the output in GiB.

    Returns:
        Free space in GiB before writing.

    Raises:
        InsufficientStorageError: If free space minus ``required_gb`` would drop
            below ``storage.min_free_gb``.
    """
    storage = cfg.get("storage", {})
    min_free = float(storage.get("min_free_gb", 2.0))
    warn_free = float(storage.get("warn_free_gb", 10.0))
    available = free_gb(path)
    remaining = available - required_gb
    if remaining < min_free:
        raise InsufficientStorageError(
            f"Not enough disk space for {path}: {available:.1f} GiB free, "
            f"{required_gb:.1f} GiB needed, reserve {min_free:.1f} GiB"
        )
    if remaining < warn_free:
        logger.warning(
            "Low disk space at %s: %.1f GiB free (%.1f GiB after this job)",
            path, available, remaining,
        )
    return available


def memory_status() -> dict[str, float]:
    """Return total and available physical memory in GiB."""
    vm = psutil.virtual_memory()
    return {"total_gb": vm.total / GB, "available_gb": vm.available / GB, "percent_used": vm.percent}
