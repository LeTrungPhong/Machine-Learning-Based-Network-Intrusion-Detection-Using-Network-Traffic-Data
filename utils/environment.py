"""Runtime environment report (Python, packages, capture backend, resources)."""

from __future__ import annotations

import importlib.metadata as metadata
import os
import platform
import sys
from pathlib import Path
from typing import Any

from utils.storage import free_gb, memory_status

CORE_PACKAGES: tuple[str, ...] = (
    "numpy", "pandas", "pyarrow", "scipy", "scikit-learn", "imbalanced-learn",
    "xgboost", "torch", "matplotlib", "seaborn", "networkx", "scapy",
    "joblib", "PyYAML", "psutil", "tqdm", "pytest",
)


def package_versions(packages: tuple[str, ...] = CORE_PACKAGES) -> dict[str, str | None]:
    """Return installed versions; ``None`` marks a missing package."""
    versions: dict[str, str | None] = {}
    for name in packages:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = None
    return versions


def capture_backend() -> dict[str, Any]:
    """Describe whether live packet capture is likely to work on this OS.

    Windows needs Npcap; Linux needs root or CAP_NET_RAW (checked only as
    ``euid == 0`` here; capabilities are verified when capture starts).
    """
    system = platform.system()
    if system == "Windows":
        npcap = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap"
        return {"os": system, "backend": "Npcap", "available": npcap.is_dir()}
    if system == "Linux":
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        return {"os": system, "backend": "raw socket / libpcap", "available": is_root,
                "note": None if is_root else "run as root or grant CAP_NET_RAW for live capture"}
    return {"os": system, "backend": "unknown", "available": False}


def environment_report(project_root: Path) -> dict[str, Any]:
    """Collect a full environment summary for ``main.py --mode check``."""
    return {
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "platform": platform.platform(),
        "in_venv": sys.prefix != sys.base_prefix,
        "cpu_count": os.cpu_count(),
        "memory": memory_status(),
        "free_gb_project_drive": free_gb(project_root),
        "packages": package_versions(),
        "capture": capture_backend(),
    }
