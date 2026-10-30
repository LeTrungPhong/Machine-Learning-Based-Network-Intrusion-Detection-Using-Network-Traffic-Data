"""Configuration loading and path resolution.

Every module obtains its settings through :func:`load_config` so that the
project behaves identically on Windows (development) and Kali Linux
(deployment). Relative paths in the YAML file are resolved against the
project root, never against the current working directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH: Path = PROJECT_ROOT / "configs" / "config.yaml"

REQUIRED_SECTIONS: tuple[str, ...] = (
    "project",
    "paths",
    "storage",
    "logging",
    "datasets",
    "pcap",
    "flow",
    "host_features",
    "preprocessing",
    "models",
    "realtime",
)


class ConfigError(ValueError):
    """Raised when the configuration file is missing or malformed."""


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load and validate the YAML configuration.

    Args:
        path: Path to a YAML file. Defaults to ``configs/config.yaml``.

    Returns:
        The parsed configuration as a nested dictionary.

    Raises:
        ConfigError: If the file does not exist, is not valid YAML, or lacks
            a required top-level section.
    """
    cfg_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    if not cfg_path.is_file():
        raise ConfigError(f"Configuration file not found: {cfg_path}")
    try:
        with cfg_path.open("r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {cfg_path}: {exc}") from exc
    if not isinstance(cfg, dict):
        raise ConfigError(f"Top level of {cfg_path} must be a mapping")
    missing = [s for s in REQUIRED_SECTIONS if s not in cfg]
    if missing:
        raise ConfigError(f"Missing config sections in {cfg_path}: {', '.join(missing)}")
    return cfg


def resolve_path(value: str | Path, root: Path = PROJECT_ROOT) -> Path:
    """Resolve a configured path; relative paths are anchored at ``root``."""
    p = Path(value).expanduser()
    return p if p.is_absolute() else (root / p).resolve()


def get_path(cfg: dict[str, Any], key: str, create: bool = False) -> Path:
    """Return an absolute path from the ``paths`` section.

    Args:
        cfg: Loaded configuration.
        key: Key inside ``cfg["paths"]`` (e.g. ``"processed_dir"``).
        create: Create the directory if it does not exist.

    Raises:
        ConfigError: If ``key`` is not defined.
    """
    try:
        value = cfg["paths"][key]
    except KeyError as exc:
        raise ConfigError(f"paths.{key} is not defined in the configuration") from exc
    path = resolve_path(value)
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path
