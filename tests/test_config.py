"""Tests for configuration loading, path resolution and storage guards."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from utils.config import PROJECT_ROOT, REQUIRED_SECTIONS, ConfigError, get_path, load_config, resolve_path
from utils.storage import InsufficientStorageError, ensure_free_space, free_gb


def test_default_config_loads_with_all_sections() -> None:
    cfg = load_config()
    for section in REQUIRED_SECTIONS:
        assert section in cfg


def test_default_config_safe_realtime_defaults() -> None:
    cfg = load_config()
    assert cfg["realtime"]["block_ips"] is False
    assert cfg["flow"]["idle_timeout_s"] > 0
    assert cfg["host_features"]["step_s"] <= cfg["host_features"]["window_s"]


def test_missing_config_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_missing_section_raises(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"project": {}}), encoding="utf-8")
    with pytest.raises(ConfigError, match="Missing config sections"):
        load_config(p)


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("a: [1, 2", encoding="utf-8")
    with pytest.raises(ConfigError, match="Invalid YAML"):
        load_config(p)


def test_relative_paths_anchor_at_project_root() -> None:
    assert resolve_path("outputs") == (PROJECT_ROOT / "outputs").resolve()


def test_absolute_paths_unchanged(tmp_path: Path) -> None:
    assert resolve_path(tmp_path) == tmp_path


def test_get_path_unknown_key_raises() -> None:
    with pytest.raises(ConfigError):
        get_path(load_config(), "does_not_exist")


def test_ensure_free_space_refuses_when_reserve_would_be_violated(tmp_path: Path) -> None:
    cfg = {"storage": {"min_free_gb": 1.0, "warn_free_gb": 2.0}}
    too_much = free_gb(tmp_path) + 10.0
    with pytest.raises(InsufficientStorageError):
        ensure_free_space(tmp_path, cfg, required_gb=too_much)


def test_ensure_free_space_accepts_small_write(tmp_path: Path) -> None:
    cfg = {"storage": {"min_free_gb": 0.0, "warn_free_gb": 0.0}}
    assert ensure_free_space(tmp_path, cfg, required_gb=0.0) > 0


def test_free_gb_works_for_nonexistent_subpath(tmp_path: Path) -> None:
    assert free_gb(tmp_path / "a" / "b") > 0
