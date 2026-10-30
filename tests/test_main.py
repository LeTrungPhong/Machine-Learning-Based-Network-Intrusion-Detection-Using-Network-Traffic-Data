"""Tests for the command-line entry point."""

from __future__ import annotations

import pytest

import main


def test_unimplemented_modes_exit_with_status_2() -> None:
    for mode in main.PLANNED_MODES:
        assert main.main(["--mode", mode]) == 2


def test_invalid_mode_rejected() -> None:
    with pytest.raises(SystemExit):
        main.main(["--mode", "bogus"])


def test_bad_config_path_returns_1(tmp_path) -> None:
    assert main.main(["--mode", "check", "--config", str(tmp_path / "missing.yaml")]) == 1
