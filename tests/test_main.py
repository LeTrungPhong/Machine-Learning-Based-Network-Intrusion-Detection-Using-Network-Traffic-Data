"""Tests for the command-line entry point (main.py)."""

from __future__ import annotations

import pytest

import main


def test_offline_without_inputs_exits_with_status_2() -> None:
    assert main.main(["--mode", "offline"]) == 2


def test_realtime_simulate_and_train_succeed() -> None:
    assert main.main(["--mode", "train"]) == 0
    assert main.main(["--mode", "realtime", "--simulate"]) == 0
    assert main.main(["--mode", "offline", "--simulate"]) == 0


def test_invalid_mode_rejected() -> None:
    with pytest.raises(SystemExit):
        main.main(["--mode", "bogus"])


def test_bad_config_path_returns_1(tmp_path) -> None:
    assert main.main(["--mode", "check", "--config", str(tmp_path / "missing.yaml")]) == 1
