"""Command-line entry point for the Network Intrusion Detection System.

Examples:
    python main.py --mode check
    python main.py --mode offline --pcap datasets/sample.pcap
    python main.py --mode realtime --interface eth0

Only ``check`` is implemented so far; the other modes are added in later
steps and exit with status 2 until then.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any

from utils.config import PROJECT_ROOT, ConfigError, load_config
from utils.datasets import location_hint, verify_dataset
from utils.environment import environment_report
from utils.logging_setup import setup_logging

logger = logging.getLogger("nids")

PLANNED_MODES: dict[str, str] = {
    "offline": "STEP 3-4 (PCAP processing) and STEP 11 (offline detection)",
    "realtime": "STEP 11 (real-time monitoring)",
    "train": "STEP 6-9 (model training)",
    "evaluate": "STEP 10 (model comparison)",
}


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(description="ML-based Network Intrusion Detection System")
    parser.add_argument("--mode", required=True, choices=["check", *PLANNED_MODES])
    parser.add_argument("--config", default=None, help="Path to config.yaml")
    parser.add_argument("--pcap", default=None, help="Capture file for --mode offline")
    parser.add_argument("--interface", default=None, help="Network interface for --mode realtime")
    return parser


def run_check(cfg: dict[str, Any]) -> int:
    """Report environment and dataset status. Returns 0 when everything required is present."""
    env = environment_report(PROJECT_ROOT)
    logger.info("Python %s (%s), venv=%s", env["python"], env["executable"], env["in_venv"])
    logger.info("Platform %s, CPUs=%s", env["platform"], env["cpu_count"])
    mem = env["memory"]
    logger.info("Memory %.1f GiB total, %.1f GiB available", mem["total_gb"], mem["available_gb"])
    logger.info("Free space on project drive: %.1f GiB", env["free_gb_project_drive"])
    logger.info("Capture backend: %s", env["capture"])

    status = 0
    missing_pkgs = [k for k, v in env["packages"].items() if v is None]
    for name, version in env["packages"].items():
        logger.info("  %-18s %s", name, version or "MISSING")
    if missing_pkgs:
        logger.error("Missing packages: %s (pip install -r requirements.txt)", ", ".join(missing_pkgs))
        status = 1

    for name in cfg["datasets"]:
        hint = location_hint(cfg, name)
        if hint:
            logger.warning("[%s] %s", name, hint)
        results = verify_dataset(cfg, name)
        if not results:
            logger.warning("[%s] no expected files configured", name)
            continue
        bad = [r for r in results if not r.ok]
        logger.info("[%s] %d/%d expected files OK", name, len(results) - len(bad), len(results))
        for r in bad:
            logger.error("[%s] %s: %s (expected %d bytes, found %s)",
                         name, r.relpath, r.status, r.expected_size, r.actual_size)
        if bad and name == "cicids2017":
            status = 1
    return status


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and dispatch to the selected mode."""
    args = build_parser().parse_args(argv)
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    setup_logging(cfg)

    if args.mode == "check":
        return run_check(cfg)

    logger.error("Mode '%s' is not implemented yet; planned in %s", args.mode, PLANNED_MODES[args.mode])
    return 2


if __name__ == "__main__":
    sys.exit(main())
