"""Command-line entry point for the Network Intrusion Detection System.

Examples:
    python main.py --mode check
    python main.py --mode train
    python main.py --mode evaluate
    python main.py --mode offline --pcap datasets/sample.pcap
    python main.py --mode realtime --simulate
    python main.py --mode realtime --interface eth0 --duration 60
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

import pandas as pd

from utils.config import PROJECT_ROOT, ConfigError, load_config
from utils.datasets import location_hint, verify_dataset
from utils.environment import environment_report
from utils.logging_setup import setup_logging

logger = logging.getLogger("nids")

MODES: tuple[str, ...] = ("check", "train", "evaluate", "offline", "realtime")


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(description="ML-based Network Intrusion Detection System")
    parser.add_argument("--mode", required=True, choices=list(MODES))
    parser.add_argument("--config", default=None, help="Path to config.yaml")
    parser.add_argument("--pcap", default=None, help="Capture file (.pcap/.pcapng) for --mode offline")
    parser.add_argument("--flows", default=None, help="Flow table (.parquet/.csv) for --mode offline")
    parser.add_argument("--interface", default=None, help="Network interface for --mode realtime (e.g. eth0)")
    parser.add_argument("--duration", type=float, default=30.0, help="Capture duration in seconds for --mode realtime")
    parser.add_argument("--simulate", action="store_true", help="Run multi-scenario attack simulation in realtime/offline mode")
    parser.add_argument("--block-ips", action="store_true", help="Enable active firewall blocking (iptables dry-run)")
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
            if not r.required and r.status == "missing":
                logger.warning("[%s] %s: missing (optional - only needed to re-run the steps that read it)",
                               name, r.relpath)
                continue
            logger.error("[%s] %s: %s (expected %d bytes, found %s)",
                         name, r.relpath, r.status, r.expected_size, r.actual_size)
            if name == "cicids2017":
                status = 1
    return status


def run_train(cfg: dict[str, Any]) -> int:
    """Train and persist the 3-stage NIDS pipeline and botnet graph models."""
    from graph.botnet_graph import generate_synthetic_botnet_flows, run_pipeline as run_graph_pipeline
    from models.pipeline import MultiStageNIDSPipeline, generate_multistage_benchmark_data

    clean_path = PROJECT_ROOT / cfg["datasets"]["cicids2017"]["clean_output"]
    if clean_path.is_file():
        logger.info("Loading cleaned dataset from %s", clean_path)
        df = pd.read_parquet(clean_path)
        if len(df) > 50_000:
            df = df.sample(n=50_000, random_state=42).reset_index(drop=True)
    else:
        logger.info("Cleaned dataset not found; generating synthetic training benchmark")
        df = generate_multistage_benchmark_data(n_flows=4000, include_unseen_attack=False, seed=42)

    pipe = MultiStageNIDSPipeline(seed=42).fit(df)
    saved_pipe = pipe.save()
    logger.info("Saved 3-stage NIDS pipeline to %s", saved_pipe)

    g_flows, gt_roles = generate_synthetic_botnet_flows(scenario="hybrid", seed=42)
    run_graph_pipeline(g_flows, gt_roles=gt_roles, cfg=cfg.get("models", {}).get("botnet_graph", {}), save_outputs=True)
    logger.info("Saved botnet graph model and topology report to outputs/botnet_graph/")
    return 0


def run_evaluate(cfg: dict[str, Any]) -> int:
    """Run full model comparison and ablation study."""
    from evaluation.evaluate_pipeline import evaluate_all_approaches

    res = evaluate_all_approaches(save_outputs=True)
    logger.info("Evaluation complete. Comparison rows=%d, Ablation rows=%d",
                len(res["comparison_df"]), len(res["ablation_df"]))
    return 0


def run_offline(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    """Run offline detection on a PCAP file, flow table, or simulation."""
    from preprocessing.read_pcap import iter_raw_frames
    from realtime.monitor import RealtimeNIDSMonitor

    monitor = RealtimeNIDSMonitor(block_ips=args.block_ips)
    if args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.is_file():
            logger.error("PCAP file not found: %s", pcap_path)
            return 1
        for frame in iter_raw_frames(pcap_path):
            monitor.ingest_raw_frame(frame.ts_ns, frame.data, link_type=frame.linktype)
        alerts, summary = monitor.flush_and_analyze()
        logger.info("Offline PCAP analysis complete: %d flows, %d alerts", summary["n_flows"], len(alerts))
        return 0

    if args.flows:
        flow_path = Path(args.flows)
        if not flow_path.is_file():
            logger.error("Flow file not found: %s", flow_path)
            return 1
        df = pd.read_parquet(flow_path) if flow_path.suffix == ".parquet" else pd.read_csv(flow_path)
        alerts, summary = monitor.flush_and_analyze(extra_flows=df)
        logger.info("Offline flow analysis complete: %d flows, %d alerts", summary["n_flows"], len(alerts))
        return 0

    if args.simulate:
        from realtime.attack_simulator import run_realtime_simulation
        run_realtime_simulation(block_ips=args.block_ips, save_report=True)
        return 0

    logger.error("Mode 'offline' requires --pcap <file>, --flows <file>, or --simulate")
    return 2


def run_realtime(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    """Run real-time packet sniffing or multi-scenario attack simulation."""
    if args.simulate:
        from realtime.attack_simulator import run_realtime_simulation
        rep = run_realtime_simulation(block_ips=args.block_ips, save_report=True)
        logger.info("Real-time simulation complete: %d alerts written to %s",
                    rep["total_alerts_logged"], rep["alert_log_file"])
        return 0

    iface = args.interface or cfg.get("realtime", {}).get("interface")
    if not iface:
        logger.error("Mode 'realtime' requires --interface <iface> or --simulate")
        return 2

    from realtime.monitor import RealtimeNIDSMonitor
    monitor = RealtimeNIDSMonitor(block_ips=args.block_ips or bool(cfg.get("realtime", {}).get("block_ips", False)))
    bpf = cfg.get("realtime", {}).get("bpf_filter", "ip")
    monitor.run_live_capture(interface=iface, bpf_filter=bpf, duration_s=args.duration)
    return 0


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
    if args.mode == "train":
        return run_train(cfg)
    if args.mode == "evaluate":
        return run_evaluate(cfg)
    if args.mode == "offline":
        return run_offline(args, cfg)
    if args.mode == "realtime":
        return run_realtime(args, cfg)

    return 2


if __name__ == "__main__":
    sys.exit(main())
