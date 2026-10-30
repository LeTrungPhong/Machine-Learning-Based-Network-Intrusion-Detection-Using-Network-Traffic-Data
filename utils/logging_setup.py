"""Logging configuration shared by all entry points."""

from __future__ import annotations

import logging
import logging.handlers
from typing import Any

from utils.config import get_path

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"


def setup_logging(cfg: dict[str, Any], console: bool = True) -> logging.Logger:
    """Configure the root logger with a rotating file handler and console output.

    Calling this more than once replaces previously installed handlers, so
    tests and notebooks can re-initialise logging safely.

    Args:
        cfg: Loaded configuration (uses the ``logging`` and ``paths`` sections).
        console: Also log to stderr.

    Returns:
        The project logger (``"nids"``).
    """
    log_cfg = cfg["logging"]
    level = getattr(logging, str(log_cfg.get("level", "INFO")).upper(), logging.INFO)
    log_file = get_path(cfg, "logs_dir", create=True) / log_cfg.get("file", "nids.log")

    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
        h.close()
    root.setLevel(level)

    formatter = logging.Formatter(LOG_FORMAT)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=int(log_cfg.get("max_bytes", 10 * 1024 * 1024)),
        backupCount=int(log_cfg.get("backup_count", 5)),
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        root.addHandler(stream)

    # Scapy is noisy at INFO level (e.g. missing optional backends).
    logging.getLogger("scapy").setLevel(logging.ERROR)
    return logging.getLogger("nids")
