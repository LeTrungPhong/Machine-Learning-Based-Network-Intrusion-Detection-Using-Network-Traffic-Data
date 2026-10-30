"""Verify that configured dataset files exist and match their recorded sizes.

Usage:
    python scripts/verify_datasets.py [--dataset cicids2017] [--config configs/config.yaml]

Exit status is 0 when every expected file of the selected datasets is OK.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.config import load_config  # noqa: E402
from utils.datasets import dataset_root, location_hint, verify_dataset  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", action="append", help="Dataset key (repeatable); default: all")
    parser.add_argument("--config", default=None)
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    names = args.dataset or list(cfg["datasets"])
    failed = False
    for name in names:
        print(f"== {name}: {dataset_root(cfg, name)}")
        hint = location_hint(cfg, name)
        if hint:
            print(f"   ! {hint}")
        results = verify_dataset(cfg, name)
        if not results:
            print("   (no expected files configured)")
            continue
        for r in results:
            extra = f" [{r.detail}]" if r.detail else ""
            size = "-" if r.actual_size is None else f"{r.actual_size:,}"
            print(f"   {r.status:<13} {size:>16}  {r.relpath}{extra}")
        n_ok = sum(r.ok for r in results)
        print(f"   {n_ok}/{len(results)} OK")
        failed |= n_ok != len(results)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
