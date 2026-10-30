"""Static EDA charts (PNG) with a table-view CSV saved next to each figure.

Styling follows one palette for every figure: light chart surface, hairline
grid, single-series bars in slot-1 blue, BENIGN vs attack in blue / orange
(validated pair: CVD dE 24.7, normal-vision dE 33.6), and a blue-gray-red
diverging map for correlations.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
BLUE = "#2a78d6"
ORANGE = "#eb6834"
CLASS_COLORS = {0: BLUE, 1: ORANGE}
CLASS_NAMES = {0: "BENIGN", 1: "Attack"}
DIVERGING = LinearSegmentedColormap.from_list(
    "blue_gray_red", ["#104281", "#3987e5", "#f0efec", "#e66767", "#a61e1e"])


@contextmanager
def chart_style() -> Iterator[None]:
    """Matplotlib rc settings shared by all charts."""
    rc = {
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": AXIS, "axes.labelcolor": INK_2, "axes.titlecolor": INK,
        "axes.titlesize": 12, "axes.titleweight": "semibold", "axes.titlelocation": "left",
        "axes.labelsize": 10, "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "grid.linestyle": "-",
        "axes.axisbelow": True, "xtick.color": MUTED, "ytick.color": MUTED,
        "xtick.labelsize": 9, "ytick.labelsize": 9, "legend.frameon": False,
        "legend.fontsize": 9, "font.family": ["Segoe UI", "DejaVu Sans", "sans-serif"],
    }
    with plt.rc_context(rc):
        yield


def _save(fig: plt.Figure, path: Path, table: pd.DataFrame | pd.Series | None = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    if table is not None:
        table.to_csv(path.with_suffix(".csv"))
    return path


def bar_counts(counts: pd.Series, title: str, xlabel: str, path: Path, log: bool = True,
               annotate: bool = True) -> Path:
    """Horizontal bars, largest on top; one color (the categories are nominal)."""
    counts = counts.sort_values()
    with chart_style():
        fig, ax = plt.subplots(figsize=(8, 0.32 * len(counts) + 1.2))
        ax.barh(counts.index.astype(str), counts.to_numpy(), color=BLUE, height=0.62)
        ax.grid(axis="y", visible=False)
        if log:
            ax.set_xscale("log")
        ax.set_xlabel(xlabel)
        ax.set_title(title)
        if annotate:
            for i, v in enumerate(counts.to_numpy()):
                ax.annotate(f"{v:,.0f}" if float(v).is_integer() else f"{v:.3g}", (v, i), xytext=(4, 0),
                            textcoords="offset points", va="center", fontsize=8, color=INK_2)
        ax.margins(x=0.12)
    return _save(fig, path, counts.sort_values(ascending=False).rename("value"))


def hist_compare(df: pd.DataFrame, col: str, path: Path, title: str, xlabel: str,
                 by: str = "label_binary", log10: bool = True, bins: int = 60) -> Path:
    """Overlaid density step histograms for BENIGN vs attack (log10(x+1) axis by default)."""
    with chart_style():
        fig, ax = plt.subplots(figsize=(8, 3.6))
        vals = df[col].astype("float64")
        x = np.log10(vals.clip(lower=0) + 1) if log10 else vals
        edges = np.histogram_bin_edges(x.dropna(), bins=bins)
        rows = {}
        for k in sorted(df[by].unique()):
            xi = x[df[by] == k].dropna()
            h, _ = np.histogram(xi, bins=edges, density=True)
            ax.stairs(h, edges, color=CLASS_COLORS[k], linewidth=2, label=f"{CLASS_NAMES[k]} (n={len(xi):,})")
            rows[CLASS_NAMES[k]] = h
        ax.set_xlabel(xlabel)
        ax.set_ylabel("density")
        ax.set_title(title)
        ax.legend(loc="upper left")
    table = pd.DataFrame(rows, index=pd.Index(np.round(edges[:-1], 4), name="bin_left"))
    return _save(fig, path, table)


def corr_heatmap(corr: pd.DataFrame, path: Path, title: str) -> Path:
    """Correlation matrix on a diverging map centred on 0 (gray)."""
    n = len(corr)
    with chart_style():
        fig, ax = plt.subplots(figsize=(0.17 * n + 3, 0.17 * n + 2))
        im = ax.imshow(corr.to_numpy(), cmap=DIVERGING, vmin=-1, vmax=1, interpolation="nearest")
        ax.grid(False)
        ax.set_xticks(range(n), corr.columns, rotation=90, fontsize=6)
        ax.set_yticks(range(n), corr.index, fontsize=6)
        ax.set_title(title)
        cb = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.01)
        cb.outline.set_visible(False)
        cb.ax.tick_params(labelsize=8, colors=MUTED)
        cb.set_label("Pearson r", color=INK_2, fontsize=9)
    return _save(fig, path, corr.round(4))


def box_compare(df: pd.DataFrame, cols: Sequence[str], path: Path, title: str,
                by: str = "label_binary") -> Path:
    """Small multiples: one box plot pair (BENIGN vs attack) per feature, log10(x+1) scale."""
    cols = list(cols)
    ncol = 3
    nrow = int(np.ceil(len(cols) / ncol))
    stats = []
    with chart_style():
        fig, axes = plt.subplots(nrow, ncol, figsize=(10, 2.6 * nrow), squeeze=False)
        for ax, col in zip(axes.flat, cols):
            data, labels, colors = [], [], []
            for k in (0, 1):
                v = np.log10(df.loc[df[by] == k, col].astype("float64").clip(lower=0).dropna() + 1)
                data.append(v.to_numpy())
                labels.append(CLASS_NAMES[k])
                colors.append(CLASS_COLORS[k])
                raw = df.loc[df[by] == k, col]
                stats.append({"feature": col, "class": CLASS_NAMES[k], "median": raw.median(),
                              "q1": raw.quantile(0.25), "q3": raw.quantile(0.75), "n": int(raw.notna().sum())})
            bp = ax.boxplot(data, tick_labels=labels, widths=0.5, patch_artist=True, showfliers=False,
                            medianprops={"color": INK, "linewidth": 1.5}, whiskerprops={"color": AXIS},
                            capprops={"color": AXIS})
            for patch, c in zip(bp["boxes"], colors):
                patch.set_facecolor(c)
                patch.set_edgecolor(c)
                patch.set_alpha(0.85)
            ax.set_title(col, fontsize=10)
            ax.set_ylabel("log10(x+1)", fontsize=8)
            ax.grid(axis="x", visible=False)
        for ax in list(axes.flat)[len(cols):]:
            ax.set_visible(False)
        fig.suptitle(title, x=0.01, ha="left", fontsize=12, fontweight="semibold", color=INK)
        fig.tight_layout()
    return _save(fig, path, pd.DataFrame(stats).set_index(["feature", "class"]))
