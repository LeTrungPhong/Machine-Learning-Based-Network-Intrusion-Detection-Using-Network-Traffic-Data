"""Build and execute ``eda/data_analysis.ipynb``.

The notebook is generated from the cell list below so it can be rebuilt
reproducibly; ``--no-exec`` only writes it. Findings cells (``FINDINGS``)
were written after inspecting the executed outputs of the analysis cells.

Usage:
    python scripts/build_eda_notebook.py [--no-exec]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import nbformat
from nbclient import NotebookClient

ROOT = Path(__file__).resolve().parent.parent
NB_PATH = ROOT / "eda" / "data_analysis.ipynb"

md = nbformat.v4.new_markdown_cell
code = nbformat.v4.new_code_cell

FINDINGS: dict[str, str] = {}  # filled from findings file if present
_FINDINGS_FILE = ROOT / "eda" / "findings.md"
if _FINDINGS_FILE.is_file():
    key = None
    for line in _FINDINGS_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("@@ "):
            key = line[3:].strip()
            FINDINGS[key] = ""
        elif key:
            FINDINGS[key] += line + "\n"


def findings(key: str) -> list:
    text = FINDINGS.get(key, "").strip()
    return [md(f"**Findings.** {text}")] if text else []


CELLS = [
    md("# CIC-IDS-2017 - Exploratory Data Analysis\n\n"
       "Source: `GeneratedLabelledFlows/TrafficLabelling` CSVs (identical feature values to "
       "`MachineLearningCVE`, plus timestamps and flow identifiers). Raw-file statistics come from the "
       "cleaning report written by `preprocessing/data_cleaning.py`; distributions are computed on the cleaned "
       "table. Charts are saved to `outputs/eda/` with a CSV table next to each figure.\n\n"
       "Every number in the findings cells comes from the outputs printed directly above it."),
    code("import json, os, sys\n"
         "from pathlib import Path\n"
         "ROOT = Path.cwd().parent if Path.cwd().name == 'eda' else Path.cwd()\n"
         "os.chdir(ROOT); sys.path.insert(0, str(ROOT))\n"
         "import numpy as np, pandas as pd\n"
         "import pyarrow.parquet as pq\n"
         "from IPython.display import Image, display\n"
         "from utils.config import load_config, resolve_path\n"
         "from preprocessing.preprocess import feature_columns, split_rows, signed_log1p\n"
         "from eda import visualization as viz\n"
         "pd.set_option('display.width', 160); pd.set_option('display.max_columns', 20)\n"
         "cfg = load_config(); ds = cfg['datasets']['cicids2017']; SEED = cfg['project']['random_seed']\n"
         "OUT = resolve_path(cfg['paths']['eda_dir']); OUT.mkdir(parents=True, exist_ok=True)\n"
         "rep = json.loads(resolve_path(ds['cleaning_report']).read_text(encoding='utf-8'))\n"
         "CLEAN = resolve_path(ds['clean_output'])"),

    md("## 1. Dimensions and data types"),
    code("pf = pq.ParquetFile(CLEAN)\n"
         "schema = pf.schema_arrow\n"
         "print(f\"raw rows read: {rep['rows_read']:,} from {len(rep['per_file'])} files\")\n"
         "print(f\"cleaned rows: {pf.metadata.num_rows:,}, columns: {len(schema)}\")\n"
         "print(pd.Series([str(t) for t in schema.types], index=schema.names).value_counts().to_string())\n"
         "rows = pd.DataFrame({k: {'rows': v['rows']} for k, v in rep['per_file'].items()}).T\n"
         "print(rows.to_string())"),
    *findings("dims"),

    md("## 2. Missing, infinite, negative and duplicate values (raw files)"),
    code("q = pd.DataFrame({'NaN': pd.Series(rep['nan_by_feature']), '+-Inf': pd.Series(rep['inf_by_feature']),\n"
         "                  'negative': pd.Series(rep['negative_by_feature']),\n"
         "                  'negative -> NaN': pd.Series(rep['negative_set_nan_by_feature'])}).fillna(0).astype(int)\n"
         "print(q.sort_values('negative', ascending=False).to_string())\n"
         "print()\n"
         "print(f\"exact duplicate rows (features + label): {rep['exact_duplicates_dropped']:,} \"\n"
         "      f\"({rep['exact_duplicates_dropped'] / rep['rows_read']:.2%})\")\n"
         "print(f\"conflicting duplicates (same features, different labels): {rep['conflicting_duplicate_rows']:,}\")\n"
         "print('conflicting rows by label:', rep['conflicting_rows_by_label'])\n"
         "print('constant features dropped:', rep['constant_features_dropped'])\n"
         "viz.bar_counts(q['NaN'] + q['+-Inf'] + q['negative -> NaN'], 'Invalid values per feature (raw files)',\n"
         "               'rows set to NaN (log scale)', OUT / 'missing_values.png')\n"
         "display(Image(OUT / 'missing_values.png'))"),
    *findings("quality"),

    md("## 3. Label distribution and class imbalance"),
    code("lab = pd.DataFrame({'raw': pd.Series(rep['labels_before']), 'after cleaning': pd.Series(rep['labels_after'])}).fillna(0).astype(int)\n"
         "lab['removed %'] = (1 - lab['after cleaning'] / lab['raw']).mul(100).round(1)\n"
         "lab['share %'] = (lab['after cleaning'] / lab['after cleaning'].sum() * 100).round(4)\n"
         "print(lab.sort_values('after cleaning', ascending=False).to_string())\n"
         "after = lab['after cleaning']\n"
         "print(f\"\\nattack share: {1 - after['BENIGN'] / after.sum():.2%}; imbalance BENIGN : smallest class = {after.max() / after.min():,.0f} : 1\")\n"
         "viz.bar_counts(after, 'Flows per label after cleaning', 'flows (log scale)', OUT / 'class_distribution.png')\n"
         "display(Image(OUT / 'class_distribution.png'))"),
    *findings("labels"),

    md("## 4. Attack distribution by family and capture day"),
    code("meta = pd.read_parquet(CLEAN, columns=['day', 'label', 'label_group', 'label_binary', 'timestamp'])\n"
         "att = meta[meta.label_binary == 1]\n"
         "by_day = pd.crosstab(att.label, att.day)[['Tuesday', 'Wednesday', 'Thursday', 'Friday']]\n"
         "print(by_day.to_string())\n"
         "print()\n"
         "print(meta.groupby('day', sort=False).agg(flows=('label', 'size'), attack_share=('label_binary', 'mean')).round(4).to_string())\n"
         "viz.bar_counts(att.label_group.value_counts(), 'Attack flows per family', 'flows (log scale)', OUT / 'attack_distribution.png')\n"
         "display(Image(OUT / 'attack_distribution.png'))"),
    *findings("attacks"),

    md("## 5. Analysis sample\n\nDistribution plots use a label-capped sample: up to 30,000 flows per "
       "label (all flows of rarer labels), drawn with a fixed seed. Rates are therefore *per class*, not "
       "dataset-wide."),
    code("cols = [c for c in pq.ParquetFile(CLEAN).schema_arrow.names if c not in ('flow_id', 'src_ip', 'dst_ip', 'src_port')]\n"
         "df = pd.read_parquet(CLEAN, columns=cols)  # identifiers not needed for EDA (saves memory)\n"
         "FEATS = feature_columns(df)\n"
         "def capped_sample(d, cap, by='label'):\n"
         "    return pd.concat([g.sample(min(len(g), cap), random_state=SEED) for _, g in d.groupby(by)])\n"
         "sample = capped_sample(df, 30000)\n"
         "print(f'numeric features: {len(FEATS)}; sample rows: {len(sample):,}')\n"
         "print(sample.label.value_counts().to_string())"),

    md("## 6. Feature distributions: packet size and flow duration"),
    code("viz.hist_compare(sample, 'average_packet_size', OUT / 'packet_size_distribution.png',\n"
         "                 'Average packet size per flow', 'log10(bytes + 1)')\n"
         "viz.hist_compare(sample, 'flow_duration', OUT / 'flow_duration_distribution.png',\n"
         "                 'Flow duration', 'log10(microseconds + 1)')\n"
         "display(Image(OUT / 'packet_size_distribution.png')); display(Image(OUT / 'flow_duration_distribution.png'))\n"
         "for c in ['average_packet_size', 'flow_duration']:\n"
         "    print(c); print(sample.groupby('label')[c].median().sort_values().to_string()); print()\n"
         "print('share of flows with duration < 1 ms by class:')\n"
         "print((sample.flow_duration < 1000).groupby(sample.label).mean().round(3).sort_values().to_string())"),
    *findings("distributions"),

    md("## 7. Correlation matrix\n\nPearson correlation on `sign(x)*log1p(|x|)`-transformed features "
       "(the same transform the pipeline applies), computed on the label-capped sample."),
    code("Z = pd.DataFrame(signed_log1p(sample[FEATS].to_numpy('float64')), columns=FEATS)\n"
         "corr = Z.corr()\n"
         "viz.corr_heatmap(corr, OUT / 'correlation_heatmap.png', 'Feature correlation (signed log1p, label-capped sample)')\n"
         "display(Image(OUT / 'correlation_heatmap.png'))\n"
         "iu = np.triu_indices_from(corr, 1)\n"
         "pairs = pd.Series(corr.to_numpy()[iu], index=pd.MultiIndex.from_arrays([corr.index[iu[0]], corr.columns[iu[1]]]))\n"
         "for t in (0.9, 0.95, 0.99): print(f'pairs with |r| > {t}: {(pairs.abs() > t).sum()}')\n"
         "print(pairs.abs().sort_values(ascending=False).head(12).round(4).to_string())"),
    *findings("correlation"),

    md("## 8. Outliers\n\nShare of flows outside the 1.5 x IQR fences, computed separately for BENIGN and "
       "attack flows so that attack traffic is not counted as 'outlier' of benign traffic."),
    code("def iqr_share(x):\n"
         "    q1, q3 = x.quantile(0.25), x.quantile(0.75); r = q3 - q1\n"
         "    return ((x < q1 - 1.5 * r) | (x > q3 + 1.5 * r)).mean()\n"
         "out = pd.DataFrame({name: sample.loc[sample.label_binary == k, FEATS].apply(iqr_share) for k, name in [(0, 'BENIGN'), (1, 'Attack')]})\n"
         "print(out.sort_values('BENIGN', ascending=False).head(15).round(3).to_string())\n"
         "print(f\"\\nmedian outlier share across features: BENIGN {out.BENIGN.median():.3f}, Attack {out.Attack.median():.3f}\")\n"
         "viz.bar_counts(out['BENIGN'].sort_values(ascending=False).head(20), 'BENIGN flows outside 1.5 x IQR (top 20 features)',\n"
         "               'share of BENIGN sample', OUT / 'outliers_benign.png', log=False)\n"
         "display(Image(OUT / 'outliers_benign.png'))"),
    *findings("outliers"),

    md("## 9. BENIGN vs attack"),
    code("key = ['flow_duration', 'total_fwd_packets', 'total_length_of_fwd_packets', 'fwd_packet_length_max',\n"
         "       'flow_bytes_s', 'init_win_bytes_backward']\n"
         "viz.box_compare(sample, key, OUT / 'benign_vs_attack.png', 'BENIGN vs attack (label-capped sample, outliers hidden)')\n"
         "display(Image(OUT / 'benign_vs_attack.png'))\n"
         "print(sample.groupby('label')[key].median().round(1).to_string())\n"
         "print()\n"
         "print('destination ports, top 5 per attack family:')\n"
         "for g, x in df[df.label_binary == 1].groupby('label_group'): print(f'  {g:13s}', x.dst_port.value_counts().head(5).to_dict())"),
    *findings("comparison"),

    md("## 10. Feature importance (exploratory)\n\nRandom Forest impurity importance, fitted **only on the "
       "training split** of the `temporal_per_class` strategy (label-capped sample of it, median imputation "
       "from those rows). Correlated features share importance, so this ranks groups rather than single "
       "columns; model-based importance and ablations follow in STEP 10."),
    code("from sklearn.ensemble import RandomForestClassifier\n"
         "split = split_rows(df[['label', 'timestamp', 'day', 'row_in_file', 'source_file']], 'temporal_per_class', cfg['preprocessing'], SEED)\n"
         "tr = df[split.to_numpy() == 'train']\n"
         "tr = capped_sample(tr, 20000)\n"
         "X = tr[FEATS].fillna(tr[FEATS].median())\n"
         "rf = RandomForestClassifier(n_estimators=150, min_samples_leaf=2, n_jobs=-1, random_state=SEED, class_weight='balanced')\n"
         "rf.fit(X, tr.label)\n"
         "imp = pd.Series(rf.feature_importances_, index=FEATS).sort_values(ascending=False)\n"
         "print(f'train rows used: {len(tr):,}')\n"
         "print(imp.head(20).round(4).to_string())\n"
         "viz.bar_counts(imp.head(20), 'Random Forest feature importance (train split, top 20)', 'mean decrease in impurity',\n"
         "               OUT / 'feature_importance.png', log=False)\n"
         "display(Image(OUT / 'feature_importance.png'))"),
    *findings("importance"),

    md("## 11. Summary"),
    *findings("summary"),
]


def build() -> nbformat.NotebookNode:
    nb = nbformat.v4.new_notebook()
    nb.cells = CELLS
    nb.metadata["kernelspec"] = {"name": "nids", "display_name": "NIDS (.venv)", "language": "python"}
    return nb


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--no-exec", action="store_true")
    args = ap.parse_args(argv)
    nb = build()
    if not args.no_exec:
        NotebookClient(nb, timeout=1800, kernel_name="nids", resources={"metadata": {"path": str(ROOT / "eda")}}).execute()
    nbformat.write(nb, NB_PATH)
    print(f"wrote {NB_PATH} ({len(nb.cells)} cells, executed={not args.no_exec})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
