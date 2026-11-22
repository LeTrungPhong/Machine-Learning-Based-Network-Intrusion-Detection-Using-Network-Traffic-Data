# -*- coding: utf-8 -*-
"""CHẠY TRÊN KAGGLE (dán vào một cell, cùng input CIC-IDS2017 MachineLearningCVE như lúc huấn luyện).

Tái tạo CHÍNH XÁC tập test CIC-IDS2017 của notebook (cùng hàm làm sạch, cùng SEED = 42, cùng thứ tự
lấy mẫu/chia tập) rồi xuất:
  - sample_test.csv : 20.000 dòng lấy ngẫu nhiên từ tập test (Sample_Part = 'uniform')
                      + toàn bộ dòng test của các lớp hiếm (< 1.000 dòng, Sample_Part = 'rare').
                      Cột đặc trưng giữ nguyên tên CIC-IDS2017, cột 'Label' là nhãn gốc (vd 'DoS Hulk').
  - versions.json   : phiên bản thư viện trên Kaggle.
Tải hai file này về, đặt vào nids_demo/data/ (sample_test.csv) và nids_demo/artifacts/ (versions.json).

Vì chỉ dùng dòng của TẬP TEST (mô hình chưa từng thấy), accuracy trên phần 'uniform' phải xấp xỉ
kết quả Kaggle (RF đa lớp ~0,9988) – đây là phép kiểm tra pipeline của app.
"""
import json
import os
import re
import platform

import numpy as np
import pandas as pd
import sklearn
from sklearn.model_selection import train_test_split

SEED = 42
CIC_SAMPLE_FRAC, CIC_MIN_PER_CLASS = 0.5, 5000
N_UNIFORM, RARE_MAX = 20_000, 1_000
DROP_COLS = ['Flow ID', 'Source IP', 'Src IP', 'Destination IP', 'Dst IP', 'Timestamp',
             'Source Port', 'Src Port', 'Label_orig']
LABEL_COLS = ['y_bin', 'y_multi']

# ---- tìm thư mục MachineLearningCVE
files = []
for dp, _, fs in os.walk('/kaggle/input'):
    if 'machinelearningcve' in dp.lower():
        files += [os.path.join(dp, f) for f in fs if f.lower().endswith('.csv')]
files = sorted(files)
assert len(files) == 8, f'Cần 8 file MachineLearningCVE, tìm thấy {len(files)}'


# ---- các hàm sao chép từ notebook huấn luyện
def reduce_memory(df):
    i32 = np.iinfo(np.int32)
    for c in df.columns:
        dt = df[c].dtype
        if dt == np.float64:
            df[c] = df[c].astype(np.float32)
        elif dt == np.int64:
            cmin, cmax = df[c].min(), df[c].max()
            ok = (cmin >= i32.min) and (cmax <= i32.max)
            df[c] = df[c].astype(np.int32 if ok else np.float32)
    return df


def read_table(path):
    df = pd.read_csv(path, low_memory=False, encoding='latin1')
    df.columns = [str(c).strip() for c in df.columns]
    idx_cols = [c for c in df.columns if c.lower().startswith('unnamed')]
    return df.drop(columns=idx_cols) if idx_cols else df


def normalize_cic_label(s):
    s = str(s).strip()
    if s.lower().startswith('web attack'):
        rest = re.sub(r'^web attack[^a-z]*', '', s, flags=re.I)
        return 'Web Attack - ' + rest.strip()
    return s


def group_cic_label(lbl):
    l = str(lbl).lower()
    if l == 'benign': return 'Benign'
    if 'ddos' in l: return 'DDoS'
    if l.startswith('dos'): return 'DoS'
    if 'portscan' in l or 'port scan' in l: return 'PortScan'
    if 'web attack' in l or 'xss' in l or 'sql' in l: return 'Web Attack'
    if 'patator' in l or 'brute' in l: return 'Brute Force'
    if l.startswith('bot'): return 'Bot'
    if 'infiltration' in l: return 'Infiltration'
    if 'heartbleed' in l: return 'Heartbleed'
    return 'Other'


def load_cic(files):
    df = pd.concat([reduce_memory(read_table(p)) for p in files], ignore_index=True)
    lab_col = [c for c in df.columns if c.lower() == 'label'][0]
    keep_text = set(DROP_COLS) | {lab_col}
    for c in df.columns:
        if c not in keep_text and not pd.api.types.is_numeric_dtype(df[c]):
            df[c] = pd.to_numeric(df[c], errors='coerce')
    df = reduce_memory(df)
    lab_str = df[lab_col].astype(str).str.strip()
    valid = df[lab_col].notna() & ~lab_str.str.lower().isin(['', 'nan', 'none'])
    if (~valid).any():
        df = df.loc[valid].reset_index(drop=True)
        lab_str = lab_str.loc[valid].reset_index(drop=True)
    norm_map = {u: normalize_cic_label(u) for u in lab_str.unique()}
    df['Label_orig'] = lab_str.map(norm_map).values
    group_map = {v: group_cic_label(v) for v in set(norm_map.values())}
    df['y_multi'] = df['Label_orig'].map(group_map).values
    df['y_bin'] = (df['y_multi'] != 'Benign').astype(np.int8).values
    df.drop(columns=[lab_col], inplace=True)
    return df


def stratified_cap_sample(df, label_col, frac, min_keep, seed=SEED):
    parts = []
    for _, g in df.groupby(label_col, sort=False):
        k = max(int(round(len(g) * frac)), min(len(g), min_keep))
        parts.append(g.sample(n=k, random_state=seed) if k < len(g) else g)
    return pd.concat(parts).sample(frac=1.0, random_state=seed).reset_index(drop=True)


# ---- tái tạo clean_frame của notebook nhưng giữ lại nhãn gốc theo index
full = load_cic(files)
lab_orig = full['Label_orig']
df = full.drop(columns=[c for c in DROP_COLS if c in full.columns])
feats = [c for c in df.columns if c not in LABEL_COLS]
for c in feats:
    if pd.api.types.is_float_dtype(df[c]):
        m = np.isinf(df[c].to_numpy())
        if m.any():
            df.loc[m, c] = np.nan
nan_rows = df[feats].isna().any(axis=1)
if nan_rows.mean() < 0.01:
    df = df.loc[~nan_rows]
df = df.drop_duplicates()
df['Label'] = lab_orig.loc[df.index].values
df = df.reset_index(drop=True)
print('Sau làm sạch:', df.shape)            # notebook: 2.498.185 dòng

full_s = stratified_cap_sample(df, 'y_multi', CIC_SAMPLE_FRAC, CIC_MIN_PER_CLASS)
tr, tmp = train_test_split(full_s, test_size=0.30, stratify=full_s['y_multi'], random_state=SEED)
va, te = train_test_split(tmp, test_size=0.50, stratify=tmp['y_multi'], random_state=SEED)
print('Test:', te.shape)                     # notebook: 187.738 dòng
print(te['y_multi'].value_counts())

uni = te.sample(n=min(N_UNIFORM, len(te)), random_state=SEED).assign(Sample_Part='uniform')
vc = te['y_multi'].value_counts()
rare_cls = vc[vc < RARE_MAX].index
rare = te[te['y_multi'].isin(rare_cls) & ~te.index.isin(uni.index)].assign(Sample_Part='rare')
out = pd.concat([uni, rare]).drop(columns=LABEL_COLS)
out.to_csv('/kaggle/working/sample_test.csv', index=False)
print('sample_test.csv:', out.shape, '| lớp hiếm:', list(rare_cls))

import tensorflow as tf, keras
versions = {'python': platform.python_version(), 'numpy': np.__version__, 'pandas': pd.__version__,
            'scikit-learn': sklearn.__version__, 'tensorflow': tf.__version__, 'keras': keras.__version__}
json.dump(versions, open('/kaggle/working/versions.json', 'w'), indent=1)
print(versions)
