# -*- coding: utf-8 -*-
r"""CHẠY TRÊN KAGGLE (dán toàn bộ file vào MỘT cell) – huấn luyện lại mô hình CIC-IDS2017 với lưu lượng BENIGN
thu thập trên máy của bạn (trang "Giám sát trực tiếp" → chế độ "Thu thập lưu lượng bình thường").

Mục tiêu: giảm báo nhầm trên mạng của bạn mà không làm mô hình quên các loại tấn công.

Chuẩn bị Input cho notebook Kaggle:
  1. CIC-IDS2017 MachineLearningCVE (giống lúc huấn luyện).
  2. Một Kaggle Dataset bạn tự tạo (vd tên "nids-benign"), gồm:
       - các file nids_demo/data/benign_capture/live_*.csv
       - thư mục nids_demo/core/ (để dùng đúng bộ ánh xạ tên cột của app)
  3. Một Kaggle Dataset chứa thư mục nids_results/models/ (preprocessor, label encoder, 4 mô hình).

Cách làm (KHÔNG fit lại preprocessor – giữ nguyên bộ chuẩn hóa để app dùng được ngay):
  - Tái tạo đúng tập train/val/test của notebook (cùng SEED, cùng làm sạch/lấy mẫu).
  - Chia lưu lượng BENIGN của bạn theo FILE: 80% để huấn luyện, 20% để đo tỉ lệ báo nhầm (không dùng khi train).
  - Random Forest: huấn luyện lại với cùng siêu tham số trên train + BENIGN (nhân BENIGN_WEIGHT lần).
  - CNN-BiLSTM: fine-tune từ trọng số cũ vài epoch, learning rate nhỏ, trên BENIGN + một phần train (replay)
    để không quên các lớp tấn công.
  - So sánh TRƯỚC / SAU trên tập test CIC-IDS2017 (Accuracy, F1-macro, DR, FAR) và trên BENIGN giữ lại (tỉ lệ báo nhầm).
Kết quả lưu ở /kaggle/working/finetuned/ với CÙNG tên file. Tải về, đặt vào nids_demo/artifacts_finetuned/ và chạy app:
    $env:NIDS_ARTIFACT_DIR = "artifacts_finetuned"; .\.venv\Scripts\streamlit.exe run app.py
Bộ artifacts gốc không bị sửa.
"""
import glob
import os
import re
import shutil
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split

SEED = 42
CIC_SAMPLE_FRAC, CIC_MIN_PER_CLASS = 0.5, 5000
BENIGN_WEIGHT = 3          # mỗi luồng BENIGN của bạn được lặp lại bao nhiêu lần khi train
BENIGN_HOLDOUT = 0.2       # tỉ lệ FILE benign giữ lại để đo báo nhầm
DL_EPOCHS, DL_LR, DL_BATCH = 3, 1e-4, 1024
DL_REPLAY = 300_000        # số dòng train gốc trộn vào khi fine-tune CNN-BiLSTM
OUT_DIR = '/kaggle/working/finetuned'
DROP_COLS = ['Flow ID', 'Source IP', 'Src IP', 'Destination IP', 'Dst IP', 'Timestamp',
             'Source Port', 'Src Port', 'Label_orig']
LABEL_COLS = ['y_bin', 'y_multi']
np.random.seed(SEED)


def find_files(pred):
    out = []
    for dp, _, fs in os.walk('/kaggle/input'):
        out += [os.path.join(dp, f) for f in fs if pred(dp, f)]
    return sorted(out)


# ---------------------------------------------------------------- 1. tìm input
cic_files = find_files(lambda dp, f: 'machinelearningcve' in dp.lower() and f.lower().endswith('.csv'))
assert len(cic_files) == 8, f'Cần 8 file MachineLearningCVE, tìm thấy {len(cic_files)}'
schema_py = find_files(lambda dp, f: f == 'schema.py' and dp.replace('\\', '/').endswith('/core'))
assert schema_py, 'Không thấy core/schema.py – thêm thư mục nids_demo/core vào dataset benign.'
sys.path.insert(0, os.path.dirname(os.path.dirname(schema_py[0])))
benign_files = find_files(lambda dp, f: f.lower().endswith('.csv') and 'machinelearningcve' not in dp.lower()
                          and (f.startswith('live_') or 'benign' in dp.lower()))
assert benign_files, 'Không thấy CSV benign (live_*.csv).'
prep_path = find_files(lambda dp, f: f == 'preprocessor_cic_ids2017.joblib')
assert prep_path, 'Không thấy preprocessor_cic_ids2017.joblib – thêm dataset chứa nids_results/models.'
MODEL_DIR = os.path.dirname(prep_path[0])
print('CIC:', len(cic_files), 'file | benign:', len(benign_files), 'file | models:', MODEL_DIR)

from core.preprocess import NIDSPreprocessor, register_pickle_class   # noqa: E402
from core.schema import align_features                                # noqa: E402
sys.modules['__main__'].NIDSPreprocessor = NIDSPreprocessor
register_pickle_class()
prep = joblib.load(prep_path[0])
le = joblib.load(os.path.join(MODEL_DIR, 'label_encoder_cic_ids2017.joblib'))
FEATS = list(prep.num_cols_) + list(prep.cat_cols_)


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


# ---------------------------------------------------------------- 2. tái tạo train/val/test của notebook
df = load_cic(cic_files)
df = df.drop(columns=[c for c in DROP_COLS if c in df.columns])
feats = [c for c in df.columns if c not in LABEL_COLS]
for c in feats:
    if pd.api.types.is_float_dtype(df[c]):
        m = np.isinf(df[c].to_numpy())
        if m.any():
            df.loc[m, c] = np.nan
nan_rows = df[feats].isna().any(axis=1)
if nan_rows.mean() < 0.01:
    df = df.loc[~nan_rows]
df = df.drop_duplicates().reset_index(drop=True)
full_s = stratified_cap_sample(df, 'y_multi', CIC_SAMPLE_FRAC, CIC_MIN_PER_CLASS)
del df
tr, tmp = train_test_split(full_s, test_size=0.30, stratify=full_s['y_multi'], random_state=SEED)
va, te = train_test_split(tmp, test_size=0.50, stratify=tmp['y_multi'], random_state=SEED)
del full_s, tmp
print('train/val/test:', len(tr), len(va), len(te))   # notebook: test 187.738 dòng

X_tr, X_va, X_te = prep.transform(tr), prep.transform(va), prep.transform(te)
y_tr = {'multi': le.transform(tr['y_multi']), 'binary': tr['y_bin'].to_numpy()}
y_va = {'multi': le.transform(va['y_multi']), 'binary': va['y_bin'].to_numpy()}
y_te = {'multi': le.transform(te['y_multi']), 'binary': te['y_bin'].to_numpy()}
BENIGN_IDX = int(np.where(le.classes_ == 'Benign')[0][0])

# ---------------------------------------------------------------- 3. lưu lượng BENIGN của bạn
rng = np.random.default_rng(SEED)
files = np.array(benign_files)
rng.shuffle(files)
n_hold = max(1, int(round(len(files) * BENIGN_HOLDOUT))) if len(files) > 1 else 0
hold_files, train_files = files[:n_hold], files[n_hold:]


def load_benign(paths):
    if len(paths) == 0:
        return np.zeros((0, len(prep.feature_names_)), np.float32)
    frames = []
    for p in paths:
        raw = pd.read_csv(p, low_memory=False)
        X, _, rep = align_features(raw, FEATS)
        if rep.missing:
            print(f'  ! {os.path.basename(p)} thiếu {len(rep.missing)} cột: {rep.missing[:5]}')
        frames.append(X)
    return prep.transform(pd.concat(frames, ignore_index=True))


Xb_tr, Xb_ho = load_benign(train_files), load_benign(hold_files)
print(f'BENIGN train: {len(Xb_tr):,} luồng ({len(train_files)} file) | giữ lại: {len(Xb_ho):,} luồng ({len(hold_files)} file)')
if len(Xb_ho) == 0:
    print('! Chỉ có 1 file benign -> không có dữ liệu giữ lại để đo báo nhầm khách quan.')


def benign_target(task, n):
    return np.full(n, BENIGN_IDX if task == 'multi' else 0)


# ---------------------------------------------------------------- 4. đánh giá
def proba_dl(model, X):
    p = model.predict(X[..., None], batch_size=4096, verbose=0)
    return np.column_stack([1 - p.ravel(), p.ravel()]) if p.ndim == 1 or p.shape[1] == 1 else p


def scores(pred_fn, task):
    yp = pred_fn(X_te).argmax(1)
    yt = y_te[task]
    normal = BENIGN_IDX if task == 'multi' else 0
    t_att, p_att = yt != normal, yp != normal
    out = {'Accuracy': accuracy_score(yt, yp), 'F1-macro': f1_score(yt, yp, average='macro'),
           'DR': (t_att & p_att).sum() / max(t_att.sum(), 1), 'FAR (test CIC)': (~t_att & p_att).sum() / max((~t_att).sum(), 1)}
    if len(Xb_ho):
        out['Báo nhầm trên BENIGN của bạn'] = float((pred_fn(Xb_ho).argmax(1) != normal).mean())
    return {k: round(float(v), 4) for k, v in out.items()}


import keras  # noqa: E402

os.makedirs(OUT_DIR, exist_ok=True)
shutil.copy2(prep_path[0], OUT_DIR)
shutil.copy2(os.path.join(MODEL_DIR, 'label_encoder_cic_ids2017.joblib'), OUT_DIR)
report = []
for task in ('multi', 'binary'):
    # ----- Random Forest: huấn luyện lại cùng siêu tham số
    rf_old = joblib.load(os.path.join(MODEL_DIR, f'rf_cic_ids2017_{task}.joblib'))
    report.append({'Mô hình': 'Random Forest', 'Bài toán': task, 'Giai đoạn': 'trước', **scores(rf_old.predict_proba, task)})
    params = rf_old.get_params()
    params.update(n_jobs=-1, random_state=SEED)
    del rf_old
    Xb_rep = np.repeat(Xb_tr, BENIGN_WEIGHT, axis=0)
    rf_new = RandomForestClassifier(**params).fit(np.vstack([X_tr, Xb_rep]),
                                                  np.concatenate([y_tr[task], benign_target(task, len(Xb_rep))]))
    report.append({'Mô hình': 'Random Forest', 'Bài toán': task, 'Giai đoạn': 'sau', **scores(rf_new.predict_proba, task)})
    joblib.dump(rf_new, os.path.join(OUT_DIR, f'rf_cic_ids2017_{task}.joblib'), compress=3)
    del rf_new

    # ----- CNN-BiLSTM: fine-tune từ trọng số cũ
    dl = keras.models.load_model(os.path.join(MODEL_DIR, f'dl_cic_ids2017_{task}.keras'), compile=False)
    report.append({'Mô hình': 'CNN-BiLSTM', 'Bài toán': task, 'Giai đoạn': 'trước', **scores(lambda X: proba_dl(dl, X), task)})
    binary_head = dl.output_shape[-1] == 1
    dl.compile(optimizer=keras.optimizers.Adam(DL_LR),
               loss='binary_crossentropy' if binary_head else 'sparse_categorical_crossentropy')
    idx = rng.choice(len(X_tr), size=min(DL_REPLAY, len(X_tr)), replace=False)
    Xf = np.vstack([X_tr[idx], Xb_rep])
    yf = np.concatenate([y_tr[task][idx], benign_target(task, len(Xb_rep))])
    perm = rng.permutation(len(Xf))
    dl.fit(Xf[perm][..., None], yf[perm], epochs=DL_EPOCHS, batch_size=DL_BATCH,
           validation_data=(X_va[..., None], y_va[task]), verbose=2)
    report.append({'Mô hình': 'CNN-BiLSTM', 'Bài toán': task, 'Giai đoạn': 'sau', **scores(lambda X: proba_dl(dl, X), task)})
    dl.save(os.path.join(OUT_DIR, f'dl_cic_ids2017_{task}.keras'))

rep = pd.DataFrame(report)
rep.to_csv(os.path.join(OUT_DIR, 'finetune_report.csv'), index=False)
print(rep.to_string(index=False))
print('\nĐã lưu:', sorted(os.listdir(OUT_DIR)))
print('Chỉ dùng bản mới nếu "Báo nhầm trên BENIGN" giảm mà DR / F1-macro trên test CIC không giảm đáng kể.')
