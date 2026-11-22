# -*- coding: utf-8 -*-
"""Tiền xử lý GIỐNG HỆT notebook huấn luyện (kaggle_trainning.ipynb).

Lớp NIDSPreprocessor bên dưới được sao chép nguyên văn từ cell 4.3 của notebook, vì file
preprocessor_cic_ids2017.joblib được pickle từ lớp `__main__.NIDSPreprocessor`. Để load được,
ta đăng ký lớp này vào module `__main__` (register_pickle_class) trước khi gọi joblib.load.

Chỉ dùng transform() – tuyệt đối không fit lại.
"""
import sys

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

SEED = 42   # biến toàn cục mà fit() trong notebook tham chiếu


class NIDSPreprocessor:
    '''Pipeline tiền xử lý tái sử dụng: chọn cột -> inf/NaN -> signed-log -> One-Hot (gom hiếm) -> StandardScaler.
    Mọi thống kê (cột hằng, cột tương quan, median, category, scaler) CHỈ học trên tập train.'''

    def __init__(self, cat_cols=(), corr_threshold=0.95, min_cat_freq=0.005, max_cats=20,
                 use_log=True, label_cols=('y_bin', 'y_multi')):
        self.cat_cols = list(cat_cols)
        self.corr_threshold = corr_threshold
        self.min_cat_freq = min_cat_freq
        self.max_cats = max_cats
        self.use_log = use_log
        self.label_cols = list(label_cols)

    def fit(self, df):
        X = df.drop(columns=[c for c in self.label_cols if c in df.columns])
        self.cat_cols_ = [c for c in self.cat_cols if c in X.columns]
        num = [c for c in X.columns if c not in self.cat_cols_ and pd.api.types.is_numeric_dtype(X[c])]
        self.ignored_cols_ = [c for c in X.columns if c not in self.cat_cols_ and c not in num]
        # 1) Cột hằng số
        nun = X[num].nunique(dropna=False)
        self.const_cols_ = nun[nun <= 1].index.tolist()
        num = [c for c in num if c not in self.const_cols_]
        # 2) Cột tương quan cao (tính trên mẫu <= 200k dòng của train)
        samp = X[num].sample(min(len(X), 200_000), random_state=SEED).astype('float64')
        corr = samp.replace([np.inf, -np.inf], np.nan).corr().abs().fillna(0).to_numpy()
        iu = np.triu_indices(len(num), k=1)
        mask = corr[iu] > self.corr_threshold
        names = np.array(num, dtype=object)
        self.corr_pairs_ = pd.DataFrame({'feat_a': names[iu[0]][mask], 'feat_b': names[iu[1]][mask],
                                         'abs_corr': corr[iu][mask]}).sort_values('abs_corr', ascending=False)
        drop = set()
        for i, j in zip(iu[0][mask], iu[1][mask]):
            if num[i] not in drop and num[j] not in drop:
                drop.add(num[j])
        self.corr_drop_ = [c for c in num if c in drop]
        self.num_cols_ = [c for c in num if c not in drop]
        # 3) Median để impute
        self.medians_ = X[self.num_cols_].astype('float64').replace([np.inf, -np.inf], np.nan).median().fillna(0)
        # 4) Category phổ biến
        self.cat_levels_ = {}
        for c in self.cat_cols_:
            vc = X[c].astype(str).value_counts(normalize=True)
            self.cat_levels_[c] = vc[vc >= self.min_cat_freq].index[:self.max_cats].tolist()
        # 5) Scaler
        Z, self.feature_names_ = self._build(X)
        self.scaler_ = StandardScaler().fit(Z)
        return self

    def _build(self, X):
        num = X.reindex(columns=self.num_cols_)          # cột thiếu -> NaN -> median
        if (num.dtypes == object).any():
            num = num.apply(pd.to_numeric, errors='coerce')
        arr = num.to_numpy(dtype=np.float32, copy=True)
        arr[~np.isfinite(arr)] = np.nan
        rows, cols = np.where(np.isnan(arr))
        if len(rows):
            arr[rows, cols] = self.medians_.to_numpy(dtype=np.float32)[cols]
        if self.use_log:
            arr = np.sign(arr) * np.log1p(np.abs(arr))
        parts, names = [arr.astype(np.float32)], list(self.num_cols_)
        for c in self.cat_cols_:
            keep = self.cat_levels_[c]
            levels = np.array(keep + ['other'], dtype=str)
            col = X[c].astype(str).to_numpy() if c in X.columns else np.full(len(X), 'other')
            col = np.where(np.isin(col, keep), col, 'other').astype(str)
            parts.append((col[:, None] == levels[None, :]).astype(np.float32))
            names += [f'{c}={l}' for l in levels]
        return np.hstack(parts).astype(np.float32), names

    def transform(self, df):
        Z, _ = self._build(df)
        return self.scaler_.transform(Z).astype(np.float32)


def register_pickle_class():
    """Đăng ký NIDSPreprocessor vào __main__ để joblib/pickle tìm thấy lớp khi load."""
    main = sys.modules.get('__main__')
    if main is not None and not hasattr(main, 'NIDSPreprocessor'):
        setattr(main, 'NIDSPreprocessor', NIDSPreprocessor)


def clean_raw(df, keep_text=()):
    """Làm sạch dữ liệu thô như bước load của notebook.

    - strip tên cột, bỏ cột 'Unnamed*' do to_csv sinh ra;
    - cột số bị đọc thành chuỗi (vd 'Infinity', 'NaN') -> ép về số (errors='coerce');
    - inf -> NaN (NaN sẽ được điền median trong NIDSPreprocessor, vì khi suy luận không thể xóa dòng).
    keep_text: các cột thông tin dạng chữ (IP, Timestamp, Label...) giữ nguyên.
    """
    df = df.copy()
    df.columns = [' '.join(str(c).split()) for c in df.columns]
    df = df.drop(columns=[c for c in df.columns if c.lower().startswith('unnamed')])
    keep = set(keep_text)
    for c in df.columns:
        if c in keep:
            continue
        if not pd.api.types.is_numeric_dtype(df[c]):
            df[c] = pd.to_numeric(df[c], errors='coerce')
        if pd.api.types.is_float_dtype(df[c]):
            df[c] = df[c].replace([np.inf, -np.inf], np.nan)
    return df


def transform_features(prep, X_df):
    """Áp dụng bộ tiền xử lý đã học (không fit lại). Trả về ma trận float32 (n, n_features)."""
    return prep.transform(X_df)


def reshape_for_dl(X):
    """Định dạng đầu vào cho CNN-BiLSTM: (n, n_features) -> (n, n_features, 1)."""
    return np.asarray(X, dtype=np.float32)[..., np.newaxis]
