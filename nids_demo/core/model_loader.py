# -*- coding: utf-8 -*-
"""Nạp preprocessor, label encoder và các mô hình của một bộ dữ liệu (mỗi thứ chỉ nạp một lần).

Module này không phụ thuộc Streamlit; app.py bọc load_artifacts() bằng st.cache_resource (theo bộ dữ liệu).
"""
import os
import time
from dataclasses import dataclass, field

import joblib

import config
from core.preprocess import register_pickle_class

os.environ.setdefault('TF_CPP_MIN_LOG_LEVEL', '2')   # giảm log của TensorFlow


@dataclass
class Artifacts:
    prep: object
    classes_multi: list
    feature_columns: list                 # cột đầu vào mô hình cần (đúng thứ tự huấn luyện)
    feature_names: list                   # tên cột sau tiền xử lý (đầu vào thực của mô hình)
    dataset: str = config.DEFAULT_DATASET
    models: dict = field(default_factory=dict)      # (tên mô hình, task) -> model
    load_seconds: dict = field(default_factory=dict)
    errors: dict = field(default_factory=dict)      # tên file -> thông báo lỗi

    @property
    def cfg(self):
        return config.DATASETS[self.dataset]

    @property
    def normal_label(self):
        return self.cfg['normal']

    def normal(self, task):
        return 'Normal' if task == 'binary' else self.normal_label

    def has(self, model_name, task):
        return (model_name, task) in self.models

    def classes(self, task):
        return list(config.BINARY_CLASSES) if task == 'binary' else list(self.classes_multi)


def _load_keras(path):
    import keras   # nạp muộn: TensorFlow khởi động khá chậm
    return keras.models.load_model(path, compile=False)


def load_artifacts(dataset=config.DEFAULT_DATASET, model_names=None, tasks=('multi', 'binary')):
    """Nạp toàn bộ artifacts của `dataset`. Lỗi ở từng mô hình được ghi vào `errors` thay vì làm sập app."""
    register_pickle_class()
    paths = config.artifact_paths(dataset)
    if not paths['preprocessor'].exists():
        raise FileNotFoundError(f'Không thấy {paths["preprocessor"]}. Hãy copy artifacts {dataset} vào {config.ARTIFACT_DIR}.')
    prep = joblib.load(paths['preprocessor'])
    le = joblib.load(paths['label_encoder'])
    art = Artifacts(prep=prep, classes_multi=[str(c) for c in le.classes_],
                    feature_columns=list(prep.num_cols_) + list(prep.cat_cols_),
                    feature_names=list(prep.feature_names_), dataset=dataset)
    for name in (model_names or config.MODEL_NAMES):
        for task in tasks:
            path = paths['models'][name][task]
            t0 = time.perf_counter()
            try:
                model = _load_keras(path) if path.suffix == '.keras' else joblib.load(path)
                if hasattr(model, 'n_jobs'):
                    model.n_jobs = -1
                art.models[(name, task)] = model
                art.load_seconds[(name, task)] = time.perf_counter() - t0
            except Exception as e:   # thiếu file / lệch phiên bản thư viện
                art.errors[path.name] = f'{type(e).__name__}: {e}'
    return art
