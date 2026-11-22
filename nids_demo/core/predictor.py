# -*- coding: utf-8 -*-
"""Dự đoán bằng Random Forest / CNN-BiLSTM và tính độ đo đánh giá."""
import time
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score

import config
from core.preprocess import reshape_for_dl, transform_features
from core.schema import align_features, true_labels


@dataclass
class Prediction:
    """Kết quả dự đoán của một mô hình."""
    model_name: str
    task: str
    labels: np.ndarray        # nhãn dự đoán (chuỗi)
    confidence: np.ndarray    # xác suất của nhãn dự đoán
    is_attack: np.ndarray     # True nếu dự đoán là tấn công
    proba: np.ndarray         # (n, n_classes)
    classes: list
    seconds: float            # thời gian suy luận (không gồm đọc file)
    normal: str = 'Normal'     # tên lớp bình thường của bài toán này
    normal_multi: str = config.NORMAL_LABEL   # lớp bình thường của bộ dữ liệu (Benign / Normal)

    @property
    def ms_per_1000(self):
        return self.seconds / max(len(self.labels), 1) * 1e6

    def frame(self, threshold=config.DEFAULT_ALERT_THRESHOLD):
        """Bảng kết quả: nhãn, độ tin cậy, Normal/Attack, cảnh báo (attack và confidence >= ngưỡng)."""
        return pd.DataFrame({
            'Dự đoán': self.labels,
            'Độ tin cậy': np.round(self.confidence, 4),
            'Normal/Attack': np.where(self.is_attack, 'Attack', 'Normal'),
            'Cảnh báo': self.is_attack & (self.confidence >= threshold),
        })


def to_proba(p):
    """Chuẩn hóa đầu ra Keras thành ma trận xác suất (n, n_classes) – giống notebook."""
    p = np.asarray(p, dtype=np.float64)
    if p.ndim == 1 or p.shape[1] == 1:
        p = p.reshape(-1)
        return np.column_stack([1.0 - p, p])
    return p / p.sum(axis=1, keepdims=True)


class Predictor:
    """Bao bọc artifacts; cung cấp prepare() và predict() theo batch."""

    def __init__(self, artifacts):
        self.art = artifacts

    def align(self, df_raw):
        """Ánh xạ cột theo bộ dữ liệu của mô hình. Trả về (X_df, info, report, y_true hoặc None)."""
        X_df, info, report = align_features(df_raw, self.art.feature_columns)
        return X_df, info, report, true_labels(info)

    def prepare(self, df_raw):
        """Ánh xạ cột + tiền xử lý. Trả về (X_model, info, report, y_true hoặc None)."""
        X_df, info, report, y_true = self.align(df_raw)
        X = transform_features(self.art.prep, X_df) if len(X_df) else np.zeros((0, len(self.art.feature_names)), np.float32)
        return X, info, report, y_true

    def predict_matrix(self, X, model_name, task='multi', batch_size=config.BATCH_SIZE):
        """Dự đoán trên ma trận đã tiền xử lý (n, n_features), chia batch để chạy được file lớn."""
        model = self.art.models[(model_name, task)]
        classes = self.art.classes(task)
        t0 = time.perf_counter()
        parts = []
        for s in range(0, len(X), batch_size):
            xb = X[s:s + batch_size]
            if model_name == 'CNN-BiLSTM':
                pb = to_proba(model.predict(reshape_for_dl(xb), batch_size=config.DL_PREDICT_BATCH, verbose=0))
            else:
                pb = model.predict_proba(xb)
            parts.append(pb)
        P = np.vstack(parts) if parts else np.zeros((0, len(classes)))
        seconds = time.perf_counter() - t0
        idx = P.argmax(axis=1) if len(P) else np.zeros(0, int)       # nhãn = argmax (giống notebook)
        labels = np.array(classes, dtype=object)[idx] if len(P) else np.array([], dtype=object)
        conf = P[np.arange(len(P)), idx] if len(P) else np.zeros(0)
        normal = self.art.normal(task)
        return Prediction(model_name, task, labels.astype(str), conf, labels != normal, P, classes, seconds, normal, self.art.normal_label)

    def predict(self, df_raw, model_name, task='multi'):
        """predict(df, model_name) -> (Prediction, info, report, y_true)."""
        X, info, report, y_true = self.prepare(df_raw)
        return self.predict_matrix(X, model_name, task), info, report, y_true


# ----------------------------------------------------------------------------- đánh giá
def binary_truth(y_true, task, normal_label=config.NORMAL_LABEL):
    """Quy nhãn thật về dạng của bài toán: đa lớp giữ nguyên, nhị phân -> Normal/Attack."""
    if task == 'binary':
        yt = np.asarray(y_true)
        if set(np.unique(yt)) <= {'Normal', 'Attack'}:     # nhãn đã ở dạng nhị phân
            return yt
        return np.where(yt == normal_label, 'Normal', 'Attack')
    return np.asarray(y_true)


def evaluate(y_true, pred, normal_label=None):
    """Accuracy, F1-macro, DR, FAR, confusion matrix, classification report."""
    yt = binary_truth(y_true, pred.task, normal_label or pred.normal_multi)
    yp = pred.labels
    normal = pred.normal
    labels = [c for c in list(pred.classes) if c in set(yt) | set(yp)]
    extra = sorted(set(yt) - set(labels))            # vd 'Other' (nhãn ngoài 9 nhóm)
    labels += extra
    t_att, p_att = yt != normal, yp != normal
    tp, fn = int(np.sum(t_att & p_att)), int(np.sum(t_att & ~p_att))
    fp, tn = int(np.sum(~t_att & p_att)), int(np.sum(~t_att & ~p_att))
    rep = classification_report(yt, yp, labels=labels, output_dict=True, zero_division=0)
    return {
        'accuracy': accuracy_score(yt, yp),
        'f1_macro': f1_score(yt, yp, labels=[c for c in labels if c in set(yt)], average='macro', zero_division=0),
        'dr': tp / max(tp + fn, 1),
        'far': fp / max(fp + tn, 1),
        'labels': labels,
        'cm': confusion_matrix(yt, yp, labels=labels),
        'report': pd.DataFrame(rep).T.round(4),
    }
