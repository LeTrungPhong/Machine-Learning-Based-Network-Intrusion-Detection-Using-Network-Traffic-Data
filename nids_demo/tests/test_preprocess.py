# -*- coding: utf-8 -*-
"""Kiểm thử pipeline: ánh xạ cột, tiền xử lý, và độ chính xác trên sample_test.csv so với Kaggle."""
import numpy as np
import pandas as pd
import pytest

import config
from core.schema import _CFM4_TO_2017, align_features

TO_CFM4 = {v: k for k, v in _CFM4_TO_2017.items()}


def py_name(cfm4):
    """Tên cột kiểu gói Python cicflowmeter: snake_case của tên CICFlowMeter 4.0."""
    return cfm4.lower().replace('/', '_').replace(' ', '_')


def make_rows(features, n=5, seed=0):
    rng = np.random.default_rng(seed)
    return pd.DataFrame(rng.integers(0, 1000, size=(n, len(features))).astype(float), columns=features)


# ----------------------------------------------------------------------------- artifacts
def test_artifacts_loaded(artifacts):
    assert len(artifacts.feature_columns) == 45
    assert artifacts.feature_columns == artifacts.feature_names      # CIC không có One-Hot
    assert artifacts.classes_multi == ['Benign', 'Bot', 'Brute Force', 'DDoS', 'DoS', 'Heartbleed',
                                       'Infiltration', 'PortScan', 'Web Attack']
    for name in config.MODEL_NAMES:
        for task in ('multi', 'binary'):
            assert artifacts.has(name, task)


def test_every_feature_has_cfm4_alias(artifacts):
    missing = [c for c in artifacts.feature_columns if c not in TO_CFM4]
    assert not missing, f'Thiếu ánh xạ CICFlowMeter 4.0 cho: {missing}'


# ----------------------------------------------------------------------------- align_features
@pytest.mark.parametrize('style', ['cic2017', 'cfm4', 'python'])
def test_align_three_schemas(artifacts, style):
    feats = artifacts.feature_columns
    base = make_rows(feats)
    if style == 'cic2017':
        df = base.rename(columns={c: ' ' + c for c in feats})            # tên gốc có khoảng trắng đầu
    elif style == 'cfm4':
        df = base.rename(columns=TO_CFM4)
    else:
        df = base.rename(columns={c: py_name(TO_CFM4[c]) for c in feats})
    df['Src IP'] = '10.0.0.1'
    df['Label'] = 'BENIGN'
    df['Some Unknown Col'] = 1
    X, info, rep = align_features(df, feats)
    assert rep.match_ratio == 1.0, rep.missing
    assert list(X.columns) == feats
    np.testing.assert_array_equal(X.to_numpy(), base.to_numpy())
    assert 'Src IP' in info.columns and 'Label' in info.columns and 'Dst Port' in info.columns
    assert 'Some Unknown Col' in rep.extra


def test_missing_columns_reported_and_filled(artifacts, predictor):
    feats = artifacts.feature_columns
    df = make_rows(feats[:30])
    X, info, rep = align_features(df, feats)
    assert len(rep.missing) == 15 and rep.match_ratio == pytest.approx(30 / 45)
    Z = predictor.art.prep.transform(X)                                  # cột thiếu -> median của train
    assert Z.shape == (len(df), 45) and np.isfinite(Z).all()


def test_inf_nan_and_text_values(artifacts, predictor):
    feats = artifacts.feature_columns
    df = make_rows(feats, n=4).astype(object)
    df.loc[0, 'Flow Bytes/s'] = np.inf
    df.loc[1, 'Flow Packets/s'] = 'Infinity'
    df.loc[2, 'Flow Duration'] = np.nan
    df.loc[3, 'Destination Port'] = 'abc'
    X, _, _ = align_features(df, feats)
    Z = predictor.art.prep.transform(X)
    assert np.isfinite(Z).all()
    pred, *_ = predictor.predict(df, 'Random Forest')
    assert len(pred.labels) == 4


def test_dl_and_rf_shapes(predictor, artifacts):
    df = make_rows(artifacts.feature_columns, n=7)
    for name in config.MODEL_NAMES:
        for task in ('multi', 'binary'):
            p, *_ = predictor.predict(df, name, task)
            assert p.proba.shape == (7, len(artifacts.classes(task)))
            np.testing.assert_allclose(p.proba.sum(axis=1), 1.0, atol=1e-5)


# ----------------------------------------------------------------------------- độ chính xác
@pytest.fixture(scope='module')
def sample_df():
    if not config.SAMPLE_CSV.exists():
        pytest.skip(f'Chưa có {config.SAMPLE_CSV} – chạy tools/kaggle_export_sample.py trên Kaggle để tạo.')
    return pd.read_csv(config.SAMPLE_CSV, low_memory=False)


@pytest.mark.parametrize('model_name,task', [('Random Forest', 'multi'), ('CNN-BiLSTM', 'multi'),
                                             ('Random Forest', 'binary'), ('CNN-BiLSTM', 'binary')])
def test_accuracy_matches_kaggle(predictor, sample_df, model_name, task):
    from core.predictor import evaluate
    uni = sample_df[sample_df['Sample_Part'] == 'uniform'] if 'Sample_Part' in sample_df else sample_df
    pred, info, rep, y_true = predictor.predict(uni, model_name, task)
    assert rep.match_ratio == 1.0
    m = evaluate(y_true, pred)
    ref = config.KAGGLE_REFERENCE[(model_name, task)]['accuracy']
    print(f'{model_name} {task}: accuracy = {m["accuracy"]:.4f} (Kaggle {ref:.4f}), n = {len(uni)}')
    assert abs(m['accuracy'] - ref) < 0.005, 'Lệch lớn so với Kaggle -> pipeline sai'


def test_rare_classes_detected(predictor, sample_df):
    from core.predictor import evaluate
    pred, info, rep, y_true = predictor.predict(sample_df, 'Random Forest', 'multi')
    m = evaluate(y_true, pred)
    rec = m['report']['recall']
    for cls in ('Bot', 'Web Attack', 'Brute Force'):
        if cls in rec.index:
            assert rec[cls] > 0.7, f'Recall {cls} = {rec[cls]:.3f}'
