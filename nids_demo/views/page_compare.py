# -*- coding: utf-8 -*-
"""Trang 3 – So sánh hai mô hình trên cùng dữ liệu."""
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import config
from core.predictor import evaluate
from views import common


def render():
    c = common.ctx()
    st.title('So sánh Random Forest và CNN-BiLSTM')
    common.note()
    options = {}
    sample = common.load_sample()
    if sample is not None:
        options[f'Dữ liệu mẫu ({c.sample_csv.name})'] = (common.sample_token(), sample)
    if st.session_state.get('dataset') is not None and not str(st.session_state.get('dataset_token')).startswith('sample'):
        options[f'File đã tải: {st.session_state.get("dataset_name")}'] = (st.session_state['dataset_token'], st.session_state['dataset'])
    if not options:
        common.sample_missing_help()
        return
    src = st.radio('Nguồn dữ liệu', list(options), horizontal=True)
    token, df = options[src]
    task = st.radio('Bài toán', ['multi', 'binary'], format_func=common.TASK_LABEL.get, horizontal=True,
                    index=0 if c.task == 'multi' else 1)
    names = [m for m in config.MODEL_NAMES if c.art.has(m, task)]
    if len(names) < 2:
        st.error('Cần đủ cả hai mô hình để so sánh.')
        return

    res = {}
    for m in names:
        with st.spinner(f'{m} đang dự đoán...'):
            res[m] = common.run_cached(df, token, m, task)
    y = res[names[0]][3]

    rows = []
    for m, (p, info, rep, _) in res.items():
        r = {'Mô hình': m, 'Số luồng': len(p.labels), 'Thời gian (s)': round(p.seconds, 3),
             'ms / 1.000 luồng': round(p.ms_per_1000, 2), '% dự đoán Attack': round(100 * p.is_attack.mean(), 2)}
        if y is not None:
            ev = evaluate(y, p)
            r.update({'Accuracy': round(ev['accuracy'], 4), 'F1-macro': round(ev['f1_macro'], 4),
                      'DR': round(ev['dr'], 4), 'FAR': round(ev['far'], 4)})
        rows.append(r)
    st.dataframe(pd.DataFrame(rows), hide_index=True, width='stretch')
    if y is None:
        st.caption('File không có cột Label nên chỉ so sánh thời gian và mức đồng thuận.')

    p1, p2 = res[names[0]][0], res[names[1]][0]
    agree = float(np.mean(p1.labels == p2.labels))
    agree_bin = float(np.mean(p1.is_attack == p2.is_attack))
    a, b = st.columns(2)
    a.metric('Hai mô hình đồng ý (cùng nhãn)', f'{agree:.2%}')
    b.metric('Đồng ý về Normal/Attack', f'{agree_bin:.2%}')

    left, right = st.columns(2)
    ct = pd.crosstab(pd.Series(p1.labels, name=names[0]), pd.Series(p2.labels, name=names[1]))
    fig = go.Figure(go.Heatmap(z=np.log10(ct.to_numpy() + 1), x=list(ct.columns), y=list(ct.index), text=ct.to_numpy(),
                               texttemplate='%{text}', colorscale='Blues', showscale=False))
    fig.update_layout(title='Bảng chéo nhãn dự đoán', xaxis_title=names[1], yaxis_title=names[0],
                      yaxis_autorange='reversed', height=460, margin=dict(l=10, r=10, t=50, b=10))
    left.plotly_chart(fig, width='stretch')
    if y is not None:
        f1 = []
        for m, (p, *_rest) in res.items():
            rep = evaluate(y, p)['report']
            for cls in p.classes:
                if cls in rep.index and rep.loc[cls, 'support'] > 0:
                    f1.append({'Lớp': cls, 'Mô hình': m, 'F1': rep.loc[cls, 'f1-score']})
        fig = px.bar(pd.DataFrame(f1), x='F1', y='Lớp', color='Mô hình', barmode='group', orientation='h',
                     color_discrete_map=common.MODEL_COLORS, range_x=[0, 1.05])
        fig.update_layout(title='F1 theo lớp', height=460, margin=dict(l=10, r=10, t=50, b=10))
        right.plotly_chart(fig, width='stretch')
    with st.expander('Các luồng hai mô hình bất đồng'):
        info = res[names[0]][1]
        diff = np.where(p1.labels != p2.labels)[0]
        tbl = info.iloc[diff].reset_index(drop=True)
        tbl[names[0]] = p1.labels[diff]
        tbl[names[1]] = p2.labels[diff]
        if y is not None:
            tbl['Nhãn thật'] = np.asarray(y)[diff]
        st.dataframe(tbl.head(1000), width='stretch')
