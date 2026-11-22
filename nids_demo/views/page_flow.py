# -*- coding: utf-8 -*-
"""Trang 2 – Kiểm tra từng luồng: nhãn thật vs dự đoán của cả hai mô hình."""
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import config
from views import common


def _dataset():
    """Ưu tiên dữ liệu mẫu; nếu chưa có thì dùng file đã tải ở trang 1."""
    sample = common.load_sample()
    options = {}
    if sample is not None:
        options[f'Dữ liệu mẫu ({common.ctx().sample_csv.name})'] = sample
    if st.session_state.get('dataset') is not None and not str(st.session_state.get('dataset_token')).startswith('sample'):
        options[f'File đã tải: {st.session_state.get("dataset_name")}'] = st.session_state['dataset']
    return options


def render():
    c = common.ctx()
    st.title('Kiểm tra từng luồng')
    common.note()
    options = _dataset()
    if not options:
        common.sample_missing_help()
        return
    src = st.radio('Nguồn dữ liệu', list(options), horizontal=True)
    df = options[src]
    _, info_all, _, y_all = c.predictor.align(df)

    col1, col2 = st.columns([2, 1])
    if y_all is not None:
        classes = ['(Tất cả)'] + sorted(y_all.unique())
        pick = col1.selectbox('Chọn theo nhãn thật', classes)
        pool = np.arange(len(df)) if pick == '(Tất cả)' else np.where(y_all.to_numpy() == pick)[0]
    else:
        col1.caption('File không có cột Label – chọn ngẫu nhiên trong toàn bộ dữ liệu.')
        pool = np.arange(len(df))
    if col2.button('🎲 Chọn ngẫu nhiên 1 luồng', type='primary') or st.session_state.get('flow_idx') not in set(pool):
        st.session_state['flow_idx'] = int(np.random.default_rng().choice(pool))
    i = st.session_state['flow_idx']
    row = df.iloc[[i]]

    X_df, info, rep, y = c.predictor.align(row)
    Z = c.art.prep.transform(X_df)
    st.markdown(f'**Luồng #{i}**' + (f' – nhãn thật: **{y.iloc[0]}**' if y is not None else ''))
    if len(info.columns):
        st.dataframe(info, hide_index=True, width='stretch')

    task = 'multi'
    preds = {m: c.predictor.predict_matrix(Z, m, task) for m in config.MODEL_NAMES if c.art.has(m, task)}
    cols = st.columns(len(preds))
    for col, (m, p) in zip(cols, preds.items()):
        ok = (y is not None) and (p.labels[0] == y.iloc[0])
        col.metric(m, p.labels[0], f'tin cậy {p.confidence[0]:.3f}' + ('' if y is None else (' ✓ đúng' if ok else ' ✗ sai')),
                   delta_color='normal' if ok or y is None else 'inverse')

    classes = c.art.classes(task)
    fig = go.Figure()
    for m, p in preds.items():
        fig.add_bar(name=m, x=classes, y=p.proba[0], marker_color=common.MODEL_COLORS[m],
                    text=[f'{v:.2f}' for v in p.proba[0]], textposition='outside')
    fig.update_layout(barmode='group', title='Xác suất các lớp (đa lớp)', yaxis_range=[0, 1.15], height=400,
                      margin=dict(l=10, r=10, t=50, b=10))
    st.plotly_chart(fig, width='stretch')

    rf = c.art.models.get(('Random Forest', task))
    if rf is not None and hasattr(rf, 'feature_importances_'):
        st.subheader('Đặc trưng quan trọng của Random Forest')
        st.caption('Độ quan trọng là **toàn cục** (Gini importance của mô hình), kèm giá trị thô và giá trị đã chuẩn hóa '
                   '(z-score sau signed-log) của luồng này. Giá trị |z| lớn = luồng khác xa trung bình tập train ở đặc trưng đó.')
        imp = pd.DataFrame({'Đặc trưng': c.art.feature_names, 'Độ quan trọng': rf.feature_importances_,
                            'Giá trị chuẩn hóa (z)': Z[0]})
        raw = X_df.iloc[0]
        levels = getattr(c.art.prep, 'cat_levels_', {})

        def raw_value(f):
            if f in raw.index:
                return float(raw[f])
            col, lvl = f.split('=', 1)                    # cột One-Hot, vd 'proto=tcp' -> 1 nếu proto của luồng là tcp
            v = str(raw.get(col))
            return float((v if v in levels.get(col, []) else 'other') == lvl)
        imp['Giá trị thô'] = [raw_value(f) for f in imp['Đặc trưng']]
        imp = imp[['Đặc trưng', 'Độ quan trọng', 'Giá trị thô', 'Giá trị chuẩn hóa (z)']]
        imp = imp.sort_values('Độ quan trọng', ascending=False).head(10)
        st.dataframe(imp.style.format({'Độ quan trọng': '{:.4f}', 'Giá trị thô': '{:,.2f}', 'Giá trị chuẩn hóa (z)': '{:+.2f}'}),
                     hide_index=True, width='stretch')
