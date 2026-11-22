# -*- coding: utf-8 -*-
"""Trang 5 – Giám sát trực tiếp (cấp 3): đọc các dòng mới trong WATCH_DIR, có chế độ mô phỏng."""
import time
from datetime import datetime

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import config
from adapters.base import SourceUnavailable
from adapters.live_source import FlowSimulator, LiveFolderSource
from views import common

S = st.session_state


def _start(mode):
    config.WATCH_DIR.mkdir(parents=True, exist_ok=True)
    S.live_source = LiveFolderSource(config.WATCH_DIR)
    S.live_hist = pd.DataFrame(columns=['Thời điểm', 'Số luồng', 'Số Attack'])
    S.live_alerts = pd.DataFrame()
    S.live_total = {'flows': 0, 'attacks': 0}
    if mode == 'sim':
        sample = common.load_sample()
        S.live_sim = FlowSimulator(sample)
        S.live_sim.start()
        S.live_source.reset(skip_existing=False)
    else:
        S.live_sim = None
        S.live_source.reset(skip_existing=True)     # chỉ đọc luồng ghi SAU khi bấm Bắt đầu
    S.live_running = True


def _tick(c, model_name):
    """Một chu kỳ: (mô phỏng ghi thêm) -> đọc dòng mới -> dự đoán -> cập nhật lịch sử."""
    if S.get('live_sim') is not None and S.live_sim.step() == 0:
        S.live_running = False
        st.toast('Mô phỏng đã phát hết dữ liệu mẫu.', icon='✅')
    try:
        new = S.live_source.get_flows()
    except SourceUnavailable as e:
        st.error(str(e))
        st.markdown(e.help_md)
        S.live_running = False
        return
    now = datetime.now().strftime('%H:%M:%S')
    n_att = 0
    if len(new):
        pred, info, rep, y = c.predictor.predict(new.drop(columns=['__source_file'], errors='ignore'), model_name, c.task)
        tbl = pd.concat([pd.Series([now] * len(new), name='Thời điểm'), info, pred.frame(c.threshold)], axis=1)
        if y is not None:
            tbl['Nhãn thật'] = np.asarray(y)
        alerts = tbl[tbl['Cảnh báo']]
        n_att = int(pred.is_attack.sum())
        if len(alerts):
            top = alerts['Dự đoán'].value_counts().index[0]
            st.toast(f'⚠️ {len(alerts)} cảnh báo mới (nhiều nhất: {top})', icon='🚨')
            S.live_alerts = pd.concat([alerts, S.live_alerts]).head(config.LIVE_HISTORY_LIMIT)
        S.live_total['flows'] += len(new)
        S.live_total['attacks'] += n_att
    S.live_hist = pd.concat([S.live_hist, pd.DataFrame([{'Thời điểm': now, 'Số luồng': len(new), 'Số Attack': n_att}])],
                            ignore_index=True).tail(300)


def _dashboard():
    t = S.get('live_total', {'flows': 0, 'attacks': 0})
    c = st.columns(3)
    c[0].metric('Tổng luồng đã xử lý', f'{t["flows"]:,}')
    c[1].metric('Tổng dự đoán Attack', f'{t["attacks"]:,}')
    c[2].metric('Số cảnh báo', f'{len(S.get("live_alerts", [])):,}')
    hist = S.get('live_hist')
    if hist is not None and len(hist):
        fig = go.Figure()
        fig.add_scatter(x=hist['Thời điểm'], y=hist['Số luồng'], name='Số luồng', mode='lines+markers', line_color=common.BLUE)
        fig.add_scatter(x=hist['Thời điểm'], y=hist['Số Attack'], name='Số Attack', mode='lines+markers', line_color=common.RED)
        fig.update_layout(title='Số luồng và số tấn công theo thời gian', height=320, margin=dict(l=10, r=10, t=50, b=10))
        st.plotly_chart(fig, width='stretch')
    al = S.get('live_alerts')
    st.subheader('Cảnh báo mới nhất')
    if al is not None and len(al):
        st.dataframe(al.head(50), width='stretch', hide_index=True)
    else:
        st.caption('Chưa có cảnh báo.')


def render():
    c = common.ctx()
    st.title('Giám sát trực tiếp')
    st.write(f'Theo dõi thư mục `{config.WATCH_DIR}` nơi CICFlowMeter (chế độ realtime) ghi CSV; mỗi chu kỳ chỉ đọc các dòng mới.')
    common.note()
    model_name = c.models[0] if c.models else None
    if c.model_choice == config.COMPARE_MODE:
        st.caption('Chế độ "So sánh cả hai" không áp dụng cho giám sát – dùng Random Forest.')
    if model_name is None:
        st.error('Không có mô hình khả dụng.')
        return

    has_sample = common.load_sample() is not None
    mode = st.radio('Chế độ', ['sim', 'real'], horizontal=True, disabled=S.get('live_running', False),
                    format_func=lambda m: f'Mô phỏng (phát lại {c.sample_csv.name})' if m == 'sim' else 'Thư mục giám sát thật')
    if mode == 'sim' and not has_sample:
        common.sample_missing_help()
    if mode == 'real' and not config.WATCH_DIR.exists():
        st.warning(f'Thư mục giám sát chưa tồn tại: `{config.WATCH_DIR}`. Bấm Bắt đầu để tạo, rồi cấu hình CICFlowMeter '
                   'ghi CSV vào đây (xem README – cấp 3).')
    interval = st.slider('Chu kỳ làm mới (giây)', 1, 30, config.REFRESH_SECONDS, disabled=S.get('live_running', False))

    b1, b2, _ = st.columns([1, 1, 4])
    if b1.button('▶ Bắt đầu', type='primary', disabled=S.get('live_running', False) or (mode == 'sim' and not has_sample)):
        _start(mode)
        st.rerun()
    if b2.button('■ Dừng', disabled=not S.get('live_running', False)):
        S.live_running = False
        st.rerun()

    @st.fragment(run_every=interval if S.get('live_running') else None)
    def live_panel():
        if S.get('live_running'):
            _tick(c, model_name)
            st.caption(f'Đang chạy – {model_name}, cập nhật lúc {datetime.now():%H:%M:%S}')
        _dashboard()
        if not S.get('live_running') and S.get('live_hist') is not None and len(S.live_hist):
            st.caption('Đã dừng.')

    live_panel()
