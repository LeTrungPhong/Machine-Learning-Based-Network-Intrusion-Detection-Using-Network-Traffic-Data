# -*- coding: utf-8 -*-
"""Trang 1 – Phân tích file CSV (cấp 1)."""
import streamlit as st

import config
from adapters.csv_source import CSVSource
from views import common


def render():
    c = common.ctx()
    st.title('Phân tích file CSV luồng mạng')
    n_in = len(c.art.feature_columns)
    st.write('Tải lên CSV do CICFlowMeter tạo ra (CIC-IDS2017, CICFlowMeter 4.0 hoặc gói Python `cicflowmeter`). '
             f'App tự ánh xạ tên cột về đúng {n_in} đặc trưng mô hình dùng.')
    common.note()

    up = st.file_uploader('Chọn file CSV', type=['csv'])
    b1, b2 = st.columns([1, 4])
    use_sample = b1.button('Dùng dữ liệu mẫu', disabled=not c.sample_csv.exists())
    if not c.sample_csv.exists():
        b2.caption(f'Chưa có data/{c.sample_csv.name} – xem README mục "Dữ liệu mẫu".')

    if up is not None:
        token = f'upload:{up.name}:{up.size}'
        if st.session_state.get('dataset_token') != token:
            with st.spinner('Đang đọc file...'):
                st.session_state['dataset'] = CSVSource(up).get_flows()
            st.session_state['dataset_token'] = token
            st.session_state['dataset_name'] = up.name
    elif use_sample:
        st.session_state['dataset'] = common.load_sample()
        st.session_state['dataset_token'] = common.sample_token()
        st.session_state['dataset_name'] = c.sample_csv.name

    df = st.session_state.get('dataset')
    if df is None:
        st.info('Hãy tải lên một file CSV hoặc bấm "Dùng dữ liệu mẫu".')
        return
    token = st.session_state['dataset_token']
    st.success(f'Dữ liệu: **{st.session_state.get("dataset_name")}** – {len(df):,} dòng × {df.shape[1]} cột')
    if not c.models:
        st.error('Không có mô hình nào khả dụng cho lựa chọn hiện tại.')
        return

    results = {}
    for m in c.models:
        with st.spinner(f'{m} đang dự đoán ({common.TASK_LABEL[c.task]})...'):
            try:
                results[m] = common.run_cached(df, token, m, c.task)
            except Exception as e:
                st.error(f'Lỗi khi chạy {m}: {e}')
                return
    first = next(iter(results.values()))
    common.show_align_report(first[2])
    if first[2].match_ratio < 0.5:
        st.error(f'Dưới 50% cột khớp – file có thể không đúng loại đặc trưng của mô hình {c.dataset}, kết quả không đáng tin.')

    if len(results) == 1:
        (name, (pred, info, rep, y)), = results.items()
        st.subheader(f'Kết quả – {name} ({common.TASK_LABEL[c.task]})')
        common.show_results(pred, info, y, c.threshold, key=f'csv_{name}')
    else:
        tabs = st.tabs(list(results))
        for tab, (name, (pred, info, rep, y)) in zip(tabs, results.items()):
            with tab:
                common.show_results(pred, info, y, c.threshold, key=f'csv_{name}')
