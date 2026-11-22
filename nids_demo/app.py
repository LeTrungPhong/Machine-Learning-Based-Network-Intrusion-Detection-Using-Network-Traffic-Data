# -*- coding: utf-8 -*-
"""Ứng dụng demo NIDS (CIC-IDS2017) – chạy: streamlit run app.py"""
import os
import warnings

os.environ.setdefault('TF_CPP_MIN_LOG_LEVEL', '2')
warnings.filterwarnings('ignore', category=UserWarning)

import streamlit as st

import config
from core.model_loader import load_artifacts
from core.predictor import Predictor
from views import common, page_compare, page_csv, page_flow, page_live, page_pcap

st.set_page_config(page_title='NIDS Demo – CIC-IDS2017', page_icon='🛡️', layout='wide')


@st.cache_resource(show_spinner='Đang nạp mô hình (lần đầu mất khoảng 10–20 giây)...')
def get_artifacts(dataset):
    """Nạp preprocessor, label encoder và 4 mô hình của một bộ dữ liệu, đúng một lần cho cả phiên chạy app."""
    return load_artifacts(dataset)


dataset = config.DEFAULT_DATASET

try:
    art = get_artifacts(dataset)
except Exception as e:
    st.error(f'Không nạp được artifacts: {e}')
    st.markdown(f'Kiểm tra thư mục `{config.ARTIFACT_DIR}` và phiên bản thư viện trong `requirements.txt`.')
    st.stop()

# ----------------------------------------------------------------------------- sidebar
with st.sidebar:
    st.header('🛡️ NIDS Demo')
    st.caption('Mô hình huấn luyện trên CIC-IDS2017')
    model_choice = st.radio('Mô hình', config.MODEL_NAMES + [config.COMPARE_MODE], key='model_choice')
    task = st.radio('Bài toán', ['multi', 'binary'], format_func=common.TASK_LABEL.get, key='task',
                    help=f'Đa lớp: dự đoán loại tấn công ({len(art.classes_multi)} lớp). Nhị phân: Normal/Attack.')
    threshold = st.slider('Ngưỡng cảnh báo (độ tin cậy)', 0.0, 1.0, config.DEFAULT_ALERT_THRESHOLD, 0.05, key='threshold',
                          help='Nhãn vẫn là lớp có xác suất cao nhất (như lúc huấn luyện). Chỉ phát CẢNH BÁO khi '
                               'dự đoán là tấn công và độ tin cậy ≥ ngưỡng.')
    st.divider()
    st.subheader('Trạng thái mô hình')
    for name in config.MODEL_NAMES:
        for t in ('multi', 'binary'):
            ok = art.has(name, t)
            sec = art.load_seconds.get((name, t))
            st.markdown(f'{"🟢" if ok else "🔴"} {name} – {common.TASK_LABEL[t]}' + (f' <small>({sec:.1f}s)</small>' if ok else ''),
                        unsafe_allow_html=True)
    for f, err in art.errors.items():
        st.error(f'{f}: {err}')
    st.caption(f'{len(art.feature_columns)} đặc trưng đầu vào · lớp: {", ".join(art.classes_multi)}')

st.session_state['ctx'] = common.Ctx(art=art, predictor=Predictor(art), model_choice=model_choice,
                                     task=task, threshold=threshold, dataset=dataset)

pages = [
    st.Page(page_csv.render, title='Phân tích file CSV', icon='📄', url_path='csv', default=True),
    st.Page(page_flow.render, title='Kiểm tra từng luồng', icon='🔎', url_path='flow'),
    st.Page(page_compare.render, title='So sánh mô hình', icon='⚖️', url_path='compare'),
    st.Page(page_pcap.render, title='Phân tích PCAP (cấp 2)', icon='📦', url_path='pcap'),
    st.Page(page_live.render, title='Giám sát trực tiếp (cấp 3)', icon='📡', url_path='live'),
]
st.navigation(pages).run()
