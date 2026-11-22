# -*- coding: utf-8 -*-
"""Trang 4 – Phân tích PCAP (cấp 2): pcap -> CICFlowMeter -> CSV -> pipeline như trang 1."""
import time

import streamlit as st

import config
from adapters.base import SourceUnavailable
from adapters.pcap_source import HELP_JAVA, HELP_PYTHON, PcapSource, backend_status
from views import common


def render():
    c = common.ctx()
    st.title('Phân tích file PCAP')
    st.write('File .pcap/.pcapng được chuyển thành bảng luồng bằng CICFlowMeter, sau đó đi qua cùng pipeline với trang CSV.')
    common.note()
    stt = backend_status()
    a, b, d = st.columns(3)
    a.metric('Gói Python cicflowmeter', 'Sẵn sàng' if stt['python'] else 'Chưa cài')
    b.metric('CICFlowMeter Java', 'Sẵn sàng' if stt['java'] else 'Chưa cấu hình')
    d.metric('Backend đang chọn (config)', config.PCAP_BACKEND)
    if not (stt['python'] or stt['java']):
        st.warning('Chưa có backend CICFlowMeter nào. Cài một trong hai cách dưới đây rồi tải lại trang.')
        with st.expander('Hướng dẫn cài đặt', expanded=True):
            st.markdown(HELP_PYTHON)
            st.markdown(HELP_JAVA)

    up = st.file_uploader('Chọn file PCAP', type=['pcap', 'pcapng', 'cap'])
    if up is None:
        return
    if not st.button('Trích xuất luồng và phân tích', type='primary'):
        return
    config.PCAP_WORK_DIR.mkdir(parents=True, exist_ok=True)
    path = config.PCAP_WORK_DIR / f'{int(time.time())}_{up.name}'
    path.write_bytes(up.getvalue())
    src = PcapSource(path)
    try:
        with st.spinner('CICFlowMeter đang trích xuất luồng...'):
            df = src.get_flows()
    except SourceUnavailable as e:
        st.error(str(e))
        st.markdown(e.help_md)
        return
    except Exception as e:
        st.error(f'Không trích xuất được luồng: {e}')
        if src.last_command:
            st.code(src.last_command)
        return
    st.success(f'Trích xuất được {len(df):,} luồng ({df.shape[1]} cột). Lệnh: `{src.last_command}`')
    token = f'pcap:{path.name}'
    for m in c.models:
        pred, info, rep, y = common.run_cached(df, token, m, c.task)
        st.subheader(f'Kết quả – {m}')
        common.show_align_report(rep)
        common.show_results(pred, info, y, c.threshold, key=f'pcap_{m}')
