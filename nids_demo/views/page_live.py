# -*- coding: utf-8 -*-
"""Trang 5 – Giám sát trực tiếp.

Chế độ:
  sim     : phát lại sample_test.csv (gán IP giả lập) – thử dashboard, gom cảnh báo, whitelist.
  capture : bắt lưu lượng thật của máy (dumpcap + CICFlowMeter Java) -> WATCH_DIR.
  folder  : chỉ đọc thư mục CSV do công cụ khác ghi (vd CICFlowMeter giao diện đồ họa).
  benign  : thu thập lưu lượng bình thường (nhãn BENIGN) vào BENIGN_DIR để huấn luyện lại; đồng thời đo tỉ lệ
            báo nhầm của mô hình hiện tại trên chính lưu lượng đó.
"""
import time
from datetime import datetime

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import config
from adapters.base import SourceUnavailable
from adapters.live_capture import CaptureSession, capture_status, is_admin, list_interfaces, missing_help
from adapters.live_source import FlowSimulator, LiveFolderSource
from core.alerting import (ALERT_COLUMNS, AlertAggregator, append_alert_log, load_whitelist, parse_list,
                           save_whitelist, whitelist_mask)
from views import common

S = st.session_state
MODES = {
    'sim': 'Mô phỏng (phát lại dữ liệu mẫu)',
    'capture': 'Bắt lưu lượng thật của máy',
    'folder': 'Đọc thư mục CSV có sẵn',
    'benign': 'Thu thập lưu lượng bình thường (BENIGN)',
}


# ----------------------------------------------------------------------------- điều khiển phiên
def _reset_state(mode):
    S.live_mode = mode
    S.live_hist = pd.DataFrame(columns=['t', 'Thời điểm', 'Số luồng', 'Nghi ngờ', 'Cảnh báo'])
    S.live_alerts = pd.DataFrame(columns=ALERT_COLUMNS)
    S.live_total = {'flows': 0, 'suspicious': 0, 'whitelisted': 0, 'alerts': 0}
    S.live_types = pd.Series(dtype=int)          # loại tấn công của các luồng nghi ngờ
    S.live_ip_alerts = pd.Series(dtype=int)      # số cảnh báo theo IP nguồn
    S.live_agg = AlertAggregator()
    S.live_sim = None
    S.live_capture = None


def _start(mode, iface=None):
    _reset_state(mode)
    if mode == 'sim':
        config.WATCH_DIR.mkdir(parents=True, exist_ok=True)
        S.live_sim = FlowSimulator(common.load_sample(), synth_ips=True)
        S.live_sim.start()
        S.live_source = LiveFolderSource(config.WATCH_DIR, pattern=config.SIM_FILE_NAME)
        S.live_source.reset(skip_existing=False)
    elif mode in ('capture', 'benign'):
        out = config.BENIGN_DIR if mode == 'benign' else config.WATCH_DIR
        S.live_capture = CaptureSession(iface, out_dir=out, benign=(mode == 'benign'))
        S.live_capture.start()                   # có thể ném SourceUnavailable
        S.live_source = LiveFolderSource(out, pattern=f'{config.CAPTURE_FILE_PREFIX}_*.csv')
        S.live_source.reset(skip_existing=True)
    else:
        config.WATCH_DIR.mkdir(parents=True, exist_ok=True)
        S.live_source = LiveFolderSource(config.WATCH_DIR)
        S.live_source.reset(skip_existing=True)  # chỉ đọc luồng ghi SAU khi bấm Bắt đầu
    S.live_started = time.time()
    S.live_running = True


def _stop():
    S.live_running = False
    cap = S.get('live_capture')
    if cap is not None:
        with st.spinner('Đang dừng dumpcap và xử lý nốt file pcap cuối...'):
            cap.stop()
        _tick_once(final=True)


# ----------------------------------------------------------------------------- một chu kỳ
def _tick_once(final=False):
    c = common.ctx()
    model_name = S.live_model
    if S.get('live_sim') is not None and not final and S.live_sim.step() == 0:
        S.live_running = False
        st.toast('Mô phỏng đã phát hết dữ liệu mẫu.', icon='✅')
    cap = S.get('live_capture')
    if cap is not None and cap.error is not None and S.get('live_running'):
        S.live_running = False
        cap.stop()
    try:
        new = S.live_source.get_flows()
    except SourceUnavailable as e:
        st.error(str(e))
        st.markdown(e.help_md)
        S.live_running = False
        return
    now = time.time()
    n_new, n_susp, n_alert = len(new), 0, 0
    if n_new:
        pred, info, rep, y = c.predictor.predict(new.drop(columns=['__source_file'], errors='ignore'), model_name, c.task)
        susp = pred.is_attack & (pred.confidence >= c.threshold)
        wl = whitelist_mask(info, S.live_whitelist)
        S.live_total['whitelisted'] += int((susp & wl).sum())
        susp &= ~wl
        n_susp = int(susp.sum())
        agg = S.live_agg
        agg.window_s, agg.min_flows = float(S.live_window), int(S.live_min_flows)
        alerts = agg.add(info, pred.labels, pred.confidence, susp, model_name=model_name, mode=MODES[S.live_mode])
        n_alert = len(alerts)
        if n_susp:
            S.live_types = S.live_types.add(pd.Series(pred.labels[susp]).value_counts(), fill_value=0)
        if n_alert:
            S.live_alerts = pd.concat([alerts, S.live_alerts], ignore_index=True).head(config.LIVE_HISTORY_LIMIT)
            S.live_ip_alerts = S.live_ip_alerts.add(alerts['IP nguồn'].value_counts(), fill_value=0)
            append_alert_log(alerts)
            top = alerts.iloc[0]
            st.toast(f'🚨 {n_alert} cảnh báo: {top["Loại tấn công"]} từ {top["IP nguồn"]} ({top["Số luồng"]} luồng)', icon='🚨')
        S.live_total['flows'] += n_new
        S.live_total['suspicious'] += n_susp
        S.live_total['alerts'] += n_alert
    row = {'t': now, 'Thời điểm': datetime.fromtimestamp(now).strftime('%H:%M:%S'), 'Số luồng': n_new,
           'Nghi ngờ': n_susp, 'Cảnh báo': n_alert}
    S.live_hist = pd.concat([S.live_hist, pd.DataFrame([row])], ignore_index=True).tail(600)


# ----------------------------------------------------------------------------- dashboard
def _dashboard():
    t = S.get('live_total')
    if t is None:
        st.caption('Chưa chạy phiên giám sát nào.')
        return
    hist = S.live_hist
    now = time.time()
    last_min = hist[hist['t'] >= now - 60]['Số luồng'].sum() if len(hist) else 0
    elapsed = max(now - S.get('live_started', now), 1)
    agg_counts = S.live_agg.suspicious_counts(now)
    top_ip = (S.live_ip_alerts.sort_values(ascending=False).index[0] if len(S.live_ip_alerts)
              else (agg_counts.index[0] if len(agg_counts) else '–'))
    top_type = S.live_types.sort_values(ascending=False).index[0] if len(S.live_types) else '–'

    k = st.columns(5)
    k[0].metric('Luồng / phút (60s gần nhất)', f'{int(last_min):,}', f'TB {t["flows"] / elapsed * 60:,.0f}/phút', delta_color='off')
    k[1].metric('Tổng luồng đã xử lý', f'{t["flows"]:,}')
    if S.live_mode == 'benign':
        fpr = t['suspicious'] / max(t['flows'], 1)
        k[2].metric('Luồng bị báo nhầm', f'{t["suspicious"]:,}', f'{fpr:.2%} số luồng', delta_color='off')
    else:
        k[2].metric('Luồng nghi ngờ', f'{t["suspicious"]:,}', f'{t["whitelisted"]:,} bỏ qua do whitelist', delta_color='off')
    k[3].metric('Số cảnh báo (đã gom)', f'{t["alerts"]:,}')
    k[4].metric('Top IP nghi ngờ', str(top_ip), f'loại phổ biến: {top_type}', delta_color='off')

    left, right = st.columns([3, 2])
    with left:
        fig = go.Figure()
        fig.add_scatter(x=hist['Thời điểm'], y=hist['Số luồng'], name='Luồng', mode='lines', line_color=common.BLUE)
        fig.add_scatter(x=hist['Thời điểm'], y=hist['Nghi ngờ'], name='Nghi ngờ', mode='lines', line_color=common.ORANGE)
        fig.add_bar(x=hist['Thời điểm'], y=hist['Cảnh báo'], name='Cảnh báo', marker_color=common.RED, yaxis='y2')
        fig.update_layout(title='Luồng và cảnh báo theo thời gian', height=330, margin=dict(l=10, r=10, t=50, b=10),
                          yaxis=dict(title='Số luồng / chu kỳ'),
                          yaxis2=dict(title='Cảnh báo', overlaying='y', side='right', rangemode='tozero', showgrid=False),
                          legend=dict(orientation='h', y=-0.2))
        st.plotly_chart(fig, width='stretch')
    with right:
        tabs = st.tabs(['IP nghi ngờ', 'Loại tấn công'])
        with tabs[0]:
            ip_tbl = pd.DataFrame({'Luồng nghi ngờ (cửa sổ hiện tại)': agg_counts}).join(
                pd.DataFrame({'Số cảnh báo': S.live_ip_alerts}), how='outer').fillna(0).astype(int)
            ip_tbl = ip_tbl.sort_values(['Số cảnh báo', 'Luồng nghi ngờ (cửa sổ hiện tại)'], ascending=False).head(10)
            st.dataframe(ip_tbl.rename_axis('IP nguồn'), width='stretch', height=260)
        with tabs[1]:
            ty = S.live_types.sort_values(ascending=False).astype(int).rename('Luồng nghi ngờ').rename_axis('Loại')
            st.dataframe(ty.to_frame(), width='stretch', height=260)

    st.subheader('Cảnh báo mới nhất')
    al = S.live_alerts
    if len(al):
        st.dataframe(al.head(50), width='stretch', hide_index=True)
    else:
        st.caption(f'Chưa có cảnh báo (cần ≥ {S.live_min_flows} luồng nghi ngờ từ cùng một IP nguồn trong '
                   f'{S.live_window} giây, độ tin cậy ≥ {common.ctx().threshold:.2f}).')

    cap = S.get('live_capture')
    if cap is not None:
        with st.expander(f'Nhật ký bắt lưu lượng – {cap.files_done} file pcap, {cap.flows_written:,} luồng đã ghi'):
            st.code('\n'.join(cap.log[-40:]) or '(trống)')


# ----------------------------------------------------------------------------- cấu hình giảm báo nhầm
def _fp_settings():
    if 'live_whitelist' not in S:
        S.live_whitelist = load_whitelist()
    with st.expander('Giảm báo nhầm: ngưỡng, gom cảnh báo, whitelist'):
        st.markdown(f'- **Ngưỡng tin cậy**: chỉnh ở sidebar (hiện tại **{common.ctx().threshold:.2f}**). '
                    'Luồng nghi ngờ = dự đoán Attack **và** độ tin cậy ≥ ngưỡng.')
        a, b = st.columns(2)
        S.live_window = a.number_input('Cửa sổ gom (giây)', 10, 3600, int(S.get('live_window', config.AGG_WINDOW_SECONDS)), 10)
        S.live_min_flows = b.number_input('Số luồng nghi ngờ tối thiểu / IP nguồn', 1, 1000,
                                          int(S.get('live_min_flows', config.AGG_MIN_FLOWS)))
        wl = S.live_whitelist
        ips = st.text_area('Whitelist IP (router, DNS...) – cách nhau bởi dấu phẩy', ', '.join(wl['ips']), height=68)
        ports = st.text_input('Whitelist cổng đích', ', '.join(map(str, wl['ports'])))
        c1, c2 = st.columns([1, 3])
        if c1.button('Lưu whitelist'):
            S.live_whitelist = save_whitelist(parse_list(ips), parse_list(ports, int))
            st.success(f'Đã lưu vào {config.WHITELIST_FILE.name}: {len(S.live_whitelist["ips"])} IP, '
                       f'{len(S.live_whitelist["ports"])} cổng.')
        c2.caption('Luồng có IP nguồn/đích hoặc cổng đích thuộc whitelist không bao giờ tạo cảnh báo.')


def _capture_panel(mode):
    """Kiểm tra công cụ + chọn card mạng. Trả về Interface đã chọn hoặc None."""
    stt = capture_status()
    k = st.columns(4)
    k[0].metric('dumpcap (Wireshark)', 'Sẵn sàng' if stt['dumpcap'] else 'Chưa cài')
    k[1].metric('CICFlowMeter Java', 'Sẵn sàng' if stt['cicflowmeter_java'] else 'Chưa cấu hình')
    k[2].metric('Java', 'Có' if stt['java'] else 'Chưa cài')
    k[3].metric('Quyền Administrator', 'Có' if stt['admin'] else 'Không')
    help_md = missing_help(stt)
    if help_md:
        st.warning('Thiếu công cụ để bắt lưu lượng thật – cài theo hướng dẫn rồi tải lại trang.')
        st.markdown(help_md)
        return None
    if not stt['admin']:
        st.caption('App không chạy bằng quyền Administrator. Nếu Npcap chỉ cho phép Administrator bắt gói, '
                   'bấm Bắt đầu sẽ báo lỗi – khi đó chạy lại app trong PowerShell "Run as administrator".')
    try:
        ifaces = list_interfaces()
    except SourceUnavailable as e:
        st.error(str(e))
        st.markdown(e.help_md)
        return None
    pick = st.selectbox('Card mạng', ifaces, format_func=lambda i: i.label, disabled=S.get('live_running', False),
                        help='Wi-Fi/Ethernet: lưu lượng thật của máy. VMware VMnet1 / VirtualBox Host-Only: lab máy ảo.')
    out = config.BENIGN_DIR if mode == 'benign' else config.WATCH_DIR
    st.caption(f'dumpcap cắt file pcap mỗi {config.CAPTURE_ROTATE_SECONDS}s → CICFlowMeter → CSV trong `{out}`.')
    if mode == 'benign':
        st.info('Chỉ dùng khi chắc chắn mạng **không có tấn công** (duyệt web, họp online, cập nhật phần mềm...). '
                'Mọi luồng được gán nhãn BENIGN; số "báo nhầm" trên dashboard là tỉ lệ báo nhầm của mô hình hiện tại. '
                'Dùng `tools/finetune_benign.py` để huấn luyện lại với dữ liệu này.')
    return pick


# ----------------------------------------------------------------------------- trang
def render():
    c = common.ctx()
    st.title('Giám sát trực tiếp')
    common.note()
    st.caption('🔒 ' + config.UI_NOTE_CAPTURE)
    model_name = c.models[0] if c.models else None
    if c.model_choice == config.COMPARE_MODE:
        st.caption('Chế độ "So sánh cả hai" không áp dụng cho giám sát – dùng Random Forest.')
    if model_name is None:
        st.error('Không có mô hình khả dụng.')
        return
    running = S.get('live_running', False)
    mode = st.radio('Chế độ', list(MODES), format_func=MODES.get, horizontal=True, disabled=running,
                    index=list(MODES).index(S.get('live_mode', 'sim')))

    iface, can_start = None, True
    if mode == 'sim':
        if common.load_sample() is None:
            common.sample_missing_help()
            can_start = False
        else:
            st.caption('Dữ liệu mẫu không có cột IP → app gán IP giả lập (mỗi loại tấn công một "máy tấn công" '
                       '192.168.56.1xx) để thử tính năng gom cảnh báo theo IP.')
    elif mode in ('capture', 'benign'):
        iface = _capture_panel(mode)
        can_start = iface is not None
    else:
        st.write(f'Đọc các dòng mới trong `{config.WATCH_DIR}` (vd CICFlowMeter giao diện đồ họa ghi realtime vào đây).')

    _fp_settings()
    interval = st.slider('Chu kỳ làm mới (giây)', 1, 30, config.REFRESH_SECONDS, disabled=running)

    b1, b2, b3 = st.columns([1, 1, 4])
    if b1.button('▶ Bắt đầu', type='primary', disabled=running or not can_start):
        try:
            S.live_model = model_name
            _start(mode, iface)
        except SourceUnavailable as e:
            S.live_running = False
            st.error(str(e))
            st.markdown(e.help_md)
            return
        st.rerun()
    if b2.button('■ Dừng', disabled=not running):
        _stop()
        st.rerun()
    if config.ALERTS_LOG.exists():
        b3.download_button('Tải alerts.csv', config.ALERTS_LOG.read_bytes(), file_name='alerts.csv', mime='text/csv')

    @st.fragment(run_every=interval if S.get('live_running') else None)
    def live_panel():
        if S.get('live_running'):
            _tick_once()
            cap = S.get('live_capture')
            if cap is not None and cap.error is not None:
                st.error(cap.error[0])
                st.markdown(cap.error[1])
            extra = ''
            if cap is not None:
                extra = f' · đã xử lý {cap.files_done} file pcap (luồng đầu tiên xuất hiện sau khoảng {cap.rotate_s}s)'
            st.caption(f'Đang chạy – {MODES[S.live_mode]} – {S.live_model}, cập nhật {datetime.now():%H:%M:%S}{extra}')
        _dashboard()
        if not S.get('live_running') and S.get('live_hist') is not None and len(S.live_hist):
            st.caption(f'Đã dừng. Cảnh báo được ghi vào `{config.ALERTS_LOG}`.')

    live_panel()
