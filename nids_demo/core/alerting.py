# -*- coding: utf-8 -*-
"""Giảm báo nhầm cho giám sát realtime: whitelist, gom cảnh báo theo IP nguồn trong cửa sổ thời gian, log CSV.

Luồng xử lý mỗi chu kỳ:
  1. Mỗi luồng có dự đoán + độ tin cậy. Luồng "nghi ngờ" = dự đoán Attack và độ tin cậy >= ngưỡng.
  2. Bỏ luồng thuộc whitelist (IP nguồn/đích trong WHITELIST_IPS hoặc cổng đích trong WHITELIST_PORTS).
  3. AlertAggregator giữ các luồng nghi ngờ trong AGG_WINDOW_SECONDS giây gần nhất, gom theo IP nguồn.
     Chỉ khi một IP có >= AGG_MIN_FLOWS luồng nghi ngờ trong cửa sổ mới phát MỘT cảnh báo; sau đó IP này
     im lặng một cửa sổ (cooldown) để không bắn cảnh báo liên tục cho cùng một đợt tấn công.
Module không phụ thuộc Streamlit để kiểm thử được.
"""
import json
import time
from collections import deque
from pathlib import Path

import numpy as np
import pandas as pd

import config

ALERT_COLUMNS = ['Thời gian', 'IP nguồn', 'IP đích', 'Cổng đích', 'Loại tấn công', 'Xác suất TB', 'Xác suất max',
                 'Số luồng', 'Mô hình', 'Chế độ']


# ----------------------------------------------------------------------------- whitelist
def load_whitelist(path=None):
    """Đọc whitelist từ file JSON (nếu có), ngược lại dùng giá trị mặc định trong config."""
    path = Path(path or config.WHITELIST_FILE)
    wl = {'ips': list(config.WHITELIST_IPS), 'ports': list(config.WHITELIST_PORTS)}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            wl['ips'] = [str(x).strip() for x in data.get('ips', wl['ips']) if str(x).strip()]
            wl['ports'] = [int(x) for x in data.get('ports', wl['ports'])]
        except (ValueError, TypeError):
            pass
    return wl


def save_whitelist(ips, ports, path=None):
    path = Path(path or config.WHITELIST_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    wl = {'ips': sorted({str(x).strip() for x in ips if str(x).strip()}),
          'ports': sorted({int(x) for x in ports})}
    path.write_text(json.dumps(wl, indent=1), encoding='utf-8')
    return wl


def parse_list(text, kind=str):
    """'a, b; c' -> ['a','b','c'] (bỏ phần tử sai kiểu)."""
    out = []
    for tok in str(text).replace(';', ',').replace('\n', ',').split(','):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.append(kind(tok))
        except ValueError:
            pass
    return out


def whitelist_mask(info, wl):
    """True cho luồng thuộc whitelist."""
    n = len(info)
    m = np.zeros(n, dtype=bool)
    ips = set(wl.get('ips', []))
    if ips:
        for col in ('Src IP', 'Dst IP'):
            if col in info.columns:
                m |= info[col].astype(str).str.strip().isin(ips).to_numpy()
    ports = set(wl.get('ports', []))
    if ports and 'Dst Port' in info.columns:
        m |= pd.to_numeric(info['Dst Port'], errors='coerce').isin(ports).to_numpy()
    return m


# ----------------------------------------------------------------------------- gom cảnh báo
class AlertAggregator:
    def __init__(self, window_s=None, min_flows=None):
        self.window_s = float(window_s or config.AGG_WINDOW_SECONDS)
        self.min_flows = int(min_flows or config.AGG_MIN_FLOWS)
        self._events = deque()      # (t, src, dst, port, label, conf)
        self._last_alert = {}       # src -> thời điểm cảnh báo gần nhất

    def _expire(self, now):
        while self._events and self._events[0][0] < now - self.window_s:
            self._events.popleft()

    def suspicious_counts(self, now=None):
        """Số luồng nghi ngờ theo IP nguồn trong cửa sổ hiện tại (cho bảng 'IP nghi ngờ')."""
        self._expire(now if now is not None else time.time())
        s = pd.Series([e[1] for e in self._events], dtype=object)
        return s.value_counts() if len(s) else pd.Series(dtype=int)

    def add(self, info, labels, confidence, suspicious, model_name='', mode='', now=None):
        """Thêm các luồng của một chu kỳ, trả về DataFrame cảnh báo MỚI (đã gom)."""
        now = now if now is not None else time.time()
        idx = np.where(np.asarray(suspicious))[0]
        def get(col, i, d='?'):
            if col not in info.columns:
                return d
            v = info[col].iloc[i]
            if col == 'Dst Port':
                try:
                    return str(int(float(v)))
                except (TypeError, ValueError):
                    return str(v)
            return str(v)
        for i in idx:
            self._events.append((now, get('Src IP', i, '(không rõ)'), get('Dst IP', i), get('Dst Port', i),
                                 str(labels[i]), float(confidence[i])))
        self._expire(now)
        if not self._events:
            return pd.DataFrame(columns=ALERT_COLUMNS)
        ev = pd.DataFrame(list(self._events), columns=['t', 'src', 'dst', 'port', 'label', 'conf'])
        rows = []
        for src, g in ev.groupby('src', sort=False):
            last = self._last_alert.get(src)
            if last is not None and now - last < self.window_s:
                continue                                 # cooldown
            g = g[g['t'] > last] if last is not None else g
            if len(g) < self.min_flows:
                continue
            self._last_alert[src] = now
            port_top = g['port'].value_counts().index[0]
            rows.append({
                'Thời gian': pd.Timestamp.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S'),
                'IP nguồn': src,
                'IP đích': ', '.join(g['dst'].value_counts().index[:3]),
                'Cổng đích': port_top if g['port'].nunique() == 1 else f'{port_top} (+{g["port"].nunique() - 1} cổng)',
                'Loại tấn công': g['label'].value_counts().index[0],
                'Xác suất TB': round(g['conf'].mean(), 4),
                'Xác suất max': round(g['conf'].max(), 4),
                'Số luồng': len(g),
                'Mô hình': model_name,
                'Chế độ': mode,
            })
        return pd.DataFrame(rows, columns=ALERT_COLUMNS)


def append_alert_log(alerts, path=None):
    """Ghi thêm cảnh báo vào alerts.csv (tạo header nếu file chưa có)."""
    if alerts is None or not len(alerts):
        return
    path = Path(path or config.ALERTS_LOG)
    path.parent.mkdir(parents=True, exist_ok=True)
    alerts.to_csv(path, mode='a', header=not path.exists(), index=False, encoding='utf-8-sig' if not path.exists() else 'utf-8')
