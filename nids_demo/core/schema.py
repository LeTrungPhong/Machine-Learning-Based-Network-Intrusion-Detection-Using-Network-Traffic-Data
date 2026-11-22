# -*- coding: utf-8 -*-
"""Đối chiếu và ánh xạ tên cột từ nhiều nguồn về tên cột lúc huấn luyện (CIC-IDS2017).

Hỗ trợ 3 kiểu tên cột:
  (a) CIC-IDS2017 gốc          : ' Flow Duration', 'Total Fwd Packets', 'Destination Port'
  (b) CICFlowMeter Java 4.0 /  : 'Flow Duration', 'Tot Fwd Pkts', 'Dst Port'
      CSE-CIC-IDS2018
  (c) gói Python `cicflowmeter`: 'flow_duration', 'tot_fwd_pkts', 'dst_port'
  (d) CICFlowMeter GitHub master : 'Total Fwd Packet', 'FWD Init Win Bytes', 'Packet Length Min'

Cách làm: mọi tên cột được quy về "khóa chuẩn" (chữ thường, bỏ ký tự không phải chữ/số),
vd 'Flow Byts/s' và 'flow_byts_s' cùng thành 'flowbytss'. Bảng ALIASES ánh xạ khóa chuẩn của
kiểu (b)/(c) sang tên CIC-IDS2017; kiểu (a) khớp trực tiếp.
"""
import re
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from core.preprocess import clean_raw


def normalize_name(c):
    """strip + gộp khoảng trắng thừa."""
    return ' '.join(str(c).split())


def canon(c):
    """Khóa chuẩn để so khớp: chữ thường, bỏ mọi ký tự không phải chữ/số."""
    return re.sub(r'[^0-9a-z]', '', str(c).lower())


# Tên CICFlowMeter 4.0 / CSE-CIC-IDS2018 -> tên CIC-IDS2017.
# Tên của gói Python `cicflowmeter` là dạng snake_case của các tên này nên dùng chung bảng.
_CFM4_TO_2017 = {
    'Dst Port': 'Destination Port',
    'Flow Duration': 'Flow Duration',
    'Tot Fwd Pkts': 'Total Fwd Packets',
    'Tot Bwd Pkts': 'Total Backward Packets',
    'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
    'TotLen Bwd Pkts': 'Total Length of Bwd Packets',
    'Fwd Pkt Len Max': 'Fwd Packet Length Max',
    'Fwd Pkt Len Min': 'Fwd Packet Length Min',
    'Fwd Pkt Len Mean': 'Fwd Packet Length Mean',
    'Fwd Pkt Len Std': 'Fwd Packet Length Std',
    'Bwd Pkt Len Max': 'Bwd Packet Length Max',
    'Bwd Pkt Len Min': 'Bwd Packet Length Min',
    'Bwd Pkt Len Mean': 'Bwd Packet Length Mean',
    'Bwd Pkt Len Std': 'Bwd Packet Length Std',
    'Flow Byts/s': 'Flow Bytes/s',
    'Flow Pkts/s': 'Flow Packets/s',
    'Flow IAT Mean': 'Flow IAT Mean',
    'Flow IAT Std': 'Flow IAT Std',
    'Flow IAT Max': 'Flow IAT Max',
    'Flow IAT Min': 'Flow IAT Min',
    'Fwd IAT Tot': 'Fwd IAT Total',
    'Fwd IAT Mean': 'Fwd IAT Mean',
    'Fwd IAT Std': 'Fwd IAT Std',
    'Fwd IAT Max': 'Fwd IAT Max',
    'Fwd IAT Min': 'Fwd IAT Min',
    'Bwd IAT Tot': 'Bwd IAT Total',
    'Bwd IAT Mean': 'Bwd IAT Mean',
    'Bwd IAT Std': 'Bwd IAT Std',
    'Bwd IAT Max': 'Bwd IAT Max',
    'Bwd IAT Min': 'Bwd IAT Min',
    'Fwd PSH Flags': 'Fwd PSH Flags',
    'Bwd PSH Flags': 'Bwd PSH Flags',
    'Fwd URG Flags': 'Fwd URG Flags',
    'Bwd URG Flags': 'Bwd URG Flags',
    'Fwd Header Len': 'Fwd Header Length',
    'Bwd Header Len': 'Bwd Header Length',
    'Fwd Pkts/s': 'Fwd Packets/s',
    'Bwd Pkts/s': 'Bwd Packets/s',
    'Pkt Len Min': 'Min Packet Length',
    'Pkt Len Max': 'Max Packet Length',
    'Pkt Len Mean': 'Packet Length Mean',
    'Pkt Len Std': 'Packet Length Std',
    'Pkt Len Var': 'Packet Length Variance',
    'FIN Flag Cnt': 'FIN Flag Count',
    'SYN Flag Cnt': 'SYN Flag Count',
    'RST Flag Cnt': 'RST Flag Count',
    'PSH Flag Cnt': 'PSH Flag Count',
    'ACK Flag Cnt': 'ACK Flag Count',
    'URG Flag Cnt': 'URG Flag Count',
    'CWE Flag Count': 'CWE Flag Count',
    'ECE Flag Cnt': 'ECE Flag Count',
    'Down/Up Ratio': 'Down/Up Ratio',
    'Pkt Size Avg': 'Average Packet Size',
    'Fwd Seg Size Avg': 'Avg Fwd Segment Size',
    'Bwd Seg Size Avg': 'Avg Bwd Segment Size',
    'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Pkts/b Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Blk Rate Avg': 'Fwd Avg Bulk Rate',
    'Bwd Byts/b Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Pkts/b Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
    'Subflow Fwd Pkts': 'Subflow Fwd Packets',
    'Subflow Fwd Byts': 'Subflow Fwd Bytes',
    'Subflow Bwd Pkts': 'Subflow Bwd Packets',
    'Subflow Bwd Byts': 'Subflow Bwd Bytes',
    'Init Fwd Win Byts': 'Init_Win_bytes_forward',
    'Init Bwd Win Byts': 'Init_Win_bytes_backward',
    'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Seg Size Min': 'min_seg_size_forward',
    'Active Mean': 'Active Mean',
    'Active Std': 'Active Std',
    'Active Max': 'Active Max',
    'Active Min': 'Active Min',
    'Idle Mean': 'Idle Mean',
    'Idle Std': 'Idle Std',
    'Idle Max': 'Idle Max',
    'Idle Min': 'Idle Min',
}
# Tên cột của CICFlowMeter bản mã nguồn GitHub (ahlashkari/CICFlowMeter, nhánh master) – bản app tự build
# trong tools_ext/ để bắt lưu lượng thật. Chỉ liệt kê các tên khác với bảng trên.
_CFM_GITHUB_TO_2017 = {
    'Total Fwd Packet': 'Total Fwd Packets',
    'Total Bwd packets': 'Total Backward Packets',
    'Total Length of Fwd Packet': 'Total Length of Fwd Packets',
    'Total Length of Bwd Packet': 'Total Length of Bwd Packets',
    'Packet Length Min': 'Min Packet Length',
    'Packet Length Max': 'Max Packet Length',
    'FWD Init Win Bytes': 'Init_Win_bytes_forward',
    'Bwd Init Win Bytes': 'Init_Win_bytes_backward',
    'Fwd Segment Size Avg': 'Avg Fwd Segment Size',
    'Bwd Segment Size Avg': 'Avg Bwd Segment Size',
    'Fwd Bytes/Bulk Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Packet/Bulk Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Bulk Rate Avg': 'Fwd Avg Bulk Rate',
    'Bwd Bytes/Bulk Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Packet/Bulk Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Bulk Rate Avg': 'Bwd Avg Bulk Rate',
}
ALIASES = {canon(k): v for k, v in {**_CFM4_TO_2017, **_CFM_GITHUB_TO_2017}.items()}

# Cột thông tin: giữ lại để hiển thị, KHÔNG đưa vào mô hình (khóa chuẩn -> tên hiển thị)
INFO_COLUMNS = {
    'flowid': 'Flow ID',
    'srcip': 'Src IP', 'sourceip': 'Src IP',
    'dstip': 'Dst IP', 'destinationip': 'Dst IP',
    'srcport': 'Src Port', 'sourceport': 'Src Port',
    'protocol': 'Protocol',
    'timestamp': 'Timestamp',
    'label': 'Label',
}
# Cột cổng đích vừa là đặc trưng của mô hình vừa được hiển thị
DST_PORT_FEATURE = 'Destination Port'


@dataclass
class AlignReport:
    """Báo cáo khớp cột để hiển thị trên giao diện."""
    n_expected: int
    matched: list = field(default_factory=list)       # cột đặc trưng tìm thấy (tên huấn luyện)
    missing: list = field(default_factory=list)       # cột đặc trưng thiếu -> điền median trong preprocessor
    extra: list = field(default_factory=list)         # cột đầu vào không dùng tới
    renamed: dict = field(default_factory=dict)       # tên gốc -> tên huấn luyện (khi khác nhau)
    info_cols: list = field(default_factory=list)     # cột thông tin giữ lại để hiển thị
    n_rows: int = 0

    @property
    def match_ratio(self):
        return len(self.matched) / self.n_expected if self.n_expected else 0.0

    def as_dict(self):
        return {'Số cột mô hình cần': self.n_expected, 'Số cột khớp': len(self.matched),
                'Số cột thiếu': len(self.missing), 'Số cột thừa': len(self.extra),
                'Tỉ lệ khớp': f'{self.match_ratio:.0%}'}


def map_column(name, feature_set_canon):
    """Trả về tên cột lúc huấn luyện tương ứng với `name` (hoặc None nếu không phải đặc trưng)."""
    k = canon(name)
    if k in feature_set_canon:            # (a) trùng tên CIC-IDS2017 (sau khi bỏ khoảng trắng/ký tự)
        return feature_set_canon[k]
    if k in ALIASES:                      # (b), (c)
        return ALIASES[k]
    return None


def align_features(df, feature_columns, fill_missing='median'):
    """Ánh xạ cột của `df` về đúng tên và thứ tự `feature_columns`.

    Trả về (X, info, report):
      X      : DataFrame các cột đặc trưng theo đúng thứ tự huấn luyện. Cột thiếu để NaN
               (NIDSPreprocessor sẽ điền median của train) hoặc 0 nếu fill_missing=0.
      info   : DataFrame các cột thông tin (IP, port, Timestamp, Label...) để hiển thị.
      report : AlignReport liệt kê cột khớp/thiếu/thừa và tỉ lệ khớp.
    """
    feature_columns = list(feature_columns)
    feat_canon = {canon(c): c for c in feature_columns}
    df = df.copy()
    df.columns = [normalize_name(c) for c in df.columns]
    df = df.loc[:, ~pd.Index(df.columns).duplicated()]   # vd 'Fwd Header Length.1' vẫn là tên riêng

    report = AlignReport(n_expected=len(feature_columns), n_rows=len(df))
    rename, info_map, used = {}, {}, set()
    for c in df.columns:
        k = canon(c)
        target = map_column(c, feat_canon)
        if target is not None and target in feat_canon.values():
            if target in used:            # trùng ánh xạ -> giữ cột đầu tiên
                report.extra.append(c)
                continue
            used.add(target)
            rename[c] = target
            if c != target:
                report.renamed[c] = target
        elif k in INFO_COLUMNS:
            info_map[c] = INFO_COLUMNS[k]
        elif target is not None:          # là đặc trưng CICFlowMeter nhưng mô hình không dùng
            report.extra.append(c)
        else:
            report.extra.append(c)

    info = df[list(info_map)].rename(columns=info_map) if info_map else pd.DataFrame(index=df.index)
    info = info.loc[:, ~info.columns.duplicated()]
    X = df[list(rename)].rename(columns=rename)
    X = clean_raw(X)                      # ép số, inf -> NaN
    report.matched = [c for c in feature_columns if c in X.columns]
    report.missing = [c for c in feature_columns if c not in X.columns]
    for c in report.missing:
        X[c] = np.nan if fill_missing == 'median' else fill_missing
    X = X[feature_columns]
    if DST_PORT_FEATURE in X.columns:
        info.insert(0, 'Dst Port', X[DST_PORT_FEATURE].values)
    report.info_cols = list(info.columns)
    return X.reset_index(drop=True), info.reset_index(drop=True), report


# ----------------------------------------------------------------------------- nhãn
def normalize_cic_label(s):
    """Chuẩn hóa ký tự lỗi encoding trong nhãn Web Attack (giống notebook)."""
    s = str(s).strip()
    if s.lower().startswith('web attack'):
        rest = re.sub(r'^web attack[^a-z]*', '', s, flags=re.I)
        return 'Web Attack - ' + rest.strip()
    return s


def group_cic_label(lbl):
    """Gộp 15 nhãn gốc CIC-IDS2017 thành 9 nhóm (giống notebook)."""
    l = str(lbl).lower()
    if l == 'benign':
        return 'Benign'
    if 'ddos' in l:
        return 'DDoS'
    if l.startswith('dos'):
        return 'DoS'
    if 'portscan' in l or 'port scan' in l:
        return 'PortScan'
    if 'web attack' in l or 'xss' in l or 'sql' in l:
        return 'Web Attack'
    if 'patator' in l or 'brute' in l:
        return 'Brute Force'
    if l.startswith('bot'):
        return 'Bot'
    if 'infiltration' in l:
        return 'Infiltration'
    if 'heartbleed' in l:
        return 'Heartbleed'
    return 'Other'


def true_labels(info):
    """Nếu có cột Label: trả về Series nhãn đã gộp 9 nhóm; ngược lại None.

    Hỗ trợ cả nhãn đã gộp sẵn, nhãn gốc CIC-IDS2017 và nhãn CSE-CIC-IDS2018 (vd 'DoS attacks-Hulk',
    'FTP-BruteForce'); nhãn không nhận ra được -> 'Other'.
    """
    if 'Label' not in info.columns:
        return None
    lab = info['Label'].astype(str).str.strip()
    if lab.str.lower().isin(['', 'nan', 'none']).all():
        return None
    # CSE-CIC-IDS2018 viết sai chính tả 'Infilteration'
    lab = lab.str.replace('Infilteration', 'Infiltration', case=False, regex=False)
    return lab.map(lambda s: group_cic_label(normalize_cic_label(s)))
