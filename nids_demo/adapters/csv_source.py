# -*- coding: utf-8 -*-
"""Cấp 1: đọc file CSV luồng mạng (tải lên từ giao diện hoặc từ đường dẫn)."""
import io

import pandas as pd

from adapters.base import FlowSource


def read_flow_csv(src, nrows=None):
    """Đọc CSV giống notebook (low_memory=False); thử utf-8 trước rồi latin1 (file CIC-IDS2017 gốc)."""
    data = src.getvalue() if hasattr(src, 'getvalue') else None
    for enc in ('utf-8', 'latin1'):
        try:
            handle = io.BytesIO(data) if data is not None else src
            return pd.read_csv(handle, low_memory=False, encoding=enc, nrows=nrows)
        except UnicodeDecodeError:
            continue
    raise ValueError('Không đọc được file CSV (lỗi mã hóa ký tự).')


class CSVSource(FlowSource):
    """Nguồn từ một file CSV (đường dẫn hoặc đối tượng UploadedFile của Streamlit)."""

    name = 'csv'

    def __init__(self, src, nrows=None):
        self.src = src
        self.nrows = nrows

    def get_flows(self):
        return read_flow_csv(self.src, self.nrows)
