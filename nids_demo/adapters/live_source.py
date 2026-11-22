# -*- coding: utf-8 -*-
"""Cấp 3: theo dõi thư mục mà CICFlowMeter (chế độ realtime) ghi CSV vào; chỉ đọc các dòng MỚI.

Cơ chế: với mỗi file *.csv, ghi nhớ header và vị trí byte đã đọc. Lần gọi sau chỉ đọc phần được
ghi thêm, và chỉ lấy tới ký tự xuống dòng cuối cùng (dòng đang ghi dở được để lần sau).

FlowSimulator: chế độ mô phỏng – phát lại một CSV mẫu từng đợt nhỏ vào thư mục giám sát.
"""
import io
from pathlib import Path

import pandas as pd

import config
from adapters.base import FlowSource, SourceUnavailable


class LiveFolderSource(FlowSource):
    name = 'live'

    def __init__(self, watch_dir=None, pattern='*.csv'):
        self.watch_dir = Path(watch_dir or config.WATCH_DIR)
        self.pattern = pattern
        self._offsets = {}    # file -> vị trí byte đã đọc
        self._headers = {}    # file -> dòng header

    def reset(self, skip_existing=False):
        """Quên trạng thái đọc. skip_existing=True: bỏ qua dữ liệu đã có, chỉ đọc dữ liệu ghi sau thời điểm này."""
        self._offsets.clear()
        self._headers.clear()
        if skip_existing and self.watch_dir.exists():
            for f in self.watch_dir.glob(self.pattern):
                self._read_header(f)
                self._offsets[f] = f.stat().st_size

    def _read_header(self, f):
        with open(f, 'rb') as fh:
            line = fh.readline()
        if line.endswith(b'\n'):
            self._headers[f] = line.decode('utf-8', errors='replace').rstrip('\r\n')
            return len(line)
        return None

    def get_flows(self):
        if not self.watch_dir.exists():
            raise SourceUnavailable(f'Thư mục giám sát chưa tồn tại: {self.watch_dir}',
                                    'Tạo thư mục này hoặc đổi `WATCH_DIR` trong config.py / biến môi trường `NIDS_WATCH_DIR`.')
        frames = []
        for f in sorted(self.watch_dir.glob(self.pattern)):
            size = f.stat().st_size
            if f not in self._headers:
                start = self._read_header(f)
                if start is None:
                    continue          # header chưa ghi xong
                self._offsets[f] = start
            pos = self._offsets.get(f, 0)
            if size < pos:            # file bị ghi đè/cắt ngắn -> đọc lại từ đầu
                self._headers.pop(f, None)
                self._offsets.pop(f, None)
                continue
            if size == pos:
                continue
            with open(f, 'rb') as fh:
                fh.seek(pos)
                chunk = fh.read(size - pos)
            cut = chunk.rfind(b'\n')
            if cut < 0:
                continue              # chưa có dòng hoàn chỉnh
            self._offsets[f] = pos + cut + 1
            text = self._headers[f] + '\n' + chunk[:cut + 1].decode('utf-8', errors='replace')
            df = pd.read_csv(io.StringIO(text), low_memory=False)
            if len(df):
                df['__source_file'] = f.name
                frames.append(df)
        return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


class FlowSimulator:
    """Phát lại sample CSV vào WATCH_DIR theo từng đợt để demo khi chưa có lab thật."""

    def __init__(self, sample_df, watch_dir=None, chunk_rows=None, file_name=None, seed=42):
        self.df = sample_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
        self.watch_dir = Path(watch_dir or config.WATCH_DIR)
        self.chunk = chunk_rows or config.SIM_CHUNK_ROWS
        self.path = self.watch_dir / (file_name or config.SIM_FILE_NAME)
        self.pos = 0

    def start(self):
        """Tạo file mới (ghi header)."""
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.df.iloc[:0].to_csv(self.path, index=False)
        self.pos = 0

    def step(self):
        """Ghi thêm một đợt dòng; trả về số dòng đã ghi (0 khi hết dữ liệu)."""
        if self.pos >= len(self.df):
            return 0
        part = self.df.iloc[self.pos:self.pos + self.chunk]
        part.to_csv(self.path, mode='a', header=False, index=False)
        self.pos += len(part)
        return len(part)
