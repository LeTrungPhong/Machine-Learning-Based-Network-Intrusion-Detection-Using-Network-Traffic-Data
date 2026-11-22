# -*- coding: utf-8 -*-
"""Cấp 2: chuyển .pcap/.pcapng thành bảng luồng bằng CICFlowMeter rồi đưa vào pipeline.

Hai backend (chọn trong config.PCAP_BACKEND):
  'python' : gói Python `cicflowmeter`   -> cicflowmeter -f file.pcap -c out.csv
  'java'   : CICFlowMeter Java (cfm.bat)  -> cfm.bat <thư mục pcap> <thư mục output>
Thiếu backend -> ném SourceUnavailable kèm hướng dẫn cài đặt (giao diện hiển thị, không crash).
"""
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd

import config
from adapters.base import FlowSource, SourceUnavailable
from adapters.csv_source import read_flow_csv

HELP_PYTHON = """
**Backend Python (`cicflowmeter`)**
```powershell
.\\.venv\\Scripts\\pip install cicflowmeter
```
Trên Windows cần cài thêm **Npcap** (https://npcap.com) để đọc file pcap. Kiểm tra: `cicflowmeter -h`.
Gói này cho tên cột dạng `flow_duration`, `tot_fwd_pkts`… (app tự ánh xạ).
"""

HELP_JAVA = """
**Backend Java (CICFlowMeter 4.0)**
1. Cài Java JDK 8+ và Npcap (Windows).
2. Tải và build CICFlowMeter: https://github.com/ahlashkari/CICFlowMeter (`gradlew distZip`), giải nén bản phân phối.
3. Đặt biến môi trường trỏ tới script trong thư mục `bin`, rồi chạy lại app:
```powershell
$env:NIDS_CFM_JAVA_BIN = "C:\\CICFlowMeter-4.0\\bin\\cfm.bat"
```
"""


def python_backend_cmd():
    """Trả về lệnh gọi cicflowmeter (list) hoặc None nếu chưa cài."""
    exe = shutil.which(config.CICFLOWMETER_PY_CMD)
    if exe:
        return [exe]
    scripts = Path(sys.executable).parent      # cài trong venv nhưng venv chưa nằm trong PATH
    for name in ('cicflowmeter.exe', 'cicflowmeter'):
        if (scripts / name).exists():
            return [str(scripts / name)]
    return None


def java_backend_cmd():
    """Trả về đường dẫn cfm.bat/cfm hoặc None."""
    p = config.CICFLOWMETER_JAVA_BIN
    if p and Path(p).exists() and shutil.which('java'):
        return [p]
    return None


def backend_status():
    """Trạng thái từng backend để hiển thị trên giao diện."""
    return {
        'python': python_backend_cmd() is not None,
        'java': java_backend_cmd() is not None,
        'java_bin': config.CICFLOWMETER_JAVA_BIN or '(chưa cấu hình)',
        'java_runtime': shutil.which('java') is not None,
    }


def pick_backend(preferred=None):
    pref = preferred or config.PCAP_BACKEND
    order = ['python', 'java'] if pref == 'auto' else [pref]
    for b in order:
        if b == 'python' and python_backend_cmd():
            return 'python'
        if b == 'java' and java_backend_cmd():
            return 'java'
    raise SourceUnavailable('Chưa cài backend CICFlowMeter nào để xử lý PCAP.', HELP_PYTHON + '\n' + HELP_JAVA)


class PcapSource(FlowSource):
    """Chạy CICFlowMeter trên một file pcap và trả về DataFrame luồng."""

    name = 'pcap'

    def __init__(self, pcap_path, backend=None, work_dir=None):
        self.pcap_path = Path(pcap_path)
        self.backend = backend
        self.work_dir = Path(work_dir or config.PCAP_WORK_DIR)
        self.last_command = None
        self.last_log = ''

    def _run(self, cmd):
        self.last_command = ' '.join(map(str, cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=config.PCAP_TIMEOUT_S)
        self.last_log = (proc.stdout or '') + (proc.stderr or '')
        if proc.returncode != 0:
            raise RuntimeError(f'CICFlowMeter lỗi (mã {proc.returncode}):\n{self.last_log[-2000:]}')

    def get_flows(self):
        if not self.pcap_path.exists():
            raise FileNotFoundError(self.pcap_path)
        backend = pick_backend(self.backend)
        out_dir = self.work_dir / f'run_{int(time.time())}'
        out_dir.mkdir(parents=True, exist_ok=True)
        if backend == 'python':
            out_csv = out_dir / (self.pcap_path.stem + '_flows.csv')
            self._run(python_backend_cmd() + ['-f', str(self.pcap_path), '-c', str(out_csv)])
        else:
            in_dir = out_dir / 'in'
            in_dir.mkdir(exist_ok=True)
            shutil.copy2(self.pcap_path, in_dir / self.pcap_path.name)
            self._run(java_backend_cmd() + [str(in_dir), str(out_dir)])
            found = sorted(out_dir.glob('*.csv'))
            if not found:
                raise RuntimeError('CICFlowMeter Java không tạo file CSV nào.\n' + self.last_log[-2000:])
            out_csv = found[0]
        if not out_csv.exists() or out_csv.stat().st_size == 0:
            raise RuntimeError('CICFlowMeter không tạo ra luồng nào (file pcap rỗng hoặc định dạng không hỗ trợ).')
        return read_flow_csv(out_csv)
