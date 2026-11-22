# -*- coding: utf-8 -*-
"""Bắt lưu lượng thật của máy và chuyển thành CSV luồng cho trang "Giám sát trực tiếp".

Hướng Java (khớp đặc trưng CIC-IDS2017 nhất):

    dumpcap -i <card> -b duration:N -F pcap -w capture/live.pcap      (Wireshark, dùng Npcap)
        └─ mỗi N giây đóng một file pcap: live_00001_<thời điểm>.pcap
    CaptureSession._worker: file pcap nào đã đóng -> cfm.bat <file> <thư mục tạm>   (CICFlowMeter Java)
        └─ <file>_Flow.csv -> (thêm cột Label=BENIGN nếu đang thu thập) -> os.replace vào thư mục đích
    LiveFolderSource (live_source.py) đọc các dòng mới trong thư mục đích như cũ.

Lý do không bắt trực tiếp bằng CICFlowMeter: bản Java chỉ bắt realtime qua giao diện đồ họa; lệnh `cfm`
chỉ xử lý file pcap. Độ trễ ≈ CAPTURE_ROTATE_SECONDS + flow timeout của CICFlowMeter.
"""
import ctypes
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd

import config
from adapters.base import SourceUnavailable
from adapters.pcap_source import HELP_JAVA, java_backend_cmd

HELP_DUMPCAP = """
**dumpcap (Wireshark)** – dùng để bắt gói qua Npcap:
```powershell
winget install WiresharkFoundation.Wireshark
```
Khi cài, có thể bỏ chọn Npcap nếu máy đã có. Đường dẫn khác mặc định → đặt biến `NIDS_DUMPCAP`.
"""

HELP_PERMISSION = """
Không mở được card mạng. Thử lần lượt:
1. Đóng app, mở **PowerShell bằng *Run as administrator***, chạy lại `streamlit run app.py`.
2. Kiểm tra Npcap đang chạy: `Get-Service npcap`. Nếu lúc cài Npcap chọn *Restrict Npcap driver's access to
   Administrators only* thì bắt buộc chạy app bằng quyền Administrator.
3. Chọn đúng card đang có kết nối (Wi-Fi / Ethernet / VMware VMnet1 cho mạng Host-only).
"""

_NO_WINDOW = 0x08000000 if sys.platform == 'win32' else 0      # CREATE_NO_WINDOW – không bật cửa sổ console


@dataclass(frozen=True)
class Interface:
    index: str          # số thứ tự theo `dumpcap -D` (dùng cho -i)
    device: str         # \Device\NPF_{...}
    name: str           # tên thân thiện (Wi-Fi, VMware Network Adapter VMnet1...)

    @property
    def label(self):
        hint = ''
        n = self.name.lower()
        if 'vmnet1' in n or 'host-only' in n or 'virtualbox' in n:
            hint = ' – mạng Host-only (lab máy ảo)'
        elif 'loopback' in n:
            hint = ' – loopback'
        return f'{self.name}{hint}'


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin()) if sys.platform == 'win32' else os.geteuid() == 0
    except Exception:
        return False


def dumpcap_path():
    p = Path(config.DUMPCAP_BIN)
    if p.exists():
        return str(p)
    return shutil.which('dumpcap')


def capture_status():
    """Trạng thái các thành phần cần cho bắt lưu lượng thật (hiển thị trên UI)."""
    return {
        'dumpcap': dumpcap_path() is not None,
        'cicflowmeter_java': java_backend_cmd() is not None,
        'java': shutil.which('java') is not None,
        'admin': is_admin(),
    }


def missing_help(status=None):
    """Markdown hướng dẫn cài phần còn thiếu ('' nếu đủ)."""
    s = status or capture_status()
    parts = []
    if not s['dumpcap']:
        parts.append(HELP_DUMPCAP)
    if not s['cicflowmeter_java']:
        parts.append(HELP_JAVA)
    return '\n'.join(parts)


_IFACE_RE = re.compile(r'^\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$')


def parse_interfaces(text):
    """Phân tích đầu ra `dumpcap -D`."""
    out = []
    for line in text.splitlines():
        m = _IFACE_RE.match(line)
        if m:
            out.append(Interface(m.group(1), m.group(2), m.group(3) or m.group(2)))
    return out


def list_interfaces():
    """Danh sách card mạng (Wi-Fi, Ethernet, card ảo VMware/VirtualBox...)."""
    exe = dumpcap_path()
    if not exe:
        raise SourceUnavailable('Chưa cài dumpcap (Wireshark).', HELP_DUMPCAP)
    proc = subprocess.run([exe, '-D'], capture_output=True, text=True, timeout=30, creationflags=_NO_WINDOW)
    if proc.returncode != 0:
        raise SourceUnavailable(f'dumpcap -D lỗi: {(proc.stderr or proc.stdout).strip()[:500]}', HELP_PERMISSION)
    ifaces = parse_interfaces(proc.stdout)
    # card hay dùng lên đầu
    rank = lambda i: (0 if i.name.lower().startswith(('wi-fi', 'ethernet')) else
                      1 if 'vmnet1' in i.name.lower() or 'host-only' in i.name.lower() else
                      2 if 'local area connection' not in i.name.lower() else 3)
    return sorted(ifaces, key=rank)


def label_benign(csv_path, label=None):
    """Ghi đè cột Label = BENIGN (chế độ thu thập lưu lượng bình thường)."""
    df = pd.read_csv(csv_path, low_memory=False)
    lab = [c for c in df.columns if c.strip().lower() == 'label']
    df = df.drop(columns=lab)
    df['Label'] = label or config.BENIGN_LABEL
    df.to_csv(csv_path, index=False)
    return len(df)


class CaptureSession:
    """Một phiên bắt lưu lượng: tiến trình dumpcap + luồng nền chạy CICFlowMeter trên từng file pcap đã đóng."""

    def __init__(self, interface, out_dir=None, benign=False, rotate_s=None, capture_dir=None,
                 keep_pcap=None, flow_cmd=None, dumpcap=None):
        self.interface = interface                      # Interface hoặc chuỗi chỉ số/tên card
        self.out_dir = Path(out_dir or (config.BENIGN_DIR if benign else config.WATCH_DIR))
        self.benign = benign
        self.rotate_s = int(rotate_s or config.CAPTURE_ROTATE_SECONDS)
        self.capture_dir = Path(capture_dir or config.CAPTURE_DIR) / datetime.now().strftime('%Y%m%d_%H%M%S')
        self.keep_pcap = config.CAPTURE_KEEP_PCAP if keep_pcap is None else keep_pcap
        self.flow_cmd = flow_cmd                         # để test: hàm (pcap, out_dir) -> list lệnh
        self.dumpcap = dumpcap
        self.proc = None
        self._thread = None
        self._stop = threading.Event()
        self._done = set()
        self.log = []                                    # nhật ký hiển thị trên UI
        self.error = None                                # (message, help_md) khi lỗi
        self.files_done = 0
        self.flows_written = 0
        self.started_at = None

    # ------------------------------------------------------------------ tiện ích
    def _log(self, msg):
        self.log.append(f'{datetime.now():%H:%M:%S} {msg}')
        del self.log[:-200]

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def _iface_arg(self):
        return self.interface.index if isinstance(self.interface, Interface) else str(self.interface)

    # ------------------------------------------------------------------ điều khiển
    def start(self):
        exe = self.dumpcap or dumpcap_path()
        if not exe:
            raise SourceUnavailable('Chưa cài dumpcap (Wireshark).', HELP_DUMPCAP)
        if self.flow_cmd is None and java_backend_cmd() is None:
            raise SourceUnavailable('Chưa cấu hình CICFlowMeter bản Java (biến NIDS_CFM_JAVA_BIN).', HELP_JAVA)
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        cmd = (list(exe) if isinstance(exe, (list, tuple)) else [exe]) + ['-i', self._iface_arg(), '-q', '-F', 'pcap', '-b', f'duration:{self.rotate_s}',
               '-w', str(self.capture_dir / f'{config.CAPTURE_FILE_PREFIX}.pcap')]
        self._log('Chạy: ' + ' '.join(cmd))
        self._stderr = open(self.capture_dir / 'dumpcap.log', 'w', encoding='utf-8', errors='replace')
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=self._stderr, creationflags=_NO_WINDOW)
        except OSError as e:
            raise SourceUnavailable(f'Không chạy được dumpcap: {e}', HELP_PERMISSION)
        time.sleep(1.5)                                  # lỗi quyền/card sai thường làm dumpcap thoát ngay
        if self.proc.poll() is not None:
            msg = self._dumpcap_output()
            self.proc = None
            raise SourceUnavailable(f'dumpcap dừng ngay khi khởi động: {msg}', HELP_PERMISSION)
        self.started_at = time.time()
        self._stop.clear()
        self._thread = threading.Thread(target=self._worker, name='nids-capture', daemon=True)
        self._thread.start()
        self._log(f'Đang bắt trên card {self._iface_arg()} – cắt file mỗi {self.rotate_s}s → {self.out_dir}')

    def stop(self):
        """Dừng dumpcap rồi xử lý nốt các file pcap còn lại."""
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=config.PCAP_TIMEOUT_S)
        self._process_ready(final=True)
        try:
            self._stderr.close()
        except Exception:
            pass
        self._log('Đã dừng bắt lưu lượng.')

    def _dumpcap_output(self):
        try:
            self._stderr.flush()
            return (self.capture_dir / 'dumpcap.log').read_text(encoding='utf-8', errors='replace').strip()[-800:]
        except Exception:
            return '(không đọc được log)'

    # ------------------------------------------------------------------ xử lý pcap -> CSV
    def _worker(self):
        while not self._stop.is_set():
            if self.proc is not None and self.proc.poll() is not None and self.error is None:
                self.error = (f'dumpcap đã dừng (mã {self.proc.returncode}): {self._dumpcap_output()}', HELP_PERMISSION)
                self._log(self.error[0])
            try:
                self._process_ready(final=False)
            except Exception as e:                       # không để luồng nền chết vì một file lỗi
                self._log(f'Lỗi xử lý: {e}')
            self._stop.wait(2)

    def pending_files(self, final=False):
        files = sorted(p for p in self.capture_dir.glob('*.pcap') if p not in self._done)
        if not final and files:
            files = files[:-1]                           # file mới nhất đang được dumpcap ghi
        return files

    def _flow_cmd(self, pcap, out_dir):
        if self.flow_cmd is not None:
            return self.flow_cmd(pcap, out_dir)
        return java_backend_cmd() + [str(pcap), str(out_dir)]

    def _process_ready(self, final=False):
        for pcap in self.pending_files(final):
            self._done.add(pcap)
            if pcap.stat().st_size <= 24:                # chỉ có header pcap, không có gói
                self._cleanup(pcap)
                continue
            tmp = self.capture_dir / f'out_{pcap.stem}'
            tmp.mkdir(exist_ok=True)
            proc = subprocess.run(self._flow_cmd(pcap, tmp), capture_output=True, text=True,
                                  timeout=config.PCAP_TIMEOUT_S, creationflags=_NO_WINDOW)
            csvs = sorted(tmp.glob('*.csv'))
            if proc.returncode != 0 or not csvs:
                self._log(f'CICFlowMeter lỗi với {pcap.name} (mã {proc.returncode}): '
                          f'{((proc.stdout or "") + (proc.stderr or "")).strip()[-300:]}')
                continue
            for csv in csvs:
                n = label_benign(csv) if self.benign else max(sum(1 for _ in open(csv, 'rb')) - 1, 0)
                if n <= 0:
                    continue
                stem = pcap.stem if pcap.stem.startswith(config.CAPTURE_FILE_PREFIX + '_') else f'{config.CAPTURE_FILE_PREFIX}_{pcap.stem}'
                dest = self.out_dir / f'{stem}.csv'
                os.replace(csv, dest)                    # chuyển nguyên file -> LiveFolderSource không đọc dở
                self.flows_written += n
                self._log(f'{pcap.name}: {n} luồng → {dest.name}')
            self.files_done += 1
            shutil.rmtree(tmp, ignore_errors=True)
            self._cleanup(pcap)

    def _cleanup(self, pcap):
        if not self.keep_pcap:
            try:
                pcap.unlink()
            except OSError:
                pass
