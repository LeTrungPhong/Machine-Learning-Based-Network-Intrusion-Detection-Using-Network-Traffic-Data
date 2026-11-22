# -*- coding: utf-8 -*-
"""Cấu hình chung của ứng dụng demo NIDS.

Mọi đường dẫn đều tính tương đối so với thư mục chứa file này (không hard-code đường dẫn tuyệt đối).
Có thể ghi đè một số giá trị bằng biến môi trường (xem từng mục).
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# ----------------------------------------------------------------------------- artifacts
ARTIFACT_DIR = Path(os.environ.get('NIDS_ARTIFACT_DIR', BASE_DIR / 'artifacts'))
DATA_DIR = Path(os.environ.get('NIDS_DATA_DIR', BASE_DIR / 'data'))

MODEL_NAMES = ['Random Forest', 'CNN-BiLSTM']
COMPARE_MODE = 'So sánh cả hai'
BINARY_CLASSES = ['Normal', 'Attack']   # thứ tự lớp của mô hình nhị phân (y_bin = 0/1)

# Mỗi bộ dữ liệu huấn luyện = một bộ artifacts riêng (preprocessor, label encoder, 4 mô hình).
#   key        : hậu tố tên file trong artifacts/ (vd rf_<key>_multi.joblib)
#   normal     : tên lớp bình thường trong bài toán đa lớp
#   sample_csv : dữ liệu mẫu (tập test) dùng cho các trang demo và kiểm thử
#   kaggle_ref : kết quả trên tập test Kaggle (nids_results/results/summary_metrics.csv)
#   input      : loại đặc trưng đầu vào (để hiển thị hướng dẫn)
DATASETS = {
    'CIC-IDS2017': {
        'key': 'cic_ids2017',
        'normal': 'Benign',
        'sample_csv': DATA_DIR / 'sample_test.csv',      # xuất từ Kaggle bằng tools/kaggle_export_sample.py
        'input': 'CICFlowMeter',
        'kaggle_ref': {
            ('Random Forest', 'multi'): {'accuracy': 0.9988, 'f1_macro': 0.9832},
            ('CNN-BiLSTM', 'multi'): {'accuracy': 0.9977, 'f1_macro': 0.9694},
            ('Random Forest', 'binary'): {'accuracy': 0.9989, 'f1_macro': 0.9981},
            ('CNN-BiLSTM', 'binary'): {'accuracy': 0.9985, 'f1_macro': 0.9974},
        },
    },
}
DATASET_NAMES = list(DATASETS)
DEFAULT_DATASET = 'CIC-IDS2017'


def artifact_paths(dataset):
    """Đường dẫn preprocessor, label encoder và 4 mô hình của một bộ dữ liệu."""
    k = DATASETS[dataset]['key']
    return {
        'preprocessor': ARTIFACT_DIR / f'preprocessor_{k}.joblib',
        'label_encoder': ARTIFACT_DIR / f'label_encoder_{k}.joblib',
        'models': {
            'Random Forest': {'multi': ARTIFACT_DIR / f'rf_{k}_multi.joblib',
                              'binary': ARTIFACT_DIR / f'rf_{k}_binary.joblib'},
            'CNN-BiLSTM': {'multi': ARTIFACT_DIR / f'dl_{k}_multi.keras',
                           'binary': ARTIFACT_DIR / f'dl_{k}_binary.keras'},
        },
    }


# Giữ tương thích với mã/kiểm thử cũ (mặc định CIC-IDS2017)
_cic = artifact_paths('CIC-IDS2017')
PREPROCESSOR_FILE = _cic['preprocessor']
LABEL_ENCODER_FILE = _cic['label_encoder']
MODEL_FILES = _cic['models']
NORMAL_LABEL = DATASETS['CIC-IDS2017']['normal']
SAMPLE_CSV = DATASETS['CIC-IDS2017']['sample_csv']
KAGGLE_REFERENCE = DATASETS['CIC-IDS2017']['kaggle_ref']

# ----------------------------------------------------------------------------- suy luận
# Lúc huấn luyện, nhãn dự đoán = argmax xác suất (tương đương ngưỡng 0,5 cho nhị phân).
# Ngưỡng dưới đây chỉ dùng để quyết định có PHÁT CẢNH BÁO hay không trên giao diện.
DEFAULT_ALERT_THRESHOLD = 0.9    # mặc định cao để giảm báo nhầm trên lưu lượng thật
BATCH_SIZE = 20_000          # số dòng mỗi batch khi dự đoán file lớn
DL_PREDICT_BATCH = 4096      # batch_size cho model.predict của Keras (giống notebook)
MAX_STYLED_ROWS = 2_000      # số dòng tối đa được tô màu trong bảng (tránh chậm giao diện)

# ----------------------------------------------------------------------------- cấp 2: PCAP
# 'auto' = thử gói Python trước, sau đó tới bản Java
PCAP_BACKEND = os.environ.get('NIDS_PCAP_BACKEND', 'auto')       # 'auto' | 'python' | 'java'
CICFLOWMETER_PY_CMD = os.environ.get('NIDS_CFM_PY_CMD', 'cicflowmeter')
# Đường dẫn tới cfm.bat (Windows) hoặc cfm (Linux) trong thư mục bin của CICFlowMeter Java
_CFM_LOCAL = BASE_DIR / 'tools_ext' / 'CICFlowMeter-4.0' / 'bin' / 'cfm.bat'   # bản build sẵn trong dự án
CICFLOWMETER_JAVA_BIN = os.environ.get('NIDS_CFM_JAVA_BIN', str(_CFM_LOCAL) if _CFM_LOCAL.exists() else '')
PCAP_WORK_DIR = DATA_DIR / 'pcap_work'
PCAP_TIMEOUT_S = 600

# ----------------------------------------------------------------------------- cấp 3: giám sát
WATCH_DIR = Path(os.environ.get('NIDS_WATCH_DIR', DATA_DIR / 'live'))
REFRESH_SECONDS = 3            # chu kỳ tự làm mới trang giám sát
SIM_CHUNK_ROWS = 50            # số dòng mỗi đợt ở chế độ mô phỏng
SIM_FILE_NAME = 'simulated_flows.csv'
LIVE_HISTORY_LIMIT = 5_000     # số luồng gần nhất giữ trong bộ nhớ

UI_NOTE = ('Kết quả trên lưu lượng ngoài CICIDS2017 có thể kém hơn do khác biệt '
           'môi trường mạng và phiên bản CICFlowMeter.')

# ----------------------------------------------------------------------------- cấp 3+: bắt lưu lượng thật của máy
# Hướng Java: dumpcap (Wireshark, dùng Npcap) cắt pcap mỗi CAPTURE_ROTATE_SECONDS giây -> CICFlowMeter Java (cfm)
# chuyển từng file đã cắt xong thành CSV -> chuyển vào WATCH_DIR -> LiveFolderSource đọc dòng mới.
DUMPCAP_BIN = os.environ.get('NIDS_DUMPCAP', r'C:\Program Files\Wireshark\dumpcap.exe')
CAPTURE_ROTATE_SECONDS = int(os.environ.get('NIDS_CAPTURE_ROTATE', 30))   # độ trễ tối thiểu ~ giá trị này + flow timeout
CAPTURE_DIR = DATA_DIR / 'capture'           # file pcap tạm (xóa sau khi xử lý nếu CAPTURE_KEEP_PCAP=False)
CAPTURE_KEEP_PCAP = False
CAPTURE_FILE_PREFIX = 'live'                 # tên CSV trong WATCH_DIR: live_<thời điểm>.csv

# Giảm báo nhầm
AGG_WINDOW_SECONDS = 60      # cửa sổ gom cảnh báo theo IP nguồn
AGG_MIN_FLOWS = 5            # cần >= N luồng nghi ngờ của cùng IP nguồn trong cửa sổ mới phát cảnh báo
WHITELIST_FILE = DATA_DIR / 'whitelist.json'  # bản chỉnh trên UI được lưu ở đây (ghi đè giá trị mặc định dưới)
WHITELIST_IPS = []           # vd ['192.168.1.1'] – router, DNS nội bộ...
WHITELIST_PORTS = [53, 67, 68, 123, 137, 138, 1900, 5353, 5355]   # DNS, DHCP, NTP, NetBIOS, SSDP, mDNS, LLMNR
ALERTS_LOG = DATA_DIR / 'alerts.csv'          # log cảnh báo (minh chứng cho báo cáo)

# Thu thập lưu lượng bình thường (để huấn luyện lại / fine-tune)
BENIGN_DIR = DATA_DIR / 'benign_capture'
BENIGN_LABEL = 'BENIGN'

UI_NOTE_CAPTURE = ('Chỉ giám sát mạng thuộc quyền quản lý của bạn. Luồng chỉ được ghi sau khi kết thúc hoặc hết '
                   'flow timeout của CICFlowMeter (cộng thời gian cắt file pcap), nên cảnh báo trễ hơn thực tế.')
