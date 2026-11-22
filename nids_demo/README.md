# NIDS Demo – ứng dụng web phát hiện xâm nhập mạng (CIC-IDS2017)

Ứng dụng Streamlit chạy local, dùng các mô hình **Random Forest** và **CNN-BiLSTM** đã huấn luyện trên
CIC-IDS2017 (notebook `../nids_results/kaggle_trainning.ipynb`). Có 3 cấp độ:

| Cấp | Nguồn dữ liệu | Trạng thái |
|---|---|---|
| 1 | File CSV luồng mạng (CICFlowMeter) | Hoàn chỉnh |
| 2 | File `.pcap/.pcapng` → CICFlowMeter → CSV | Khung sẵn, cần cài CICFlowMeter |
| 3 | Thư mục CSV do CICFlowMeter ghi liên tục (giám sát trực tiếp) | Khung sẵn + chế độ mô phỏng |

> ⚠️ Kết quả trên lưu lượng ngoài CICIDS2017 có thể kém hơn do khác biệt môi trường mạng và phiên bản CICFlowMeter.

## Cấu trúc

```
nids_demo/
├── app.py                 # Streamlit entry, điều hướng 5 trang
├── config.py              # đường dẫn artifacts, tên model, ngưỡng, thư mục watch, backend PCAP
├── requirements.txt       # phiên bản pin theo môi trường Kaggle
├── artifacts/             # preprocessor, label encoder, 4 mô hình, feature_columns.json
├── data/                  # sample_test.csv (xuất từ Kaggle), live/ (thư mục giám sát)
├── core/
│   ├── schema.py          # chuẩn hóa & ánh xạ tên cột (CIC-IDS2017 / CICFlowMeter 4.0 / cicflowmeter Python)
│   ├── preprocess.py      # NIDSPreprocessor (sao chép nguyên văn từ notebook), làm sạch, reshape
│   ├── model_loader.py    # nạp artifacts một lần
│   └── predictor.py       # dự đoán theo batch, đánh giá
├── adapters/
│   ├── base.py            # FlowSource: get_flows() -> DataFrame
│   ├── csv_source.py      # cấp 1
│   ├── pcap_source.py     # cấp 2
│   └── live_source.py     # cấp 3 + FlowSimulator
├── views/                 # 5 trang giao diện
├── tools/kaggle_export_sample.py   # chạy trên Kaggle để tạo sample_test.csv
└── tests/                 # pytest
```

## Pipeline tiền xử lý (giống hệt notebook)

1. Chuẩn hóa tên cột (strip, gộp khoảng trắng) và ánh xạ về 45 đặc trưng lúc huấn luyện (`artifacts/feature_columns.json`).
2. Ép cột về số (`'Infinity'`, chuỗi lạ → NaN), inf → NaN.
3. `NIDSPreprocessor.transform()` đã học trên train: chọn đúng 45 cột theo thứ tự, NaN/cột thiếu → **median của train**,
   signed-log `sign(x)·log1p(|x|)`, `StandardScaler`. Không fit lại.
4. CNN-BiLSTM: reshape `(n, 45, 1)`. Nhãn = argmax xác suất (như notebook); lớp đa lớp giải mã bằng `LabelEncoder`.
5. "Ngưỡng cảnh báo" trên giao diện chỉ quyết định có phát cảnh báo hay không (dự đoán Attack **và** độ tin cậy ≥ ngưỡng).

Khác biệt duy nhất so với lúc train: khi train, dòng chứa NaN bị **xóa** (2.867 dòng); khi suy luận không thể xóa
luồng nên dùng median – đúng cơ chế đã có sẵn trong `NIDSPreprocessor`.

---

## Cấp 1 – Cài đặt và chạy

### 1. Môi trường

Cần **Python 3.12** (Kaggle dùng 3.13; scikit-learn 1.6.1, TensorFlow 2.21 và numpy 2.1.3 đều có bản cho 3.12 trên Windows).

```powershell
cd nids_demo
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Phiên bản đã pin: numpy 2.1.3 · pandas 2.3.3 · scikit-learn 1.6.1 · tensorflow 2.21.0 · keras 3.13.2.
Không nâng cấp scikit-learn/keras – file `.joblib`/`.keras` có thể không nạp được.

### 2. Artifacts

Copy từ `nids_results/models/` (hoặc từ Output của notebook Kaggle) vào `artifacts/`:

```
preprocessor_cic_ids2017.joblib   label_encoder_cic_ids2017.joblib
rf_cic_ids2017_multi.joblib       rf_cic_ids2017_binary.joblib
dl_cic_ids2017_multi.keras        dl_cic_ids2017_binary.keras
```

### 3. Dữ liệu mẫu (chạy một lần trên Kaggle)

Dữ liệu CIC-IDS2017 chỉ có trên Kaggle. Mở notebook Kaggle (cùng input `MachineLearningCVE`), dán toàn bộ nội dung
`tools/kaggle_export_sample.py` vào một cell và chạy. Cell này tái tạo **đúng tập test** của notebook (cùng SEED) và ghi:

- `sample_test.csv` → đặt vào `nids_demo/data/`
- `versions.json` → đặt vào `nids_demo/artifacts/` (để đối chiếu phiên bản)

`sample_test.csv` gồm 20.000 dòng ngẫu nhiên của tập test (`Sample_Part = uniform`) và toàn bộ dòng test của các lớp hiếm.

### 4. Chạy app

```powershell
.\.venv\Scripts\streamlit.exe run app.py
```

Mở http://localhost:8501. Lần đầu nạp mô hình mất khoảng 10–20 giây.

| Trang | Chức năng |
|---|---|
| Phân tích file CSV | Upload CSV / dữ liệu mẫu, báo cáo khớp cột, KPI, bảng tô màu, phân bố tấn công, lọc, tải CSV; nếu có cột `Label`: accuracy, F1-macro, DR, FAR, confusion matrix, classification report |
| Kiểm tra từng luồng | Chọn ngẫu nhiên 1 luồng (lọc theo nhãn thật), so sánh dự đoán 2 mô hình, biểu đồ xác suất, đặc trưng quan trọng của RF |
| So sánh mô hình | Metric + thời gian suy luận của 2 mô hình, tỉ lệ đồng thuận, bảng chéo dự đoán, F1 theo lớp |
| Phân tích PCAP | Cấp 2 |
| Giám sát trực tiếp | Cấp 3 |

### 5. Kiểm thử

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests
```

- Ánh xạ cột với 3 bộ tên: CIC-IDS2017 gốc, CICFlowMeter 4.0/CSE-CIC-IDS2018, gói Python `cicflowmeter`.
- Xử lý inf/NaN/chuỗi lạ/cột thiếu; hình dạng đầu ra của 4 mô hình.
- Adapter PCAP báo lỗi thân thiện khi thiếu backend; giám sát chỉ đọc dòng mới.
- **Độ chính xác trên `sample_test.csv` so với Kaggle** (sai lệch accuracy < 0,005; ví dụ RF đa lớp ≈ 0,9988).
  Các test này tự bỏ qua nếu chưa có `data/sample_test.csv`.

---

## Cấp 2 – Phân tích PCAP

Cài **một** trong hai backend rồi mở trang "Phân tích PCAP". Trên Windows cần **Npcap** (https://npcap.com).

**(1) Gói Python `cicflowmeter`**

```powershell
.\.venv\Scripts\python.exe -m pip install cicflowmeter
.\.venv\Scripts\cicflowmeter.exe -h
```

App gọi `cicflowmeter -f file.pcap -c out.csv`. Tên cột dạng `flow_duration`, `tot_fwd_pkts`… được ánh xạ tự động.

**(2) CICFlowMeter Java 4.0**

1. Cài JDK 8+ (kiểm tra `java -version`).
2. Tải mã nguồn https://github.com/ahlashkari/CICFlowMeter, build bản phân phối (`gradlew distZip`) và giải nén.
3. Trỏ app tới script trong thư mục `bin`:

```powershell
$env:NIDS_CFM_JAVA_BIN = "C:\CICFlowMeter-4.0\bin\cfm.bat"
$env:NIDS_PCAP_BACKEND = "java"     # hoặc để 'auto'
.\.venv\Scripts\streamlit.exe run app.py
```

Lưu ý: các phiên bản CICFlowMeter khác nhau có thể tính một số đặc trưng khác nhau (đơn vị thời gian, cách tách luồng).
Kiểm tra "Báo cáo khớp cột" và đối chiếu thử với một pcap đã biết nhãn trước khi tin kết quả.

---

## Cấp 3 – Giám sát trực tiếp

### Chế độ mô phỏng (không cần lab)

Trang "Giám sát trực tiếp" → chọn **Mô phỏng** → **Bắt đầu**. App phát lại `sample_test.csv` từng đợt
(`SIM_CHUNK_ROWS` dòng) vào `data/live/simulated_flows.csv`, đọc phần mới mỗi `N` giây, cập nhật biểu đồ và
hiện toast khi có cảnh báo.

### Lab thật với VM (mạng Host-only)

> Chỉ thực hiện tấn công thử nghiệm trong lab cô lập do bạn sở hữu.

1. **VirtualBox/VMware**: tạo mạng **Host-only** (ví dụ `192.168.56.0/24`), không có NAT ra Internet cho các VM thử nghiệm.
2. **VM nạn nhân** (Ubuntu Server hoặc Metasploitable 2) và **VM tấn công** (Kali Linux) cùng gắn vào mạng Host-only.
3. **Máy host Windows** (chạy app) cài Npcap và một backend CICFlowMeter, bắt gói trên card mạng Host-only:
   - Gói Python (ghi liên tục vào một CSV):
     ```powershell
     .\.venv\Scripts\cicflowmeter.exe -i "VirtualBox Host-Only Ethernet Adapter" -c data\live\realtime_flows.csv
     ```
   - Hoặc CICFlowMeter Java bản GUI → *Network* → *Realtime*, chọn card Host-only và thư mục output `data\live`.
4. Trong app: trang "Giám sát trực tiếp" → **Thư mục CICFlowMeter thật** → **Bắt đầu**. App bỏ qua dữ liệu cũ, chỉ đọc luồng ghi sau thời điểm bấm.
5. Từ VM tấn công, tạo lưu lượng giống các lớp trong CIC-IDS2017, ví dụ: quét cổng (`nmap -sS 192.168.56.101`),
   dò mật khẩu SSH/FTP (`hydra`), DoS HTTP (`slowhttptest`). Luồng xuất hiện trong bảng cảnh báo sau khi CICFlowMeter đóng luồng (timeout).

Đổi thư mục giám sát bằng biến môi trường `NIDS_WATCH_DIR` hoặc `WATCH_DIR` trong `config.py`.

---

## Cấu hình

| Biến (config.py / môi trường) | Mặc định | Ý nghĩa |
|---|---|---|
| `ARTIFACT_DIR` / `NIDS_ARTIFACT_DIR` | `artifacts/` | Thư mục mô hình |
| `DATA_DIR` / `NIDS_DATA_DIR` | `data/` | Chứa `sample_test.csv`, `live/`, `pcap_work/` |
| `DEFAULT_ALERT_THRESHOLD` | 0,5 | Ngưỡng cảnh báo mặc định |
| `BATCH_SIZE` | 20.000 | Số dòng mỗi batch khi dự đoán |
| `PCAP_BACKEND` / `NIDS_PCAP_BACKEND` | `auto` | `auto`, `python`, `java` |
| `CICFLOWMETER_JAVA_BIN` / `NIDS_CFM_JAVA_BIN` | rỗng | Đường dẫn `cfm.bat` |
| `WATCH_DIR` / `NIDS_WATCH_DIR` | `data/live` | Thư mục giám sát |
| `REFRESH_SECONDS`, `SIM_CHUNK_ROWS` | 3, 50 | Chu kỳ làm mới, số dòng mỗi đợt mô phỏng |

## Giới hạn

- Mô hình chỉ biết 9 nhóm lưu lượng của CIC-IDS2017; lưu lượng mạng khác có thể bị phân loại sai.
- Mô hình dựa nhiều vào `Destination Port` và `Init_Win_bytes_*` (đặc trưng gắn với môi trường thử nghiệm).
- Cột thiếu được điền median của train – nếu thiếu nhiều cột, kết quả không đáng tin (app cảnh báo khi khớp < 50%).
- TensorFlow trên Windows chỉ chạy CPU (đủ nhanh cho demo).
