# NIDS Demo – ứng dụng web phát hiện xâm nhập mạng (CIC-IDS2017)

Ứng dụng Streamlit chạy local, dùng các mô hình **Random Forest** và **CNN-BiLSTM** đã huấn luyện trên
CIC-IDS2017 (notebook `../nids_results/kaggle_trainning.ipynb`). Có 3 cấp độ:

| Cấp | Nguồn dữ liệu | Trạng thái |
|---|---|---|
| 1 | File CSV luồng mạng (CICFlowMeter) | Hoàn chỉnh |
| 2 | File `.pcap/.pcapng` → CICFlowMeter → CSV | Khung sẵn, cần cài CICFlowMeter |
| 3 | Giám sát trực tiếp: mô phỏng, bắt lưu lượng thật (dumpcap + CICFlowMeter Java), thu thập BENIGN | Đã chạy thử mô phỏng và bắt thật trên Wi-Fi |

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
│   ├── predictor.py       # dự đoán theo batch, đánh giá
│   └── alerting.py        # giảm báo nhầm: whitelist, gom cảnh báo theo IP, log alerts.csv
├── adapters/
│   ├── base.py            # FlowSource: get_flows() -> DataFrame
│   ├── csv_source.py      # cấp 1
│   ├── pcap_source.py     # cấp 2
│   ├── live_source.py     # cấp 3: đọc dòng mới + FlowSimulator
│   └── live_capture.py    # bắt lưu lượng thật: dumpcap + CICFlowMeter Java, liệt kê card mạng
├── views/                 # 5 trang giao diện
├── tools/kaggle_export_sample.py   # chạy trên Kaggle để tạo sample_test.csv
├── tools/finetune_benign.py      # chạy trên Kaggle: huấn luyện lại với lưu lượng BENIGN đã thu thập
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
| Giám sát trực tiếp | Mô phỏng, bắt lưu lượng thật, thu thập BENIGN (xem mục Cấp 3) |

Trang "Phân tích PCAP" (`views/page_pcap.py`) đang **ẩn** khỏi menu; muốn hiện lại, bỏ comment dòng `st.Page(page_pcap...)` trong `app.py`.

### 5. Kiểm thử

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests
```

- Ánh xạ cột với 4 bộ tên: CIC-IDS2017 gốc, CICFlowMeter 4.0/CSE-CIC-IDS2018, gói Python `cicflowmeter`,
  CICFlowMeter build từ GitHub (bản dùng khi bắt lưu lượng thật).
- Xử lý inf/NaN/chuỗi lạ/cột thiếu; hình dạng đầu ra của 4 mô hình.
- Adapter PCAP báo lỗi thân thiện khi thiếu backend; giám sát chỉ đọc dòng mới.
- Giám sát thật (`tests/test_live_capture.py`, không cần quyền Admin/mạng): phân tích danh sách card, gom cảnh báo
  theo IP (ngưỡng, cửa sổ, cooldown), whitelist, pipeline pcap → CSV với dumpcap/CICFlowMeter giả lập, lỗi dumpcap thoát ngay.
- **Độ chính xác trên `sample_test.csv` so với Kaggle** (sai lệch accuracy < 0,005; ví dụ RF đa lớp ≈ 0,9988).
  Các test này tự bỏ qua nếu chưa có `data/sample_test.csv`.

---

## Cấp 2 – Phân tích PCAP (trang đang ẩn)

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

> 🔒 Chỉ giám sát và tấn công thử nghiệm trên mạng/máy thuộc quyền quản lý của bạn.
> Độ trễ cảnh báo ≈ thời gian cắt file pcap (`CAPTURE_ROTATE_SECONDS`, mặc định 30 s) + flow timeout của CICFlowMeter
> (luồng chỉ được ghi khi kết thúc FIN/RST hoặc hết timeout).

Trang "Giám sát trực tiếp" có 4 chế độ:

| Chế độ | Nguồn | Dùng khi |
|---|---|---|
| Mô phỏng | Phát lại `sample_test.csv` (gán IP giả lập 192.168.56.x) | Thử dashboard, gom cảnh báo, whitelist – **chạy chế độ này trước** |
| Bắt lưu lượng thật của máy | `dumpcap` → CICFlowMeter Java → `data/live/live_*.csv` | Giám sát card Wi-Fi / Ethernet / Host-only |
| Đọc thư mục CSV có sẵn | Mọi `*.csv` trong `data/live/` | CICFlowMeter giao diện đồ họa (*Realtime*) tự ghi vào thư mục |
| Thu thập lưu lượng bình thường | Như "bắt thật" nhưng ghi vào `data/benign_capture/`, cột `Label = BENIGN` | Tạo dữ liệu để huấn luyện lại, đo tỉ lệ báo nhầm |

### Kiến trúc bắt lưu lượng thật (hướng Java)

```
dumpcap -i <card> -F pcap -b duration:30 -w data/capture/<phiên>/live.pcap      (Wireshark + Npcap)
   └─ mỗi 30 s đóng một file  live_00001_<thời điểm>.pcap
adapters/live_capture.py (luồng nền): file đã đóng → cfm.bat <pcap> <tmp>       (CICFlowMeter Java 4.0)
   └─ <pcap>_Flow.csv → os.replace → data/live/live_<số>_<thời điểm>.csv   (pcap tạm bị xóa)
adapters/live_source.py: đọc các dòng mới → mô hình → giảm báo nhầm → dashboard + data/alerts.csv
```

CICFlowMeter bản Java chỉ bắt realtime qua giao diện đồ họa, lệnh `cfm` chỉ xử lý file pcap – nên app cắt pcap
theo chu kỳ rồi gọi `cfm`. Bản Java được ưu tiên vì là công cụ sinh ra CIC-IDS2017 (cùng cách tính đặc trưng).

### Cài đặt

1. **Npcap** – thường đã cài cùng Wireshark. Kiểm tra: `Get-Service npcap`.
2. **Wireshark** (cung cấp `dumpcap.exe`; đường dẫn khác mặc định → biến `NIDS_DUMPCAP`):
   ```powershell
   winget install WiresharkFoundation.Wireshark
   ```
3. **Java** (đã thử với JDK 21) và **CICFlowMeter 4.0 bản Java** – đã có sẵn bản build trong
   `tools_ext/CICFlowMeter-4.0/` (app tự dùng `tools_ext/CICFlowMeter-4.0/bin/cfm.bat`, không cần đặt biến môi trường).
   Bản này được build lại từ mã nguồn https://github.com/ahlashkari/CICFlowMeter vì Gradle 4.2 của dự án không chạy
   trên JDK 21:
   - biên dịch `src/main/java` bằng `javac --release 8` với các thư viện Maven Central (commons-lang3/math3/io, guava,
     jfreechart, tika-core, weka-stable, slf4j) và `jnetpcap.jar` + DLL đi kèm mã nguồn;
   - ghi log bằng `slf4j-simple` thay cho log4j 2.11 (bản có lỗ hổng Log4Shell);
   - `cfm.bat` thêm `System32\Npcap` vào PATH để jnetpcap tìm thấy `wpcap.dll`.

   Muốn dùng bản khác: đặt `NIDS_CFM_JAVA_BIN` trỏ tới `cfm.bat` của bản đó. Thư mục `tools_ext/` không được commit.

Trang giám sát hiển thị trạng thái 4 thành phần (dumpcap, CICFlowMeter Java, Java, quyền Administrator) và
hướng dẫn cài phần còn thiếu.

### Chạy với quyền Administrator và chọn card mạng

Npcap mặc định cho phép người dùng thường bắt gói; nếu lúc cài chọn *Restrict Npcap driver's access to
Administrators only* thì phải chạy app bằng quyền Administrator:

1. Bấm Start → gõ *PowerShell* → chuột phải → **Run as administrator**.
2. Chạy app:
   ```powershell
   cd E:\HK9\ATTT_CK\nids_demo
   ```
   ```powershell
   .\.venv\Scripts\streamlit.exe run app.py
   ```
3. Trang "Giám sát trực tiếp" → **Bắt lưu lượng thật của máy** → chọn **Card mạng**:
   - `Wi-Fi` / `Ethernet`: lưu lượng thật của máy;
   - `VMware Network Adapter VMnet1` (VMware) hoặc `VirtualBox Host-Only Ethernet Adapter`: mạng Host-only của lab.
4. Bấm **Bắt đầu**. Luồng đầu tiên xuất hiện sau khoảng 30 s. Nếu dumpcap thoát ngay (sai card, thiếu quyền),
   app báo lỗi kèm hướng dẫn.

### Giảm báo nhầm

- **Ngưỡng tin cậy** (sidebar, mặc định **0,9**): luồng *nghi ngờ* = dự đoán Attack và độ tin cậy ≥ ngưỡng.
- **Gom theo IP nguồn**: chỉ cảnh báo khi một IP có ≥ `AGG_MIN_FLOWS` (5) luồng nghi ngờ trong
  `AGG_WINDOW_SECONDS` (60) giây; sau đó IP đó im lặng một cửa sổ để không bắn cảnh báo liên tục.
- **Whitelist** IP (router, DNS…) và cổng đích (mặc định 53, 67, 68, 123, 137, 138, 1900, 5353, 5355): chỉnh
  trong mục *Giảm báo nhầm* trên trang, bấm **Lưu whitelist** → ghi vào `data/whitelist.json`.
- Mọi cảnh báo được ghi vào **`data/alerts.csv`** (thời gian, IP nguồn/đích, cổng, loại tấn công, xác suất,
  số luồng, mô hình, chế độ) – dùng làm minh chứng cho báo cáo; tải trực tiếp bằng nút **Tải alerts.csv**.

### Kịch bản kiểm thử với máy ảo Kali (Host-only)

1. **Mô phỏng trước**: chế độ *Mô phỏng* → Bắt đầu → kiểm tra có cảnh báo PortScan/DoS/DDoS… và `data/alerts.csv` được ghi.
2. **Lab**: VMware → *Virtual Network Editor*: VMnet1 là Host-only (ví dụ `192.168.56.0/24` hoặc `192.168.x.0/24`).
   Gắn card của VM Kali vào **VMnet1**. Trên Windows, xem IP của VMnet1: `ipconfig` → mục *VMware Network Adapter VMnet1*
   (giả sử `192.168.56.1`).
3. App chạy bằng quyền Administrator → *Bắt lưu lượng thật* → card **VMnet1** → Bắt đầu.
4. Từ Kali, tấn công **chính máy Windows của bạn** qua địa chỉ VMnet1:
   - Quét cổng (kỳ vọng `PortScan`):
     ```bash
     nmap -sS -p 1-1000 192.168.56.1
     nmap -sT -T4 -p- 192.168.56.1
     ```
   - Thử đăng nhập SSH (kỳ vọng `Brute Force`; cần bật OpenSSH Server trên Windows:
     *Settings → Optional features → OpenSSH Server*, `Start-Service sshd`; dùng tài khoản thử nghiệm):
     ```bash
     hydra -l testuser -P /usr/share/wordlists/fasttrack.txt -t 4 ssh://192.168.56.1
     ```
5. Chờ 30–120 s (cắt pcap + flow timeout) → cảnh báo xuất hiện trên dashboard, kèm toast và một dòng trong `data/alerts.csv`.
6. Tắt tường lửa không bắt buộc: SYN scan vẫn sinh luồng ngay cả khi cổng bị chặn. Nếu không thấy cảnh báo, hạ ngưỡng
   tin cậy hoặc `Số luồng nghi ngờ tối thiểu` để xem mô hình có nhận ra không.

Lưu ý: mô hình học trên mạng testbed của CIC-IDS2017 (2017), nên nhãn có thể khác kỳ vọng (vd quét cổng bị gán DoS),
và lưu lượng bình thường của máy bạn có thể bị báo nhầm – xem phần dưới.

### Thu thập lưu lượng bình thường và huấn luyện lại

1. Chế độ **Thu thập lưu lượng bình thường (BENIGN)** → chọn card (Wi-Fi) → Bắt đầu, dùng máy bình thường
   (duyệt web, họp online, cập nhật…) 30–60 phút. **Không** chạy tấn công trong lúc này. CSV có `Label = BENIGN`
   được ghi vào `data/benign_capture/`. Dashboard hiện **tỉ lệ báo nhầm** của mô hình hiện tại trên lưu lượng đó.
2. Tạo một Kaggle Dataset gồm `data/benign_capture/live_*.csv` và thư mục `core/`; thêm làm Input cùng với
   CIC-IDS2017 `MachineLearningCVE` và thư mục `nids_results/models/`.
3. Dán `tools/finetune_benign.py` vào một cell và chạy. Script tái tạo đúng train/val/test của notebook, giữ lại 20% file
   benign để đo báo nhầm, huấn luyện lại Random Forest (cùng siêu tham số) và fine-tune CNN-BiLSTM (learning rate nhỏ,
   có trộn dữ liệu train gốc để không quên tấn công), **không fit lại preprocessor**, rồi in bảng TRƯỚC/SAU
   (Accuracy, F1-macro, DR, FAR trên test CIC; tỉ lệ báo nhầm trên benign giữ lại).
4. Tải `/kaggle/working/finetuned/` về `nids_demo/artifacts_finetuned/` và chạy app với bộ mô hình mới
   (bộ gốc trong `artifacts/` không bị sửa):
   ```powershell
   $env:NIDS_ARTIFACT_DIR = "artifacts_finetuned"; .\.venv\Scripts\streamlit.exe run app.py
   ```

Chỉ dùng bản mới khi tỉ lệ báo nhầm giảm mà DR/F1-macro trên test CIC không giảm đáng kể.

---

## Cấu hình

| Biến (config.py / môi trường) | Mặc định | Ý nghĩa |
|---|---|---|
| `ARTIFACT_DIR` / `NIDS_ARTIFACT_DIR` | `artifacts/` | Thư mục mô hình |
| `DATA_DIR` / `NIDS_DATA_DIR` | `data/` | Chứa `sample_test.csv`, `live/`, `pcap_work/` |
| `DEFAULT_ALERT_THRESHOLD` | 0,9 | Ngưỡng tin cậy để coi một luồng là nghi ngờ / cảnh báo |
| `BATCH_SIZE` | 20.000 | Số dòng mỗi batch khi dự đoán |
| `PCAP_BACKEND` / `NIDS_PCAP_BACKEND` | `auto` | `auto`, `python`, `java` |
| `CICFLOWMETER_JAVA_BIN` / `NIDS_CFM_JAVA_BIN` | rỗng | Đường dẫn `cfm.bat` |
| `WATCH_DIR` / `NIDS_WATCH_DIR` | `data/live` | Thư mục giám sát |
| `REFRESH_SECONDS`, `SIM_CHUNK_ROWS` | 3, 50 | Chu kỳ làm mới, số dòng mỗi đợt mô phỏng |
| `DUMPCAP_BIN` / `NIDS_DUMPCAP` | `C:\Program Files\Wireshark\dumpcap.exe` | dumpcap để bắt gói |
| `CAPTURE_ROTATE_SECONDS` / `NIDS_CAPTURE_ROTATE` | 30 | Chu kỳ cắt file pcap (ảnh hưởng độ trễ) |
| `CAPTURE_KEEP_PCAP` | `False` | Giữ lại file pcap sau khi xử lý |
| `AGG_WINDOW_SECONDS`, `AGG_MIN_FLOWS` | 60, 5 | Gom cảnh báo theo IP nguồn |
| `WHITELIST_IPS`, `WHITELIST_PORTS` | [], DNS/DHCP/NTP/... | Whitelist mặc định (bản chỉnh trên UI lưu ở `data/whitelist.json`) |
| `ALERTS_LOG` | `data/alerts.csv` | Log cảnh báo |
| `BENIGN_DIR` | `data/benign_capture` | Lưu lượng bình thường đã thu thập |

## Giới hạn

- Mô hình chỉ biết 9 nhóm lưu lượng của CIC-IDS2017; lưu lượng mạng khác có thể bị phân loại sai.
- Mô hình dựa nhiều vào `Destination Port` và `Init_Win_bytes_*` (đặc trưng gắn với môi trường thử nghiệm).
- Cột thiếu được điền median của train – nếu thiếu nhiều cột, kết quả không đáng tin (app cảnh báo khi khớp < 50%).
- TensorFlow trên Windows chỉ chạy CPU (đủ nhanh cho demo).
- Giám sát thật: cảnh báo trễ khoảng 30 s + flow timeout; dumpcap cắt file theo thời gian nên một luồng kéo dài qua ranh giới hai file bị tách thành hai luồng.
