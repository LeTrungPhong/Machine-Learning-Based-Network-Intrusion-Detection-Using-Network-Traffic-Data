# Phát hiện xâm nhập mạng bằng học máy (ML-based NIDS)

Hệ thống phát hiện xâm nhập mạng (Network Intrusion Detection System) dựa trên học máy, xây dựng từ
dữ liệu lưu lượng mạng thật. Mục tiêu:

- **Phát hiện bất thường** (anomaly detection): chỉ học traffic bình thường, cảnh báo cái lạ;
- **Phân loại tấn công** (attack classification): DoS, DDoS, PortScan, Brute Force, Web Attack, Bot…;
- **Phát hiện botnet bằng đồ thị** (graph-based, dataset CTU-13);
- **Phát hiện thời gian thực** trên Kali Linux, dùng chung bộ trích đặc trưng với phần offline.

Dataset chính: **CIC-IDS-2017** (PCAP gốc + CSV có nhãn). Dataset botnet: **CTU-13** (chưa tải).

> Báo cáo khoa học của dự án nằm ở [report.docx](report.docx), được sinh ra từ
> [docs/report.md](docs/report.md) và được cập nhật sau mỗi STEP.

---

## Tiến độ

| STEP | Nội dung | Trạng thái |
|---|---|---|
| 1 | Kiểm tra môi trường, dataset, lập kế hoạch | Xong |
| 2 | Cấu trúc project, `config.yaml`, logging, kiểm tra dataset | Xong |
| 3 | Đọc PCAP và trích xuất trường gói tin | Xong |
| 4 | Tái tạo flow hai chiều, đặc trưng flow và host | Xong |
| 5 | Làm sạch CSV, EDA, chia dữ liệu, tiền xử lý, gán nhãn flow | Xong |
| 6 | Phát hiện bất thường: Gaussian, Isolation Forest | Chưa làm |
| 7 | Phân loại có giám sát: Random Forest, XGBoost | Chưa làm |
| 8 | Deep learning: Autoencoder / VAE | Chưa làm |
| 9 | Phát hiện botnet bằng đồ thị (CTU-13) | Chưa làm |
| 10 | So sánh mô hình, ablation, đánh giá tấn công chưa thấy | Chưa làm |
| 11 | Phát hiện thời gian thực trên Kali | Chưa làm |
| 12 | Kiểm thử tổng thể, tài liệu, báo cáo cuối | Chưa làm |

---

## Cấu trúc thư mục

```
ATTT_Project/
├── configs/config.yaml        # mọi tham số (đường dẫn, timeout flow, split, ngưỡng...)
├── main.py                    # CLI: --mode check | offline | realtime | train | evaluate
├── utils/                     # config, logging, kiểm tra dung lượng/RAM, kiểm tra dataset
├── preprocessing/
│   ├── read_pcap.py           # đọc pcap/pcapng theo luồng, timestamp nano giây chính xác
│   ├── extract_packets.py     # parser header bằng struct (Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP)
│   ├── flow_extraction.py     # tái tạo flow hai chiều kiểu CICFlowMeter, ~80 đặc trưng
│   ├── host_features.py       # đặc trưng theo host trong cửa sổ trượt, PortScan, beaconing
│   ├── cic_csv.py             # đọc CSV CIC (lỗi mã hoá nhãn, timestamp 12 giờ không AM/PM)
│   ├── data_cleaning.py       # làm sạch CSV CIC -> 1 file Parquet + báo cáo
│   ├── preprocess.py          # chia train/val/test, pipeline tiền xử lý, class weight, SMOTE
│   └── labeling.py            # gán nhãn CIC cho flow tự trích từ PCAP
├── eda/
│   ├── data_analysis.ipynb    # notebook EDA (đã chạy)
│   ├── findings.md            # nhận xét viết sau khi đọc kết quả thật
│   └── visualization.py       # hàm vẽ dùng chung
├── models/  graph/  evaluation/  realtime/   # STEP 6-11
├── scripts/                   # kiểm tra dataset, kiểm chứng parser, so sánh với CIC, build notebook
├── tests/                     # pytest (79 test)
├── outputs/eda/               # biểu đồ PNG + bảng CSV + báo cáo JSON
├── outputs/validation/        # so sánh flow của project với CSV của CIC
├── docs/report.md             # nguồn của báo cáo khoa học
└── report.docx                # báo cáo khoa học (Word)
```

Các thư mục `datasets/`, `processed/`, `saved_models/*.joblib` và `outputs/logs/` **không đưa lên
GitHub** (quá lớn hoặc sinh lại được). Xem `.gitignore`.

---

## Cài đặt

Yêu cầu: Python 3.12, khoảng 60 GB trống cho dataset (52 GB) và dữ liệu trung gian (~2 GB).
Trên Windows cần [Npcap](https://npcap.com/) nếu muốn bắt gói thật; đọc file PCAP thì không cần.

```bash
python -m venv .venv
```

```bash
.venv/Scripts/activate        # Windows (Git Bash); trên Linux: source .venv/bin/activate
```

```bash
pip install -r requirements.txt
```

PyTorch được cài bản CPU (`--extra-index-url` trong `requirements.txt`).

### Tải dataset

CIC-IDS-2017 được lấy từ bản mirror trên HuggingFace `bencorn/CICIDS2017` và đặt vào:

```
datasets/CIC-IDS-2017/
├── pcaps/                                      # 5 file PCAP (thực chất là pcapng), 52 GB
└── csvs/
    ├── MachineLearningCVE/                     # 8 CSV, 79 cột
    └── GeneratedLabelledFlows/TrafficLabelling/  # 8 CSV, 85 cột (có IP, port, timestamp)
```

Kiểm tra đủ 21 file và đúng kích thước:

```bash
python main.py --mode check
```

---

## Chạy pipeline (STEP 3–5)

```bash
python -m preprocessing.extract_packets --pcap datasets/CIC-IDS-2017/pcaps/Friday-WorkingHours.pcap --max-packets 200000
```

```bash
python -m preprocessing.flow_extraction --pcap datasets/CIC-IDS-2017/pcaps/Friday-WorkingHours.pcap
```

```bash
python -m preprocessing.host_features --flows processed/flows/Friday-WorkingHours.flows.parquet
```

```bash
python -m preprocessing.labeling --flows processed/flows/Friday-WorkingHours.flows.parquet
```

```bash
python -m preprocessing.data_cleaning
```

```bash
python -m preprocessing.preprocess --strategy temporal_per_class
```

```bash
python -m preprocessing.preprocess --strategy by_day --fit-on benign
```

```bash
python -m preprocessing.preprocess --strategy stratified_random
```

```bash
python scripts/build_eda_notebook.py
```

Kiểm thử:

```bash
python -m pytest
```

Kiểm chứng parser và flow so với nguồn tham chiếu:

```bash
python scripts/validate_packet_parser.py --pcap datasets/CIC-IDS-2017/pcaps/Monday-WorkingHours.pcap
```

```bash
python scripts/compare_flows_with_cic.py --flows processed/flows/Friday-WorkingHours.flows.parquet --cic datasets/CIC-IDS-2017/csvs/GeneratedLabelledFlows/TrafficLabelling/Friday-*.csv
```

---

## Mô tả từng bước

### STEP 1–2: Môi trường và khung project
- Kiểm tra Python 3.12, thư viện, RAM, dung lượng ổ, Npcap; ghim phiên bản trong `requirements.txt`.
- Mọi tham số nằm trong `configs/config.yaml`; không hard-code đường dẫn hay ngưỡng.
- `main.py --mode check` kiểm tra môi trường và từng file dataset (tên, kích thước, định dạng).

### STEP 3: Đọc PCAP và trích trường gói tin
- Scapy chỉ dùng để đọc file; header được giải mã bằng `struct`, nhanh hơn khoảng 58 lần
  (~260k gói/s so với ~4,5k gói/s khi Scapy tự phân tích).
- **Cùng một parser cho offline và realtime**, nên mô hình nhận đúng một schema đặc trưng.
- Kiểm chứng: 0 sai lệch so với Scapy trên 100.000 gói thật của cả 5 ngày.

### STEP 4: Flow và đặc trưng host
- Flow hai chiều theo quy ước CICFlowMeter: timeout 120 s, activity timeout 5 s, đơn vị µs,
  máy gửi gói đầu tiên là chiều forward.
- Bổ sung: thời gian chờ sau FIN/RST, xử lý gói trả lời có timestamp sớm hơn gói SYN,
  giới hạn số flow đang mở.
- Ngày thứ Sáu: 9.944.187 gói → 549.191 flow; khớp 97,85% flow của CIC
  (PortScan 99,996%, DDoS 100%, Bot 100%).
- Đặc trưng host theo cửa sổ 60 s: số IP/cổng đích khác nhau, entropy cổng, tỉ lệ kết nối lỗi,
  cờ nghi ngờ PortScan, phát hiện beaconing.

### STEP 5: Làm sạch, EDA, chia dữ liệu, tiền xử lý
- CSV CIC: 2.830.743 → 2.498.103 dòng sau khi bỏ 331.202 dòng trùng và 7.144 dòng trùng khác nhãn;
  68 đặc trưng số + 2 đặc trưng hạng mục.
- Ba cách chia dữ liệu:
  - `temporal_per_class` (phân loại): mỗi lớp chia theo thời gian 65/15/20;
  - `by_day` (bất thường, tấn công chưa thấy): train thứ Hai–Tư, test thứ Năm–Sáu;
  - `stratified_random`: chỉ làm mốc so sánh.
- Pipeline chỉ fit trên train: median imputer → signed log1p → RobustScaler, one-hot cho top 32 cổng,
  loại đặc trưng tương quan > 0,99.
- Gán nhãn cho 2.109.714 flow tự trích của 5 ngày; 0,28% không khớp.

Chi tiết số liệu, biểu đồ và thảo luận: xem [report.docx](report.docx) và
[eda/data_analysis.ipynb](eda/data_analysis.ipynb).

---

## Nguyên tắc của dự án

- Không bịa dữ liệu, nhãn hay kết quả; mọi con số trong tài liệu đều từ lần chạy thật.
- Tránh rò rỉ dữ liệu: mọi thống kê tiền xử lý chỉ fit trên tập train.
- Không tuyên bố phát hiện zero-day từ chia ngẫu nhiên.
- **Không tự động chặn IP** (`realtime.block_ips: false` mặc định).
- Chỉ chạy thử realtime trên mạng lab cô lập hoặc mạng đã được cho phép.

## Hạn chế đã biết

- Ba lớp hiếm nhất (Heartbleed, Sql Injection, Infiltration) chỉ có 2–7 flow trong tập test.
- Nhãn CIC có lỗi: ~31 nghìn mảnh DDoS bị gán BENIGN; một số cột cờ TCP bị đặt sai tên.
- Một số đặc trưng mạnh (`init_win_bytes_backward`, cổng đích) phụ thuộc môi trường lab;
  STEP 10 sẽ đánh giá bằng ablation.
- Heuristic beaconing chưa phát hiện được Bot của CIC-IDS-2017.

## Tài liệu tham khảo

- I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani. *Toward Generating a New Intrusion Detection Dataset
  and Intrusion Traffic Characterization.* ICISSP 2018. (CIC-IDS-2017)
- S. García, M. Grill, J. Stiborek, A. Zunino. *An empirical comparison of botnet detection methods.*
  Computers & Security, 2014. (CTU-13)
