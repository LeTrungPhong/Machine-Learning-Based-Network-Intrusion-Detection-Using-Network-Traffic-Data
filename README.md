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
| 6 | Phát hiện bất thường: Gaussian, Isolation Forest (trên CIC-IDS-2017, split `by_day`) | Xong |
| 7 | Phân loại có giám sát: Random Forest, XGBoost (trên CIC-IDS-2017, split `temporal_per_class`) | Xong |
| 8 | Deep learning: Autoencoder, VAE (trên CIC-IDS-2017, split `by_day`) | Xong |
| 9 | Phát hiện botnet bằng đồ thị (CTU-13) | Có code, chưa tải CTU-13 |
| 10 | So sánh mô hình, ablation, pipeline kết hợp | Có code, chưa đánh giá trên dữ liệu thật |
| 11 | Phát hiện thời gian thực trên Kali | Có code, chưa thử trên mạng lab |
| 12 | Kiểm thử tổng thể, tài liệu, báo cáo cuối | Chưa làm |

> Các con số của STEP 7–12 mà commit `57b0bad` đưa vào README và báo cáo được tính trên **dữ liệu tổng hợp**
> (`generate_multistage_benchmark_data`, `generate_synthetic_botnet_flows`), không phải CIC-IDS-2017 hay CTU-13.
> Vì vậy chúng đã bị gỡ khỏi phần kết quả; STEP 6–8 đã được làm lại trên dữ liệu thật (xem mục 7–10 của báo cáo).

---

## Cấu trúc thư mục

```
ATTT_Project/
├── configs/config.yaml        # mọi tham số (đường dẫn, timeout flow, split, ngưỡng, botnet_graph...)
├── main.py                    # CLI: --mode check | train | evaluate | offline | realtime
├── utils/                     # config, logging, kiểm tra dung lượng/RAM, kiểm tra dataset
├── preprocessing/
│   ├── read_pcap.py           # đọc pcap/pcapng theo luồng, timestamp nano giây chính xác
│   ├── extract_packets.py     # parser header bằng struct (Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP)
│   ├── flow_extraction.py     # tái tạo flow hai chiều kiểu CICFlowMeter, ~80 đặc trưng
│   ├── host_features.py       # đặc trưng theo host trong cửa sổ trượt, PortScan, beaconing
│   ├── cic_csv.py             # đọc CSV CIC (lỗi mã hoá nhãn, timestamp 12 giờ không AM/PM)
│   ├── data_cleaning.py       # làm sạch CSV CIC -> 1 file Parquet + báo cáo
│   ├── preprocess.py          # chia train/val/test, pipeline tiền xử lý, class weight, SMOTE
│   ├── transforms.py          # hàm biến đổi dùng trong pipeline đã pickle (signed log1p)
│   └── labeling.py            # gán nhãn CIC cho flow tự trích từ PCAP
├── eda/
│   ├── data_analysis.ipynb    # notebook EDA (đã chạy)
│   ├── findings.md            # nhận xét viết sau khi đọc kết quả thật
│   └── visualization.py       # hàm vẽ dùng chung
├── models/
│   ├── anomaly.py             # STEP 6: Gaussian (diag/full) và Isolation Forest
│   ├── train_anomaly.py       # STEP 6/8: huấn luyện, chọn ngưỡng, đánh giá trên CIC (--section)
│   ├── deep_anomaly.py        # STEP 8: Autoencoder và VAE (PyTorch)
│   ├── supervised.py          # STEP 7: Random Forest / XGBoost, class weight, SMOTE
│   ├── train_supervised.py    # STEP 7: huấn luyện, chọn mô hình theo validation, đánh giá trên CIC
│   ├── feature_cache.py       # cache ma trận đặc trưng đã biến đổi (.npy memmap), dùng chung
│   ├── model_training.ipynb   # notebook ML/DL (đã chạy trên dữ liệu tổng hợp, chưa phải kết quả thật)
│   └── pipeline.py            # Pipeline kết hợp 3 tầng (Gaussian -> Random Forest -> Host/Graph)
├── graph/
│   └── botnet_graph.py        # Đồ thị giao tiếp mạng, phát hiện Centralized C2 vs P2P & ML trên đồ thị
├── evaluation/
│   ├── metrics.py             # ngưỡng, Precision/Recall/FPR, ROC/PR-AUC, chỉ số đa lớp và theo nhóm
│   └── evaluate_pipeline.py   # So sánh mô hình & ablation (hiện chạy trên dữ liệu tổng hợp)
├── realtime/
│   ├── monitor.py             # Giám sát thời gian thực (Scapy sniff / FlowManager / JSONL alerts / iptables)
│   └── attack_simulator.py    # Mô phỏng tấn công (PortScan, DoS Flood, Botnet C2, Zero-Day) & đo độ trễ
├── scripts/                   # kiểm tra dataset, kiểm chứng parser, build notebook & báo cáo Word
├── tests/                     # pytest (kiểm thử toàn diện từ gói tin đến đồ thị và realtime)
├── outputs/                   # eda/, validation/, anomaly/ (STEP 6), supervised/ (STEP 7), deep_anomaly/ (STEP 8), botnet_graph/, evaluation/, alerts/
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

Kiểm tra đủ 21 file và đúng kích thước. PCAP và `MachineLearningCVE` là tuỳ chọn (`optional_paths` trong
`config.yaml`): chỉ cần khi chạy lại STEP 3–4, hoặc phép kiểm tra hai bộ CSV giống nhau ở STEP 5. Từ STEP 5 trở đi
mọi bước đọc `TrafficLabelling` và `processed/`, nên thiếu PCAP chỉ sinh cảnh báo.

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
python scripts/build_training_notebook.py
```

### STEP 6: phát hiện bất thường trên CIC-IDS-2017

Cần chạy `preprocessing.data_cleaning` và `preprocessing.preprocess --strategy by_day --fit-on benign` trước.
Lần chạy đầu ghi khoảng 0,8 GB ma trận đặc trưng vào `processed/features/` (khoảng 3 phút, khoảng 2 GB RAM).

```bash
python -m models.train_anomaly
```

```bash
python scripts/anomaly_fp_diagnostic.py
```

Kết quả nằm ở `outputs/anomaly/`: `anomaly_summary.csv`, `anomaly_results.json`, kết quả theo nhãn, đường ROC/PR
và phân tích báo động sai.

### STEP 7: phân loại có giám sát trên CIC-IDS-2017

Cần chạy `preprocessing.preprocess --strategy temporal_per_class` trước. Mất khoảng 15 phút cho 4 biến thể
(CPU 12 luồng); RAM dùng tối đa khoảng 2 GB. Cache khoảng 0,8 GB, cộng 0,7 GB cho file SMOTE.

```bash
python -m models.train_supervised
```

```bash
python scripts/supervised_error_diagnostic.py
```

Kết quả nằm ở `outputs/supervised/`: bảng tổng hợp, F1/precision/recall theo nhãn và theo nhóm, ma trận nhầm lẫn,
mức độ quan trọng của đặc trưng và phân tích lỗi. Chạy một phần: `--only rf_weighted xgb_weighted`.

### STEP 8: Autoencoder và VAE trên CIC-IDS-2017

Dùng lại cache đặc trưng của STEP 6 và kết quả STEP 6 làm tham chiếu (chạy STEP 6 trước). Mất khoảng 5 phút trên CPU.

```bash
python -m models.train_anomaly --section deep_anomaly
```

```bash
python scripts/anomaly_fp_diagnostic.py --section deep_anomaly
```

Kết quả nằm ở `outputs/deep_anomaly/`.

### Các module STEP 9–12 (mới kiểm thử chức năng trên dữ liệu tổng hợp)

Các lệnh dưới đây chạy được, nhưng mặc định dùng dữ liệu tổng hợp hoặc mô hình huấn luyện trên dữ liệu tổng hợp.
Số liệu chúng in ra **không phải kết quả trên CIC-IDS-2017 / CTU-13**.

```bash
# Huấn luyện toàn bộ pipeline 3 tầng & mô hình đồ thị Botnet
python main.py --mode train

# Đánh giá so sánh các thuật toán & nghiên cứu Ablation Study (STEP 10)
python main.py --mode evaluate

# Chạy phân tích đồ thị Botnet (Centralized C2 vs P2P Mesh)
python -m graph.botnet_graph --demo

# Chạy giám sát thời gian thực với các kịch bản tấn công mô phỏng (STEP 11)
python main.py --mode realtime --simulate --block-ips

# Chạy giám sát thời gian thực trên card mạng Kali Linux
python main.py --mode realtime --interface eth0 --duration 60
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
- Kiểm tra Python, thư viện, RAM, dung lượng ổ, Npcap; ghim phiên bản trong `requirements.txt`.
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

### STEP 6: Phát hiện bất thường (`models/anomaly.py`, `models/train_anomaly.py`)
- Học trên thứ Hai–Tư, kiểm tra trên thứ Năm–Sáu: cả 7 loại tấn công trong test đều chưa thấy khi huấn luyện.
- 4 biến thể: Gaussian đường chéo, Gaussian hiệp phương sai đầy đủ, Isolation Forest học trên BENIGN,
  Isolation Forest học trên train không lọc nhãn.
- Ngưỡng chọn trên validation: FPR 1% / 0,1% trên benign (không cần nhãn tấn công), hoặc best-F1.
- Kết quả trên test:
  - Gaussian full đạt ROC-AUC 0,909, PR-AUC 0,576, nhưng ở FPR 1% recall chỉ 6,6%
    (Isolation Forest học trên BENIGN: 9,6%);
  - Bot (64%) và Infiltration (69%) được phát hiện một phần; Web Attack và PortScan gần như không;
  - 45–59% báo động sai trên test nằm trong đợt DDoS, nơi CIC gán nhầm nhãn BENIGN.

### STEP 7: Phân loại có giám sát (`models/supervised.py`, `models/train_supervised.py`)
- Mỗi nhãn: 65% flow sớm nhất để train, 15% kế tiếp để validation, 20% muộn nhất để test; 15 nhãn.
- 4 biến thể: Random Forest và XGBoost, mỗi mô hình với class weight hoặc SMOTE (SMOTE chỉ trên train).
  Chọn mô hình theo macro-F1 trên validation.
- Kết quả trên test (mô hình chọn theo validation là Random Forest + SMOTE):
  - macro-F1 0,774 trên 15 nhãn, 0,835 trên 8 nhóm; accuracy 0,993; FPR 0,03%;
  - DoS Hulk, DDoS, PortScan, GoldenEye, Patator đạt F1 ≥ 0,96; Web Brute Force và XSS bị nhầm lẫn qua lại
    (nhóm WebAttack F1 0,93);
  - **Bot F1 = 0** ở cả 4 mô hình: flow Bot trong test (tới C2 205.174.165.73:8080, không payload) giống hệt
    966 flow mà CIC gán BENIGN tới cùng đích;
  - biến thể class weight đoán 6,7–11,4 nghìn flow "BENIGN" thành DDoS; 99,9% trong số đó là mảnh DDoS
    mà CIC gán nhầm nhãn.

### STEP 8: Phát hiện bất thường bằng học sâu (`models/deep_anomaly.py`)
- Autoencoder (82-64-32-16) và VAE (latent 16, β = 1), chỉ học trên BENIGN thứ Hai–Tư, dừng sớm theo loss
  trên benign của validation. Cùng split, đặc trưng và cách chọn ngưỡng như STEP 6.
- Ở FPR 1% (chỉnh trên validation): recall 30,9% (Autoencoder), 27,9% (VAE), so với 6,6–9,6% ở STEP 6;
  DDoS bị phát hiện 48–51%, Infiltration 72–89%; Web Attack và PortScan vẫn ≤ 5%.
- FPR trên test 4,5–5,1%, chủ yếu do các mảnh DDoS mà CIC gán nhầm là BENIGN (mô hình gắn cờ 85–91% số
  mảnh đó). Ngoài khung DDoS, FPR là 1,1–1,4%. Nếu tính đúng các mảnh đó là tấn công, F1 đạt 0,51–0,54.
- Notebook `models/model_training.ipynb` (Autoencoder/MLP trên dữ liệu tổng hợp) không còn dùng cho kết quả.

### STEP 9: Phát hiện Botnet dựa trên Đồ thị Giao tiếp Mạng (`graph/botnet_graph.py`)
- Xây dựng đồ thị có hướng $G = (V, E)$ từ bảng Flow hoặc file `.binetflow` của **CTU-13**.
- Trích xuất 20 đặc trưng đồ thị cấp nút (In/Out-Degree, PageRank, Clustering Coefficient, Betweenness Centrality, Reciprocity Ratio, số cạnh Beaconing định kỳ).
- Có luật nhận diện **Centralized C2 (`c2_server`, `centralized_bot`)** và **Peer-to-Peer (`p2p_bot`)**. Mới chạy trên đồ thị tổng hợp; chưa đánh giá trên CTU-13.

### STEP 10: Pipeline Kết hợp 3 Tầng & Nghiên cứu Ablation (`models/pipeline.py`, `evaluation/evaluate_pipeline.py`)
- Kết hợp nối tiếp: **Tầng 1 (Gaussian Anomaly lọc & bắt Zero-Day)** $\to$ **Tầng 2 (Random Forest phân loại chi tiết & khử báo động giả)** $\to$ **Tầng 3 (Host Beaconing & Đồ thị Botnet)**.
- Bảng ablation hiện có (100% recall, FPR 0%) được tính trên dữ liệu tổng hợp, trong đó lớp `ZeroDay_Exploit` được sinh để dễ phát hiện. Không dùng làm kết quả.

### STEP 11–12: Giám sát Thời gian thực trên Kali Linux & Kiểm thử Tổng thể (`realtime/`)
- Bắt gói trực tiếp qua Scapy hoặc luồng frame Ethernet/IPv4/TCP thô, tái tạo flow thời gian thực, đẩy qua Pipeline 3 tầng, ghi cảnh báo ra `outputs/alerts/alerts.jsonl`. Có tuỳ chọn chặn IP qua `iptables`, mặc định tắt và chỉ chạy thử (dry-run). Chưa thử trên mạng lab; kịch bản tấn công hiện là frame tự dựng trong Python.

Chi tiết số liệu, biểu đồ và thảo luận: xem [report.docx](report.docx),
[eda/data_analysis.ipynb](eda/data_analysis.ipynb) và [models/model_training.ipynb](models/model_training.ipynb).

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
- Phát hiện bất thường mức flow (STEP 6) bỏ sót gần hết Web Attack và PortScan ở FPR 1%.
- Phân loại mức flow (STEP 7) không phát hiện được Bot giai đoạn cuối, vì flow của nó trùng với flow CIC gán BENIGN.
- Chạy test hiện ghi đè `outputs/botnet_graph/*` và `saved_models/*.joblib` (cần sửa ở STEP 12).

## Tài liệu tham khảo

- I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani. *Toward Generating a New Intrusion Detection Dataset
  and Intrusion Traffic Characterization.* ICISSP 2018. (CIC-IDS-2017)
- S. García, M. Grill, J. Stiborek, A. Zunino. *An empirical comparison of botnet detection methods.*
  Computers & Security, 2014. (CTU-13)
