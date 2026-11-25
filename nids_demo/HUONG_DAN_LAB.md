# Hướng dẫn lab NIDS Demo — cài đặt từ đầu, chạy app và triển khai tấn công

Tài liệu này hướng dẫn **cài đặt từ máy trắng (chưa có gì)** đến khi demo phát hiện được tấn công DoS:
cài phần mềm nền, build công cụ, dựng server nạn nhân, chạy app NIDS, và tấn công từ máy ảo Kali.

Các giá trị (IP, đường dẫn) lấy theo máy tham chiếu; máy bạn khác thì thay tương ứng — xem
[mục 0](#0-thông-số-tham-chiếu).

> ⚠️ **Chỉ tấn công trên mạng Host-only cô lập và máy do bạn sở hữu.** Không nhắm vào Wi-Fi hay máy khác.

---

## Mục lục

0. [Thông số tham chiếu](#0-thông-số-tham-chiếu)
1. [Kiến trúc lab](#1-kiến-trúc-lab)
2. [Tổng quan phần mềm cần cài](#2-tổng-quan-phần-mềm-cần-cài)
3. [Cài phần mềm nền trên Windows](#3-cài-phần-mềm-nền-trên-windows)
4. [Lấy mã nguồn app và tạo môi trường](#4-lấy-mã-nguồn-app-và-tạo-môi-trường)
5. [Build CICFlowMeter](#5-build-cicflowmeter)
6. [Tạo máy ảo Kali và mạng Host-only](#6-tạo-máy-ảo-kali-và-mạng-host-only)
7. [Dựng server nạn nhân trên Windows](#7-dựng-server-nạn-nhân-trên-windows)
8. [Chạy app demo](#8-chạy-app-demo)
9. [Triển khai tấn công từ Kali](#9-triển-khai-tấn-công-từ-kali)
10. [Quan sát kết quả](#10-quan-sát-kết-quả)
11. [Dọn dẹp sau khi thử](#11-dọn-dẹp-sau-khi-thử)
12. [Xử lý sự cố](#12-xử-lý-sự-cố)
13. [Phụ lục — bảng lệnh nhanh](#13-phụ-lục--bảng-lệnh-nhanh)

---

## 0. Thông số tham chiếu

| Mục | Giá trị tham chiếu |
|---|---|
| Thư mục app | `E:\HK9\ATTT_CK\nids_demo` |
| Card lab (Host-only) | **VMware VMnet1** |
| IP máy Windows trên VMnet1 | **192.168.136.1** |
| IP máy Kali trên VMnet1 | **192.168.136.128** |
| Dải mạng lab | `192.168.136.0/24` |

Xem IP máy Windows (PowerShell): `Get-NetIPAddress -AddressFamily IPv4 | ? InterfaceAlias -match VMnet1 | select IPAddress`
Xem IP Kali (Kali): `ip a | grep eth`

---

## 1. Kiến trúc lab

```
┌─────────────────────────────┐        VMware Host-only (VMnet1)        ┌──────────────────┐
│   Windows (192.168.136.1)   │◄──────────── 192.168.136.0/24 ────────►│  Kali            │
│  • App NIDS (Streamlit)     │                                        │  192.168.136.128 │
│  • Server nạn nhân :80      │   ◄── tấn công: ab / nmap / hydra ──    │  • ab, nmap,     │
│  • dumpcap bắt gói VMnet1   │                                        │    hydra         │
│  • CICFlowMeter trích luồng │                                        │                  │
└─────────────────────────────┘                                        └──────────────────┘
```

Luồng xử lý khi bắt lưu lượng thật:

```
dumpcap (VMnet1) ─cắt pcap mỗi 30s─► editcap (nano→micro) ─► CICFlowMeter ─► CSV luồng
     ─► app đọc dòng mới ─► tiền xử lý ─► mô hình (RF / CNN-BiLSTM) ─► cảnh báo + alerts.csv
```

---

## 2. Tổng quan phần mềm cần cài

**Máy Windows (chạy app + là mục tiêu):**

| Phần mềm | Vai trò | Cài ở mục |
|---|---|---|
| Git | Tải mã nguồn + clone CICFlowMeter | 3 |
| Python 3.12 | Chạy app (Streamlit) | 3 |
| Wireshark (+ Npcap) | `dumpcap` bắt gói, `editcap` chuyển định dạng pcap | 3 |
| Java JDK 21 | Biên dịch & chạy CICFlowMeter | 3 |
| CICFlowMeter 4.0 | Trích đặc trưng luồng từ pcap | 5 (build bằng script) |
| VMware Workstation Player | Chạy máy ảo Kali | 3 |

**Máy ảo Kali (tấn công):** đã có sẵn `ab` (apache2-utils), `nmap`, `hydra`.

> Máy tham chiếu dùng Windows 11, đã có đủ các phần mềm trên. Mục 3 hướng dẫn cài lại từ đầu bằng `winget`.

---

## 3. Cài phần mềm nền trên Windows

Mở **PowerShell (Run as administrator)**. Dùng `winget` (có sẵn trên Windows 10/11); nếu chưa có, cài
"App Installer" từ Microsoft Store.

```powershell
winget install --id Git.Git -e
winget install --id Python.Python.3.12 -e
winget install --id EclipseAdoptium.Temurin.21.JDK -e
winget install --id WiresharkFoundation.Wireshark -e
```

- **Wireshark**: trong lúc cài, chọn cài kèm **Npcap** (tích "Install Npcap"). Npcap là driver bắt gói bắt buộc.
  Nếu đã bỏ qua, tải riêng tại <https://npcap.com> và cài.
- **VMware Workstation Player** (miễn phí cho mục đích cá nhân):

```powershell
winget install --id VMware.WorkstationPlayer -e
```

Nếu `winget` không có gói VMware, tải thủ công từ trang Broadcom/VMware và cài.

**Đóng PowerShell và mở lại** để nạp PATH mới, rồi kiểm tra:

```powershell
git --version
python --version          # mong doi Python 3.12.x
java -version             # mong doi 21.x
javac -version
Get-Service npcap         # phai Running
Test-Path 'C:\Program Files\Wireshark\dumpcap.exe'
Test-Path 'C:\Program Files\Wireshark\editcap.exe'
```

> Nếu `python` mở Microsoft Store: tắt "App execution aliases" cho Python trong *Settings → Apps → Advanced
> app settings → App execution aliases*, hoặc dùng lệnh `py -3.12` thay cho `python`.

---

## 4. Lấy mã nguồn app và tạo môi trường

### 4.1 Lấy mã nguồn

Clone kho dự án của bạn (hoặc sao chép thư mục dự án) về máy. Giả sử đặt tại `E:\HK9\ATTT_CK`, thư mục app
là `E:\HK9\ATTT_CK\nids_demo`.

```powershell
cd E:\HK9\ATTT_CK\nids_demo
```

### 4.2 Môi trường ảo Python

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Phiên bản đã pin: numpy 2.1.3 · pandas 2.3.3 · scikit-learn 1.6.1 · tensorflow 2.21.0 · keras 3.13.2.
**Không nâng cấp scikit-learn/keras** — file mô hình có thể không nạp được.

### 4.3 Artifacts (mô hình)

Chép 6 file sau vào `nids_demo\artifacts\` (từ `nids_results\models\` hoặc Output của notebook Kaggle):

```
preprocessor_cic_ids2017.joblib   label_encoder_cic_ids2017.joblib
rf_cic_ids2017_multi.joblib       rf_cic_ids2017_binary.joblib
dl_cic_ids2017_multi.keras        dl_cic_ids2017_binary.keras
```

### 4.4 Dữ liệu mẫu (cho test và chế độ Mô phỏng)

Chạy `tools/kaggle_export_sample.py` trong một cell trên Kaggle (cùng input CIC-IDS2017), tải
`sample_test.csv` về đặt vào `nids_demo\data\`.

### 4.5 Kiểm tra

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests
```

Mong đợi: tất cả **passed**.

---

## 5. Build CICFlowMeter

Bản build sẵn của CICFlowMeter không chạy với JDK mới (Gradle 4.2 cũ), và thư viện `jnetpcap` không có trên
Maven Central. Dự án đã kèm **script tự build**: clone mã nguồn → tải thư viện → biên dịch bằng `javac` →
đóng gói. Chạy trong thư mục `nids_demo` (cần internet):

```powershell
powershell -ExecutionPolicy Bypass -File tools\build_cicflowmeter.ps1
```

Kết quả: `nids_demo\tools_ext\CICFlowMeter-4.0\bin\cfm.bat` — app tự dò và dùng file này (không cần đặt biến
môi trường). Thư mục `tools_ext\` không được commit nên **mỗi máy mới phải chạy script này một lần**.

Kiểm tra nhanh (tùy chọn) trên một file pcap bất kỳ:

```powershell
& 'tools_ext\CICFlowMeter-4.0\bin\cfm.bat' <duong_dan.pcap> <thu_muc_out>
```

> Muốn dùng bản CICFlowMeter khác: đặt biến `NIDS_CFM_JAVA_BIN` trỏ tới `cfm.bat` của bản đó.

---

## 6. Tạo máy ảo Kali và mạng Host-only

1. **Tải Kali cho VMware**: trang <https://www.kali.org/get-kali/> → *Virtual Machines* → bản **VMware**
   (file `.7z` chứa `.vmwarevm`/`.vmx`). Giải nén.
2. **Mở trong VMware**: *Open a Virtual Machine* → chọn file `.vmx`. Đăng nhập mặc định `kali` / `kali`.
3. **Mạng Host-only**: *Player → Manage → Virtual Machine Settings → Network Adapter* → chọn **Host-only**.
   (Trên VMware Workstation có thể vào *Edit → Virtual Network Editor* để xem/đặt subnet cho **VMnet1**,
   ví dụ `192.168.136.0/24`.)
4. Khởi động Kali, kiểm tra IP và thông mạng tới Windows:

```bash
ip a | grep 192.168.136
ping -c 3 192.168.136.1
```

5. **Mở tường lửa Windows cho dải lab** — chỉ mở cho mạng Host-only, không ảnh hưởng Wi-Fi
   (PowerShell **Run as administrator**):

```powershell
New-NetFirewallRule -DisplayName "Lab VMnet1" -Direction Inbound -RemoteAddress 192.168.136.0/24 -Action Allow
```

Sau đó `ping` từ Kali phải thông.

---

## 7. Dựng server nạn nhân trên Windows

DoS tầng HTTP là loại app bắt tốt nhất, nên cần một web server để Kali tấn công. Dự án có sẵn
`tools/victim_http.py` (web server tối giản, chỉ lắng nghe trên VMnet1, không mở ra Wi-Fi).

Mở **một cửa sổ PowerShell riêng** và để nguyên trong lúc tấn công:

```powershell
cd E:\HK9\ATTT_CK\nids_demo
.\.venv\Scripts\python.exe tools\victim_http.py 192.168.136.1 80
```

Thấy `Victim HTTP server tren http://192.168.136.1:80/` là được. Kiểm tra từ Kali:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://192.168.136.1/
```

Trả về `200` là sẵn sàng. Dừng server: **Ctrl + C**.

---

## 8. Chạy app demo

Mở **một cửa sổ PowerShell khác**:

```powershell
cd E:\HK9\ATTT_CK\nids_demo
.\.venv\Scripts\streamlit.exe run app.py
```

Trình duyệt mở `http://localhost:8501` (lần đầu nạp mô hình mất 10–20 giây). Dừng app: **Ctrl + C**.

**Thiết lập để demo DoS:**

1. Sidebar → **Mô hình**: **CNN-BiLSTM** (nhạy với DoS hơn Random Forest rõ rệt).
2. Sidebar → **Ngưỡng cảnh báo**: `0.9`.
3. Trang **Giám sát trực tiếp** → mục *Giảm báo nhầm* → **Số luồng tối thiểu / IP** = `5` (hoặc `3` cho nhạy hơn).
4. Chọn **Bắt lưu lượng thật của máy** → card **VMware Network Adapter VMnet1** → **Bắt đầu**.

> Trang hiển thị trạng thái: dumpcap, CICFlowMeter Java, Java — cả ba phải **Sẵn sàng**. Nếu Npcap chặn
> người dùng thường, chạy app trong PowerShell *Run as administrator*.

---

## 9. Triển khai tấn công từ Kali

Chạy **sau khi** đã bấm *Bắt đầu* ở app. Cảnh báo trễ **~30–60 giây** (cắt pcap mỗi 30s + thời gian trích luồng).

### 9.1 DoS HTTP — ApacheBench (khuyến nghị, app bắt tốt nhất)

```bash
ab -n 10000 -c 50 -r http://192.168.136.1/
```

Bị `Connection reset by peer` → hạ đồng thời: `ab -n 10000 -c 20 -r http://192.168.136.1/`.
Thực nghiệm: **CNN-BiLSTM gán ~40% luồng là DoS** (phần lớn tin cậy ≥ 0,9); Random Forest ~13%.

(Tùy chọn) Slowloris:

```bash
sudo apt install -y slowhttptest
slowhttptest -c 300 -H -i 10 -r 50 -u http://192.168.136.1/ -x 24 -p 3
```

### 9.2 Quét cổng — nmap

```bash
nmap -sS -T4 -p- 192.168.136.1
```

> Quét cổng tạo luồng **một gói** nên mô hình CIC-IDS2017 thường **không** nhận ra (gán Benign) — giới hạn
> đã biết của mô hình. Dùng để minh họa, không phải để "bắt" như DoS.

### 9.3 Brute force SSH (tùy chọn)

Trên **Windows (PowerShell Run as administrator)**:

```powershell
$cap = (Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1).Name
Add-WindowsCapability -Online -Name $cap
Set-Service sshd -StartupType Automatic; Start-Service sshd
$p = ConvertTo-SecureString 'LabP@ss2026' -AsPlainText -Force
New-LocalUser -Name 'labtest' -Password $p -PasswordNeverExpires -AccountNeverExpires
New-NetFirewallRule -DisplayName "Lab SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress 192.168.136.0/24 -Action Allow
```

Trên **Kali**:

```bash
printf '123456\npassword\nadmin\nqwerty\nletmein\nLabP@ss2026\n' > /tmp/lab_pw.txt
hydra -l labtest -P /tmp/lab_pw.txt -t 4 ssh://192.168.136.1
```

---

## 10. Quan sát kết quả

Trang **Giám sát trực tiếp**:

- **KPI**: luồng/phút, luồng nghi ngờ, số cảnh báo, top IP nghi ngờ, loại tấn công phổ biến.
- **Biểu đồ** luồng và cảnh báo theo thời gian (đỉnh ứng với mỗi đợt pcap 30s).
- Tab **🚨 Cảnh báo mới nhất**: cảnh báo đã gom theo IP nguồn.
- Tab **📋 Tất cả luồng**: mọi luồng, lọc theo IP `192.168.136.128` để xem riêng traffic Kali; dòng nghi ngờ tô hồng; có nút tải CSV.
- Cảnh báo được ghi ra **`data/alerts.csv`** (nút *Tải alerts.csv*) — minh chứng cho báo cáo.

---

## 11. Dọn dẹp sau khi thử

Đóng app và server bằng **Ctrl + C**. Nếu còn sót tiến trình bắt gói:

```powershell
Get-Process dumpcap -ErrorAction SilentlyContinue | Stop-Process -Force
```

Dọn file bắt tạm:

```powershell
Remove-Item 'E:\HK9\ATTT_CK\nids_demo\data\live\*.csv' -Force -ErrorAction SilentlyContinue
Remove-Item 'E:\HK9\ATTT_CK\nids_demo\data\capture' -Recurse -Force -ErrorAction SilentlyContinue
```

Gỡ cấu hình lab (PowerShell **Run as administrator**):

```powershell
Remove-NetFirewallRule -DisplayName "Lab VMnet1" -ErrorAction SilentlyContinue
# Nếu đã bật SSH (mục 9.3):
Stop-Service sshd -ErrorAction SilentlyContinue; Set-Service sshd -StartupType Manual
Remove-LocalUser -Name 'labtest' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "Lab SSH" -ErrorAction SilentlyContinue
```

---

## 12. Xử lý sự cố

| Triệu chứng | Nguyên nhân | Cách xử lý |
|---|---|---|
| `ping`/`ab`/`hydra` timeout tới 192.168.136.1 | Tường lửa Windows chặn | Thêm rule `Lab VMnet1` (mục 6.5), chạy trong PowerShell admin |
| Lệnh `Set-NetFirewallRule`/`winget`… báo *command not found* trong Kali | Gõ nhầm lệnh Windows vào Kali | Lệnh `powershell` chạy trên **Windows**, lệnh `bash` chạy trên **Kali** |
| `ab` báo `Connection reset by peer` | Server quá tải | Server mẫu đã đặt hàng đợi 512; nếu vẫn lỗi, hạ `-c 20` |
| App bắt được luồng nhưng **không phát hiện DoS** | (a) thiếu `editcap` nên pcap nanosecond không xử lý được; (b) đang dùng Random Forest | (a) cài Wireshark (có editcap); (b) đổi sang **CNN-BiLSTM** |
| Dashboard đứng/giật khi flood | File pcap quá lớn (vd `hping3 --flood`) | **Không** dùng `--flood`; dùng `ab` tốc độ vừa |
| Quét cổng ra toàn Benign | Luồng một-gói không giống CIC-IDS2017 | Giới hạn mô hình; dùng **DoS HTTP** để minh họa phát hiện |
| `build_cicflowmeter.ps1` lỗi thiếu `git`/`javac` | Chưa cài Git/JDK hoặc PATH chưa nạp | Cài ở mục 3, **mở PowerShell mới**, chạy lại |
| Trang giám sát báo thiếu dumpcap/CICFlowMeter | Chưa cài Wireshark / chưa build CICFlowMeter | Xem mục 3, 5 |
| `python` mở Microsoft Store | App execution alias | Tắt alias hoặc dùng `py -3.12` |
| `Add-WindowsCapability` treo ở `[ooooo]` | Đang tải gói từ Windows Update | Chờ 2–5 phút; nếu lâu, Ctrl+C rồi `winget install --id Microsoft.OpenSSH.Beta -e` |

---

## 13. Phụ lục — bảng lệnh nhanh

**Cài phần mềm nền (Windows, admin):**
```powershell
winget install --id Git.Git -e; winget install --id Python.Python.3.12 -e; winget install --id EclipseAdoptium.Temurin.21.JDK -e; winget install --id WiresharkFoundation.Wireshark -e; winget install --id VMware.WorkstationPlayer -e
```

**Thiết lập app (Windows, trong `nids_demo`):**
| Việc | Lệnh |
|---|---|
| Tạo venv + cài thư viện | `py -3.12 -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements.txt` |
| Build CICFlowMeter | `powershell -ExecutionPolicy Bypass -File tools\build_cicflowmeter.ps1` |
| Kiểm thử | `.\.venv\Scripts\python.exe -m pytest -q tests` |

**Khởi chạy demo:**
| Việc | Máy | Lệnh |
|---|---|---|
| Mở tường lửa lab | Windows (admin) | `New-NetFirewallRule -DisplayName "Lab VMnet1" -Direction Inbound -RemoteAddress 192.168.136.0/24 -Action Allow` |
| Chạy server nạn nhân | Windows | `.\.venv\Scripts\python.exe tools\victim_http.py 192.168.136.1 80` |
| Chạy app | Windows | `.\.venv\Scripts\streamlit.exe run app.py` |
| Tấn công DoS | Kali | `ab -n 10000 -c 50 -r http://192.168.136.1/` |
| Quét cổng | Kali | `nmap -sS -T4 -p- 192.168.136.1` |
| Brute force SSH | Kali | `hydra -l labtest -P /tmp/lab_pw.txt -t 4 ssh://192.168.136.1` |

**Trình tự demo gọn:** (1) mở tường lửa → (2) chạy server nạn nhân → (3) chạy app, chọn CNN-BiLSTM, Bắt lưu
lượng thật trên VMnet1 → (4) từ Kali chạy `ab` → (5) chờ ~30–60s, xem cảnh báo DoS và `alerts.csv`.
