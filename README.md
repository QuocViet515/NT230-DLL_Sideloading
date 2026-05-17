# NT230 - Phòng thí nghiệm phát hiện DLL Side-Loading (`winmm.dll`)

## Lưu ý an toàn
Dự án này phục vụ mục đích học tập, nghiên cứu và xây dựng phòng thủ trong môi trường lab có kiểm soát.
Không sử dụng bản PoC để triển khai trên hệ thống thật.

## Tổng quan nhanh
Repository gồm hai phần chính:

- `Dll1/`: mẫu DLL PoC mô phỏng kỹ thuật DLL side-loading với tên `winmm.dll`.
- `guardian/`: công cụ giám sát, phát hiện và chặn mã độc mẫu theo cơ chế rule/score.

---

## 1) Tổng quan mẫu DLL PoC (side-load qua `winmm.dll`)

Mẫu DLL trong `Dll1` được thiết kế theo kiểu **proxy DLL**:

- Export nhiều hàm tương thích với `winmm.dll` để ứng dụng host vẫn tiếp tục hoạt động.
- Có thêm export đặc trưng như `DllRegisterServer` và `RunMalware`.
- Khi DLL được nạp (`DLL_PROCESS_ATTACH`), code khởi động một worker để chạy logic chính và tạo dấu vết persistence.

Hành vi chính quan sát được từ mã nguồn:

1. Tải payload đã mã hóa trong `payload_hex.c`.
2. Giải mã payload trong bộ nhớ (AES-CBC), thay đổi quyền trang nhớ (`NtProtectVirtualMemory`/`VirtualProtect`) và thực thi trong memory.
3. Tạo persistence bằng cách:
   - sao chép DLL sang `%TEMP%` (tên ví dụ `SysUpdateCore.dll`),
   - tạo script VBS launcher (ví dụ `SystemUpdate.vbs`, `SysCheck.vbs`),
   - kích hoạt chuỗi gọi qua `rundll32`.

Mục tiêu của phần này là tạo mẫu hành vi side-loading để đánh giá bộ quy tắc phát hiện.

---

## 2) Công cụ `guardian` phát hiện như thế nào

`guardian` dùng mô hình **rule + score** và có 3 lớp phát hiện bổ trợ nhau:

### Lớp A - Phát hiện ở mức file (static/behavioral IOC)

File chính: `guardian/guardian.py`

- Theo dõi realtime thư mục bằng `ReadDirectoryChangesW`.
- Quét các định dạng ứng viên: `.dll`, `.exe`, `.vbs`, `.cmd`, `.zip`, ...
- Trích xuất và chấm điểm theo nhiều tín hiệu:
  - hash trùng với `known_sha256` (+120),
  - tên file đáng ngờ (+40),
  - chuỗi IOC trong binary (cộng điểm theo số lượng),
  - nhóm chuỗi quan trọng (ví dụ `rundll32 + runmalware + systemupdate.vbs`) (+40/nhóm),
  - pattern export proxy `winmm` (>= `min_winmm_export_matches`) (+60),
  - cặp export `RunMalware + DllRegisterServer` (+25).
- Có allowlist chữ ký: file được Microsoft ký hợp lệ có thể được ưu tiên (score = 0).
- Hỗ trợ quét `.zip` để phát hiện DLL nằm bên trong archive.

Mặc định, file đạt `score >= block_threshold` (trong `rules.json`, hiện tại là `70`) sẽ được coi là malicious.

### Lớp B - Tương quan tiến trình (process) và registry thời gian chạy

Các module chính:

- `guardian/process_scanner.py`
- `guardian/registry_scanner.py`
- `guardian/technique_mapper.py`

Process scanner tập trung vào chuỗi side-loading:

- Theo dõi profile process host (mặc định Notepad++: `notepad++.exe`, `npp.exe`).
- Kiểm tra module `winmm.dll` được nạp từ đâu:
  - có phải đường dẫn hệ thống hay không,
  - có nằm trong đường dẫn có thể ghi bởi người dùng hay không,
  - chữ ký có hợp lệ/Microsoft hay không.
- Bắt các commandline có IOC (`rundll32`, `runmalware`, `sysupdatecore.dll`, ...).
- Có thể bổ sung enrichment từ VirusTotal (tùy chọn) để tăng điểm nếu file/module bị engine bên ngoài đánh dấu.

Registry scanner quét:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- Thư mục Startup (script `.vbs`)

để tìm các token persistence liên quan tới chuỗi side-loading.

### Lớp C - Mapping kỹ thuật ATT&CK và phản ứng

- `technique_mapper.py` suy luận kỹ thuật (ví dụ `T1574.001`, `T1218.011`, `T1547.001`, ...).
- Khi vượt ngưỡng block, `guardian` có thể:
  - dừng process theo đường dẫn mẫu,
  - chặn các LOLBins phổ biến (`rundll32`, `regsvr32`, `fodhelper`) nếu liên quan DLL,
  - cách ly (quarantine) file vào `guardian/quarantine/`,
  - ghi sự kiện ở định dạng JSONL trong `guardian/logs/detections.jsonl`.

---

## 3) Luồng xử lý tổng quát

1. Có file mới/thay đổi trong thư mục watch.
2. `guardian.py` quét, tính score và tạo IOC/reasons.
3. `technique_mapper` gán kỹ thuật ATT&CK tương ứng.
4. Nếu score đủ ngưỡng: chặn + quarantine; nếu không: ghi alert.
5. Dashboard đọc log và hiển thị sự kiện, IOC, kỹ thuật, trạng thái.

---

## 4) Đánh giá chất lượng detector

Script: `guardian/evaluate_sideload_detector.py`

- Đọc manifest mẫu từ `guardian/eval_manifest_sideload.json`.
- Chạy detector trên bộ mẫu malicious/benign.
- Tính các chỉ số:
  - Precision, Recall, F1, Accuracy,
  - Technique recall (mức độ map đúng ATT&CK mong đợi).
- Xuất báo cáo:
  - `guardian/logs/eval_sideload_report.json`
  - `guardian/logs/eval_sideload_report.md`

---

## 5) Chạy nhanh

Chạy detector ở chế độ cảnh báo (không block):

```powershell
python .\guardian\guardian.py --dry-run --scan-existing --verbose
```

Chạy detector ở chế độ block:

```powershell
python .\guardian\guardian.py --scan-existing
```

Mở dashboard:

```powershell
python .\guardian\dashboard.py --open-browser
```

Đánh giá detector:

```powershell
python .\guardian\evaluate_sideload_detector.py
```
