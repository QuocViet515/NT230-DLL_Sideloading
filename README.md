# NT230 - DLL Side-Loading (`winmm.dll`) Detection Lab

## Luu y an toan
Du an nay phuc vu muc dich hoc tap nghien cuu va xay dung phong thu trong moi truong lab co kiem soat.  
Khong su dung mau PoC de trien khai tren he thong that.

## Tong quan nhanh
Repo gom 2 khoi chinh:

- `Dll1/`: mau DLL PoC mo phong ky thuat DLL side-loading qua ten `winmm.dll`.
- `guardian/`: cong cu giam sat + phat hien + chan mau nghiem ngo theo rule/scoring.

---

## 1) Tong quan DLL PoC (side-load qua `winmm.dll`)

Mau DLL trong `Dll1` duoc thiet ke theo huong **proxy DLL**:

- Xuat ra nhieu export tuong thich voi `winmm.dll` de ung dung host van tiep tuc chay.
- Co them export dac trung nhu `DllRegisterServer` va `RunMalware`.
- Khi DLL duoc nap (`DLL_PROCESS_ATTACH`), code khoi dong worker de chay logic chinh va tao dau vet persistence.

Hanh vi chinh quan sat duoc tu source:

1. Tai payload da ma hoa trong `payload_hex.c`.
2. Giai ma payload trong bo nho (AES-CBC), doi quyen trang nho (`NtProtectVirtualMemory`/`VirtualProtect`) va thuc thi trong memory.
3. Tao persistence bang cach:
   - copy DLL sang `%TEMP%` (ten nhu `SysUpdateCore.dll`),
   - tao script VBS launcher (vi du `SystemUpdate.vbs`, `SysCheck.vbs`),
   - kich hoat chuoi goi qua `rundll32`.

Muc tieu cua phan nay trong bai toan la tao mau hanh vi side-loading de danh gia bo quy tac phat hien.

---

## 2) Cong cu `guardian` phat hien nhu the nao

`guardian` dung mo hinh **rule + score** va co 3 lop phat hien bo tro nhau:

## Lop A - File-level detection (static/behavioral IOC)

File chinh: `guardian/guardian.py`

- Theo doi realtime thu muc bang `ReadDirectoryChangesW`.
- Scan cac dinh dang ung vien: `.dll`, `.exe`, `.vbs`, `.cmd`, `.zip`, ...
- Trich xuat va cham diem theo nhieu tin hieu:
  - hash trung `known_sha256` (+120),
  - ten file nghi ngo (+40),
  - string IOC trong binary (+diem theo so luong),
  - critical string groups (vd `rundll32 + runmalware + systemupdate.vbs`) (+40/group),
  - pattern export proxy `winmm` (>= `min_winmm_export_matches`) (+60),
  - cap export `RunMalware + DllRegisterServer` (+25).
- Co allowlist chu ky: file Microsoft signed hop le co the duoc ha uu tien (score = 0).
- Ho tro scan `.zip` de bat DLL nghi ngo nam ben trong archive.

Mac dinh, file dat `score >= block_threshold` (trong `rules.json`, hien tai la `70`) se bi xem la malicious.

## Lop B - Runtime process va registry correlation

Cac module chinh:

- `guardian/process_scanner.py`
- `guardian/registry_scanner.py`
- `guardian/technique_mapper.py`

Process scanner tap trung vao chain side-loading:

- Theo doi host process profile (mac dinh Notepad++: `notepad++.exe`, `npp.exe`).
- Kiem tra module `winmm.dll` duoc nap tu dau:
  - dung duong dan he thong hay khong,
  - co nam trong user-writable path hay khong,
  - chu ky co hop le/Microsoft hay khong.
- Bat cac commandline co IOC (`rundll32`, `runmalware`, `sysupdatecore.dll`, ...).
- Co the bo sung VT enrichment (tuy chon) de tang diem neu file/module bi engine ben ngoai danh dau.

Registry scanner quet:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- Startup folder script (`.vbs`)

de tim persistence token lien quan side-loading chain.

## Lop C - Mapping ky thuat ATT&CK + phan ung

- `technique_mapper.py` suy luan ky thuat (vd `T1574.001`, `T1218.011`, `T1547.001`, ...).
- Khi vuot nguong block, guardian co the:
  - stop process map dung path mau,
  - stop LOLBins pho bien (`rundll32`, `regsvr32`, `fodhelper`) neu lien quan DLL,
  - quarantine file vao `guardian/quarantine/`,
  - ghi su kien JSONL trong `guardian/logs/detections.jsonl`.

---

## 3) Luong xu ly tong quat

1. Co file moi/thay doi trong thu muc watch.  
2. `guardian.py` scan + tinh score + tao IOC/reasons.  
3. `technique_mapper` gan ATT&CK techniques.  
4. Neu score du nguong: chan + quarantine; neu khong: ghi alert.  
5. Dashboard doc log va hien thi su kien, IOC, ky thuat, trang thai.

---

## 4) Danh gia chat luong detector

Script: `guardian/evaluate_sideload_detector.py`

- Doc manifest mau tu `guardian/eval_manifest_sideload.json`.
- Chay detector tren bo mau malicious/benign.
- Tinh chi so:
  - Precision, Recall, F1, Accuracy,
  - Technique recall (muc do map dung ATT&CK ky vong).
- Xuat bao cao:
  - `guardian/logs/eval_sideload_report.json`
  - `guardian/logs/eval_sideload_report.md`

---

## 5) Chay nhanh

Chay detector o che do canh bao (khong block):

```powershell
python .\guardian\guardian.py --dry-run --scan-existing --verbose
```

Chay detector o che do block:

```powershell
python .\guardian\guardian.py --scan-existing
```

Mo dashboard:

```powershell
python .\guardian\dashboard.py --open-browser
```

Danh gia detector:

```powershell
python .\guardian\evaluate_sideload_detector.py
```
