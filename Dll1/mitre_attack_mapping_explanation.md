# MITRE ATT&CK Mapping Explanation

Tai lieu nay mo ta cac ky thuat MITRE ATT&CK duoc the hien trong diagram `mitre_attack_mapping_light.drawio` va `mitre_attack_mapping_dark.drawio`.

## Initial Access

### T1566.002 - Spearphishing Link

Ky thuat nay mo ta viec tac nhan de doa gui email phishing co chua duong dan tai file doc hai. Trong kich ban bao cao, email gia mao chuong trinh trai nghiem Notepad++ ban thu nghiem va dan nguoi dung den link tai goi cai dat. Day la diem khoi dau cua chuoi lay nhiem, dua nguoi dung den file nen/cai dat co chua thanh phan doc hai.

Muc do tu tin: Trung binh. Day la kich ban lay nhiem duoc xay dung cho bao cao, khong phai hanh vi truc tiep nam trong `dllmain.cpp`.

## Execution

### T1204.002 - User Execution: Malicious File

Ky thuat nay xay ra khi nguoi dung bi thuyet phuc tai, giai nen va chay file cai dat/EXE. Trong kich ban nay, nguoi dung tin rang goi tai ve la ban thu nghiem Notepad++ va tu thuc thi file. Hanh dong nay kich hoat chuoi load DLL doc hai.

Muc do tu tin: Trung binh. Day la thanh phan cua kich ban phishing va phu hop voi chuoi lay nhiem du kien.

### T1059.005 - Command and Scripting Interpreter: Visual Basic

Mau tao file VBScript de chay lai DLL thong qua `WScript.Shell`. Trong code, `SetResilientPersistence` ghi noi dung VBS gom `Set ws = CreateObject("WScript.Shell")`, `WScript.Sleep 5000`, va lenh `ws.Run` de goi `rundll32.exe`.

Bang chung: `dllmain.cpp`, ham `SetResilientPersistence`, doan tao `SysCheck.vbs` va `SystemUpdate.vbs`.

Muc do tu tin: Cao.

### T1106 - Native API

Mau khai bao va goi truc tiep `NtProtectVirtualMemory`, mot Native API cua Windows, de thay doi quyen vung nho chua payload da giai ma sang `PAGE_EXECUTE_READ`. Viec nay cho phep shellcode duoc thuc thi trong tien trinh hien tai.

Bang chung: `dllmain.cpp`, khai bao `NtProtectVirtualMemory` va doan goi ham truoc khi thuc thi shellcode.

Muc do tu tin: Cao.

### T1620 - Reflective Code Loading

Sau khi payload duoc giai ma trong bo nho, mau doi quyen vung nho sang executable va goi truc tiep buffer `decrypted` nhu mot ham. Payload khong duoc ghi ra dia o dang file thuc thi rieng, ma duoc load va chay truc tiep trong RAM cua tien trinh hien tai.

Bang chung: `VirtualAlloc`, `CryptDecrypt`, `NtProtectVirtualMemory`/`VirtualProtect`, `FlushInstructionCache`, va `((void(*)(void))decrypted)()`.

Muc do tu tin: Cao.

## Persistence

### T1547.001 - Registry Run Keys / Startup Folder

Mau tao file `SystemUpdate.vbs` trong Startup Folder cua user. Khi nguoi dung dang nhap lai Windows, script nay se duoc chay tu dong va goi lai DLL thong qua `rundll32.exe`.

Bang chung: `dllmain.cpp`, ham `SetResilientPersistence`, doan goi `SHGetFolderPathA(NULL, CSIDL_STARTUP, ...)` va ghi file `SystemUpdate.vbs`.

Muc do tu tin: Cao.

## Defense Evasion / Stealth

### T1574.001 - Hijack Execution Flow: DLL

Mau su dung mo hinh DLL sideloading/proxy DLL. DLL doc hai duoc dat de ung dung hop le nap vao, dong thoi forward nhieu export sang DLL hop le de tranh lam ung dung bi crash. Theo ATT&CK live hien tai, DLL side-loading nam trong `T1574.001 - Hijack Execution Flow: DLL`.

Bang chung: phan export forwarding trong `dllmain.cpp`, su dung `winmm.dll`, va quy trinh tao proxy DLL bang SharpDllProxy.

Muc do tu tin: Cao.

### T1218.011 - System Binary Proxy Execution: Rundll32

Mau tao VBScript de goi `rundll32.exe` voi cu phap chay DLL va export `RunMalware`. Day la viec loi dung binary hop phap cua Windows de proxy execution cua DLL.

Bang chung: `ws.Run "rundll32.exe ... ,RunMalware"` trong file VBS duoc sinh boi `SetResilientPersistence`.

Muc do tu tin: Cao.

### T1027.013 - Obfuscated Files or Information: Encrypted/Encoded File

Payload khong duoc luu duoi dang shellcode ro trong DLL, ma duoc ma hoa bang AES-256-CBC va luu thanh `IV` va `CIPHERTEXT`. Cach nay giup che giau payload khi phan tich tinh.

Bang chung: `payload_hex.c`/`payload_hex_encrypted.c` co `IV` va `CIPHERTEXT`; script `encrypted_payload_hex.py` thuc hien AES-CBC encryption.

Muc do tu tin: Cao.

### T1140 - Deobfuscate/Decode Files or Information

Khi chay, loader su dung CryptoAPI de import key AES, set CBC mode, set IV va goi `CryptDecrypt` de giai ma payload trong bo nho. Day la buoc khoi phuc payload da bi ma hoa truoc khi thuc thi.

Bang chung: `dllmain.cpp`, ham `DoMagic`, cac loi goi `CryptAcquireContextA`, `CryptImportKey`, `CryptSetKeyParam`, va `CryptDecrypt`.

Muc do tu tin: Cao.

### T1036.005 - Masquerading: Match Legitimate Resource Name or Location

Mau dat ten file giong thanh phan he thong/cap nhat nhu `SysUpdateCore.dll`, `SysCheck.vbs`, va `SystemUpdate.vbs`. Cac ten nay co muc dich lam artifact trong he thong trong hop le hon va giam su chu y cua nguoi dung.

Bang chung: `dllmain.cpp`, ham `SetResilientPersistence`, doan tao ten file trong `%TEMP%` va Startup Folder.

Muc do tu tin: Cao.

### T1564.003 - Hide Artifacts: Hidden Window

VBScript su dung `WScript.Shell` voi tham so window style bang `0`, giup tien trinh `rundll32.exe` duoc chay o che do an cua so. Dieu nay lam giam kha nang nguoi dung nhin thay cua so lenh hoac tien trinh bat thuong.

Bang chung: `ws.Run "...", 0, False` trong cac file VBS duoc tao boi `SetResilientPersistence`.

Muc do tu tin: Cao.

## Command and Control

### T1071.001 - Application Layer Protocol: Web Protocols

Payload Beacon duoc tao tu Cobalt Strike va co dau hieu giao tiep C2 qua web protocols. Trong payload goc co cac chuoi HTTP-like nhu `Host`, `Connection`, `Accept`, `User-Agent`, va dia chi C2. Ngoai ra, file log trong thu muc test cho thay beacon goi ve va nhan lenh.

Bang chung: `payload_hex.c` trong thu muc `test` chua cac chuoi HTTP-like; `note.txt` co log beacon.

Muc do tu tin: Trung binh den cao. Day la hanh vi thuoc payload Beacon da duoc nhung/ma hoa, khong phai hanh vi ket noi truc tiep nam trong `dllmain.cpp`.

## Ghi Chu Mapping

- Khong dua `Process Injection` vao bang chinh vi code khong co `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` hoac API injection lien tien trinh tuong duong.
- Khong dua `Sleep Mask` vao bang chinh vi code chi co `WScript.Sleep 5000` va `Sleep(100)`, chua co co che ma hoa lai payload/beacon trong luc sleep.
- `DLL Side-Loading` nen map theo ATT&CK live la `T1574.001 - Hijack Execution Flow: DLL`.
