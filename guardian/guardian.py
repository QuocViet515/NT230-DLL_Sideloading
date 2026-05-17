#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import logging
import os
import queue
import re
import shutil
import signal
import struct
import subprocess
import threading
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from technique_mapper import infer_techniques


FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE_VALUE = wt.HANDLE(-1).value

NOTIFY_FILTER = (
    0x00000001  # FILE_NOTIFY_CHANGE_FILE_NAME
    | 0x00000002  # FILE_NOTIFY_CHANGE_DIR_NAME
    | 0x00000004  # FILE_NOTIFY_CHANGE_ATTRIBUTES
    | 0x00000008  # FILE_NOTIFY_CHANGE_SIZE
    | 0x00000010  # FILE_NOTIFY_CHANGE_LAST_WRITE
    | 0x00000020  # FILE_NOTIFY_CHANGE_LAST_ACCESS
    | 0x00000040  # FILE_NOTIFY_CHANGE_CREATION
    | 0x00000100  # FILE_NOTIFY_CHANGE_SECURITY
)

ACTION_CREATED = 1
ACTION_MODIFIED = 3
ACTION_RENAMED_NEW_NAME = 5

CANDIDATE_EXTENSIONS = {
    ".dll",
    ".exe",
    ".msi",
    ".vbs",
    ".js",
    ".ps1",
    ".bat",
    ".cmd",
    ".zip",
}

MAX_SCAN_BYTES = 30 * 1024 * 1024
SIGNED_TRUSTED_EXTENSIONS = {".dll", ".exe", ".msi", ".sys", ".ocx", ".cpl"}
MICROSOFT_SIGNER_TOKENS = {
    "o=microsoft corporation",
    "cn=microsoft windows",
    "cn=microsoft corporation",
}
AUTH_SIG_CACHE: dict[str, tuple[float, int, str, str]] = {}


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [
    wt.LPCWSTR,
    wt.DWORD,
    wt.DWORD,
    wt.LPVOID,
    wt.DWORD,
    wt.DWORD,
    wt.HANDLE,
]
CreateFileW.restype = wt.HANDLE

ReadDirectoryChangesW = kernel32.ReadDirectoryChangesW
ReadDirectoryChangesW.argtypes = [
    wt.HANDLE,
    wt.LPVOID,
    wt.DWORD,
    wt.BOOL,
    wt.DWORD,
    ctypes.POINTER(wt.DWORD),
    wt.LPVOID,
    wt.LPVOID,
]
ReadDirectoryChangesW.restype = wt.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wt.HANDLE]
CloseHandle.restype = wt.BOOL


@dataclass
class ScanRules:
    known_sha256: set[str]
    suspicious_filenames: set[str]
    suspicious_strings: list[str]
    critical_string_groups: list[list[str]]
    winmm_proxy_exports: set[str]
    min_winmm_export_matches: int
    block_threshold: int
    active_profile: str
    host_processes: set[str]
    target_dlls: set[str]
    expected_system_paths: set[str]
    user_writable_path_tokens: set[str]
    trusted_host_path_tokens: set[str]

    @staticmethod
    def from_json(path: Path) -> "ScanRules":
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)

        profiles = raw.get("profiles", {})
        active_profile = str(raw.get("active_profile", "")).strip()
        selected_profile: dict = {}
        if active_profile and isinstance(profiles, dict):
            candidate = profiles.get(active_profile)
            if isinstance(candidate, dict):
                selected_profile = candidate

        def pick_value(key: str, default):
            if key in selected_profile:
                return selected_profile.get(key)
            return raw.get(key, default)

        def to_lower_set(value, *, path_mode: bool = False) -> set[str]:
            if not isinstance(value, list):
                return set()
            out: set[str] = set()
            for item in value:
                text = str(item).strip()
                if not text:
                    continue
                if path_mode:
                    text = text.replace("/", "\\")
                out.add(text.lower())
            return out

        return ScanRules(
            known_sha256={x.lower() for x in raw.get("known_sha256", [])},
            suspicious_filenames={x.lower() for x in raw.get("suspicious_filenames", [])},
            suspicious_strings=[x.lower() for x in raw.get("suspicious_strings", [])],
            critical_string_groups=[
                [token.lower() for token in group]
                for group in raw.get("critical_string_groups", [])
            ],
            winmm_proxy_exports={x.lower() for x in raw.get("winmm_proxy_exports", [])},
            min_winmm_export_matches=int(raw.get("min_winmm_export_matches", 25)),
            block_threshold=int(raw.get("block_threshold", 70)),
            active_profile=active_profile or "default",
            host_processes=to_lower_set(
                pick_value("host_processes", ["notepad++.exe", "npp.exe"])
            ),
            target_dlls=to_lower_set(pick_value("target_dlls", ["winmm.dll"])),
            expected_system_paths=to_lower_set(
                pick_value("expected_system_paths", [r"C:\Windows\System32\winmm.dll"]),
                path_mode=True,
            ),
            user_writable_path_tokens=to_lower_set(
                pick_value(
                    "user_writable_path_tokens",
                    [
                        "\\users\\",
                        "\\downloads\\",
                        "\\desktop\\",
                        "\\appdata\\",
                        "\\temp\\",
                        "\\onedrive\\",
                    ],
                ),
                path_mode=True,
            ),
            trusted_host_path_tokens=to_lower_set(
                pick_value(
                    "trusted_host_path_tokens",
                    [
                        "\\program files\\notepad++\\",
                        "\\program files (x86)\\notepad++\\",
                    ],
                ),
                path_mode=True,
            ),
        )


@dataclass
class Detection:
    path: Path
    score: int
    severity: str
    reasons: list[str]
    sha256: str
    blocked: bool
    quarantined_path: str | None
    iocs: list[dict[str, str]] = field(default_factory=list)
    malware_types: list[str] = field(default_factory=list)
    malware_confidence: float = 0.0
    techniques: list[dict[str, object]] = field(default_factory=list)


@dataclass
class ScanResult:
    score: int
    reasons: list[str]
    sha256: str
    iocs: list[dict[str, str]] = field(default_factory=list)


def build_ioc(ioc_type: str, value: str, source: str) -> dict[str, str]:
    return {
        "type": str(ioc_type).strip().lower(),
        "value": str(value).strip(),
        "source": str(source).strip().lower(),
    }


def dedupe_iocs(iocs: list[dict[str, str]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in iocs:
        if not isinstance(item, dict):
            continue
        ioc_type = str(item.get("type", "")).strip().lower()
        value = str(item.get("value", "")).strip()
        source = str(item.get("source", "")).strip().lower()
        if not ioc_type or not value:
            continue
        key = f"{ioc_type}|{value.lower()}|{source}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": ioc_type, "value": value, "source": source})
    return out


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _decode_subprocess_output(raw: bytes) -> str:
    if not raw:
        return ""
    for encoding in ("utf-8-sig", "utf-8", "utf-16le"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode(errors="replace")


def _escape_ps_single_quotes(value: str) -> str:
    return value.replace("'", "''")


def get_authenticode_info(path: Path) -> tuple[str, str]:
    try:
        stat = path.stat()
    except OSError:
        return "UnknownError", ""

    cache_key = str(path.resolve()).lower()
    cached = AUTH_SIG_CACHE.get(cache_key)
    if cached and cached[0] == stat.st_mtime and cached[1] == stat.st_size:
        return cached[2], cached[3]

    path_escaped = _escape_ps_single_quotes(str(path))
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$sig=Get-AuthenticodeSignature -LiteralPath '{path_escaped}'; "
        "$subject=''; "
        "if($sig.SignerCertificate){$subject=$sig.SignerCertificate.Subject}; "
        "$obj=[pscustomobject]@{Status=[string]$sig.Status; Subject=$subject}; "
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "$obj | ConvertTo-Json -Compress"
    )

    status = "UnknownError"
    subject = ""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=False,
            check=False,
            timeout=10,
        )
        if proc.returncode == 0:
            stdout_text = _decode_subprocess_output(proc.stdout or b"").strip()
            if stdout_text:
                line = stdout_text.splitlines()[-1].strip()
                try:
                    parsed = json.loads(line)
                    status = str(parsed.get("Status", "UnknownError"))
                    subject = str(parsed.get("Subject", ""))
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass

    AUTH_SIG_CACHE[cache_key] = (stat.st_mtime, stat.st_size, status, subject)
    return status, subject


def is_microsoft_trusted_signature(path: Path) -> tuple[bool, str, str]:
    status, subject = get_authenticode_info(path)
    normalized_subject = subject.lower()
    if status == "Valid" and any(token in normalized_subject for token in MICROSOFT_SIGNER_TOKENS):
        return True, status, subject
    return False, status, subject


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def safe_read_bytes(path: Path, max_bytes: int = MAX_SCAN_BYTES) -> bytes:
    size = path.stat().st_size
    if size > max_bytes:
        with path.open("rb") as handle:
            return handle.read(max_bytes)
    return path.read_bytes()


def extract_strings_from_bytes(data: bytes, min_len: int = 6) -> set[str]:
    strings = set()

    ascii_pattern = rb"[ -~]{%d,}" % min_len
    for match in re.finditer(ascii_pattern, data):
        try:
            strings.add(match.group().decode("ascii", errors="ignore").lower())
        except Exception:
            continue

    utf16_pattern = rb"(?:[ -~]\x00){%d,}" % min_len
    for match in re.finditer(utf16_pattern, data):
        raw = match.group()
        try:
            strings.add(raw.decode("utf-16le", errors="ignore").lower())
        except Exception:
            continue

    return strings


def parse_pe_exports(data: bytes) -> set[str]:
    exports: set[str] = set()

    if len(data) < 0x100 or data[0:2] != b"MZ":
        return exports

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 0x18 >= len(data):
            return exports
        if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return exports

        file_header_off = e_lfanew + 4
        (
            _machine,
            number_of_sections,
            _time_date_stamp,
            _ptr_symbol_table,
            _num_symbols,
            size_of_optional_header,
            _characteristics,
        ) = struct.unpack_from("<HHIIIHH", data, file_header_off)

        optional_header_off = file_header_off + 20
        optional_header_end = optional_header_off + size_of_optional_header
        if optional_header_end > len(data):
            return exports

        magic = struct.unpack_from("<H", data, optional_header_off)[0]
        if magic == 0x10B:
            data_dir_off = optional_header_off + 96
        elif magic == 0x20B:
            data_dir_off = optional_header_off + 112
        else:
            return exports

        if data_dir_off + 8 > len(data):
            return exports

        export_rva, _export_size = struct.unpack_from("<II", data, data_dir_off)
        if export_rva == 0:
            return exports

        section_table_off = optional_header_end
        sections = []
        for idx in range(number_of_sections):
            off = section_table_off + idx * 40
            if off + 40 > len(data):
                break
            (
                _name,
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                _pointer_to_relocations,
                _pointer_to_linenumbers,
                _number_of_relocations,
                _number_of_linenumbers,
                _characteristics,
            ) = struct.unpack_from("<8sIIIIIIHHI", data, off)
            mapped_size = max(virtual_size, size_of_raw_data)
            sections.append((virtual_address, mapped_size, pointer_to_raw_data))

        def rva_to_offset(rva: int) -> int | None:
            for va, size_mapped, ptr_raw in sections:
                if va <= rva < va + size_mapped:
                    result = ptr_raw + (rva - va)
                    if 0 <= result < len(data):
                        return result
            return None

        export_off = rva_to_offset(export_rva)
        if export_off is None or export_off + 40 > len(data):
            return exports

        (
            _characteristics,
            _time_date_stamp,
            _major_version,
            _minor_version,
            _name_rva,
            _base,
            _number_of_functions,
            number_of_names,
            _address_of_functions_rva,
            address_of_names_rva,
            _address_of_name_ordinals_rva,
        ) = struct.unpack_from("<IIHHIIIIIII", data, export_off)

        names_array_off = rva_to_offset(address_of_names_rva)
        if names_array_off is None:
            return exports

        max_names = min(number_of_names, 2500)
        for idx in range(max_names):
            name_rva_off = names_array_off + idx * 4
            if name_rva_off + 4 > len(data):
                break
            name_rva = struct.unpack_from("<I", data, name_rva_off)[0]
            name_off = rva_to_offset(name_rva)
            if name_off is None:
                continue

            end = name_off
            while end < len(data) and data[end] != 0 and end - name_off < 256:
                end += 1
            if end <= name_off:
                continue

            export_name = data[name_off:end].decode("ascii", errors="ignore").strip().lower()
            if export_name:
                exports.add(export_name)
    except Exception:
        return set()

    return exports


def score_strings(
    strings: set[str], rules: ScanRules, reasons: list[str]
) -> tuple[int, list[str], list[list[str]]]:
    score = 0
    matched: list[str] = []
    matched_groups: list[list[str]] = []

    blob = "\n".join(strings)
    for token in rules.suspicious_strings:
        if token in blob:
            matched.append(token)

    if matched:
        token_boost = min(48, len(matched) * 6)
        score += token_boost
        preview = ", ".join(matched[:8])
        reasons.append(
            f"matched suspicious strings ({len(matched)}): {preview} (+{token_boost})"
        )

    for group in rules.critical_string_groups:
        if all(token in blob for token in group):
            score += 40
            matched_groups.append(group)
            reasons.append(f"matched critical string group: {', '.join(group)} (+40)")

    return score, matched, matched_groups


def score_exports(
    exports: set[str], rules: ScanRules, reasons: list[str]
) -> tuple[int, int, list[str]]:
    if not exports:
        return 0, 0, []

    score = 0
    matched_exports: list[str] = []
    proxy_matched_names = sorted(exports & rules.winmm_proxy_exports)
    proxy_matches = len(proxy_matched_names)
    if proxy_matches >= rules.min_winmm_export_matches:
        score += 60
        reasons.append(
            f"winmm proxy export pattern detected ({proxy_matches} matches) (+60)"
        )
        matched_exports.extend(proxy_matched_names[:80])
    elif proxy_matches >= 15:
        score += 30
        reasons.append(f"partial winmm proxy export pattern ({proxy_matches}) (+30)")
        matched_exports.extend(proxy_matched_names[:40])

    if "runmalware" in exports and "dllregisterserver" in exports:
        score += 25
        reasons.append("exports include RunMalware + DllRegisterServer (+25)")
        matched_exports.extend(["runmalware", "dllregisterserver"])

    return score, proxy_matches, sorted(set(matched_exports))


def severity_from_score(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 30:
        return "low"
    return "info"


def sanitize_file_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return cleaned[:180]


def quarantine_file(path: Path, quarantine_dir: Path) -> Path | None:
    try:
        ensure_dir(quarantine_dir)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        target = quarantine_dir / f"{stamp}_{sanitize_file_name(path.name)}.blocked"
        if target.exists():
            target = quarantine_dir / (
                f"{stamp}_{int(time.time() * 1000)}_{sanitize_file_name(path.name)}.blocked"
            )
        shutil.move(str(path), str(target))
        return target
    except Exception as exc:
        logging.error("quarantine failed for %s: %s", path, exc)
        return None


def stop_process_by_exact_path(path: Path) -> None:
    target = _escape_ps_single_quotes(str(path))
    script = (
        "$target='" + target + "'; "
        "Get-Process -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Path -and ($_.Path -ieq $target) } | "
        "Stop-Process -Force -ErrorAction SilentlyContinue"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
    )


def stop_common_lolbins() -> None:
    script = (
        "Get-Process rundll32,regsvr32,fodhelper -ErrorAction SilentlyContinue | "
        "Stop-Process -Force -ErrorAction SilentlyContinue"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
    )


def evaluate_binary_blob(
    path_label: str,
    data: bytes,
    rules: ScanRules,
    base_name: str,
    known_sha256: str | None = None,
) -> ScanResult:
    score = 0
    reasons: list[str] = []
    iocs: list[dict[str, str]] = []
    sha256 = known_sha256 or hashlib.sha256(data).hexdigest()
    iocs.append(build_ioc("sha256", sha256, "file_hash"))
    iocs.append(build_ioc("filename", base_name, "file_name"))

    if sha256.lower() in rules.known_sha256:
        score += 120
        reasons.append("hash matched known malicious sample (+120)")
        iocs.append(build_ioc("sha256", sha256, "known_malicious_hash"))

    if base_name.lower() in rules.suspicious_filenames:
        score += 40
        reasons.append(f"suspicious filename: {base_name} (+40)")
        iocs.append(build_ioc("filename", base_name, "rule_suspicious_filename"))

    strings = extract_strings_from_bytes(data)
    string_score, matched_strings, matched_groups = score_strings(strings, rules, reasons)
    score += string_score
    for token in matched_strings[:50]:
        iocs.append(build_ioc("string", token, "rule_suspicious_string"))
    for group in matched_groups[:20]:
        iocs.append(build_ioc("string_group", " | ".join(group), "rule_critical_group"))

    exports = parse_pe_exports(data)
    export_score, proxy_matches, matched_exports = score_exports(exports, rules, reasons)
    score += export_score
    for export_name in matched_exports[:80]:
        iocs.append(build_ioc("export", export_name, "pe_export"))
    if proxy_matches:
        iocs.append(build_ioc("behavior", f"winmm_proxy_exports={proxy_matches}", "pe_exports_pattern"))

    if score == 0:
        reasons.append("no malicious indicators matched")

    return ScanResult(score=score, reasons=reasons, sha256=sha256, iocs=dedupe_iocs(iocs))


def evaluate_zip(path: Path, rules: ScanRules) -> ScanResult:
    reasons: list[str] = []
    iocs: list[dict[str, str]] = []
    score = 0
    archive_hash = sha256_file(path)
    iocs.append(build_ioc("sha256", archive_hash, "archive_hash"))
    iocs.append(build_ioc("filename", path.name, "archive_name"))

    try:
        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                inner_name = Path(info.filename).name.lower()
                inner_ext = Path(inner_name).suffix.lower()

                iocs.append(build_ioc("archive_entry", info.filename, "zip_entry"))
                if inner_name in rules.suspicious_filenames:
                    score += 45
                    reasons.append(
                        f"zip contains suspicious filename: {info.filename} (+45)"
                    )
                    iocs.append(
                        build_ioc("filename", inner_name, "zip_suspicious_filename")
                    )

                if inner_ext != ".dll":
                    continue

                if info.file_size > MAX_SCAN_BYTES:
                    continue

                inner_data = zf.read(info)
                inner_result = evaluate_binary_blob(
                    f"{path}!{info.filename}",
                    inner_data,
                    rules,
                    inner_name,
                )
                iocs.extend(inner_result.iocs)
                if inner_result.score >= 50:
                    boost = min(70, inner_result.score)
                    score += boost
                    reasons.append(
                        f"embedded DLL '{info.filename}' is suspicious (+{boost})"
                    )
                    reasons.extend([f"inner: {r}" for r in inner_result.reasons[:3]])
                    break
    except zipfile.BadZipFile:
        reasons.append("file extension is .zip but archive parse failed")
    except Exception as exc:
        reasons.append(f"zip scan error: {exc}")

    if score == 0:
        reasons.append("zip scan found no strong indicators")

    return ScanResult(score=score, reasons=reasons, sha256=archive_hash, iocs=dedupe_iocs(iocs))


def evaluate_file_detailed(path: Path, rules: ScanRules) -> ScanResult:
    ext = path.suffix.lower()

    if ext == ".zip":
        return evaluate_zip(path, rules)

    file_hash = sha256_file(path)
    iocs: list[dict[str, str]] = [build_ioc("sha256", file_hash, "file_hash")]
    iocs.append(build_ioc("filename", path.name, "file_name"))

    if ext in SIGNED_TRUSTED_EXTENSIONS:
        trusted, sig_status, sig_subject = is_microsoft_trusted_signature(path)
        if trusted:
            reasons = [
                f"authenticode status: {sig_status}",
                f"trusted microsoft signer: {sig_subject}",
                "allowlisted by trusted microsoft signature",
            ]
            iocs.append(build_ioc("signature_status", sig_status, "authenticode"))
            if sig_subject:
                iocs.append(build_ioc("signature_subject", sig_subject, "authenticode"))
            return ScanResult(
                score=0,
                reasons=reasons,
                sha256=file_hash,
                iocs=dedupe_iocs(iocs),
            )

    data = safe_read_bytes(path)
    inner_result = evaluate_binary_blob(
        str(path), data, rules, path.name.lower(), file_hash
    )
    iocs.extend(inner_result.iocs)
    reasons = list(inner_result.reasons)

    if ext in SIGNED_TRUSTED_EXTENSIONS:
        sig_status, sig_subject = get_authenticode_info(path)
        if sig_status:
            iocs.append(build_ioc("signature_status", sig_status, "authenticode"))
        if sig_subject:
            iocs.append(build_ioc("signature_subject", sig_subject, "authenticode"))
        if sig_status == "Valid":
            reasons.append(
                f"signature valid but signer not allowlisted: {sig_subject or 'unknown'}"
            )
        elif sig_status not in {"NotSigned", ""}:
            reasons.append(f"signature status: {sig_status}")

    return ScanResult(
        score=inner_result.score,
        reasons=reasons,
        sha256=inner_result.sha256,
        iocs=dedupe_iocs(iocs),
    )


def evaluate_file(path: Path, rules: ScanRules) -> tuple[int, list[str], str]:
    detailed = evaluate_file_detailed(path, rules)
    return detailed.score, detailed.reasons, detailed.sha256


def write_detection_log(log_path: Path, detection: Detection) -> None:
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "path": str(detection.path),
        "score": detection.score,
        "severity": detection.severity,
        "sha256": detection.sha256,
        "blocked": detection.blocked,
        "quarantined_path": detection.quarantined_path,
        "reasons": detection.reasons,
        "iocs": detection.iocs,
        "malware_types": detection.malware_types,
        "malware_confidence": detection.malware_confidence,
        "techniques": detection.techniques,
    }
    ensure_dir(log_path.parent)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=True) + "\n")


def is_candidate_path(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False
    ext = path.suffix.lower()
    return ext in CANDIDATE_EXTENSIONS


class DirectoryWatcher(threading.Thread):
    def __init__(self, root: Path, out_queue: queue.Queue[Path], stop_event: threading.Event):
        super().__init__(daemon=True)
        self.root = root
        self.out_queue = out_queue
        self.stop_event = stop_event

    def run(self) -> None:
        handle = CreateFileW(
            str(self.root),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )

        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            logging.error("cannot watch %s (CreateFileW error=%s)", self.root, err)
            return

        logging.info("watching directory: %s", self.root)
        buffer = ctypes.create_string_buffer(64 * 1024)

        try:
            while not self.stop_event.is_set():
                bytes_returned = wt.DWORD(0)
                ok = ReadDirectoryChangesW(
                    handle,
                    ctypes.byref(buffer),
                    ctypes.sizeof(buffer),
                    True,
                    NOTIFY_FILTER,
                    ctypes.byref(bytes_returned),
                    None,
                    None,
                )
                if not ok:
                    err = ctypes.get_last_error()
                    logging.error("ReadDirectoryChangesW failed on %s (error=%s)", self.root, err)
                    time.sleep(0.5)
                    continue

                raw = buffer.raw[: bytes_returned.value]
                for action, relative_name in parse_notifications(raw):
                    if action not in {ACTION_CREATED, ACTION_MODIFIED, ACTION_RENAMED_NEW_NAME}:
                        continue
                    candidate = self.root / relative_name
                    self.out_queue.put(candidate)
        finally:
            CloseHandle(handle)


def parse_notifications(raw: bytes) -> Iterable[tuple[int, str]]:
    offset = 0
    while offset + 12 <= len(raw):
        next_entry_offset, action, name_len = struct.unpack_from("<III", raw, offset)
        name_start = offset + 12
        name_end = name_start + name_len
        if name_end > len(raw):
            break
        name = raw[name_start:name_end].decode("utf-16le", errors="ignore")
        yield action, name

        if next_entry_offset == 0:
            break
        offset += next_entry_offset


def default_watch_dirs() -> list[Path]:
    dirs = []
    home = Path.home()
    downloads = home / "Downloads"
    desktop = home / "Desktop"
    temp_env = os.environ.get("TEMP")
    local_app_data = os.environ.get("LOCALAPPDATA")

    for item in (downloads, desktop):
        if item.exists():
            dirs.append(item)

    if temp_env:
        temp_path = Path(temp_env)
        if temp_path.exists():
            dirs.append(temp_path)

    if local_app_data:
        latemp = Path(local_app_data) / "Temp"
        if latemp.exists():
            dirs.append(latemp)

    unique = []
    seen = set()
    for path in dirs:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)

    return unique


def run_scan_existing(paths: list[Path], schedule: dict[Path, float], delay: float) -> None:
    for watch_dir in paths:
        for file_path in watch_dir.rglob("*"):
            if file_path.is_file() and is_candidate_path(file_path):
                schedule[file_path] = time.time() + delay


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Realtime DLL malware detector and blocker (Windows)."
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=Path(__file__).resolve().parent / "rules.json",
        help="Path to JSON rule file.",
    )
    parser.add_argument(
        "--watch",
        action="append",
        default=[],
        help="Directory to watch (can be used multiple times).",
    )
    parser.add_argument(
        "--quarantine-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "quarantine",
        help="Where blocked files are moved.",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path(__file__).resolve().parent / "logs" / "detections.jsonl",
        help="JSONL detection log file.",
    )
    parser.add_argument(
        "--delay-seconds",
        type=float,
        default=1.5,
        help="Delay before scanning a changed file, to avoid partial writes.",
    )
    parser.add_argument(
        "--scan-existing",
        action="store_true",
        help="Also scan existing files inside watch directories at startup.",
    )
    parser.add_argument(
        "--scan-file",
        action="append",
        default=[],
        help="One-shot scan one file path (can be used multiple times), then exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not quarantine/kill. Log only.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logs.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)

    if not args.rules.exists():
        logging.error("rule file not found: %s", args.rules)
        return 2

    rules = ScanRules.from_json(args.rules)
    logging.info("loaded rules from %s", args.rules)
    logging.info("block threshold score: %s", rules.block_threshold)

    if args.scan_file:
        exit_code = 0
        for file_input in args.scan_file:
            path = Path(file_input).expanduser().resolve()
            if not path.exists() or not path.is_file():
                logging.error("scan target not found: %s", path)
                exit_code = 2
                continue

            try:
                scan_result = evaluate_file_detailed(path, rules)
            except Exception as exc:
                logging.error("scan failed for %s: %s", path, exc)
                exit_code = 2
                continue

            score = scan_result.score
            reasons = scan_result.reasons
            sample_hash = scan_result.sha256
            techniques = infer_techniques(
                path=path,
                reasons=reasons,
                iocs=scan_result.iocs,
                score=score,
            )
            severity = severity_from_score(score)
            should_block = score >= rules.block_threshold
            quarantined_path: str | None = None

            if should_block and not args.dry_run:
                stop_process_by_exact_path(path)
                if path.suffix.lower() == ".dll":
                    stop_common_lolbins()
                quarantine_target = quarantine_file(path, args.quarantine_dir)
                quarantined_path = str(quarantine_target) if quarantine_target else None

            detection = Detection(
                path=path,
                score=score,
                severity=severity,
                reasons=reasons,
                sha256=sample_hash,
                blocked=should_block and not args.dry_run,
                quarantined_path=quarantined_path,
                iocs=scan_result.iocs,
                techniques=techniques,
            )
            write_detection_log(args.log_file, detection)

            verdict = "BLOCK" if should_block else "ALLOW"
            print(f"{verdict} score={score} severity={severity} path={path}")
            print(f"sha256={sample_hash}")
            if scan_result.iocs:
                print("iocs:")
                for item in scan_result.iocs[:16]:
                    print(f" - [{item.get('type', 'ioc')}] {item.get('value', '')}")
            for reason in reasons:
                print(f" - {reason}")

            if should_block:
                exit_code = 1
        return exit_code

    watch_dirs = [Path(p).expanduser().resolve() for p in args.watch] if args.watch else []
    if not watch_dirs:
        watch_dirs = default_watch_dirs()
    watch_dirs = [p for p in watch_dirs if p.exists() and p.is_dir()]

    if not watch_dirs:
        logging.error("no valid watch directories")
        return 2

    for directory in watch_dirs:
        logging.info("watch target: %s", directory)

    file_events: queue.Queue[Path] = queue.Queue()
    stop_event = threading.Event()
    pending_scans: dict[Path, float] = {}
    scanned_state: dict[Path, tuple[int, float]] = {}

    def on_signal(_sig: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    watchers = [DirectoryWatcher(path, file_events, stop_event) for path in watch_dirs]
    for watcher in watchers:
        watcher.start()

    if args.scan_existing:
        run_scan_existing(watch_dirs, pending_scans, args.delay_seconds)
        logging.info("scheduled existing files for scan")

    logging.info("guardian is running")

    try:
        while not stop_event.is_set():
            try:
                changed = file_events.get(timeout=0.2)
                if changed.exists():
                    pending_scans[changed] = time.time() + args.delay_seconds
            except queue.Empty:
                pass

            now = time.time()
            due_paths = [path for path, due in pending_scans.items() if due <= now]
            for path in due_paths:
                pending_scans.pop(path, None)

                if not is_candidate_path(path):
                    continue

                try:
                    stat = path.stat()
                except FileNotFoundError:
                    continue
                except Exception as exc:
                    logging.debug("cannot stat %s: %s", path, exc)
                    continue

                old_size, old_mtime = scanned_state.get(path, (-1, -1.0))
                if old_size == stat.st_size and old_mtime == stat.st_mtime:
                    continue

                scanned_state[path] = (stat.st_size, stat.st_mtime)

                try:
                    scan_result = evaluate_file_detailed(path, rules)
                except PermissionError:
                    logging.debug("skip locked file: %s", path)
                    continue
                except Exception as exc:
                    logging.error("scan failed for %s: %s", path, exc)
                    continue

                score = scan_result.score
                reasons = scan_result.reasons
                sample_hash = scan_result.sha256
                techniques = infer_techniques(
                    path=path,
                    reasons=reasons,
                    iocs=scan_result.iocs,
                    score=score,
                )
                severity = severity_from_score(score)
                should_block = score >= rules.block_threshold
                quarantined_path: str | None = None

                if should_block and not args.dry_run:
                    stop_process_by_exact_path(path)
                    if path.suffix.lower() == ".dll":
                        stop_common_lolbins()
                    quarantine_target = quarantine_file(path, args.quarantine_dir)
                    quarantined_path = str(quarantine_target) if quarantine_target else None

                detection = Detection(
                    path=path,
                    score=score,
                    severity=severity,
                    reasons=reasons,
                    sha256=sample_hash,
                    blocked=should_block and not args.dry_run,
                    quarantined_path=quarantined_path,
                    iocs=scan_result.iocs,
                    techniques=techniques,
                )
                write_detection_log(args.log_file, detection)

                if should_block:
                    logging.warning(
                        "BLOCKED score=%s severity=%s path=%s",
                        score,
                        severity,
                        path,
                    )
                else:
                    logging.info(
                        "ALERT score=%s severity=%s path=%s",
                        score,
                        severity,
                        path,
                    )
    finally:
        stop_event.set()
        for watcher in watchers:
            watcher.join(timeout=1.5)
        logging.info("guardian stopped")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
