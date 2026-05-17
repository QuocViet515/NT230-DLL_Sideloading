#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import winreg
from datetime import datetime
from pathlib import Path
from typing import Any

from guardian import build_ioc, dedupe_iocs, get_authenticode_info, severity_from_score
from technique_mapper import infer_techniques


RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

REG_SUSPICIOUS_TOKENS = {
    "notepad++.exe",
    "npp.exe",
    "winmm.dll",
    "gup.exe",
    "runmalware",
    "sysupdatecore.dll",
    "systemupdate.vbs",
    "syscheck.vbs",
    "rundll32.exe",
    "wscript.exe",
    "dllregisterserver",
}

USER_WRITABLE_REG_PATH_TOKENS = {
    "\\users\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\appdata\\",
    "\\temp\\",
    "\\onedrive\\",
}

REF_PATH_RE = re.compile(
    r"([A-Za-z]:\\[^\"'\s,]+?\.(?:dll|exe|vbs|js|ps1|bat|cmd))",
    re.IGNORECASE,
)


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _enum_registry_values(root: int, subkey: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    access_flags = winreg.KEY_READ
    # Prefer 64-bit view when possible.
    if hasattr(winreg, "KEY_WOW64_64KEY"):
        access_flags |= winreg.KEY_WOW64_64KEY
    try:
        key = winreg.OpenKey(root, subkey, 0, access_flags)
    except OSError:
        return entries

    try:
        idx = 0
        while True:
            try:
                name, value, value_type = winreg.EnumValue(key, idx)
            except OSError:
                break
            idx += 1
            entries.append(
                {
                    "name": str(name),
                    "value": str(value),
                    "type": int(value_type),
                    "subkey": subkey,
                    "root": "HKCU",
                }
            )
    finally:
        key.Close()
    return entries


def _extract_paths(text: str) -> list[Path]:
    if not text:
        return []
    out: list[Path] = []
    expanded = os.path.expandvars(text)
    for match in REF_PATH_RE.finditer(expanded):
        candidate = match.group(1).strip().strip('"').strip("'")
        if not candidate:
            continue
        path = Path(candidate)
        try:
            if path.exists() and path.is_file():
                out.append(path.resolve())
        except OSError:
            continue
    unique: list[Path] = []
    seen: set[str] = set()
    for item in out:
        key = str(item).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _score_registry_entry(entry: dict[str, Any]) -> tuple[int, list[str], list[dict[str, str]]]:
    value_name = str(entry.get("name", "")).strip()
    value_data = str(entry.get("value", "")).strip()
    value_lower = value_data.lower()
    score = 0
    reasons: list[str] = []
    iocs: list[dict[str, str]] = [
        build_ioc("registry_value_name", value_name, "registry_scan"),
        build_ioc("registry_value_data", value_data, "registry_scan"),
    ]

    matched_tokens = [token for token in REG_SUSPICIOUS_TOKENS if token in value_lower]
    if matched_tokens:
        score += 35 + len(matched_tokens) * 10
        reasons.append(
            "registry value contains persistence/sideload tokens: "
            + ", ".join(matched_tokens[:6])
        )
        for token in matched_tokens[:12]:
            iocs.append(build_ioc("string", token, "registry_scan"))

    risky_path_tokens = ("%temp%", "\\appdata\\", "\\programdata\\", "\\startup\\")
    for token in risky_path_tokens:
        if token in value_lower:
            score += 12
            reasons.append(f"registry value points to risky location token: {token}")
            iocs.append(build_ioc("path_token", token, "registry_scan"))

    if ("notepad++.exe" in value_lower or "npp.exe" in value_lower) and "winmm.dll" in value_lower:
        score += 35
        reasons.append("registry value links Notepad++ host with winmm.dll (possible side-loading chain)")
        iocs.append(build_ioc("process_chain", "notepad++.exe -> winmm.dll", "registry_scan"))

    if any(token in value_lower for token in USER_WRITABLE_REG_PATH_TOKENS):
        if "notepad++.exe" in value_lower or "npp.exe" in value_lower or "winmm.dll" in value_lower:
            score += 18
            reasons.append("registry entry references Notepad++/winmm in user-writable location")
            iocs.append(build_ioc("path_class", "user_writable", "registry_scan"))

    for ref_path in _extract_paths(value_data):
        iocs.append(build_ioc("referenced_path", str(ref_path), "registry_scan"))
        status, subject = get_authenticode_info(ref_path)
        iocs.append(build_ioc("signature_status", status, "registry_scan"))
        if subject:
            iocs.append(build_ioc("signature_subject", subject, "registry_scan"))
        if status != "Valid":
            score += 16
            reasons.append(f"referenced file not validly signed: {ref_path.name} ({status})")
        elif "microsoft" not in subject.lower():
            score += 8
            reasons.append(f"referenced file signer is non-microsoft: {ref_path.name}")

    return min(160, score), reasons[:10], dedupe_iocs(iocs)


def _scan_startup_folder_vbs() -> list[dict[str, Any]]:
    startup = Path(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"))
    findings: list[dict[str, Any]] = []
    if not startup.exists() or not startup.is_dir():
        return findings

    for item in startup.glob("*.vbs"):
        try:
            content = item.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        low = content.lower()
        matched = [
            t
            for t in (
                "notepad++.exe",
                "npp.exe",
                "winmm.dll",
                "rundll32.exe",
                "runmalware",
                "sysupdatecore.dll",
                "systemupdate.vbs",
                "syscheck.vbs",
            )
            if t in low
        ]
        if not matched:
            continue
        score = min(150, 50 + len(matched) * 15)
        reasons = [f"startup script contains token: {token}" for token in matched]
        iocs = [
            build_ioc("startup_script", str(item), "registry_scan"),
            build_ioc("startup_script_name", item.name, "registry_scan"),
        ] + [build_ioc("string", token, "registry_scan") for token in matched]
        techniques = infer_techniques(
            path=item,
            reasons=reasons,
            iocs=iocs,
            score=score,
        )
        findings.append(
            {
                "source": "startup_folder",
                "path": str(item),
                "score": score,
                "severity": severity_from_score(score),
                "reasons": reasons[:8],
                "iocs": dedupe_iocs(iocs),
                "techniques": techniques,
                "entry": {
                    "name": item.name,
                    "value": str(item),
                    "root": "STARTUP",
                    "subkey": str(startup),
                },
            }
        )
    return findings


def scan_registry(max_findings: int = 120) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned_values = 0

    for root, subkey in RUN_KEYS:
        for entry in _enum_registry_values(root, subkey):
            scanned_values += 1
            score, reasons, iocs = _score_registry_entry(entry)
            if score <= 0:
                continue
            path_for_map = Path(str(entry.get("value", "")).strip() or "registry_entry")
            techniques = infer_techniques(
                path=path_for_map,
                reasons=reasons,
                iocs=iocs,
                score=score,
            )
            findings.append(
                {
                    "source": "registry_run_key",
                    "path": str(entry.get("value", "")),
                    "score": score,
                    "severity": severity_from_score(score),
                    "reasons": reasons,
                    "iocs": iocs,
                    "techniques": techniques,
                    "entry": entry,
                }
            )

    findings.extend(_scan_startup_folder_vbs())
    findings.sort(key=lambda row: int(row.get("score", 0)), reverse=True)
    return {
        "ok": True,
        "timestamp": _now_iso(),
        "scanned_values": scanned_values,
        "suspicious": len(findings),
        "findings": findings[: max(1, min(int(max_findings), 400))],
    }
