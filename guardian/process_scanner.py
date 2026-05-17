#!/usr/bin/env python3
from __future__ import annotations

import json
import ipaddress
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from guardian import (
    ScanRules,
    build_ioc,
    dedupe_iocs,
    get_authenticode_info,
    is_microsoft_trusted_signature,
    severity_from_score,
)
from technique_mapper import infer_techniques
from vt_enricher import check_file_path


DLL1_PROCESS_TOKENS = {
    "runmalware",
    "dllregisterserver",
    "sysupdatecore.dll",
    "systemupdate.vbs",
    "syscheck.vbs",
    "rundll32.exe",
}

CRITICAL_PARENT_DENYLIST = {
    "services.exe",
    "wininit.exe",
    "smss.exe",
    "csrss.exe",
    "lsass.exe",
    "winlogon.exe",
    "explorer.exe",
    "system",
    "system idle process",
}

DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "rules.json"
DEFAULT_HOST_PROCESSES = {"notepad++.exe", "npp.exe"}
DEFAULT_TARGET_DLLS = {"winmm.dll"}
DEFAULT_EXPECTED_SYSTEM_PATHS = {r"c:\windows\system32\winmm.dll"}
DEFAULT_USER_WRITABLE_TOKENS = {
    "\\users\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\appdata\\",
    "\\temp\\",
    "\\onedrive\\",
}
DEFAULT_TRUSTED_HOST_PATH_TOKENS = {
    "\\program files\\notepad++\\",
    "\\program files (x86)\\notepad++\\",
}

_RULES_CACHE: dict[str, Any] = {
    "mtime": None,
    "rules": None,
}

COMMAND_PATH_RE = re.compile(
    r"([A-Za-z]:\\[^\"'\s,]+?\.(?:dll|exe|vbs|js|ps1|bat|cmd))",
    re.IGNORECASE,
)


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _normalize_path_text(path_text: str) -> str:
    return str(path_text or "").strip().replace("/", "\\").lower()


def _load_scan_rules() -> ScanRules | None:
    try:
        stat = DEFAULT_RULES_PATH.stat()
    except OSError:
        return None

    cached_mtime = _RULES_CACHE.get("mtime")
    cached_rules = _RULES_CACHE.get("rules")
    if cached_rules is not None and cached_mtime == stat.st_mtime:
        return cached_rules

    try:
        rules = ScanRules.from_json(DEFAULT_RULES_PATH)
    except Exception:
        return None

    _RULES_CACHE["mtime"] = stat.st_mtime
    _RULES_CACHE["rules"] = rules
    return rules


def _get_runtime_profile() -> dict[str, set[str]]:
    rules = _load_scan_rules()
    if rules is None:
        return {
            "host_processes": set(DEFAULT_HOST_PROCESSES),
            "target_dlls": set(DEFAULT_TARGET_DLLS),
            "expected_system_paths": set(DEFAULT_EXPECTED_SYSTEM_PATHS),
            "user_writable_tokens": set(DEFAULT_USER_WRITABLE_TOKENS),
            "trusted_host_path_tokens": set(DEFAULT_TRUSTED_HOST_PATH_TOKENS),
        }

    host_processes = set(rules.host_processes or DEFAULT_HOST_PROCESSES)
    target_dlls = set(rules.target_dlls or DEFAULT_TARGET_DLLS)
    expected_system_paths = set(rules.expected_system_paths or DEFAULT_EXPECTED_SYSTEM_PATHS)
    user_writable_tokens = set(rules.user_writable_path_tokens or DEFAULT_USER_WRITABLE_TOKENS)
    trusted_host_path_tokens = set(rules.trusted_host_path_tokens or DEFAULT_TRUSTED_HOST_PATH_TOKENS)
    return {
        "host_processes": {x.lower() for x in host_processes if str(x).strip()},
        "target_dlls": {_normalize_path_text(x) for x in target_dlls if str(x).strip()},
        "expected_system_paths": {
            _normalize_path_text(x) for x in expected_system_paths if str(x).strip()
        },
        "user_writable_tokens": {
            _normalize_path_text(x) for x in user_writable_tokens if str(x).strip()
        },
        "trusted_host_path_tokens": {
            _normalize_path_text(x) for x in trusted_host_path_tokens if str(x).strip()
        },
    }


def _path_has_any_token(path_text: str, tokens: set[str]) -> bool:
    normalized = _normalize_path_text(path_text)
    if not normalized:
        return False
    return any(token and token in normalized for token in tokens)


def _is_expected_system_dll_path(path_text: str, expected_paths: set[str]) -> bool:
    normalized = _normalize_path_text(path_text)
    if not normalized:
        return False
    if normalized in expected_paths:
        return True
    return normalized.endswith(r"\windows\system32\winmm.dll")


def _is_user_writable_path(path_text: str, tokens: set[str]) -> bool:
    return _path_has_any_token(path_text, tokens)


def _is_trusted_host_path(path_text: str, tokens: set[str]) -> bool:
    normalized = _normalize_path_text(path_text)
    if not normalized:
        return False
    if _path_has_any_token(normalized, tokens):
        return True
    if normalized.startswith("c:\\program files\\notepad++\\") or normalized.startswith(
        "c:\\program files (x86)\\notepad++\\"
    ):
        return True
    return False


def _decode_output(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in ("utf-8-sig", "utf-8", "utf-16le", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode(errors="replace")


def _run_ps_any(script: str, timeout: int = 12) -> Any:
    commands = [
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
    ]
    for command in commands:
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=False,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            continue
        except Exception:
            continue
        if proc.returncode != 0:
            continue
        text = _decode_output(proc.stdout or b"").strip()
        if not text:
            continue
        line = text.splitlines()[-1].strip()
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None


def _run_ps_json_rows(script: str, timeout: int = 12) -> list[dict[str, Any]]:
    payload = _run_ps_any(script, timeout=timeout)
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def _rows_to_processes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        try:
            pid = int(row.get("ProcessId", -1))
        except (TypeError, ValueError):
            continue
        if pid <= 0:
            continue
        try:
            ppid = int(row.get("ParentProcessId", 0))
        except (TypeError, ValueError):
            ppid = 0
        name = str(row.get("Name", "")).strip()
        if name and not name.lower().endswith(".exe"):
            name = f"{name}.exe"
        out.append(
            {
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "path": str(row.get("ExecutablePath", "")).strip(),
                "command_line": str(row.get("CommandLine", "")).strip(),
                "created_at": str(row.get("CreationDate", "")).strip(),
            }
        )
    return out


def _list_processes() -> list[dict[str, Any]]:
    script = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | "
        "ConvertTo-Json -Compress"
    )
    rows = _run_ps_json_rows(script, timeout=12)
    parsed = _rows_to_processes(rows)
    if parsed:
        return parsed

    # Fallback for environments where Win32_Process query is denied.
    fallback_script = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-Process | ForEach-Object { "
        "  $n=[string]$_.ProcessName; "
        "  if(-not $n.EndsWith('.exe')) { $n = $n + '.exe' }; "
        "  $path=''; try { $path=[string]$_.Path } catch {}; "
        "  $created=''; try { $created=[string]$_.StartTime.ToString('o') } catch {}; "
        "  [pscustomobject]@{ "
        "    ProcessId=[int]$_.Id; "
        "    ParentProcessId=0; "
        "    Name=$n; "
        "    ExecutablePath=$path; "
        "    CommandLine=''; "
        "    CreationDate=$created "
        "  } "
        "} | ConvertTo-Json -Compress"
    )
    fallback_rows = _run_ps_json_rows(fallback_script, timeout=12)
    return _rows_to_processes(fallback_rows)


def _parse_remote_endpoint(endpoint: str) -> tuple[str, int]:
    value = str(endpoint or "").strip()
    if not value:
        return "", 0
    host = ""
    port_text = ""
    if value.startswith("[") and "]" in value:
        end = value.find("]")
        host = value[1:end]
        rest = value[end + 1 :]
        if rest.startswith(":"):
            port_text = rest[1:]
    elif ":" in value:
        host, port_text = value.rsplit(":", 1)
    else:
        return "", 0

    host = host.split("%", 1)[0].strip()
    try:
        port = int(port_text)
    except (TypeError, ValueError):
        port = 0
    return host, port


def _is_interesting_remote_ip(ip_text: str) -> bool:
    value = str(ip_text or "").strip()
    if not value or value in {"0.0.0.0", "::", "::1", "127.0.0.1"}:
        return False
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return False
    if ip_obj.is_multicast or ip_obj.is_unspecified:
        return False
    return True


def _list_tcp_connections_by_pid() -> dict[int, list[dict[str, Any]]]:
    out: dict[int, list[dict[str, Any]]] = {}
    try:
        proc = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            check=False,
            timeout=8,
        )
    except Exception:
        return out

    text = (proc.stdout or "").strip()
    if not text:
        return out

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or not line.lower().startswith("tcp"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 5:
            continue
        local_ep = parts[1]
        remote_ep = parts[2]
        state = parts[3]
        pid_text = parts[4]
        try:
            pid = int(pid_text)
        except (TypeError, ValueError):
            continue
        if pid <= 0:
            continue
        remote_ip, remote_port = _parse_remote_endpoint(remote_ep)
        if not remote_ip:
            continue
        entry = {
            "pid": pid,
            "local": local_ep,
            "remote": remote_ep,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": state,
        }
        out.setdefault(pid, []).append(entry)
    return out


def _extract_paths_from_command(command_line: str) -> list[Path]:
    if not command_line:
        return []
    out: list[Path] = []
    for match in COMMAND_PATH_RE.finditer(command_line):
        candidate = match.group(1).strip().strip('"').strip("'")
        if not candidate:
            continue
        p = Path(candidate)
        try:
            if p.exists() and p.is_file():
                out.append(p.resolve())
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


def _get_parent_name_map(processes: list[dict[str, Any]]) -> dict[int, str]:
    by_pid = {int(p["pid"]): p for p in processes}
    out: dict[int, str] = {}
    for row in processes:
        pid = int(row.get("pid", 0))
        ppid = int(row.get("ppid", 0))
        parent = by_pid.get(ppid, {})
        out[pid] = str(parent.get("name", "")).strip()
    return out


def _normalize_module_rows(raw_modules: Any) -> list[dict[str, str]]:
    if not isinstance(raw_modules, list):
        return []
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in raw_modules:
        if not isinstance(row, dict):
            continue
        path = str(row.get("path", "")).strip()
        if not path:
            continue
        key = path.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "path": path,
                "name": str(row.get("name", "")).strip() or Path(path).name,
            }
        )
    return out


def _list_process_modules(pid: int, max_dlls: int = 120) -> tuple[list[dict[str, str]], str | None]:
    pid = int(pid)
    if pid <= 0:
        return [], "invalid pid"
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$targetPid={pid}; "
        "try { "
        "$p=Get-Process -Id $targetPid -ErrorAction Stop; "
        "$mods=@(); "
        "foreach($m in $p.Modules){ "
        "  if($m.FileName){ "
        "    $mods += [pscustomobject]@{path=[string]$m.FileName; name=[string]$m.ModuleName}; "
        "  } "
        "} "
        "$obj=[pscustomobject]@{ok=$true; modules=$mods; error=''}; "
        "} catch { "
        "$obj=[pscustomobject]@{ok=$false; modules=@(); error=[string]$_.Exception.Message}; "
        "} "
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "$obj | ConvertTo-Json -Compress"
    )
    payload = _run_ps_any(script, timeout=12)
    if not isinstance(payload, dict):
        return [], "cannot query process modules"
    modules = _normalize_module_rows(payload.get("modules", []))
    return modules[: max(1, min(int(max_dlls), 400))], str(payload.get("error", "")).strip() or None


def _maybe_vt_for_path(
    path: Path,
    *,
    vt_enabled: bool,
    vt_api_key: str,
    vt_threshold: int = 5,
) -> dict[str, Any] | None:
    if not vt_enabled:
        return None
    vt_api_key = str(vt_api_key or "").strip()
    if not vt_api_key:
        return {"status": "api_key_missing", "positives": 0, "total": 0, "sha256": "", "message": "missing api key"}
    try:
        return check_file_path(
            path,
            api_key=vt_api_key,
            malicious_threshold=max(1, int(vt_threshold)),
        )
    except Exception as exc:
        return {
            "status": "error",
            "positives": 0,
            "total": 0,
            "sha256": "",
            "message": str(exc),
        }


def _kill_process_pid(pid: int) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["taskkill", "/PID", str(int(pid)), "/T", "/F"],
            capture_output=True,
            text=True,
            check=False,
            timeout=8,
        )
    except Exception as exc:
        return False, str(exc)
    if proc.returncode == 0:
        return True, "terminated"
    msg = (proc.stderr or proc.stdout or "").strip() or f"taskkill exit {proc.returncode}"
    return False, msg


def _attempt_remediation(
    finding: dict[str, Any],
    by_pid: dict[int, dict[str, Any]],
    *,
    auto_kill: bool,
    kill_parent: bool,
    kill_threshold: int,
) -> dict[str, Any]:
    remediation = {
        "auto_kill_enabled": bool(auto_kill),
        "killed": False,
        "killed_pid": None,
        "killed_parent_pid": None,
        "messages": [],
    }
    if not auto_kill:
        return remediation

    score = int(finding.get("score", 0))
    if score < int(kill_threshold):
        remediation["messages"].append(
            f"score {score} below kill threshold {int(kill_threshold)}"
        )
        return remediation

    proc = finding.get("process", {})
    if not isinstance(proc, dict):
        remediation["messages"].append("missing process context")
        return remediation

    pid = int(proc.get("pid", 0) or 0)
    if pid <= 0:
        remediation["messages"].append("invalid pid")
        return remediation

    proc_name = str(proc.get("name", "")).strip().lower()
    if proc_name in CRITICAL_PARENT_DENYLIST:
        remediation["messages"].append(f"skip kill for critical process: {proc_name}")
        return remediation

    killed, msg = _kill_process_pid(pid)
    remediation["killed"] = killed
    remediation["killed_pid"] = pid if killed else None
    remediation["messages"].append(f"pid {pid}: {msg}")

    if not kill_parent:
        return remediation

    parent_pid = int(proc.get("ppid", 0) or 0)
    if parent_pid <= 0:
        remediation["messages"].append("parent pid unavailable")
        return remediation

    parent_row = by_pid.get(parent_pid, {})
    parent_name = str(parent_row.get("name", "")).strip().lower()
    if parent_name in CRITICAL_PARENT_DENYLIST:
        remediation["messages"].append(f"skip parent kill for critical process: {parent_name}")
        return remediation

    parent_killed, pmsg = _kill_process_pid(parent_pid)
    if parent_killed:
        remediation["killed_parent_pid"] = parent_pid
    remediation["messages"].append(f"parent pid {parent_pid}: {pmsg}")
    return remediation


def _enrich_finding_with_dlls_and_vt(
    finding: dict[str, Any],
    *,
    include_dlls: bool,
    dll_limit: int,
    vt_enabled: bool,
    vt_api_key: str,
    vt_threshold: int = 5,
    max_vt_dll_checks: int = 12,
) -> None:
    proc = finding.get("process", {})
    if not isinstance(proc, dict):
        return
    pid = int(proc.get("pid", 0) or 0)
    if pid <= 0:
        return

    iocs = finding.get("iocs", [])
    reasons = finding.get("reasons", [])
    if not isinstance(iocs, list):
        iocs = []
    if not isinstance(reasons, list):
        reasons = []

    proc_path_text = str(proc.get("path", "")).strip()
    if vt_enabled and proc_path_text:
        p = Path(proc_path_text)
        if p.exists() and p.is_file():
            vt = _maybe_vt_for_path(
                p,
                vt_enabled=vt_enabled,
                vt_api_key=vt_api_key,
                vt_threshold=vt_threshold,
            )
            finding["process_vt"] = vt
            if isinstance(vt, dict):
                vt_status = str(vt.get("status", "unknown")).lower()
                positives = int(vt.get("positives", 0) or 0)
                total = int(vt.get("total", 0) or 0)
                iocs.append(build_ioc("virustotal_status", vt_status, "process_scan"))
                if vt_status == "malicious":
                    finding["score"] = min(180, int(finding.get("score", 0)) + 30)
                    reasons.append(
                        f"VirusTotal flagged process image as malicious ({positives}/{total})"
                    )
                elif vt_status == "suspicious":
                    finding["score"] = min(180, int(finding.get("score", 0)) + 15)
                    reasons.append(
                        f"VirusTotal flagged process image as suspicious ({positives}/{total})"
                    )

    if include_dlls or vt_enabled:
        modules, module_error = _list_process_modules(pid, max_dlls=dll_limit)
        finding["dlls"] = modules
        if module_error:
            finding["dlls_error"] = module_error
        if modules:
            iocs.append(build_ioc("process_dll_count", str(len(modules)), "process_scan"))

        if vt_enabled and modules:
            vt_modules: list[dict[str, Any]] = []
            checks = 0
            for mod in modules:
                if checks >= max(1, min(int(max_vt_dll_checks), 40)):
                    break
                mod_path = Path(str(mod.get("path", "")).strip())
                if not mod_path.exists() or not mod_path.is_file():
                    continue
                vt = _maybe_vt_for_path(
                    mod_path,
                    vt_enabled=vt_enabled,
                    vt_api_key=vt_api_key,
                    vt_threshold=vt_threshold,
                )
                checks += 1
                vt_modules.append(
                    {
                        "path": str(mod_path),
                        "name": str(mod.get("name", "")),
                        "virustotal": vt,
                    }
                )
                if not isinstance(vt, dict):
                    continue
                vt_status = str(vt.get("status", "unknown")).lower()
                positives = int(vt.get("positives", 0) or 0)
                total = int(vt.get("total", 0) or 0)
                if vt_status == "malicious":
                    finding["score"] = min(220, int(finding.get("score", 0)) + 20)
                    reasons.append(
                        f"loaded DLL flagged malicious by VirusTotal: {mod_path.name} ({positives}/{total})"
                    )
                    iocs.append(build_ioc("dll_virustotal", f"{mod_path.name}:malicious", "process_scan"))
                elif vt_status == "suspicious":
                    finding["score"] = min(220, int(finding.get("score", 0)) + 8)
                    reasons.append(
                        f"loaded DLL flagged suspicious by VirusTotal: {mod_path.name} ({positives}/{total})"
                    )
                    iocs.append(build_ioc("dll_virustotal", f"{mod_path.name}:suspicious", "process_scan"))
            finding["dll_virustotal"] = vt_modules

    finding["reasons"] = reasons[:20]
    finding["iocs"] = dedupe_iocs(iocs)
    finding["severity"] = severity_from_score(int(finding.get("score", 0)))


def _build_findings_from_processes(processes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    profile = _get_runtime_profile()
    host_processes = profile["host_processes"] or set(DEFAULT_HOST_PROCESSES)
    target_dlls = profile["target_dlls"] or set(DEFAULT_TARGET_DLLS)
    expected_system_paths = profile["expected_system_paths"] or set(DEFAULT_EXPECTED_SYSTEM_PATHS)
    user_writable_tokens = profile["user_writable_tokens"] or set(DEFAULT_USER_WRITABLE_TOKENS)
    trusted_host_path_tokens = profile["trusted_host_path_tokens"] or set(
        DEFAULT_TRUSTED_HOST_PATH_TOKENS
    )
    tcp_by_pid = _list_tcp_connections_by_pid()

    parent_name_map = _get_parent_name_map(processes)

    def add_finding(
        *,
        score: int,
        reasons: list[str],
        process: dict[str, Any],
        iocs: list[dict[str, str]],
        tag: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        p_path_raw = str(process.get("path", "")).strip() or str(process.get("name", "")).strip()
        p_path = Path(p_path_raw or "unknown_process")
        techniques = infer_techniques(
            path=p_path,
            reasons=reasons,
            iocs=iocs,
            score=score,
        )
        process_out = dict(process)
        process_out["parent_name"] = parent_name_map.get(int(process.get("pid", 0)), "")
        payload: dict[str, Any] = {
            "tag": tag,
            "score": int(score),
            "severity": severity_from_score(int(score)),
            "path": p_path_raw,
            "process": process_out,
            "reasons": reasons,
            "iocs": dedupe_iocs(iocs),
            "techniques": techniques,
        }
        if isinstance(extra, dict) and extra:
            payload.update(extra)
        findings.append(payload)

    for proc in processes:
        name = str(proc.get("name", "")).strip().lower()
        cmdline = str(proc.get("command_line", "")).strip()
        cmdline_lower = cmdline.lower()
        proc_path = str(proc.get("path", "")).strip()
        proc_path_lower = _normalize_path_text(proc_path)
        pid = int(proc.get("pid", 0))

        if name in host_processes:
            score = 0
            reasons: list[str] = []
            iocs: list[dict[str, str]] = [
                build_ioc("host_process", name, "process_scan"),
                build_ioc("process_name", name, "process_scan"),
                build_ioc("process_cmdline", cmdline, "process_scan"),
            ]
            if proc_path:
                iocs.append(build_ioc("process_path", proc_path, "process_scan"))

            if proc_path and not _is_trusted_host_path(proc_path, trusted_host_path_tokens):
                score += 18
                reasons.append(
                    f"{name} executable path outside trusted Notepad++ install dirs: {proc_path}"
                )

            if proc_path and _is_user_writable_path(proc_path, user_writable_tokens):
                score += 28
                reasons.append(f"{name} running from user-writable location: {proc_path}")

            modules, module_error = _list_process_modules(pid, max_dlls=220)
            if module_error:
                reasons.append(f"cannot enumerate modules for pid {pid}: {module_error}")
                iocs.append(build_ioc("module_enum_error", module_error, "process_scan"))

            proc_dir = ""
            try:
                proc_dir = str(Path(proc_path).parent).replace("/", "\\").lower()
            except Exception:
                proc_dir = ""

            suspicious_dll_hits = 0
            for module in modules:
                module_name = str(module.get("name", "")).strip().lower()
                module_path = str(module.get("path", "")).strip()
                module_path_lower = _normalize_path_text(module_path)
                if not module_name:
                    module_name = Path(module_path_lower).name

                if module_name not in target_dlls and Path(module_path_lower).name not in target_dlls:
                    continue

                suspicious_dll_hits += 1
                iocs.append(build_ioc("loaded_module_name", module_name, "process_scan"))
                iocs.append(build_ioc("loaded_module_path", module_path, "process_scan"))

                is_expected_system = _is_expected_system_dll_path(module_path, expected_system_paths)
                same_dir = bool(proc_dir) and module_path_lower.startswith(proc_dir + "\\")
                in_user_writable = _is_user_writable_path(module_path, user_writable_tokens)

                sig_status = ""
                sig_subject = ""
                trusted_ms = False
                module_file = Path(module_path)
                if module_file.exists() and module_file.is_file():
                    try:
                        trusted_ms, sig_status, sig_subject = is_microsoft_trusted_signature(module_file)
                    except Exception:
                        sig_status, sig_subject = get_authenticode_info(module_file)
                        trusted_ms = False
                elif module_path:
                    sig_status = "UnknownPath"
                if sig_status:
                    iocs.append(build_ioc("signature_status", sig_status, "process_scan"))
                if sig_subject:
                    iocs.append(build_ioc("signature_subject", sig_subject, "process_scan"))

                if is_expected_system and trusted_ms and sig_status == "Valid":
                    reasons.append(
                        f"{module_name} loaded from expected system path and trusted Microsoft signer: {module_path}"
                    )
                    continue

                score += 45
                reasons.append(
                    f"{name} loaded target DLL '{module_name}' from non-baseline location: {module_path}"
                )
                iocs.append(build_ioc("sideload_target_dll", module_name, "process_scan"))

                if not is_expected_system:
                    score += 15
                    reasons.append(f"target DLL not loaded from expected system path: {module_path}")
                if same_dir:
                    score += 24
                    reasons.append("target DLL loaded from same directory as host process")
                if in_user_writable:
                    score += 30
                    reasons.append("target DLL path is user-writable")
                    iocs.append(build_ioc("module_path_class", "user_writable", "process_scan"))
                elif same_dir:
                    iocs.append(build_ioc("module_path_class", "local_host_dir", "process_scan"))
                elif is_expected_system:
                    iocs.append(build_ioc("module_path_class", "system32", "process_scan"))
                else:
                    iocs.append(build_ioc("module_path_class", "other", "process_scan"))

                if sig_status != "Valid":
                    score += 20
                    reasons.append(
                        f"target DLL has invalid/unsigned signature status: {sig_status or 'Unknown'}"
                    )
                elif not trusted_ms:
                    score += 10
                    reasons.append(
                        f"target DLL signer is valid but not Microsoft allowlist: {sig_subject or 'unknown'}"
                    )

            all_conns = tcp_by_pid.get(pid, [])
            if all_conns:
                iocs.append(
                    build_ioc("process_network_connection_count", str(len(all_conns)), "process_scan")
                )
                interesting_states = {"ESTABLISHED", "SYN_SENT", "SYN_RECEIVED"}
                public_outbound = [
                    conn
                    for conn in all_conns
                    if _is_interesting_remote_ip(str(conn.get("remote_ip", "")))
                    and str(conn.get("state", "")).upper() in interesting_states
                ]
                if public_outbound:
                    score += min(60, 30 + len(public_outbound) * 10)
                    reasons.append(
                        f"{name} has outbound public network connections ({len(public_outbound)}) - possible C2/beaconing"
                    )
                    for conn in public_outbound[:8]:
                        remote_ip = str(conn.get("remote_ip", "")).strip()
                        remote_port = int(conn.get("remote_port", 0) or 0)
                        state = str(conn.get("state", "")).strip()
                        if remote_ip:
                            iocs.append(
                                build_ioc(
                                    "network_remote",
                                    f"{remote_ip}:{remote_port}",
                                    "process_scan",
                                )
                            )
                        if state:
                            iocs.append(build_ioc("network_state", state, "process_scan"))

            if suspicious_dll_hits == 0 and proc_path:
                if _is_user_writable_path(proc_path, user_writable_tokens):
                    score += 12
                    reasons.append(
                        f"{name} launched from user-writable path but target DLL not observed in module list"
                    )

            if score >= 45:
                net_preview = []
                for conn in tcp_by_pid.get(pid, [])[:12]:
                    net_preview.append(
                        {
                            "remote_ip": str(conn.get("remote_ip", "")),
                            "remote_port": int(conn.get("remote_port", 0) or 0),
                            "state": str(conn.get("state", "")),
                            "local": str(conn.get("local", "")),
                            "remote": str(conn.get("remote", "")),
                        }
                    )
                add_finding(
                    score=min(220, score),
                    reasons=reasons[:12],
                    process=proc,
                    iocs=iocs,
                    tag="notepadpp_winmm_sideload",
                    extra={
                        "network_connections": net_preview,
                        "network_connection_count": len(tcp_by_pid.get(pid, [])),
                    },
                )

        if name == "rundll32.exe":
            score = 0
            reasons: list[str] = []
            iocs = [
                build_ioc("process_name", name, "process_scan"),
                build_ioc("process_cmdline", cmdline, "process_scan"),
            ]
            for token in DLL1_PROCESS_TOKENS:
                if token in cmdline_lower:
                    score += 22
                    reasons.append(f"rundll32 commandline matched token: {token}")
                    iocs.append(build_ioc("string", token, "process_scan"))

            for dll_path in _extract_paths_from_command(cmdline):
                iocs.append(build_ioc("referenced_path", str(dll_path), "process_scan"))
                status, subject = get_authenticode_info(dll_path)
                iocs.append(build_ioc("signature_status", status, "process_scan"))
                if subject:
                    iocs.append(build_ioc("signature_subject", subject, "process_scan"))
                if status != "Valid":
                    score += 18
                    reasons.append(
                        f"rundll32 references unsigned/non-valid signed file: {dll_path.name} ({status})"
                    )
                elif "microsoft" not in subject.lower():
                    score += 8
                    reasons.append(
                        f"rundll32 references non-microsoft signed file: {dll_path.name}"
                    )

            if score >= 45:
                add_finding(
                    score=min(140, score),
                    reasons=reasons[:8],
                    process=proc,
                    iocs=iocs,
                    tag="dll1_rundll32_chain",
                )

        if name in {"wscript.exe", "cscript.exe"}:
            matched = [
                token
                for token in ("systemupdate.vbs", "syscheck.vbs", "rundll32.exe", "runmalware")
                if token in cmdline_lower
            ]
            if matched:
                reasons = [f"script host commandline matched token: {token}" for token in matched]
                iocs = [
                    build_ioc("process_name", name, "process_scan"),
                    build_ioc("process_cmdline", cmdline, "process_scan"),
                ] + [build_ioc("string", token, "process_scan") for token in matched]
                add_finding(
                    score=min(130, 40 + len(matched) * 20),
                    reasons=reasons[:8],
                    process=proc,
                    iocs=iocs,
                    tag="dll1_script_launcher",
                )

    findings.sort(key=lambda row: int(row.get("score", 0)), reverse=True)
    return findings


def _build_process_detail(
    proc: dict[str, Any],
    by_pid: dict[int, dict[str, Any]],
    *,
    include_dlls: bool,
    dll_limit: int,
    vt_enabled: bool,
    vt_api_key: str,
    vt_threshold: int,
    tcp_by_pid: dict[int, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    pid = int(proc.get("pid", 0))
    ppid = int(proc.get("ppid", 0))
    parent = by_pid.get(ppid, {})
    detail = {
        "pid": pid,
        "name": str(proc.get("name", "")).strip(),
        "path": str(proc.get("path", "")).strip(),
        "command_line": str(proc.get("command_line", "")).strip(),
        "ppid": ppid,
        "parent_name": str(parent.get("name", "")).strip(),
        "created_at": str(proc.get("created_at", "")).strip(),
        "suspicion_notes": [],
    }

    if tcp_by_pid is None:
        tcp_by_pid = _list_tcp_connections_by_pid()
    connections = list(tcp_by_pid.get(pid, []))
    detail["network_connections"] = connections[:40]
    if connections:
        interesting_states = {"ESTABLISHED", "SYN_SENT", "SYN_RECEIVED"}
        public_outbound = [
            conn
            for conn in connections
            if _is_interesting_remote_ip(str(conn.get("remote_ip", "")))
            and str(conn.get("state", "")).upper() in interesting_states
        ]
        if public_outbound:
            detail["suspicion_notes"].append(
                f"public outbound connections observed: {len(public_outbound)}"
            )

    profile = _get_runtime_profile()
    host_processes = profile["host_processes"] or set(DEFAULT_HOST_PROCESSES)
    target_dlls = profile["target_dlls"] or set(DEFAULT_TARGET_DLLS)
    user_writable_tokens = profile["user_writable_tokens"] or set(DEFAULT_USER_WRITABLE_TOKENS)
    trusted_host_path_tokens = profile["trusted_host_path_tokens"] or set(
        DEFAULT_TRUSTED_HOST_PATH_TOKENS
    )
    expected_system_paths = profile["expected_system_paths"] or set(DEFAULT_EXPECTED_SYSTEM_PATHS)

    proc_name_lower = detail["name"].lower()
    if proc_name_lower in host_processes:
        if detail["path"] and not _is_trusted_host_path(detail["path"], trusted_host_path_tokens):
            detail["suspicion_notes"].append(
                f"host executable path outside trusted Notepad++ dirs: {detail['path']}"
            )
        if detail["path"] and _is_user_writable_path(detail["path"], user_writable_tokens):
            detail["suspicion_notes"].append("host executable is running from user-writable location")

    if include_dlls or vt_enabled:
        modules, module_error = _list_process_modules(pid, max_dlls=dll_limit)
        detail["dlls"] = modules
        if module_error:
            detail["dlls_error"] = module_error
        if proc_name_lower in host_processes:
            for module in modules:
                module_name = str(module.get("name", "")).strip().lower()
                module_path = str(module.get("path", "")).strip()
                if not module_name:
                    module_name = Path(module_path).name.lower()
                if module_name not in target_dlls and Path(module_path).name.lower() not in target_dlls:
                    continue
                if _is_expected_system_dll_path(module_path, expected_system_paths):
                    detail["suspicion_notes"].append(
                        f"target DLL {module_name} loaded from expected system path"
                    )
                else:
                    detail["suspicion_notes"].append(
                        f"target DLL {module_name} loaded from non-system path: {module_path}"
                    )
                if _is_user_writable_path(module_path, user_writable_tokens):
                    detail["suspicion_notes"].append("target DLL path is user-writable")
                break
    else:
        detail["dlls"] = []

    if vt_enabled and detail["path"]:
        p = Path(detail["path"])
        if p.exists() and p.is_file():
            detail["process_vt"] = _maybe_vt_for_path(
                p,
                vt_enabled=vt_enabled,
                vt_api_key=vt_api_key,
                vt_threshold=vt_threshold,
            )

    return detail


def scan_process_by_pid(
    pid: int,
    *,
    include_dlls: bool = True,
    dll_limit: int = 120,
    vt_enabled: bool = False,
    vt_api_key: str = "",
    vt_threshold: int = 5,
) -> dict[str, Any]:
    processes = _list_processes()
    by_pid = {int(row["pid"]): row for row in processes}
    tcp_by_pid = _list_tcp_connections_by_pid()
    row = by_pid.get(int(pid))
    if not row:
        return {
            "ok": True,
            "timestamp": _now_iso(),
            "found": False,
            "pid": int(pid),
            "detail": None,
        }

    detail = _build_process_detail(
        row,
        by_pid,
        include_dlls=include_dlls,
        dll_limit=dll_limit,
        vt_enabled=vt_enabled,
        vt_api_key=vt_api_key,
        vt_threshold=vt_threshold,
        tcp_by_pid=tcp_by_pid,
    )
    return {
        "ok": True,
        "timestamp": _now_iso(),
        "found": True,
        "pid": int(pid),
        "detail": detail,
    }


def scan_processes_by_name(
    process_name: str,
    *,
    include_dlls: bool = True,
    dll_limit: int = 120,
    vt_enabled: bool = False,
    vt_api_key: str = "",
    vt_threshold: int = 5,
    max_processes: int = 50,
) -> dict[str, Any]:
    needle = str(process_name or "").strip().lower()
    if not needle:
        return {
            "ok": False,
            "error": "process_name is required",
            "timestamp": _now_iso(),
            "results": [],
        }
    candidate_names = {needle}
    if not needle.endswith(".exe"):
        candidate_names.add(f"{needle}.exe")
    if needle in {"notepad++", "notepad++.exe"}:
        candidate_names.add("npp.exe")
    if needle in {"npp", "npp.exe"}:
        candidate_names.add("notepad++.exe")

    processes = _list_processes()
    by_pid = {int(row["pid"]): row for row in processes}
    tcp_by_pid = _list_tcp_connections_by_pid()
    matches = [
        row
        for row in processes
        if str(row.get("name", "")).strip().lower() in candidate_names
    ]
    details = [
        _build_process_detail(
            row,
            by_pid,
            include_dlls=include_dlls,
            dll_limit=dll_limit,
            vt_enabled=vt_enabled,
            vt_api_key=vt_api_key,
            vt_threshold=vt_threshold,
            tcp_by_pid=tcp_by_pid,
        )
        for row in matches[: max(1, min(int(max_processes), 200))]
    ]
    return {
        "ok": True,
        "timestamp": _now_iso(),
        "process_name": process_name,
        "count": len(details),
        "results": details,
    }


def list_process_dll_inventory(
    *,
    process_name_filter: str = "",
    max_processes: int = 80,
    max_dlls_per_process: int = 60,
    vt_enabled: bool = False,
    vt_api_key: str = "",
    vt_threshold: int = 5,
    max_vt_dll_checks_per_process: int = 10,
) -> dict[str, Any]:
    processes = _list_processes()
    needle = str(process_name_filter or "").strip().lower()
    if needle:
        candidate_names = {needle}
        if not needle.endswith(".exe"):
            candidate_names.add(f"{needle}.exe")
        if needle in {"notepad++", "notepad++.exe"}:
            candidate_names.add("npp.exe")
        if needle in {"npp", "npp.exe"}:
            candidate_names.add("notepad++.exe")
        processes = [
            row
            for row in processes
            if str(row.get("name", "")).strip().lower() in candidate_names
        ]
    processes = processes[: max(1, min(int(max_processes), 400))]

    inventory: list[dict[str, Any]] = []
    for row in processes:
        pid = int(row.get("pid", 0))
        if pid <= 0:
            continue
        modules, module_error = _list_process_modules(pid, max_dlls=max_dlls_per_process)
        item: dict[str, Any] = {
            "pid": pid,
            "name": str(row.get("name", "")).strip(),
            "path": str(row.get("path", "")).strip(),
            "ppid": int(row.get("ppid", 0)),
            "command_line": str(row.get("command_line", "")).strip(),
            "dll_count": len(modules),
            "dlls": modules,
        }
        if module_error:
            item["dlls_error"] = module_error

        if vt_enabled and modules:
            vt_rows: list[dict[str, Any]] = []
            checks = 0
            for mod in modules:
                if checks >= max(1, min(int(max_vt_dll_checks_per_process), 40)):
                    break
                mod_path = Path(str(mod.get("path", "")).strip())
                if not mod_path.exists() or not mod_path.is_file():
                    continue
                checks += 1
                vt_rows.append(
                    {
                        "path": str(mod_path),
                        "name": str(mod.get("name", "")),
                        "virustotal": _maybe_vt_for_path(
                            mod_path,
                            vt_enabled=vt_enabled,
                            vt_api_key=vt_api_key,
                            vt_threshold=vt_threshold,
                        ),
                    }
                )
            item["dll_virustotal"] = vt_rows

        inventory.append(item)

    return {
        "ok": True,
        "timestamp": _now_iso(),
        "count": len(inventory),
        "processes": inventory,
    }


def scan_processes(
    max_findings: int = 120,
    *,
    include_dlls: bool = False,
    dll_limit: int = 120,
    vt_enabled: bool = False,
    vt_api_key: str = "",
    vt_threshold: int = 5,
    auto_kill: bool = False,
    kill_parent: bool = False,
    kill_threshold: int = 110,
) -> dict[str, Any]:
    processes = _list_processes()
    by_pid = {int(row["pid"]): row for row in processes}
    findings = _build_findings_from_processes(processes)

    kill_actions: list[dict[str, Any]] = []
    for finding in findings:
        _enrich_finding_with_dlls_and_vt(
            finding,
            include_dlls=include_dlls,
            dll_limit=dll_limit,
            vt_enabled=vt_enabled,
            vt_api_key=vt_api_key,
            vt_threshold=vt_threshold,
        )
        remediation = _attempt_remediation(
            finding,
            by_pid,
            auto_kill=auto_kill,
            kill_parent=kill_parent,
            kill_threshold=kill_threshold,
        )
        finding["remediation"] = remediation
        if remediation.get("killed"):
            kill_actions.append(
                {
                    "pid": remediation.get("killed_pid"),
                    "parent_pid": remediation.get("killed_parent_pid"),
                    "messages": remediation.get("messages", []),
                    "tag": finding.get("tag"),
                    "score": finding.get("score"),
                }
            )

    findings.sort(key=lambda row: int(row.get("score", 0)), reverse=True)
    return {
        "ok": True,
        "timestamp": _now_iso(),
        "scanned_processes": len(processes),
        "suspicious": len(findings),
        "auto_kill": bool(auto_kill),
        "kill_parent": bool(kill_parent),
        "kill_threshold": int(kill_threshold),
        "kill_actions": kill_actions,
        "findings": findings[: max(1, min(int(max_findings), 400))],
    }
