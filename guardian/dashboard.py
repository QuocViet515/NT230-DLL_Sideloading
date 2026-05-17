#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import threading
import time
import webbrowser
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from guardian import (
    CANDIDATE_EXTENSIONS,
    Detection,
    ScanRules,
    dedupe_iocs,
    evaluate_file_detailed,
    get_authenticode_info,
    is_microsoft_trusted_signature,
    quarantine_file,
    severity_from_score,
    stop_common_lolbins,
    stop_process_by_exact_path,
    write_detection_log,
)
from process_scanner import (
    list_process_dll_inventory,
    scan_process_by_pid,
    scan_processes,
    scan_processes_by_name,
)
from registry_scanner import scan_registry
from technique_mapper import infer_techniques


DEFAULT_LOG_FILE = Path(__file__).resolve().parent / "logs" / "detections.jsonl"
DEFAULT_QUARANTINE_DIR = Path(__file__).resolve().parent / "quarantine"
DEFAULT_RULES_FILE = Path(__file__).resolve().parent / "rules.json"
DEFAULT_DETECTOR_STDOUT = Path(__file__).resolve().parent / "logs" / "detector_stdout.log"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787


@dataclass
class DashboardConfig:
    log_file: Path
    quarantine_dir: Path
    max_api_events: int
    rules_path: Path
    scan_rules: ScanRules
    detector_stdout_log: Path


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


_DETECTOR_LOCK = threading.Lock()
_DETECTOR_PROC: subprocess.Popen | None = None
_DETECTOR_LOG_HANDLE = None
_DETECTOR_STARTED_AT: str | None = None
_DETECTOR_DRY_RUN = False
_DETECTOR_CMD: list[str] | None = None
_DETECTOR_LAST_ERROR: str | None = None

_UNIFIED_MONITOR_LOCK = threading.Lock()
_UNIFIED_MONITOR_THREAD: threading.Thread | None = None
_UNIFIED_MONITOR_STOP_EVENT: threading.Event | None = None
_UNIFIED_MONITOR_STARTED_AT: str | None = None
_UNIFIED_MONITOR_LAST_ERROR: str | None = None
_UNIFIED_MONITOR_LAST_SCAN_AT: str | None = None
DEFAULT_PROCESS_SCAN_OPTIONS = {
    "include_dlls": False,
    "dll_limit": 120,
    "vt_enabled": False,
    "vt_api_key": "",
    "vt_threshold": 5,
    "auto_kill": False,
    "kill_parent": False,
    "kill_threshold": 110,
}
_UNIFIED_MONITOR_PROCESS_SCAN_OPTIONS = dict(DEFAULT_PROCESS_SCAN_OPTIONS)
_UNIFIED_MONITOR_STATS = {
    "process_alerts": 0,
    "registry_alerts": 0,
    "total_emitted": 0,
}

MALWARE_TYPE_PROFILES: dict[str, set[str]] = {
    "trojan": {
        "trojan",
        "loader",
        "dropper",
        "backdoor",
        "sideload",
        "winmm.dll",
        "notepad++",
        "rundll32",
        "delegateexecute",
        "fodhelper",
        "startup",
        "persistence",
        "proxy export",
        "runmalware",
    },
    "ransomware": {
        "ransom",
        "encrypt",
        "decrypt",
        "extortion",
        "locked files",
        "file encryption",
        "crypto",
    },
    "worm": {
        "worm",
        "propagation",
        "lateral movement",
        "spread",
        "autorun",
    },
    "spyware": {
        "keylogger",
        "credential",
        "screen capture",
        "surveillance",
        "exfiltration",
    },
    "botnet": {
        "botnet",
        "c2",
        "command and control",
        "beacon",
        "irc",
        "ddos",
    },
    "wiper": {
        "wiper",
        "disk wipe",
        "destructive",
        "overwrite",
        "destroy",
    },
}


def open_native_folder_picker(initial_path: str | None = None) -> tuple[str | None, str | None]:
    seed = (initial_path or "").strip()
    seed_escaped = seed.replace("'", "''")
    ps_script = f"""
$shell = New-Object -ComObject Shell.Application
$root = 0
if ('{seed_escaped}' -and (Test-Path -LiteralPath '{seed_escaped}' -PathType Container)) {{
    $root = '{seed_escaped}'
}}
$folder = $shell.BrowseForFolder(0, 'Select folder to scan', 0, $root)
if ($folder -and $folder.Self -and $folder.Self.Path) {{
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    Write-Output $folder.Self.Path
}}
"""

    commands = [
        ["powershell", "-NoProfile", "-STA", "-Command", ps_script],
        ["pwsh", "-NoProfile", "-STA", "-Command", ps_script],
    ]

    def _decode_output(raw: bytes) -> str:
        if not raw:
            return ""
        for enc in ("utf-8-sig", "utf-8", "utf-16le"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        # Last-resort fallback on Windows locale
        return raw.decode(errors="replace")

    last_error: str | None = None
    for command in commands:
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=False,
                timeout=300,
                check=False,
            )
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            return None, "folder picker timed out"
        except Exception as exc:
            last_error = str(exc)
            continue

        stdout_text = _decode_output(proc.stdout or b"")
        stderr_text = _decode_output(proc.stderr or b"")
        output_lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
        if output_lines:
            return output_lines[-1], None

        if proc.returncode == 0:
            return None, None

        last_error = stderr_text.strip() or f"folder picker exited with code {proc.returncode}"

    return None, last_error or "cannot launch folder picker (powershell not available)"


def _detector_is_running() -> bool:
    return _DETECTOR_PROC is not None and _DETECTOR_PROC.poll() is None


def _detector_status_nolock() -> dict:
    running = _detector_is_running()
    pid = _DETECTOR_PROC.pid if running and _DETECTOR_PROC else None
    return_code = None
    if _DETECTOR_PROC is not None and not running:
        return_code = _DETECTOR_PROC.poll()

    return {
        "running": running,
        "pid": pid,
        "started_at": _DETECTOR_STARTED_AT,
        "dry_run": _DETECTOR_DRY_RUN,
        "command": _DETECTOR_CMD,
        "return_code": return_code,
        "last_error": _DETECTOR_LAST_ERROR,
    }


def detector_status() -> dict:
    with _DETECTOR_LOCK:
        return _detector_status_nolock()


def start_detector(
    config: DashboardConfig,
    dry_run: bool,
    watch_dirs: list[str] | None = None,
) -> dict:
    global _DETECTOR_PROC, _DETECTOR_LOG_HANDLE, _DETECTOR_STARTED_AT, _DETECTOR_DRY_RUN, _DETECTOR_CMD, _DETECTOR_LAST_ERROR

    with _DETECTOR_LOCK:
        if _detector_is_running():
            return {
                "ok": True,
                "message": "detector already running",
                "status": _detector_status_nolock(),
            }

        watch_dirs = watch_dirs or []
        normalized_watch = []
        for item in watch_dirs:
            raw = str(item).strip()
            if not raw:
                continue
            path = Path(raw).expanduser()
            if path.exists() and path.is_dir():
                normalized_watch.append(str(path.resolve()))

        script_path = Path(__file__).resolve().parent / "guardian.py"
        cmd = [
            sys.executable,
            str(script_path),
            "--scan-existing",
            "--rules",
            str(config.rules_path),
            "--log-file",
            str(config.log_file),
            "--quarantine-dir",
            str(config.quarantine_dir),
        ]
        if dry_run:
            cmd.append("--dry-run")
        for folder in normalized_watch:
            cmd.extend(["--watch", folder])

        ensure_dir(config.detector_stdout_log.parent)
        _DETECTOR_LOG_HANDLE = config.detector_stdout_log.open("a", encoding="utf-8", buffering=1)
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        try:
            _DETECTOR_PROC = subprocess.Popen(
                cmd,
                cwd=str(Path(__file__).resolve().parent.parent),
                stdout=_DETECTOR_LOG_HANDLE,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
            )
        except Exception as exc:
            _DETECTOR_LAST_ERROR = str(exc)
            if _DETECTOR_LOG_HANDLE is not None:
                _DETECTOR_LOG_HANDLE.close()
                _DETECTOR_LOG_HANDLE = None
            return {"ok": False, "error": f"failed to start detector: {exc}"}

        _DETECTOR_STARTED_AT = datetime.now().isoformat(timespec="seconds")
        _DETECTOR_DRY_RUN = dry_run
        _DETECTOR_CMD = cmd
        _DETECTOR_LAST_ERROR = None
        return {
            "ok": True,
            "message": "detector started",
            "status": _detector_status_nolock(),
        }


def stop_detector() -> dict:
    global _DETECTOR_PROC, _DETECTOR_LOG_HANDLE, _DETECTOR_STARTED_AT, _DETECTOR_DRY_RUN, _DETECTOR_CMD

    with _DETECTOR_LOCK:
        if _DETECTOR_PROC is None:
            return {"ok": True, "message": "detector not running", "status": _detector_status_nolock()}

        proc = _DETECTOR_PROC
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=4)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        _DETECTOR_PROC = None
        _DETECTOR_STARTED_AT = None
        _DETECTOR_DRY_RUN = False
        _DETECTOR_CMD = None
        if _DETECTOR_LOG_HANDLE is not None:
            _DETECTOR_LOG_HANDLE.close()
            _DETECTOR_LOG_HANDLE = None

        return {"ok": True, "message": "detector stopped", "status": _detector_status_nolock()}


def _unified_monitor_is_running() -> bool:
    return _UNIFIED_MONITOR_THREAD is not None and _UNIFIED_MONITOR_THREAD.is_alive()


def _unified_monitor_status_nolock() -> dict:
    return {
        "running": _unified_monitor_is_running(),
        "started_at": _UNIFIED_MONITOR_STARTED_AT,
        "last_scan_at": _UNIFIED_MONITOR_LAST_SCAN_AT,
        "last_error": _UNIFIED_MONITOR_LAST_ERROR,
        "stats": dict(_UNIFIED_MONITOR_STATS),
        "process_scan_options": sanitize_process_scan_options(_UNIFIED_MONITOR_PROCESS_SCAN_OPTIONS),
        "detector": _detector_status_nolock(),
    }


def unified_monitor_status() -> dict:
    with _UNIFIED_MONITOR_LOCK:
        return _unified_monitor_status_nolock()


def normalize_process_scan_options(payload: dict | None) -> dict:
    source = payload if isinstance(payload, dict) else {}
    options = dict(DEFAULT_PROCESS_SCAN_OPTIONS)

    options["include_dlls"] = bool(source.get("include_dlls", options["include_dlls"]))
    try:
        options["dll_limit"] = max(10, min(int(source.get("dll_limit", options["dll_limit"])), 300))
    except (TypeError, ValueError):
        options["dll_limit"] = int(DEFAULT_PROCESS_SCAN_OPTIONS["dll_limit"])

    options["vt_enabled"] = bool(source.get("vt_enabled", options["vt_enabled"]))
    options["vt_api_key"] = str(source.get("vt_api_key", options["vt_api_key"]) or "").strip()
    try:
        options["vt_threshold"] = max(1, min(int(source.get("vt_threshold", options["vt_threshold"])), 40))
    except (TypeError, ValueError):
        options["vt_threshold"] = int(DEFAULT_PROCESS_SCAN_OPTIONS["vt_threshold"])

    options["auto_kill"] = bool(source.get("auto_kill", options["auto_kill"]))
    options["kill_parent"] = bool(source.get("kill_parent", options["kill_parent"]))
    try:
        options["kill_threshold"] = max(40, min(int(source.get("kill_threshold", options["kill_threshold"])), 220))
    except (TypeError, ValueError):
        options["kill_threshold"] = int(DEFAULT_PROCESS_SCAN_OPTIONS["kill_threshold"])

    if not options["auto_kill"]:
        options["kill_parent"] = False
    if not options["vt_enabled"]:
        options["vt_api_key"] = ""

    return options


def sanitize_process_scan_options(options: dict | None) -> dict:
    normalized = normalize_process_scan_options(options if isinstance(options, dict) else {})
    safe = dict(normalized)
    safe["vt_api_key_set"] = bool(str(normalized.get("vt_api_key", "")).strip())
    safe.pop("vt_api_key", None)
    return safe


def _make_monitor_key(source: str, finding: dict) -> str:
    score = int(finding.get("score", 0))
    path = str(finding.get("path", "")).strip().lower()
    tag = str(finding.get("tag", "")).strip().lower()
    proc = finding.get("process", {})
    entry = finding.get("entry", {})
    pid = ""
    if isinstance(proc, dict):
        pid = str(proc.get("pid", ""))
    name = ""
    if isinstance(entry, dict):
        name = str(entry.get("name", "")).strip().lower()
    return "|".join([source, tag, path, pid, name, str(score)])


def _emit_monitor_finding(config: DashboardConfig, source: str, finding: dict) -> None:
    score = int(finding.get("score", 0))
    if score <= 0:
        return
    path_text = str(finding.get("path", "")).strip() or f"{source}_finding"
    finding_path = Path(path_text)
    reasons_raw = finding.get("reasons", [])
    reasons = [str(r) for r in reasons_raw if str(r).strip()] if isinstance(reasons_raw, list) else []
    reasons = [f"{source}: {r}" for r in reasons[:20]]
    iocs = normalize_ioc_list(finding.get("iocs", []))
    remediation = finding.get("remediation", {})
    if isinstance(remediation, dict):
        if remediation.get("auto_kill_enabled"):
            iocs.append({"type": "auto_kill_enabled", "value": "true", "source": "process_scan"})
        if remediation.get("killed"):
            killed_pid = remediation.get("killed_pid")
            reasons.insert(0, f"{source}: auto-kill executed for pid={killed_pid}")
            iocs.append({"type": "auto_kill", "value": f"pid={killed_pid}", "source": "process_scan"})
        messages = remediation.get("messages", [])
        if isinstance(messages, list):
            for message in messages[:3]:
                text = str(message).strip()
                if text:
                    reasons.append(f"{source}: remediation: {text}")
    reasons = reasons[:25]
    iocs = dedupe_iocs(iocs)
    techniques = finding.get("techniques", [])
    if not isinstance(techniques, list):
        techniques = []

    local_context = correlate_iocs_local(
        path=finding_path,
        reasons=reasons,
        iocs=iocs,
        base_score=score,
    )
    malware_types = local_context.get("malware_types", ["unknown"])
    malware_confidence = float(local_context.get("malware_confidence", 0.0))
    merged_techniques = []
    for row in techniques + (local_context.get("techniques", []) or []):
        if isinstance(row, dict):
            merged_techniques.append(row)
    # de-dupe by technique id
    uniq_techniques: list[dict] = []
    seen_tid: set[str] = set()
    for row in merged_techniques:
        tid = str(row.get("id", "")).strip().upper()
        if not tid:
            continue
        if tid in seen_tid:
            continue
        seen_tid.add(tid)
        uniq_techniques.append(row)

    detection = Detection(
        path=finding_path,
        score=score,
        severity=severity_from_score(score),
        reasons=reasons,
        sha256=str(finding.get("sha256", "")),
        blocked=False,
        quarantined_path=None,
        iocs=iocs,
        malware_types=malware_types,
        malware_confidence=malware_confidence,
        techniques=uniq_techniques,
    )
    write_detection_log(config.log_file, detection)


def _unified_monitor_worker(
    config: DashboardConfig,
    stop_event: threading.Event,
    poll_interval_sec: float,
) -> None:
    global _UNIFIED_MONITOR_LAST_ERROR, _UNIFIED_MONITOR_LAST_SCAN_AT
    seen_keys: dict[str, float] = {}
    ttl_sec = 90.0
    poll_interval_sec = max(1.0, min(float(poll_interval_sec), 30.0))

    while not stop_event.is_set():
        try:
            now = time.time()
            _UNIFIED_MONITOR_LAST_SCAN_AT = datetime.now().isoformat(timespec="seconds")
            with _UNIFIED_MONITOR_LOCK:
                proc_opts = dict(_UNIFIED_MONITOR_PROCESS_SCAN_OPTIONS)
            proc_opts = normalize_process_scan_options(proc_opts)

            proc_report = scan_processes(
                max_findings=120,
                include_dlls=bool(proc_opts.get("include_dlls", False)),
                dll_limit=int(proc_opts.get("dll_limit", 120)),
                vt_enabled=bool(proc_opts.get("vt_enabled", False)),
                vt_api_key=str(proc_opts.get("vt_api_key", "") or ""),
                vt_threshold=int(proc_opts.get("vt_threshold", 5)),
                auto_kill=bool(proc_opts.get("auto_kill", False)),
                kill_parent=bool(proc_opts.get("kill_parent", False)),
                kill_threshold=int(proc_opts.get("kill_threshold", 110)),
            )
            proc_findings = proc_report.get("findings", []) if isinstance(proc_report, dict) else []
            if isinstance(proc_findings, list):
                for finding in proc_findings:
                    if not isinstance(finding, dict):
                        continue
                    key = _make_monitor_key("process", finding)
                    last_seen = seen_keys.get(key, 0.0)
                    if now - last_seen < ttl_sec:
                        continue
                    seen_keys[key] = now
                    _emit_monitor_finding(config, "process", finding)
                    _UNIFIED_MONITOR_STATS["process_alerts"] += 1
                    _UNIFIED_MONITOR_STATS["total_emitted"] += 1

            reg_report = scan_registry(max_findings=120)
            reg_findings = reg_report.get("findings", []) if isinstance(reg_report, dict) else []
            if isinstance(reg_findings, list):
                for finding in reg_findings:
                    if not isinstance(finding, dict):
                        continue
                    key = _make_monitor_key("registry", finding)
                    last_seen = seen_keys.get(key, 0.0)
                    if now - last_seen < ttl_sec:
                        continue
                    seen_keys[key] = now
                    _emit_monitor_finding(config, "registry", finding)
                    _UNIFIED_MONITOR_STATS["registry_alerts"] += 1
                    _UNIFIED_MONITOR_STATS["total_emitted"] += 1

            # cleanup old cache keys
            stale_before = now - (ttl_sec * 2)
            stale_keys = [k for k, ts in seen_keys.items() if ts < stale_before]
            for key in stale_keys:
                seen_keys.pop(key, None)
        except Exception as exc:
            _UNIFIED_MONITOR_LAST_ERROR = str(exc)
            logging.error("unified monitor worker error: %s", exc)

        stop_event.wait(poll_interval_sec)


def start_unified_monitor(
    config: DashboardConfig,
    *,
    include_file_monitor: bool,
    file_monitor_dry_run: bool,
    poll_interval_sec: float = 3.0,
    process_scan_options: dict | None = None,
) -> dict:
    global _UNIFIED_MONITOR_THREAD, _UNIFIED_MONITOR_STOP_EVENT, _UNIFIED_MONITOR_STARTED_AT, _UNIFIED_MONITOR_LAST_ERROR, _UNIFIED_MONITOR_LAST_SCAN_AT, _UNIFIED_MONITOR_PROCESS_SCAN_OPTIONS
    with _UNIFIED_MONITOR_LOCK:
        if _unified_monitor_is_running():
            _UNIFIED_MONITOR_PROCESS_SCAN_OPTIONS = normalize_process_scan_options(process_scan_options)
            return {
                "ok": True,
                "message": "unified monitor already running (process options updated)",
                "status": _unified_monitor_status_nolock(),
            }

        if include_file_monitor:
            detector_result = start_detector(config, dry_run=file_monitor_dry_run, watch_dirs=None)
            if not detector_result.get("ok"):
                return {
                    "ok": False,
                    "error": detector_result.get("error", "failed to start file monitor"),
                }

        _UNIFIED_MONITOR_STATS["process_alerts"] = 0
        _UNIFIED_MONITOR_STATS["registry_alerts"] = 0
        _UNIFIED_MONITOR_STATS["total_emitted"] = 0
        _UNIFIED_MONITOR_LAST_ERROR = None
        _UNIFIED_MONITOR_LAST_SCAN_AT = None
        _UNIFIED_MONITOR_STARTED_AT = datetime.now().isoformat(timespec="seconds")
        _UNIFIED_MONITOR_PROCESS_SCAN_OPTIONS = normalize_process_scan_options(process_scan_options)

        _UNIFIED_MONITOR_STOP_EVENT = threading.Event()
        _UNIFIED_MONITOR_THREAD = threading.Thread(
            target=_unified_monitor_worker,
            args=(config, _UNIFIED_MONITOR_STOP_EVENT, poll_interval_sec),
            daemon=True,
        )
        _UNIFIED_MONITOR_THREAD.start()
        return {
            "ok": True,
            "message": "unified monitor started",
            "status": _unified_monitor_status_nolock(),
        }


def stop_unified_monitor(stop_file_monitor: bool) -> dict:
    global _UNIFIED_MONITOR_THREAD, _UNIFIED_MONITOR_STOP_EVENT, _UNIFIED_MONITOR_STARTED_AT
    with _UNIFIED_MONITOR_LOCK:
        thread = _UNIFIED_MONITOR_THREAD
        stop_event = _UNIFIED_MONITOR_STOP_EVENT
        _UNIFIED_MONITOR_THREAD = None
        _UNIFIED_MONITOR_STOP_EVENT = None
        _UNIFIED_MONITOR_STARTED_AT = None

    if stop_event is not None:
        stop_event.set()
    if thread is not None and thread.is_alive():
        thread.join(timeout=4.0)

    detector_status_payload = None
    if stop_file_monitor:
        detector_status_payload = stop_detector()

    with _UNIFIED_MONITOR_LOCK:
        status = _unified_monitor_status_nolock()
    return {
        "ok": True,
        "message": "unified monitor stopped",
        "status": status,
        "detector_stop": detector_status_payload,
    }


def tail_jsonl(path: Path, limit: int) -> list[dict]:
    if not path.exists():
        return []

    rows: deque[str] = deque(maxlen=max(1, limit))
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                rows.append(line)
    except Exception as exc:
        logging.error("cannot read log file %s: %s", path, exc)
        return []

    events: list[dict] = []
    for raw in rows:
        line = raw.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            if isinstance(payload, dict):
                events.append(payload)
        except json.JSONDecodeError:
            continue

    events.reverse()
    return events


def get_quarantine_files(path: Path, limit: int = 200) -> list[dict]:
    if not path.exists() or not path.is_dir():
        return []

    files = []
    for item in path.iterdir():
        if not item.is_file():
            continue
        try:
            stat = item.stat()
        except OSError:
            continue
        files.append(
            {
                "name": item.name,
                "path": str(item),
                "size_bytes": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            }
        )

    files.sort(key=lambda x: x["modified"], reverse=True)
    return files[:limit]


def summarize(events: list[dict]) -> dict:
    counts = {
        "total": len(events),
        "blocked": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for event in events:
        sev = str(event.get("severity", "info")).lower()
        if sev in counts:
            counts[sev] += 1
        if event.get("blocked"):
            counts["blocked"] += 1
    return counts


def normalize_ioc_list(iocs: list[dict] | None) -> list[dict[str, str]]:
    if not isinstance(iocs, list):
        return []
    normalized: list[dict[str, str]] = []
    for row in iocs:
        if not isinstance(row, dict):
            continue
        ioc_type = str(row.get("type", "")).strip().lower()
        value = str(row.get("value", "")).strip()
        source = str(row.get("source", "")).strip().lower()
        if not ioc_type or not value:
            continue
        normalized.append({"type": ioc_type, "value": value, "source": source})
    return dedupe_iocs(normalized)


def infer_malware_types_local(
    iocs: list[dict[str, str]],
    reasons: list[str],
    base_score: int,
) -> tuple[list[str], float]:
    # Avoid forcing malware family labels on near-clean samples.
    if int(base_score) < 30:
        return ["unknown"], 0.0

    score_by_type: dict[str, float] = {name: 0.0 for name in MALWARE_TYPE_PROFILES}
    combined_parts: list[str] = []

    for ioc in iocs:
        value = str(ioc.get("value", "")).strip().lower()
        source = str(ioc.get("source", "")).strip().lower()
        combined_parts.append(value)
        combined_parts.append(source)

    combined_parts.extend([str(reason).strip().lower() for reason in reasons[:12]])
    combined_text = " | ".join(part for part in combined_parts if part)

    for malware_type, keywords in MALWARE_TYPE_PROFILES.items():
        for keyword in keywords:
            if keyword in combined_text:
                score_by_type[malware_type] += 1.0

    # Strong IOC hints toward trojan/loader behavior in this detector context.
    high_signal_tokens = (
        "runmalware",
        "dllregisterserver",
        "delegateexecute",
        "fodhelper.exe",
        "winmm_proxy_exports",
        "notepad++.exe",
        "npp.exe",
        "winmm.dll",
        "sideload_target_dll",
        "module_path_class",
    )
    if any(token in combined_text for token in high_signal_tokens):
        score_by_type["trojan"] += 2.0

    ranked = sorted(score_by_type.items(), key=lambda item: item[1], reverse=True)
    if not ranked or ranked[0][1] < 2.0:
        return ["unknown"], 0.0

    max_score = ranked[0][1]
    selected = [name for name, score in ranked if score >= max_score * 0.6 and score > 0]
    confidence = min(1.0, max_score / 8.0)
    return selected[:3], round(confidence, 3)


def correlate_iocs_local(
    path: Path,
    reasons: list[str],
    iocs: list[dict[str, str]],
    base_score: int,
) -> dict:
    normalized_iocs = normalize_ioc_list(iocs)
    malware_types, malware_confidence = infer_malware_types_local(
        iocs=normalized_iocs,
        reasons=reasons,
        base_score=base_score,
    )
    techniques = infer_techniques(
        path=path,
        reasons=reasons,
        iocs=normalized_iocs,
        score=base_score,
    )
    return {
        "malware_types": malware_types,
        "malware_confidence": malware_confidence,
        "techniques": techniques,
    }


def build_handler(config: DashboardConfig):
    class DashboardHandler(BaseHTTPRequestHandler):
        def _send_json(self, payload: dict, code: int = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _load_events(self, limit: int | None = None) -> list[dict]:
            selected = config.max_api_events if limit is None else max(1, min(limit, 5000))
            return tail_jsonl(config.log_file, selected)

        def _serve_events(self, query: dict[str, list[str]]) -> None:
            limit = config.max_api_events
            if "limit" in query:
                raw_limit = query["limit"][0]
                try:
                    limit = int(raw_limit)
                except ValueError:
                    pass
            events = self._load_events(limit)
            self._send_json({"events": events})

        def _serve_summary(self) -> None:
            events = self._load_events(config.max_api_events)
            summary = summarize(events)
            payload = {
                "summary": summary,
                "log_file": str(config.log_file),
                "quarantine_dir": str(config.quarantine_dir),
                "updated_at": datetime.now().isoformat(timespec="seconds"),
            }
            self._send_json(payload)

        def _serve_quarantine(self) -> None:
            files = get_quarantine_files(config.quarantine_dir)
            self._send_json({"files": files})

        def _serve_detector_status(self) -> None:
            self._send_json({"ok": True, "status": detector_status()})

        def _serve_monitor_status(self) -> None:
            self._send_json({"ok": True, "status": unified_monitor_status()})

        def _serve_monitor_start(self) -> None:
            payload = self._read_json_body()
            include_file_monitor = bool(payload.get("include_file_monitor", True))
            file_monitor_dry_run = bool(payload.get("file_monitor_dry_run", False))
            poll_interval_raw = payload.get("poll_interval_sec", 3.0)
            try:
                poll_interval_sec = float(poll_interval_raw)
            except (TypeError, ValueError):
                poll_interval_sec = 3.0
            poll_interval_sec = max(1.0, min(poll_interval_sec, 30.0))
            process_scan_options = normalize_process_scan_options(payload)

            result = start_unified_monitor(
                config,
                include_file_monitor=include_file_monitor,
                file_monitor_dry_run=file_monitor_dry_run,
                poll_interval_sec=poll_interval_sec,
                process_scan_options=process_scan_options,
            )
            code = HTTPStatus.OK if result.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR
            self._send_json(result, code=code)

        def _serve_monitor_stop(self) -> None:
            payload = self._read_json_body()
            stop_file_monitor = bool(payload.get("stop_file_monitor", True))
            result = stop_unified_monitor(stop_file_monitor=stop_file_monitor)
            self._send_json(result, code=HTTPStatus.OK)

        def _serve_detector_start(self) -> None:
            payload = self._read_json_body()
            dry_run = bool(payload.get("dry_run", False))
            watch_dirs = payload.get("watch_dirs", [])
            if watch_dirs is None:
                watch_dirs = []
            if not isinstance(watch_dirs, list):
                self._send_json(
                    {"ok": False, "error": "watch_dirs must be a list"},
                    code=HTTPStatus.BAD_REQUEST,
                )
                return

            result = start_detector(config, dry_run=dry_run, watch_dirs=watch_dirs)
            code = HTTPStatus.OK if result.get("ok") else HTTPStatus.INTERNAL_SERVER_ERROR
            self._send_json(result, code=code)

        def _serve_detector_stop(self) -> None:
            result = stop_detector()
            self._send_json(result, code=HTTPStatus.OK)

        def _serve_clear_history(self) -> None:
            ensure_dir(config.log_file.parent)
            try:
                with config.log_file.open("w", encoding="utf-8"):
                    pass
            except Exception as exc:
                self._send_json(
                    {"ok": False, "error": f"failed to clear history: {exc}"},
                    code=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
                return

            self._send_json({"ok": True, "message": "history cleared"})

        def _serve_pick_folder(self) -> None:
            payload = self._read_json_body()
            seed = str(payload.get("initial_path", "")).strip()
            selected, error = open_native_folder_picker(seed)
            if error:
                self._send_json(
                    {"ok": False, "error": error},
                    code=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
                return

            if not selected:
                self._send_json(
                    {"ok": True, "selected": False, "path": None},
                    code=HTTPStatus.OK,
                )
                return

            try:
                resolved = str(Path(selected).expanduser().resolve())
            except OSError:
                resolved = selected
            self._send_json(
                {"ok": True, "selected": True, "path": resolved},
                code=HTTPStatus.OK,
            )

        def _read_json_body(self) -> dict:
            content_len_raw = self.headers.get("Content-Length", "0")
            try:
                content_len = int(content_len_raw)
            except ValueError:
                return {}

            if content_len <= 0:
                return {}

            raw = self.rfile.read(min(content_len, 1024 * 1024))
            if not raw:
                return {}

            try:
                payload = json.loads(raw.decode("utf-8", errors="ignore"))
            except json.JSONDecodeError:
                return {}
            return payload if isinstance(payload, dict) else {}

        def _serve_scan_static(self) -> None:
            payload = self._read_json_body()
            raw_path = str(payload.get("path", "")).strip()
            request_block = bool(payload.get("block", False))
            threshold = config.scan_rules.block_threshold

            if not raw_path:
                self._send_json(
                    {"ok": False, "error": "path is required"},
                    code=HTTPStatus.BAD_REQUEST,
                )
                return

            target = Path(raw_path).expanduser()
            try:
                resolved = target.resolve(strict=True)
            except FileNotFoundError:
                self._send_json(
                    {"ok": False, "error": "path not found", "path": raw_path},
                    code=HTTPStatus.NOT_FOUND,
                )
                return
            except OSError as exc:
                self._send_json(
                    {"ok": False, "error": f"cannot resolve path: {exc}", "path": raw_path},
                    code=HTTPStatus.BAD_REQUEST,
                )
                return

            if not resolved.is_file():
                self._send_json(
                    {"ok": False, "error": "path is not a file", "path": str(resolved)},
                    code=HTTPStatus.BAD_REQUEST,
                )
                return

            try:
                static_result = evaluate_file_detailed(resolved, config.scan_rules)
            except PermissionError:
                self._send_json(
                    {"ok": False, "error": "file is locked or access denied", "path": str(resolved)},
                    code=HTTPStatus.FORBIDDEN,
                )
                return
            except Exception as exc:
                self._send_json(
                    {"ok": False, "error": f"static scan failed: {exc}", "path": str(resolved)},
                    code=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
                return

            trusted_ms, sig_status, sig_subject = is_microsoft_trusted_signature(resolved)
            if not sig_status:
                sig_status, sig_subject = get_authenticode_info(resolved)
            score = max(0, int(static_result.score))
            reasons = [str(r) for r in static_result.reasons if str(r).strip()]
            iocs = normalize_ioc_list(static_result.iocs)
            if sig_status:
                iocs.append({"type": "signature_status", "value": sig_status, "source": "authenticode"})
            if sig_subject:
                iocs.append({"type": "signature_subject", "value": sig_subject, "source": "authenticode"})
            iocs = dedupe_iocs(iocs)

            signed_ext = resolved.suffix.lower() in {".dll", ".exe", ".msi", ".sys", ".ocx", ".cpl"}
            if signed_ext:
                if trusted_ms:
                    score = 0
                    reasons = [
                        f"authenticode status: {sig_status or 'Valid'}",
                        f"trusted microsoft signer: {sig_subject or 'unknown'}",
                        "allowlisted by trusted microsoft signature",
                    ]
                else:
                    if sig_status == "NotSigned":
                        score += 35
                        reasons.append("unsigned executable module detected (NotSigned)")
                    elif sig_status == "Valid":
                        score += 8
                        reasons.append(
                            f"signature valid but signer is not microsoft allowlist: {sig_subject or 'unknown'}"
                        )
                    elif sig_status:
                        score += 20
                        reasons.append(f"signature status anomaly: {sig_status}")

            score = min(180, score)
            reasons = reasons[:40]
            local_context = correlate_iocs_local(
                path=resolved,
                reasons=reasons,
                iocs=iocs,
                base_score=score,
            )
            malware_types = local_context.get("malware_types", ["unknown"])
            malware_confidence = float(local_context.get("malware_confidence", 0.0))
            techniques = local_context.get("techniques", [])

            severity = severity_from_score(score)
            is_malicious = score >= threshold
            blocked = request_block and is_malicious
            quarantined_path: str | None = None
            if blocked:
                stop_process_by_exact_path(resolved)
                if resolved.suffix.lower() == ".dll":
                    stop_common_lolbins()
                quarantined = quarantine_file(resolved, config.quarantine_dir)
                quarantined_path = str(quarantined) if quarantined else None

            detection = Detection(
                path=resolved,
                score=score,
                severity=severity,
                reasons=reasons,
                sha256=static_result.sha256,
                blocked=blocked,
                quarantined_path=quarantined_path,
                iocs=iocs,
                malware_types=malware_types,
                malware_confidence=malware_confidence,
                techniques=techniques,
            )
            write_detection_log(config.log_file, detection)

            verdict = "malicious" if is_malicious else ("trusted" if trusted_ms else "clean")
            self._send_json(
                {
                    "ok": True,
                    "path": str(resolved),
                    "score": score,
                    "severity": severity,
                    "threshold": threshold,
                    "verdict": verdict,
                    "blocked": blocked,
                    "request_block": request_block,
                    "quarantined_path": quarantined_path,
                    "sha256": static_result.sha256,
                    "signature": {
                        "status": sig_status,
                        "subject": sig_subject,
                        "trusted_microsoft": trusted_ms,
                    },
                    "reasons": reasons,
                    "iocs": iocs,
                    "malware_types": malware_types,
                    "malware_confidence": malware_confidence,
                    "techniques": techniques,
                }
            )

        def _serve_scan_processes(self) -> None:
            payload = self._read_json_body()
            mode = str(payload.get("mode", "suspicious")).strip().lower()
            mode_alias = {
                "scan": "suspicious",
                "all": "suspicious",
                "by_pid": "pid",
                "by_name": "name",
                "inventory": "dll_inventory",
                "dlls": "dll_inventory",
            }
            mode = mode_alias.get(mode, mode)
            if mode not in {"suspicious", "pid", "name", "dll_inventory"}:
                self._send_json(
                    {"ok": False, "error": "mode must be one of: suspicious, pid, name, dll_inventory"},
                    code=HTTPStatus.BAD_REQUEST,
                )
                return

            max_findings = payload.get("max_findings", 120)
            log_findings = bool(payload.get("log_findings", True))
            try:
                max_findings = max(1, min(int(max_findings), 400))
            except (TypeError, ValueError):
                max_findings = 120

            options = normalize_process_scan_options(payload)
            emitted = 0

            if mode == "suspicious":
                report = scan_processes(
                    max_findings=max_findings,
                    include_dlls=bool(options.get("include_dlls", False)),
                    dll_limit=int(options.get("dll_limit", 120)),
                    vt_enabled=bool(options.get("vt_enabled", False)),
                    vt_api_key=str(options.get("vt_api_key", "") or ""),
                    vt_threshold=int(options.get("vt_threshold", 5)),
                    auto_kill=bool(options.get("auto_kill", False)),
                    kill_parent=bool(options.get("kill_parent", False)),
                    kill_threshold=int(options.get("kill_threshold", 110)),
                )
                if not isinstance(report, dict) or not report.get("ok", False):
                    self._send_json(
                        {"ok": False, "error": "process scan failed"},
                        code=HTTPStatus.INTERNAL_SERVER_ERROR,
                    )
                    return

                findings = report.get("findings", [])
                if not isinstance(findings, list):
                    findings = []
                if log_findings:
                    for finding in findings:
                        if not isinstance(finding, dict):
                            continue
                        if int(finding.get("score", 0)) <= 0:
                            continue
                        _emit_monitor_finding(config, "process", finding)
                        emitted += 1

                self._send_json(
                    {
                        "ok": True,
                        "mode": mode,
                        "report": report,
                        "logged_events": emitted,
                        "options": sanitize_process_scan_options(options),
                    },
                    code=HTTPStatus.OK,
                )
                return

            if mode == "pid":
                pid_raw = payload.get("pid", 0)
                try:
                    pid = int(pid_raw)
                except (TypeError, ValueError):
                    pid = 0
                if pid <= 0:
                    self._send_json(
                        {"ok": False, "error": "pid must be a positive integer"},
                        code=HTTPStatus.BAD_REQUEST,
                    )
                    return
                report = scan_process_by_pid(
                    pid,
                    include_dlls=bool(options.get("include_dlls", True)),
                    dll_limit=int(options.get("dll_limit", 120)),
                    vt_enabled=bool(options.get("vt_enabled", False)),
                    vt_api_key=str(options.get("vt_api_key", "") or ""),
                    vt_threshold=int(options.get("vt_threshold", 5)),
                )
                self._send_json(
                    {
                        "ok": bool(report.get("ok", False)),
                        "mode": mode,
                        "report": report,
                        "options": sanitize_process_scan_options(options),
                    },
                    code=HTTPStatus.OK,
                )
                return

            if mode == "name":
                process_name = str(payload.get("name", "")).strip()
                if not process_name:
                    self._send_json(
                        {"ok": False, "error": "name is required"},
                        code=HTTPStatus.BAD_REQUEST,
                    )
                    return
                max_processes = payload.get("max_processes", 50)
                try:
                    max_processes = max(1, min(int(max_processes), 200))
                except (TypeError, ValueError):
                    max_processes = 50

                report = scan_processes_by_name(
                    process_name,
                    include_dlls=bool(options.get("include_dlls", True)),
                    dll_limit=int(options.get("dll_limit", 120)),
                    vt_enabled=bool(options.get("vt_enabled", False)),
                    vt_api_key=str(options.get("vt_api_key", "") or ""),
                    vt_threshold=int(options.get("vt_threshold", 5)),
                    max_processes=int(max_processes),
                )
                self._send_json(
                    {
                        "ok": bool(report.get("ok", False)),
                        "mode": mode,
                        "report": report,
                        "options": sanitize_process_scan_options(options),
                    },
                    code=HTTPStatus.OK,
                )
                return

            process_name_filter = str(payload.get("name", "")).strip()
            max_processes = payload.get("max_processes", 80)
            try:
                max_processes = max(1, min(int(max_processes), 300))
            except (TypeError, ValueError):
                max_processes = 80
            max_dlls_per_process = payload.get("max_dlls_per_process", options.get("dll_limit", 120))
            try:
                max_dlls_per_process = max(10, min(int(max_dlls_per_process), 200))
            except (TypeError, ValueError):
                max_dlls_per_process = int(options.get("dll_limit", 120))

            report = list_process_dll_inventory(
                process_name_filter=process_name_filter,
                max_processes=int(max_processes),
                max_dlls_per_process=int(max_dlls_per_process),
                vt_enabled=bool(options.get("vt_enabled", False)),
                vt_api_key=str(options.get("vt_api_key", "") or ""),
                vt_threshold=int(options.get("vt_threshold", 5)),
            )
            self._send_json(
                {
                    "ok": bool(report.get("ok", False)),
                    "mode": mode,
                    "report": report,
                    "options": sanitize_process_scan_options(options),
                },
                code=HTTPStatus.OK,
            )

        def _serve_scan_registry(self) -> None:
            payload = self._read_json_body()
            max_findings = payload.get("max_findings", 120)
            log_findings = bool(payload.get("log_findings", True))
            try:
                max_findings = max(1, min(int(max_findings), 400))
            except (TypeError, ValueError):
                max_findings = 120

            report = scan_registry(max_findings=max_findings)
            if not isinstance(report, dict) or not report.get("ok", False):
                self._send_json(
                    {"ok": False, "error": "registry scan failed"},
                    code=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
                return

            findings = report.get("findings", [])
            if not isinstance(findings, list):
                findings = []
            emitted = 0
            if log_findings:
                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    if int(finding.get("score", 0)) <= 0:
                        continue
                    _emit_monitor_finding(config, "registry", finding)
                    emitted += 1

            self._send_json(
                {
                    "ok": True,
                    "report": report,
                    "logged_events": emitted,
                },
                code=HTTPStatus.OK,
            )

        def _serve_scan_path(self) -> None:
            payload = self._read_json_body()
            raw_path = str(payload.get("path", "")).strip()
            request_block = bool(payload.get("block", False))
            threshold = config.scan_rules.block_threshold

            if not raw_path:
                self._send_json(
                    {"ok": False, "error": "path is required"},
                    code=HTTPStatus.BAD_REQUEST,
                )
                return

            target = Path(raw_path).expanduser()
            try:
                resolved = target.resolve(strict=True)
            except FileNotFoundError:
                self._send_json(
                    {"ok": False, "error": "path not found", "path": raw_path},
                    code=HTTPStatus.NOT_FOUND,
                )
                return
            except OSError as exc:
                self._send_json(
                    {"ok": False, "error": f"cannot resolve path: {exc}", "path": raw_path},
                    code=HTTPStatus.BAD_REQUEST,
                )
                return

            if not resolved.is_file():
                self._send_json(
                    {"ok": False, "error": "path is not a file", "path": str(resolved)},
                    code=HTTPStatus.BAD_REQUEST,
                )
                return

            try:
                scan_result = evaluate_file_detailed(resolved, config.scan_rules)
            except PermissionError:
                self._send_json(
                    {"ok": False, "error": "file is locked or access denied", "path": str(resolved)},
                    code=HTTPStatus.FORBIDDEN,
                )
                return
            except Exception as exc:
                self._send_json(
                    {"ok": False, "error": f"scan failed: {exc}", "path": str(resolved)},
                    code=HTTPStatus.INTERNAL_SERVER_ERROR,
                )
                return

            score = scan_result.score
            reasons = scan_result.reasons
            sample_hash = scan_result.sha256
            iocs = normalize_ioc_list(scan_result.iocs)
            local_context = correlate_iocs_local(
                path=resolved,
                reasons=reasons,
                iocs=iocs,
                base_score=score,
            )
            malware_types = local_context.get("malware_types", ["unknown"])
            malware_confidence = float(local_context.get("malware_confidence", 0.0))
            techniques = local_context.get("techniques", [])

            severity = severity_from_score(score)
            is_malicious = score >= threshold
            blocked = request_block and is_malicious
            quarantined_path: str | None = None

            if blocked:
                stop_process_by_exact_path(resolved)
                if resolved.suffix.lower() == ".dll":
                    stop_common_lolbins()
                quarantined = quarantine_file(resolved, config.quarantine_dir)
                quarantined_path = str(quarantined) if quarantined else None

            detection = Detection(
                path=resolved,
                score=score,
                severity=severity,
                reasons=reasons,
                sha256=sample_hash,
                blocked=blocked,
                quarantined_path=quarantined_path,
                iocs=iocs,
                malware_types=malware_types,
                malware_confidence=malware_confidence,
                techniques=techniques,
            )
            write_detection_log(config.log_file, detection)

            verdict = "malicious" if is_malicious else "clean"
            self._send_json(
                {
                    "ok": True,
                    "path": str(resolved),
                    "score": score,
                    "severity": severity,
                    "threshold": threshold,
                    "verdict": verdict,
                    "blocked": blocked,
                    "request_block": request_block,
                    "quarantined_path": quarantined_path,
                    "sha256": sample_hash,
                    "reasons": reasons,
                    "iocs": iocs,
                    "malware_types": malware_types,
                    "malware_confidence": malware_confidence,
                    "techniques": techniques,
                }
            )

        def _serve_scan_folder(self) -> None:
            payload = self._read_json_body()
            raw_path = str(payload.get("path", "")).strip()
            recursive = bool(payload.get("recursive", True))
            request_block = bool(payload.get("block", False))
            log_nonzero_only = bool(payload.get("log_nonzero_only", True))
            max_files = payload.get("max_files", 5000)
            try:
                max_files = max(1, min(int(max_files), 20000))
            except (TypeError, ValueError):
                max_files = 5000

            if not raw_path:
                self._send_json(
                    {"ok": False, "error": "folder path is required"},
                    code=HTTPStatus.BAD_REQUEST,
                )
                return

            target = Path(raw_path).expanduser()
            try:
                folder = target.resolve(strict=True)
            except FileNotFoundError:
                self._send_json(
                    {"ok": False, "error": "folder not found", "path": raw_path},
                    code=HTTPStatus.NOT_FOUND,
                )
                return
            except OSError as exc:
                self._send_json(
                    {"ok": False, "error": f"cannot resolve folder: {exc}", "path": raw_path},
                    code=HTTPStatus.BAD_REQUEST,
                )
                return

            if not folder.is_dir():
                self._send_json(
                    {"ok": False, "error": "path is not a folder", "path": str(folder)},
                    code=HTTPStatus.BAD_REQUEST,
                )
                return

            started_at = time.time()
            scanned_candidates = 0
            malicious_count = 0
            blocked_count = 0
            logged_count = 0
            errors: list[str] = []
            top_findings: list[dict] = []
            threshold = config.scan_rules.block_threshold

            def on_walk_error(err: OSError) -> None:
                if len(errors) < 20:
                    errors.append(str(err))

            for root, dirs, files in os.walk(folder, onerror=on_walk_error):
                for name in files:
                    file_path = Path(root) / name
                    ext = file_path.suffix.lower()
                    if ext not in CANDIDATE_EXTENSIONS:
                        continue
                    scanned_candidates += 1
                    if scanned_candidates > max_files:
                        break

                    try:
                        scan_result = evaluate_file_detailed(file_path, config.scan_rules)
                    except PermissionError:
                        if len(errors) < 20:
                            errors.append(f"access denied: {file_path}")
                        continue
                    except Exception as exc:
                        if len(errors) < 20:
                            errors.append(f"scan failed {file_path}: {exc}")
                        continue

                    score = scan_result.score
                    reasons = scan_result.reasons
                    sample_hash = scan_result.sha256
                    iocs = normalize_ioc_list(scan_result.iocs)
                    local_context = correlate_iocs_local(
                        path=file_path,
                        reasons=reasons,
                        iocs=iocs,
                        base_score=score,
                    )
                    malware_types = local_context.get("malware_types", ["unknown"])
                    malware_confidence = float(local_context.get("malware_confidence", 0.0))
                    techniques = local_context.get("techniques", [])

                    severity = severity_from_score(score)
                    is_malicious = score >= threshold
                    blocked = False
                    quarantined_path: str | None = None

                    if is_malicious:
                        malicious_count += 1
                        if request_block:
                            stop_process_by_exact_path(file_path)
                            if file_path.suffix.lower() == ".dll":
                                stop_common_lolbins()
                            quarantined = quarantine_file(file_path, config.quarantine_dir)
                            quarantined_path = str(quarantined) if quarantined else None
                            blocked = quarantined is not None
                            if blocked:
                                blocked_count += 1

                    should_log = (not log_nonzero_only) or score > 0 or is_malicious
                    if should_log:
                        detection = Detection(
                            path=file_path,
                            score=score,
                            severity=severity,
                            reasons=reasons,
                            sha256=sample_hash,
                            blocked=blocked,
                            quarantined_path=quarantined_path,
                            iocs=iocs,
                            malware_types=malware_types,
                            malware_confidence=malware_confidence,
                            techniques=techniques,
                        )
                        write_detection_log(config.log_file, detection)
                        logged_count += 1

                    if score > 0:
                        top_findings.append(
                            {
                                "path": str(file_path),
                                "score": score,
                                "severity": severity,
                                "blocked": blocked,
                                "quarantined_path": quarantined_path,
                                "sha256": sample_hash,
                                "reasons": reasons[:4],
                                "iocs": iocs[:12],
                                "malware_types": malware_types,
                                "malware_confidence": malware_confidence,
                                "techniques": techniques,
                            }
                        )
                        top_findings.sort(key=lambda x: x["score"], reverse=True)
                        if len(top_findings) > 50:
                            top_findings = top_findings[:50]

                if scanned_candidates > max_files:
                    break
                if not recursive:
                    break

            duration_sec = round(time.time() - started_at, 3)
            self._send_json(
                {
                    "ok": True,
                    "folder": str(folder),
                    "recursive": recursive,
                    "block": request_block,
                    "max_files": max_files,
                    "scanned_candidates": min(scanned_candidates, max_files),
                    "malicious": malicious_count,
                    "blocked": blocked_count,
                    "logged_events": logged_count,
                    "duration_sec": duration_sec,
                    "truncated": scanned_candidates > max_files,
                    "errors": errors,
                    "top_findings": top_findings,
                }
            )

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query or "")

            if path in {"/", "/index.html"}:
                self._send_html(INDEX_HTML)
                return
            if path == "/api/events":
                self._serve_events(query)
                return
            if path == "/api/summary":
                self._serve_summary()
                return
            if path == "/api/quarantine":
                self._serve_quarantine()
                return
            if path == "/api/detector/status":
                self._serve_detector_status()
                return
            if path == "/api/monitor/status":
                self._serve_monitor_status()
                return

            self._send_json({"error": "not found"}, code=HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/api/scan-path":
                self._serve_scan_path()
                return
            if path == "/api/scan-static":
                self._serve_scan_static()
                return
            if path == "/api/scan-folder":
                self._serve_scan_folder()
                return
            if path == "/api/scan-processes":
                self._serve_scan_processes()
                return
            if path == "/api/scan-registry":
                self._serve_scan_registry()
                return
            if path == "/api/pick-folder":
                self._serve_pick_folder()
                return
            if path == "/api/detector/start":
                self._serve_detector_start()
                return
            if path == "/api/detector/stop":
                self._serve_detector_stop()
                return
            if path == "/api/monitor/start":
                self._serve_monitor_start()
                return
            if path == "/api/monitor/stop":
                self._serve_monitor_stop()
                return
            if path == "/api/history/clear":
                self._serve_clear_history()
                return

            self._send_json({"error": "not found"}, code=HTTPStatus.NOT_FOUND)

        def log_message(self, fmt: str, *args: object) -> None:
            logging.debug("http %s - %s", self.address_string(), fmt % args)

    return DashboardHandler


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Guardian Dashboard</title>
  <style>
    :root {
      --bg: #f3f5f7;
      --panel: #ffffff;
      --ink: #1b1f23;
      --muted: #637087;
      --line: #dbe2ea;
      --danger: #b91c1c;
      --warning: #b45309;
      --ok: #0f766e;
      --critical-bg: #fee2e2;
      --high-bg: #ffedd5;
      --med-bg: #fef9c3;
      --low-bg: #ecfccb;
      --info-bg: #e0f2fe;
      --brand: #0f4c81;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      color: var(--ink);
      background: linear-gradient(180deg, #f7fafc 0%, #eef3f8 100%);
    }
    .wrap {
      width: min(85vw, 1800px);
      margin: 0 auto;
      padding: 18px;
    }
    @media (max-width: 1200px) {
      .wrap { width: 95vw; }
    }
    .hero {
      background: radial-gradient(circle at 12% 25%, #cde5ff 0%, #e8f0ff 24%, #ffffff 74%);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 16px 18px;
      margin-bottom: 14px;
    }
    .hero h1 {
      margin: 0;
      font-size: 23px;
      letter-spacing: 0.2px;
      color: #0b3558;
    }
    .hero p {
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 14px;
    }
    .meta {
      margin-top: 10px;
      font-size: 12px;
      color: #45627f;
    }
    .cards {
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      margin-bottom: 14px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 10px 12px;
    }
    .k {
      color: var(--muted);
      font-size: 12px;
    }
    .v {
      font-size: 21px;
      font-weight: 700;
      margin-top: 3px;
    }
    .controls {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 10px;
      display: flex;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }
    .controls input, .controls select, .controls button {
      padding: 8px 10px;
      border: 1px solid #c7d1dd;
      border-radius: 9px;
      font-size: 13px;
      background: #fff;
    }
    .controls button {
      cursor: pointer;
      background: var(--brand);
      color: #fff;
      border-color: #0d3d66;
    }
    .scan-controls {
      margin-top: -2px;
      margin-bottom: 12px;
    }
    .monitor-controls {
      margin-top: -2px;
      margin-bottom: 12px;
    }
    .hunt-controls {
      margin-top: -2px;
      margin-bottom: 12px;
    }
    .hunt-controls input[type="text"],
    .hunt-controls input[type="password"] {
      min-width: 240px;
      width: min(34vw, 420px);
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
    }
    .folder-controls {
      margin-top: -2px;
      margin-bottom: 12px;
    }
    .scan-controls input[type="text"] {
      min-width: 420px;
      width: min(62vw, 760px);
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
    }
    .folder-controls input[type="text"] {
      min-width: 420px;
      width: min(62vw, 760px);
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
    }
    @media (max-width: 980px) {
      .scan-controls input[type="text"] {
        width: 100%;
        min-width: 0;
      }
      .folder-controls input[type="text"] {
        width: 100%;
        min-width: 0;
      }
    }
    .scan-result.ok { color: var(--ok); }
    .scan-result.warn { color: var(--warning); }
    .scan-result.err { color: var(--danger); }
    .grid {
      display: grid;
      gap: 12px;
      grid-template-columns: 2fr 1fr;
    }
    @media (max-width: 980px) {
      .grid { grid-template-columns: 1fr; }
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 10px;
      min-height: 220px;
    }
    .panel h2 {
      margin: 0 0 10px;
      font-size: 15px;
      color: #19344d;
    }
    .events {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      table-layout: fixed;
      min-width: 1320px;
    }
    .events th, .events td {
      text-align: left;
      padding: 8px 7px;
      border-bottom: 1px solid #edf1f5;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    .events thead th {
      position: sticky;
      top: 0;
      background: #f9fbfd;
      z-index: 2;
      color: #4d5f73;
      user-select: none;
    }
    .events th.resizable {
      position: sticky;
      padding-right: 14px;
    }
    .events th .th-label {
      display: block;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .events th .col-resizer {
      position: absolute;
      top: 0;
      right: 0;
      width: 8px;
      height: 100%;
      cursor: col-resize;
      user-select: none;
      touch-action: none;
    }
    .events th .col-resizer:hover {
      background: #c7d8ea;
    }
    .events.is-resizing, .events.is-resizing * {
      cursor: col-resize !important;
    }
    .sev {
      display: inline-block;
      border-radius: 999px;
      padding: 2px 7px;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 10px;
      letter-spacing: 0.4px;
    }
    .sev-critical { background: var(--critical-bg); color: #991b1b; }
    .sev-high { background: var(--high-bg); color: #9a3412; }
    .sev-medium { background: var(--med-bg); color: #854d0e; }
    .sev-low { background: var(--low-bg); color: #3f6212; }
    .sev-info { background: var(--info-bg); color: #075985; }
    .blocked-yes { color: var(--danger); font-weight: 700; }
    .blocked-no { color: var(--ok); font-weight: 700; }
    .reason {
      margin: 0;
      padding-left: 16px;
    }
    .muted {
      color: var(--muted);
      font-size: 12px;
    }
    .qitem {
      border: 1px solid #edf1f5;
      border-radius: 10px;
      padding: 8px;
      margin-bottom: 8px;
      background: #fafcff;
    }
    .qname { font-size: 12px; font-weight: 600; }
    .qmeta { font-size: 11px; color: var(--muted); margin-top: 4px; }
    .dyn-report {
      white-space: pre-wrap;
      font-family: Consolas, "Courier New", monospace;
      font-size: 12px;
      line-height: 1.35;
      background: #f8fbff;
      border: 1px dashed #d5e1ee;
      border-radius: 8px;
      padding: 8px;
      max-height: 360px;
      overflow: auto;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>Guardian Dashboard</h1>
      <p>Realtime visibility for detections and quarantine actions.</p>
      <div class="meta" id="meta">Loading...</div>
    </section>

    <section class="cards">
      <div class="card"><div class="k">Total Events</div><div class="v" id="s-total">0</div></div>
      <div class="card"><div class="k">Blocked</div><div class="v" id="s-blocked">0</div></div>
      <div class="card"><div class="k">Critical</div><div class="v" id="s-critical">0</div></div>
      <div class="card"><div class="k">High</div><div class="v" id="s-high">0</div></div>
      <div class="card"><div class="k">Medium</div><div class="v" id="s-medium">0</div></div>
      <div class="card"><div class="k">Low</div><div class="v" id="s-low">0</div></div>
      <div class="card"><div class="k">Info</div><div class="v" id="s-info">0</div></div>
    </section>

    <section class="controls">
      <label>Search <input type="text" id="f-search" placeholder="path, reason, hash..."></label>
      <label>Severity
        <select id="f-severity">
          <option value="all">all</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="info">info</option>
        </select>
      </label>
      <label><input type="checkbox" id="f-blocked"> blocked only</label>
      <label>Auto refresh <input type="checkbox" id="f-auto" checked></label>
      <button id="btn-refresh">Refresh</button>
      <button id="btn-clear-history">Clear History</button>
      <span class="muted" id="last-refresh"></span>
    </section>
    <section class="controls monitor-controls">
      <strong>Realtime Monitor (File + Process + Registry)</strong>
      <label><input type="checkbox" id="monitor-include-file" checked> include file monitor</label>
      <label><input type="checkbox" id="monitor-file-dry-run"> file monitor dry-run</label>
      <label><input type="checkbox" id="monitor-auto-kill"> process auto-kill</label>
      <label><input type="checkbox" id="monitor-kill-parent"> kill parent too</label>
      <label>kill>= <input type="number" id="monitor-kill-threshold" min="40" max="220" value="110" style="width:84px;"></label>
      <label>poll(s) <input type="number" id="monitor-poll" min="1" max="30" value="3" style="width:78px;"></label>
      <button id="btn-monitor-start">Start Unified Monitor</button>
      <button id="btn-monitor-stop">Stop Unified Monitor</button>
      <span class="muted scan-result" id="monitor-status">Monitor: checking status...</span>
    </section>
    <section class="controls hunt-controls">
      <strong>On-demand Hunt</strong>
      <button id="btn-scan-processes">Scan Suspicious</button>
      <label>PID <input type="number" id="hunt-pid" min="1" step="1" placeholder="1234" style="width:120px;"></label>
      <button id="btn-scan-process-pid">Scan PID</button>
      <label>Name <input type="text" id="hunt-name" placeholder="notepad++.exe"></label>
      <button id="btn-scan-process-name">Scan Name</button>
      <button id="btn-dll-inventory">DLL Inventory</button>
      <label><input type="checkbox" id="hunt-include-dlls" checked> include DLL list</label>
      <label><input type="checkbox" id="hunt-vt-enabled"> VirusTotal</label>
      <label>VT key <input type="password" id="hunt-vt-api-key" placeholder="VT API key (optional)"></label>
      <label>VT>= <input type="number" id="hunt-vt-threshold" min="1" max="40" value="5" style="width:76px;"></label>
      <label><input type="checkbox" id="hunt-auto-kill"> auto-kill (suspicious mode)</label>
      <label><input type="checkbox" id="hunt-kill-parent"> kill parent too</label>
      <label>kill>= <input type="number" id="hunt-kill-threshold" min="40" max="220" value="110" style="width:84px;"></label>
      <button id="btn-scan-registry">Scan Registry</button>
      <span class="muted scan-result" id="hunt-result">Run process/registry scan directly from dashboard.</span>
    </section>
    <section class="controls scan-controls">
      <label>Scan path <input type="text" id="scan-path" placeholder="C:\\Users\\Admin\\Downloads\\sample.dll"></label>
      <label><input type="checkbox" id="scan-block"> block if malicious</label>
      <button id="btn-scan-static">Static Scan</button>
      <button id="btn-scan-path">Deep Scan</button>
      <span class="muted scan-result" id="scan-result">Static/deep scan file path directly from dashboard.</span>
    </section>
    <section class="controls folder-controls">
      <label>Import folder <input type="text" id="folder-path" placeholder="C:\\Users\\Admin\\Downloads"></label>
      <button id="btn-folder-browse">Browse...</button>
      <label><input type="checkbox" id="folder-recursive" checked> recursive</label>
      <label><input type="checkbox" id="folder-block"> block if malicious</label>
      <button id="btn-scan-folder">Scan Folder</button>
      <span class="muted scan-result" id="folder-result">Scan all candidate files in folder (and subfolders).</span>
    </section>
    <section class="grid">
      <article class="panel">
        <h2>Detections</h2>
        <div style="max-height: 560px; overflow: auto;">
          <table class="events" id="events-table">
            <colgroup id="events-colgroup">
              <col data-col="time" style="width:170px">
              <col data-col="severity" style="width:110px">
              <col data-col="score" style="width:80px">
              <col data-col="blocked" style="width:90px">
              <col data-col="malware" style="width:180px">
              <col data-col="path" style="width:360px">
              <col data-col="reasons" style="width:420px">
              <col data-col="iocs" style="width:360px">
            </colgroup>
            <thead>
              <tr>
                <th class="resizable" data-col="time"><span class="th-label">Time</span><span class="col-resizer" title="Drag to resize"></span></th>
                <th class="resizable" data-col="severity"><span class="th-label">Severity</span><span class="col-resizer" title="Drag to resize"></span></th>
                <th class="resizable" data-col="score"><span class="th-label">Score</span><span class="col-resizer" title="Drag to resize"></span></th>
                <th class="resizable" data-col="blocked"><span class="th-label">Blocked</span><span class="col-resizer" title="Drag to resize"></span></th>
                <th class="resizable" data-col="malware"><span class="th-label">Malware Type</span><span class="col-resizer" title="Drag to resize"></span></th>
                <th class="resizable" data-col="path"><span class="th-label">Path</span><span class="col-resizer" title="Drag to resize"></span></th>
                <th class="resizable" data-col="reasons"><span class="th-label">Reasons</span><span class="col-resizer" title="Drag to resize"></span></th>
                <th class="resizable" data-col="iocs"><span class="th-label">IOC</span><span class="col-resizer" title="Drag to resize"></span></th>
              </tr>
            </thead>
            <tbody id="events-body"></tbody>
          </table>
        </div>
      </article>

      <aside class="panel">
        <h2>Quarantine</h2>
        <div id="quarantine-list" class="muted">No files.</div>
      </aside>
    </section>
    <section class="panel">
      <h2>Process Hunt Report</h2>
      <div id="process-report" class="dyn-report">No process hunt run yet.</div>
    </section>
  </div>

  <script>
    let cachedEvents = [];
    const COL_STORAGE_KEY = "guardian_events_col_widths_v1";
    const DEFAULT_COLUMN_WIDTHS = {
      time: "170px",
      severity: "110px",
      score: "80px",
      blocked: "90px",
      malware: "180px",
      path: "360px",
      reasons: "420px",
      iocs: "360px"
    };

    function byId(id) {
      return document.getElementById(id);
    }

    function getTableColumns() {
      return Array.from(document.querySelectorAll("#events-colgroup col[data-col]"));
    }

    function loadColumnWidths() {
      try {
        const raw = localStorage.getItem(COL_STORAGE_KEY);
        if (!raw) return {};
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== "object") return {};
        return parsed;
      } catch (_err) {
        return {};
      }
    }

    function applyColumnWidths(widthMap) {
      const cols = getTableColumns();
      for (const col of cols) {
        const key = col.dataset.col;
        if (!key) continue;
        const width = widthMap[key] || DEFAULT_COLUMN_WIDTHS[key];
        if (width) {
          col.style.width = width;
        }
      }
    }

    function saveColumnWidths() {
      const cols = getTableColumns();
      const widthMap = {};
      for (const col of cols) {
        const key = col.dataset.col;
        if (!key) continue;
        widthMap[key] = col.style.width || `${Math.round(col.getBoundingClientRect().width)}px`;
      }
      try {
        localStorage.setItem(COL_STORAGE_KEY, JSON.stringify(widthMap));
      } catch (_err) {}
    }

    function initResizableColumns() {
      const table = byId("events-table");
      if (!table) return;

      const colByKey = {};
      for (const col of getTableColumns()) {
        if (col.dataset.col) {
          colByKey[col.dataset.col] = col;
        }
      }

      const resizers = table.querySelectorAll("th.resizable .col-resizer");
      for (const resizer of resizers) {
        resizer.addEventListener("mousedown", (event) => {
          event.preventDefault();

          const th = resizer.closest("th.resizable");
          if (!th || !th.dataset.col) return;
          const col = colByKey[th.dataset.col];
          if (!col) return;

          const startX = event.clientX;
          const startWidth = col.getBoundingClientRect().width;
          const minWidth = 60;
          table.classList.add("is-resizing");

          function onMouseMove(moveEvent) {
            const delta = moveEvent.clientX - startX;
            const newWidth = Math.max(minWidth, startWidth + delta);
            col.style.width = `${Math.round(newWidth)}px`;
          }

          function onMouseUp() {
            document.removeEventListener("mousemove", onMouseMove);
            table.classList.remove("is-resizing");
            saveColumnWidths();
          }

          document.addEventListener("mousemove", onMouseMove);
          document.addEventListener("mouseup", onMouseUp, { once: true });
        });
      }
    }

    function severityClass(sev) {
      const normalized = (sev || "info").toLowerCase();
      return "sev sev-" + normalized;
    }

    function applyFilters(events) {
      const severity = byId("f-severity").value;
      const blockedOnly = byId("f-blocked").checked;
      const search = byId("f-search").value.trim().toLowerCase();

      return events.filter((event) => {
        const sev = String(event.severity || "info").toLowerCase();
        if (severity !== "all" && sev !== severity) return false;
        if (blockedOnly && !event.blocked) return false;
        if (!search) return true;

        const iocSearchParts = Array.isArray(event.iocs)
          ? event.iocs.map((ioc) => `${ioc?.type || ""} ${ioc?.value || ""} ${ioc?.source || ""}`)
          : [];
        const techniqueSearchParts = Array.isArray(event.techniques)
          ? event.techniques.map((t) => `${t?.id || ""} ${t?.name || ""} ${(t?.evidence || []).join(" ")}`)
          : [];

        const haystack = [
          event.path || "",
          event.sha256 || "",
          sev,
          ...(event.malware_types || []),
          ...iocSearchParts,
          ...techniqueSearchParts,
          ...(event.reasons || [])
        ].join(" ").toLowerCase();
        return haystack.includes(search);
      });
    }

    function renderEvents(events) {
      const body = byId("events-body");
      body.innerHTML = "";

      if (!events.length) {
        const row = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = 8;
        td.className = "muted";
        td.textContent = "No events match current filter.";
        row.appendChild(td);
        body.appendChild(row);
        return;
      }

      for (const event of events) {
        const row = document.createElement("tr");

        const tTime = document.createElement("td");
        tTime.textContent = event.timestamp || "-";
        row.appendChild(tTime);

        const tSev = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = severityClass(event.severity);
        badge.textContent = String(event.severity || "info");
        tSev.appendChild(badge);
        row.appendChild(tSev);

        const tScore = document.createElement("td");
        tScore.textContent = String(event.score ?? 0);
        row.appendChild(tScore);

        const tBlocked = document.createElement("td");
        tBlocked.textContent = event.blocked ? "YES" : "NO";
        tBlocked.className = event.blocked ? "blocked-yes" : "blocked-no";
        row.appendChild(tBlocked);

        const tMalware = document.createElement("td");
        const malwareTypes = Array.isArray(event.malware_types) ? event.malware_types : [];
        const confidence = Number(event.malware_confidence || 0);
        if (malwareTypes.length) {
          const label = malwareTypes.join(", ");
          if (confidence > 0) {
            tMalware.textContent = `${label} (${Math.round(confidence * 100)}%)`;
          } else {
            tMalware.textContent = label;
          }
        } else {
          tMalware.textContent = "unknown";
        }
        row.appendChild(tMalware);

        const tPath = document.createElement("td");
        tPath.textContent = event.path || "-";
        row.appendChild(tPath);

        const tReasons = document.createElement("td");
        const list = document.createElement("ul");
        list.className = "reason";
        const reasons = event.reasons || [];
        const techniques = Array.isArray(event.techniques) ? event.techniques : [];
        for (const t of techniques.slice(0, 3)) {
          const liTech = document.createElement("li");
          const id = String(t?.id || "").trim();
          const name = String(t?.name || "").trim();
          const conf = Number(t?.confidence || 0);
          liTech.textContent = id ? `[Technique] ${id}${name ? ` - ${name}` : ""}${conf > 0 ? ` (${Math.round(conf * 100)}%)` : ""}` : `[Technique] ${name}`;
          list.appendChild(liTech);
        }
        if (!reasons.length) {
          const li = document.createElement("li");
          li.textContent = "-";
          list.appendChild(li);
        } else {
          for (const reason of reasons.slice(0, 4)) {
            const li = document.createElement("li");
            li.textContent = reason;
            list.appendChild(li);
          }
        }
        tReasons.appendChild(list);
        row.appendChild(tReasons);

        const tIocs = document.createElement("td");
        const iocList = document.createElement("ul");
        iocList.className = "reason";
        const iocs = Array.isArray(event.iocs) ? event.iocs : [];
        if (!iocs.length) {
          const li = document.createElement("li");
          li.textContent = "-";
          iocList.appendChild(li);
        } else {
          for (const ioc of iocs.slice(0, 6)) {
            const type = String(ioc?.type || "ioc").toUpperCase();
            const value = String(ioc?.value || "");
            const src = String(ioc?.source || "");
            const li = document.createElement("li");
            li.textContent = src ? `[${type}] ${value} (${src})` : `[${type}] ${value}`;
            iocList.appendChild(li);
          }
        }
        tIocs.appendChild(iocList);
        row.appendChild(tIocs);

        body.appendChild(row);
      }
    }

    function renderSummary(summaryPayload) {
      const summary = summaryPayload.summary || {};
      byId("s-total").textContent = summary.total ?? 0;
      byId("s-blocked").textContent = summary.blocked ?? 0;
      byId("s-critical").textContent = summary.critical ?? 0;
      byId("s-high").textContent = summary.high ?? 0;
      byId("s-medium").textContent = summary.medium ?? 0;
      byId("s-low").textContent = summary.low ?? 0;
      byId("s-info").textContent = summary.info ?? 0;

      byId("meta").textContent =
        "Log: " + (summaryPayload.log_file || "-") +
        " | Quarantine: " + (summaryPayload.quarantine_dir || "-") +
        " | Updated: " + (summaryPayload.updated_at || "-");
    }

    function renderQuarantine(files) {
      const holder = byId("quarantine-list");
      holder.innerHTML = "";
      if (!files.length) {
        holder.textContent = "No quarantined files.";
        return;
      }

      for (const file of files.slice(0, 80)) {
        const box = document.createElement("div");
        box.className = "qitem";

        const name = document.createElement("div");
        name.className = "qname";
        name.textContent = file.name || "unknown";
        box.appendChild(name);

        const meta = document.createElement("div");
        meta.className = "qmeta";
        meta.textContent =
          "Size: " + String(file.size_bytes ?? 0) +
          " bytes | Modified: " + String(file.modified || "-");
        box.appendChild(meta);

        const path = document.createElement("div");
        path.className = "qmeta";
        path.textContent = file.path || "-";
        box.appendChild(path);

        holder.appendChild(box);
      }
    }

    async function fetchJson(path) {
      const resp = await fetch(path, { cache: "no-store" });
      if (!resp.ok) {
        throw new Error("HTTP " + resp.status);
      }
      return await resp.json();
    }

    function setScanStatus(text, kind = "muted") {
      const el = byId("scan-result");
      el.textContent = text;
      el.className = `muted scan-result ${kind}`;
    }

    function setMonitorStatus(text, kind = "muted") {
      const el = byId("monitor-status");
      el.textContent = text;
      el.className = `muted scan-result ${kind}`;
    }

    function setFolderStatus(text, kind = "muted") {
      const el = byId("folder-result");
      el.textContent = text;
      el.className = `muted scan-result ${kind}`;
    }

    function setHuntStatus(text, kind = "muted") {
      const el = byId("hunt-result");
      el.textContent = text;
      el.className = `muted scan-result ${kind}`;
    }

    function renderMonitorStatus(statusPayload) {
      const status = statusPayload?.status || {};
      const stats = status.stats || {};
      const procOpts = status.process_scan_options || {};
      const detector = status.detector || {};
      const fileMonitorState = detector.running ? "RUNNING" : "STOPPED";
      const procMode = `auto_kill=${procOpts.auto_kill ? "on" : "off"}, kill_parent=${procOpts.kill_parent ? "on" : "off"}, kill_threshold=${procOpts.kill_threshold ?? 110}, vt=${procOpts.vt_enabled ? "on" : "off"}`;

      if (status.running) {
        const dry = detector.running && detector.dry_run ? " dry-run" : "";
        setMonitorStatus(
          `Monitor: RUNNING | process_alerts=${stats.process_alerts ?? 0}, registry_alerts=${stats.registry_alerts ?? 0}, emitted=${stats.total_emitted ?? 0} | process_opts(${procMode}) | file_monitor=${fileMonitorState}${dry} | started=${status.started_at || "-"} | last_scan=${status.last_scan_at || "-"}`,
          "ok"
        );
      } else {
        const base = `Monitor: STOPPED | process_opts(${procMode}) | file_monitor=${fileMonitorState}`;
        if (status.last_error) {
          setMonitorStatus(`${base} | last_error=${status.last_error}`, "err");
        } else {
          setMonitorStatus(base, "warn");
        }
      }
    }

    async function startMonitor() {
      const includeFileMonitor = byId("monitor-include-file").checked;
      const fileDryRun = byId("monitor-file-dry-run").checked;
      const processOptions = readHuntOptions();
      const monitorAutoKill = byId("monitor-auto-kill").checked;
      const monitorKillParent = byId("monitor-kill-parent").checked;
      let monitorKillThreshold = Number.parseInt(byId("monitor-kill-threshold").value, 10);
      if (Number.isNaN(monitorKillThreshold)) monitorKillThreshold = processOptions.kill_threshold;
      monitorKillThreshold = Math.max(40, Math.min(220, monitorKillThreshold));
      byId("monitor-kill-threshold").value = String(monitorKillThreshold);
      let pollSec = Number.parseFloat(byId("monitor-poll").value);
      if (Number.isNaN(pollSec)) pollSec = 3;
      pollSec = Math.max(1, Math.min(30, pollSec));
      byId("monitor-poll").value = String(pollSec);

      const btnStart = byId("btn-monitor-start");
      btnStart.disabled = true;
      setMonitorStatus("Starting unified monitor...", "muted");

      try {
        const resp = await fetch("/api/monitor/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            include_file_monitor: includeFileMonitor,
            file_monitor_dry_run: fileDryRun,
            poll_interval_sec: pollSec,
            include_dlls: processOptions.include_dlls,
            vt_enabled: processOptions.vt_enabled,
            vt_api_key: processOptions.vt_api_key,
            vt_threshold: processOptions.vt_threshold,
            auto_kill: monitorAutoKill,
            kill_parent: monitorAutoKill && monitorKillParent,
            kill_threshold: monitorKillThreshold
          })
        });
        const data = await resp.json();
        if (!resp.ok || !data.ok) {
          setMonitorStatus(`Start failed: ${data.error || ("HTTP " + resp.status)}`, "err");
          return;
        }
        renderMonitorStatus(data);
        await refreshAll();
      } catch (err) {
        setMonitorStatus(`Start error: ${err}`, "err");
      } finally {
        btnStart.disabled = false;
      }
    }

    async function stopMonitor() {
      const btnStop = byId("btn-monitor-stop");
      btnStop.disabled = true;
      setMonitorStatus("Stopping unified monitor...", "muted");

      try {
        const resp = await fetch("/api/monitor/stop", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ stop_file_monitor: true })
        });
        const data = await resp.json();
        if (!resp.ok || !data.ok) {
          setMonitorStatus(`Stop failed: ${data.error || ("HTTP " + resp.status)}`, "err");
          return;
        }
        renderMonitorStatus(data);
        await refreshAll();
      } catch (err) {
        setMonitorStatus(`Stop error: ${err}`, "err");
      } finally {
        btnStop.disabled = false;
      }
    }

    function setProcessReport(text) {
      const el = byId("process-report");
      el.textContent = text || "No process hunt run yet.";
    }

    function readHuntOptions() {
      let vtThreshold = Number.parseInt(byId("hunt-vt-threshold").value, 10);
      if (Number.isNaN(vtThreshold)) vtThreshold = 5;
      vtThreshold = Math.max(1, Math.min(40, vtThreshold));
      byId("hunt-vt-threshold").value = String(vtThreshold);

      let killThreshold = Number.parseInt(byId("hunt-kill-threshold").value, 10);
      if (Number.isNaN(killThreshold)) killThreshold = 110;
      killThreshold = Math.max(40, Math.min(220, killThreshold));
      byId("hunt-kill-threshold").value = String(killThreshold);

      return {
        include_dlls: byId("hunt-include-dlls").checked,
        vt_enabled: byId("hunt-vt-enabled").checked,
        vt_api_key: byId("hunt-vt-api-key").value.trim(),
        vt_threshold: vtThreshold,
        auto_kill: byId("hunt-auto-kill").checked,
        kill_parent: byId("hunt-kill-parent").checked,
        kill_threshold: killThreshold
      };
    }

    function summarizeDllList(modules, limit = 12) {
      const rows = Array.isArray(modules) ? modules.slice(0, limit) : [];
      return rows.map((m) => ` - ${m?.name || "?"} | ${m?.path || "-"}`);
    }

    function summarizeConnections(connections, limit = 8) {
      const rows = Array.isArray(connections) ? connections.slice(0, limit) : [];
      return rows.map((c) => {
        const remoteIp = c?.remote_ip || "-";
        const remotePort = c?.remote_port ?? 0;
        const state = c?.state || "-";
        return ` - ${remoteIp}:${remotePort} state=${state}`;
      });
    }

    function renderProcessReport(mode, payload) {
      const reportEl = byId("process-report");
      if (!payload || !payload.ok) {
        reportEl.textContent = "Process hunt failed.";
        return;
      }
      const report = payload.report || {};
      const lines = [];
      const safeMode = String(mode || payload.mode || "suspicious");

      if (safeMode === "suspicious") {
        const findings = Array.isArray(report.findings) ? report.findings : [];
        lines.push(`Mode: suspicious`);
        lines.push(`Scanned: ${report.scanned_processes ?? 0} | suspicious=${report.suspicious ?? findings.length}`);
        lines.push(`Auto-kill: ${report.auto_kill ? "ON" : "OFF"} | kill_parent=${report.kill_parent ? "true" : "false"} | kill_threshold=${report.kill_threshold ?? 110}`);
        const kills = Array.isArray(report.kill_actions) ? report.kill_actions : [];
        lines.push(`Kill actions: ${kills.length}`);
        if (kills.length) {
          for (const k of kills.slice(0, 12)) {
            lines.push(` - pid=${k?.pid ?? "?"} parent=${k?.parent_pid ?? "-"} tag=${k?.tag || "-"} score=${k?.score ?? 0}`);
          }
        }
        lines.push("");
        lines.push("Top findings:");
        if (!findings.length) {
          lines.push(" - none");
        } else {
          for (const f of findings.slice(0, 12)) {
            const proc = f?.process || {};
            const rem = f?.remediation || {};
            const prefix = ` - score=${f?.score ?? 0} sev=${f?.severity || "-"} pid=${proc?.pid ?? "?"} name=${proc?.name || "-"} tag=${f?.tag || "-"}`;
            lines.push(rem?.killed ? `${prefix} | killed=true` : prefix);
            const reasons = Array.isArray(f?.reasons) ? f.reasons : [];
            for (const r of reasons.slice(0, 2)) {
              lines.push(`    reason: ${r}`);
            }
            const conns = summarizeConnections(f?.network_connections, 3);
            for (const c of conns) {
              lines.push(`    net: ${c.replace(" - ", "")}`);
            }
          }
        }
        reportEl.textContent = lines.join("\\n");
        return;
      }

      if (safeMode === "pid") {
        lines.push(`Mode: pid`);
        lines.push(`PID: ${report.pid ?? "?"} | found=${report.found ? "true" : "false"}`);
        const detail = report.detail || null;
        if (!detail) {
          lines.push("No process detail found.");
          reportEl.textContent = lines.join("\\n");
          return;
        }
        lines.push(`Name: ${detail.name || "-"} | Parent: ${detail.parent_name || "-"} (ppid=${detail.ppid ?? "?"})`);
        lines.push(`Path: ${detail.path || "-"}`);
        lines.push(`Command: ${detail.command_line || "-"}`);
        if (detail.process_vt) {
          const vt = detail.process_vt;
          lines.push(`VirusTotal(process): status=${vt.status || "-"} positives=${vt.positives ?? 0}/${vt.total ?? 0}`);
        }
        const notes = Array.isArray(detail.suspicion_notes) ? detail.suspicion_notes : [];
        if (notes.length) {
          lines.push("Notes:");
          for (const n of notes.slice(0, 6)) lines.push(` - ${n}`);
        }
        const dlls = summarizeDllList(detail.dlls, 18);
        lines.push(`DLLs: ${Array.isArray(detail.dlls) ? detail.dlls.length : 0}`);
        for (const row of dlls) lines.push(row);
        const conns = summarizeConnections(detail.network_connections, 10);
        if (conns.length) {
          lines.push("Network:");
          for (const row of conns) lines.push(row);
        }
        reportEl.textContent = lines.join("\\n");
        return;
      }

      if (safeMode === "name") {
        lines.push(`Mode: name`);
        lines.push(`Process name: ${report.process_name || "-"} | matched=${report.count ?? 0}`);
        const results = Array.isArray(report.results) ? report.results : [];
        for (const item of results.slice(0, 8)) {
          lines.push("");
          lines.push(`pid=${item.pid ?? "?"} parent=${item.parent_name || "-"} (${item.ppid ?? "?"})`);
          lines.push(`name=${item.name || "-"} path=${item.path || "-"}`);
          lines.push(`cmd=${item.command_line || "-"}`);
          if (item.process_vt) {
            const vt = item.process_vt;
            lines.push(`vt=${vt.status || "-"} positives=${vt.positives ?? 0}/${vt.total ?? 0}`);
          }
          const dlls = summarizeDllList(item.dlls, 10);
          lines.push(`dll_count=${Array.isArray(item.dlls) ? item.dlls.length : 0}`);
          for (const row of dlls) lines.push(row);
          const conns = summarizeConnections(item.network_connections, 4);
          for (const row of conns) lines.push(row);
        }
        if (!results.length) lines.push("No matching process found.");
        reportEl.textContent = lines.join("\\n");
        return;
      }

      lines.push("Mode: dll_inventory");
      const rows = Array.isArray(report.processes) ? report.processes : [];
      lines.push(`Processes: ${report.count ?? rows.length}`);
      for (const item of rows.slice(0, 10)) {
        lines.push("");
        lines.push(`pid=${item.pid ?? "?"} name=${item.name || "-"} dll_count=${item.dll_count ?? 0}`);
        lines.push(`path=${item.path || "-"} | ppid=${item.ppid ?? "?"}`);
        const dlls = summarizeDllList(item.dlls, 12);
        for (const row of dlls) lines.push(row);
      }
      reportEl.textContent = lines.join("\\n");
    }

    async function scanProcessesNow(mode = "suspicious") {
      const buttonId =
        mode === "pid" ? "btn-scan-process-pid" :
        mode === "name" ? "btn-scan-process-name" :
        mode === "dll_inventory" ? "btn-dll-inventory" : "btn-scan-processes";
      const btn = byId(buttonId);
      btn.disabled = true;

      const options = readHuntOptions();
      const payload = {
        mode: mode,
        max_findings: 120,
        log_findings: true,
        include_dlls: options.include_dlls,
        vt_enabled: options.vt_enabled,
        vt_api_key: options.vt_api_key,
        vt_threshold: options.vt_threshold,
        auto_kill: mode === "suspicious" ? options.auto_kill : false,
        kill_parent: mode === "suspicious" ? options.kill_parent : false,
        kill_threshold: options.kill_threshold
      };

      if (mode === "pid") {
        let pid = Number.parseInt(byId("hunt-pid").value, 10);
        if (Number.isNaN(pid) || pid <= 0) {
          setHuntStatus("PID is required.", "err");
          btn.disabled = false;
          return;
        }
        payload.pid = pid;
      } else if (mode === "name" || mode === "dll_inventory") {
        const name = byId("hunt-name").value.trim();
        if (mode === "name" && !name) {
          setHuntStatus("Process name is required for name mode.", "err");
          btn.disabled = false;
          return;
        }
        if (name) payload.name = name;
      }

      setHuntStatus(`Running process hunt (${mode})...`, "muted");
      try {
        const resp = await fetch("/api/scan-processes", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await resp.json();
        if (!resp.ok || !data.ok) {
          setHuntStatus(`Process hunt failed: ${data.error || ("HTTP " + resp.status)}`, "err");
          return;
        }
        renderProcessReport(mode, data);

        if (mode === "suspicious") {
          const report = data.report || {};
          const suspicious = Number(report.suspicious || 0);
          const scanned = Number(report.scanned_processes || 0);
          const logged = Number(data.logged_events || 0);
          const killed = Array.isArray(report.kill_actions) ? report.kill_actions.length : 0;
          const msg = `Process scan: scanned=${scanned}, suspicious=${suspicious}, logged=${logged}, killed=${killed}`;
          setHuntStatus(msg, suspicious > 0 ? "warn" : "ok");
          await refreshAll();
        } else {
          setHuntStatus(`Process hunt (${mode}) completed.`, "ok");
        }
      } catch (err) {
        setHuntStatus(`Process hunt error: ${err}`, "err");
      } finally {
        btn.disabled = false;
      }
    }

    async function scanRegistryNow() {
      const btn = byId("btn-scan-registry");
      btn.disabled = true;
      setHuntStatus("Scanning registry...", "muted");
      try {
        const resp = await fetch("/api/scan-registry", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ max_findings: 120, log_findings: true })
        });
        const data = await resp.json();
        if (!resp.ok || !data.ok) {
          setHuntStatus(`Registry scan failed: ${data.error || ("HTTP " + resp.status)}`, "err");
          return;
        }
        const report = data.report || {};
        const suspicious = Number(report.suspicious || 0);
        const scanned = Number(report.scanned_values || 0);
        const logged = Number(data.logged_events || 0);
        const msg = `Registry scan: scanned=${scanned}, suspicious=${suspicious}, logged=${logged}`;
        setHuntStatus(msg, suspicious > 0 ? "warn" : "ok");
        await refreshAll();
      } catch (err) {
        setHuntStatus(`Registry scan error: ${err}`, "err");
      } finally {
        btn.disabled = false;
      }
    }

    async function clearHistory() {
      const btn = byId("btn-clear-history");
      const confirmText = "Clear all detection history from dashboard?";
      if (!window.confirm(confirmText)) {
        return;
      }

      btn.disabled = true;
      byId("last-refresh").textContent = "Clearing history...";
      try {
        const resp = await fetch("/api/history/clear", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}"
        });
        const data = await resp.json();
        if (!resp.ok || !data.ok) {
          byId("last-refresh").textContent = `Clear failed: ${data.error || ("HTTP " + resp.status)}`;
          return;
        }
        byId("last-refresh").textContent = "History cleared.";
        await refreshAll();
      } catch (err) {
        byId("last-refresh").textContent = "Clear error: " + err;
      } finally {
        btn.disabled = false;
      }
    }

    async function scanStaticNow() {
      const path = byId("scan-path").value.trim();
      const requestBlock = byId("scan-block").checked;
      const btn = byId("btn-scan-static");

      if (!path) {
        setScanStatus("Path is required.", "err");
        return;
      }

      btn.disabled = true;
      setScanStatus("Running static scan...", "muted");
      try {
        const resp = await fetch("/api/scan-static", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: path, block: requestBlock })
        });
        const data = await resp.json();
        if (!resp.ok || !data.ok) {
          setScanStatus(`Static scan failed: ${data.error || ("HTTP " + resp.status)}`, "err");
          return;
        }

        const sig = data.signature || {};
        const sigStatus = sig.status || "Unknown";
        const trustedMs = sig.trusted_microsoft === true;
        const base = `STATIC ${String(data.verdict || "").toUpperCase()} score=${data.score} severity=${data.severity} | sig=${sigStatus}`;
        if (trustedMs) {
          setScanStatus(`${base} | trusted Microsoft signer`, "ok");
        } else if (data.blocked) {
          const qpath = data.quarantined_path ? ` | quarantined: ${data.quarantined_path}` : "";
          setScanStatus(`${base} | BLOCKED${qpath}`, "err");
        } else if (data.verdict === "malicious") {
          setScanStatus(`${base} | suspicious`, "warn");
        } else {
          setScanStatus(`${base} | no block action`, "ok");
        }

        await refreshAll();
      } catch (err) {
        setScanStatus(`Static scan error: ${err}`, "err");
      } finally {
        btn.disabled = false;
      }
    }

    async function scanPathNow() {
      const path = byId("scan-path").value.trim();
      const requestBlock = byId("scan-block").checked;
      const btn = byId("btn-scan-path");

      if (!path) {
        setScanStatus("Path is required.", "err");
        return;
      }

      btn.disabled = true;
      setScanStatus("Scanning...", "muted");

      try {
        const resp = await fetch("/api/scan-path", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: path, block: requestBlock })
        });

        const data = await resp.json();
        if (!resp.ok || !data.ok) {
          const err = data.error || ("HTTP " + resp.status);
          setScanStatus(`Scan failed: ${err}`, "err");
          return;
        }

        const headline = `${data.verdict.toUpperCase()} score=${data.score} severity=${data.severity}`;
        const malware = (data.malware_types || []).join(", ") || "unknown";
        const confidence = Number(data.malware_confidence || 0);
        const iocCount = Array.isArray(data.iocs) ? data.iocs.length : 0;
        const techniques = Array.isArray(data.techniques) ? data.techniques.map((t) => t?.id).filter(Boolean) : [];
        const intel = ` | malware=${malware}${confidence > 0 ? ` (${Math.round(confidence * 100)}%)` : ""} | iocs=${iocCount}${techniques.length ? ` | techniques=${techniques.join(",")}` : ""}`;
        if (data.blocked) {
          const qpath = data.quarantined_path ? ` | quarantined: ${data.quarantined_path}` : "";
          setScanStatus(`${headline}${intel} | BLOCKED${qpath}`, "err");
        } else if (data.verdict === "malicious") {
          setScanStatus(`${headline}${intel} | suspicious (enable block to quarantine)`, "warn");
        } else {
          setScanStatus(`${headline}${intel} | no block action`, "ok");
        }

        await refreshAll();
      } catch (err) {
        setScanStatus(`Scan error: ${err}`, "err");
      } finally {
        btn.disabled = false;
      }
    }

    async function scanFolderNow() {
      const folder = byId("folder-path").value.trim();
      const recursive = byId("folder-recursive").checked;
      const requestBlock = byId("folder-block").checked;
      const btn = byId("btn-scan-folder");

      if (!folder) {
        setFolderStatus("Folder path is required.", "err");
        return;
      }

      btn.disabled = true;
      setFolderStatus("Scanning folder...", "muted");

      try {
        const resp = await fetch("/api/scan-folder", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            path: folder,
            recursive: recursive,
            block: requestBlock,
            log_nonzero_only: true,
            max_files: 5000
          })
        });
        const data = await resp.json();
        if (!resp.ok || !data.ok) {
          setFolderStatus(`Folder scan failed: ${data.error || ("HTTP " + resp.status)}`, "err");
          return;
        }

        let msg = `Done: scanned=${data.scanned_candidates}, malicious=${data.malicious}, blocked=${data.blocked}, duration=${data.duration_sec}s`;
        const findings = Array.isArray(data.top_findings) ? data.top_findings : [];
        const topTypes = [];
        for (const item of findings.slice(0, 6)) {
          const types = Array.isArray(item.malware_types) ? item.malware_types : [];
          for (const t of types) {
            if (!t || topTypes.includes(t)) continue;
            topTypes.push(t);
            if (topTypes.length >= 3) break;
          }
          if (topTypes.length >= 3) break;
        }
        if (topTypes.length) {
          msg += ` | top_type=${topTypes.join(", ")}`;
        }
        if (data.malicious > 0) {
          setFolderStatus(msg, requestBlock ? "err" : "warn");
        } else {
          setFolderStatus(msg, "ok");
        }
        await refreshAll();
      } catch (err) {
        setFolderStatus(`Folder scan error: ${err}`, "err");
      } finally {
        btn.disabled = false;
      }
    }

    async function pickFolderViaDialog() {
      const current = byId("folder-path").value.trim();
      const btn = byId("btn-folder-browse");
      btn.disabled = true;
      setFolderStatus("Opening folder picker...", "muted");

      try {
        const resp = await fetch("/api/pick-folder", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ initial_path: current })
        });
        const data = await resp.json();
        if (!resp.ok || !data.ok) {
          setFolderStatus(`Folder picker failed: ${data.error || ("HTTP " + resp.status)}`, "err");
          return;
        }
        if (!data.selected || !data.path) {
          setFolderStatus("Folder selection canceled.", "warn");
          return;
        }
        byId("folder-path").value = data.path;
        setFolderStatus(`Selected folder: ${data.path}`, "ok");
      } catch (err) {
        setFolderStatus(`Folder picker error: ${err}`, "err");
      } finally {
        btn.disabled = false;
      }
    }

    async function refreshAll() {
      try {
        const [eventsPayload, summaryPayload, quarantinePayload, monitorPayload] = await Promise.all([
          fetchJson("/api/events?limit=1000"),
          fetchJson("/api/summary"),
          fetchJson("/api/quarantine"),
          fetchJson("/api/monitor/status")
        ]);

        cachedEvents = eventsPayload.events || [];
        renderEvents(applyFilters(cachedEvents));
        renderSummary(summaryPayload);
        renderQuarantine(quarantinePayload.files || []);
        renderMonitorStatus(monitorPayload);
        byId("last-refresh").textContent = "Last refresh: " + new Date().toLocaleTimeString();
      } catch (err) {
        byId("last-refresh").textContent = "Refresh error: " + err;
        setMonitorStatus("Monitor status fetch failed. Check server/API or browser cache.", "err");
      }
    }

    function rerenderFiltered() {
      renderEvents(applyFilters(cachedEvents));
    }

    byId("btn-refresh").addEventListener("click", refreshAll);
    byId("btn-clear-history").addEventListener("click", clearHistory);
    byId("btn-monitor-start").addEventListener("click", startMonitor);
    byId("btn-monitor-stop").addEventListener("click", stopMonitor);
    byId("btn-scan-processes").addEventListener("click", () => scanProcessesNow("suspicious"));
    byId("btn-scan-process-pid").addEventListener("click", () => scanProcessesNow("pid"));
    byId("btn-scan-process-name").addEventListener("click", () => scanProcessesNow("name"));
    byId("btn-dll-inventory").addEventListener("click", () => scanProcessesNow("dll_inventory"));
    byId("btn-scan-registry").addEventListener("click", scanRegistryNow);
    byId("btn-scan-static").addEventListener("click", scanStaticNow);
    byId("btn-scan-path").addEventListener("click", scanPathNow);
    byId("btn-folder-browse").addEventListener("click", pickFolderViaDialog);
    byId("btn-scan-folder").addEventListener("click", scanFolderNow);
    byId("f-search").addEventListener("input", rerenderFiltered);
    byId("f-severity").addEventListener("change", rerenderFiltered);
    byId("f-blocked").addEventListener("change", rerenderFiltered);
    byId("scan-path").addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        scanPathNow();
      }
    });
    byId("folder-path").addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        scanFolderNow();
      }
    });
    byId("hunt-pid").addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        scanProcessesNow("pid");
      }
    });
    byId("hunt-name").addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        scanProcessesNow("name");
      }
    });

    applyColumnWidths({ ...DEFAULT_COLUMN_WIDTHS, ...loadColumnWidths() });
    initResizableColumns();
    refreshAll();
    setInterval(() => {
      if (byId("f-auto").checked) {
        refreshAll();
      }
    }, 2000);
  </script>
</body>
</html>
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Guardian local web dashboard.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind host (default: 127.0.0.1).")
    parser.add_argument("--port", default=DEFAULT_PORT, type=int, help="Bind port (default: 8787).")
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES_FILE,
        help="Path to guardian detection rules (rules.json).",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help="Path to detections JSONL log.",
    )
    parser.add_argument(
        "--detector-stdout-log",
        type=Path,
        default=DEFAULT_DETECTOR_STDOUT,
        help="Path to detector stdout log when started from dashboard.",
    )
    parser.add_argument(
        "--quarantine-dir",
        type=Path,
        default=DEFAULT_QUARANTINE_DIR,
        help="Path to quarantine directory.",
    )
    parser.add_argument(
        "--max-api-events",
        default=2000,
        type=int,
        help="Max recent events returned by API endpoints.",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Automatically open dashboard URL in default browser.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logs.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    rules_path = args.rules.expanduser().resolve()
    if not rules_path.exists():
        logging.error("rules file not found: %s", rules_path)
        return 2

    try:
        scan_rules = ScanRules.from_json(rules_path)
    except Exception as exc:
        logging.error("failed to load rules: %s", exc)
        return 2

    config = DashboardConfig(
        log_file=args.log_file.expanduser().resolve(),
        quarantine_dir=args.quarantine_dir.expanduser().resolve(),
        max_api_events=max(100, min(args.max_api_events, 5000)),
        rules_path=rules_path,
        scan_rules=scan_rules,
        detector_stdout_log=args.detector_stdout_log.expanduser().resolve(),
    )
    handler = build_handler(config)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    url = f"http://{args.host}:{args.port}"

    logging.info("dashboard starting at %s", url)
    logging.info("rules: %s (block threshold=%s)", config.rules_path, config.scan_rules.block_threshold)
    logging.info("log file: %s", config.log_file)
    logging.info("quarantine: %s", config.quarantine_dir)
    logging.info("detector stdout log: %s", config.detector_stdout_log)

    if args.open_browser:
        try:
            webbrowser.open(url)
        except Exception as exc:
            logging.warning("cannot open browser automatically: %s", exc)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_detector()
        server.server_close()
        logging.info("dashboard stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

