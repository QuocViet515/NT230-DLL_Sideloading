#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


_VT_CACHE_LOCK = threading.Lock()
_VT_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_VT_CACHE_TTL_SEC = 60 * 10


def _empty_result(status: str, message: str = "") -> dict[str, Any]:
    return {
        "ok": status in {"clean", "suspicious", "malicious", "not_found"},
        "status": status,
        "positives": 0,
        "total": 0,
        "sha256": "",
        "message": message,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _read_cache(file_hash: str) -> dict[str, Any] | None:
    now = time.time()
    with _VT_CACHE_LOCK:
        row = _VT_CACHE.get(file_hash.lower())
        if not row:
            return None
        created_at, payload = row
        if (now - created_at) > _VT_CACHE_TTL_SEC:
            _VT_CACHE.pop(file_hash.lower(), None)
            return None
        return dict(payload)


def _write_cache(file_hash: str, payload: dict[str, Any]) -> None:
    with _VT_CACHE_LOCK:
        _VT_CACHE[file_hash.lower()] = (time.time(), dict(payload))


def query_hash(
    file_hash: str,
    *,
    api_key: str,
    malicious_threshold: int = 5,
    timeout_sec: int = 10,
) -> dict[str, Any]:
    file_hash = str(file_hash).strip().lower()
    if not file_hash:
        return _empty_result("invalid_hash", "empty hash")
    api_key = str(api_key or "").strip()
    if not api_key:
        return _empty_result("api_key_missing", "VirusTotal API key missing")

    cached = _read_cache(file_hash)
    if cached:
        cached["cached"] = True
        return cached

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    request = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(request, timeout=max(3, int(timeout_sec))) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            payload = {
                "ok": True,
                "status": "not_found",
                "positives": 0,
                "total": 0,
                "sha256": file_hash,
                "message": "hash not found in VirusTotal",
                "cached": False,
            }
            _write_cache(file_hash, payload)
            return payload
        if exc.code == 401:
            return _empty_result("api_unauthorized", "VirusTotal API key unauthorized")
        if exc.code == 429:
            return _empty_result("api_limit", "VirusTotal API rate limit exceeded")
        return _empty_result("error_http", f"VirusTotal HTTP error {exc.code}")
    except urllib.error.URLError as exc:
        return _empty_result("error_request", f"VirusTotal request failed: {exc}")
    except Exception as exc:
        return _empty_result("error", f"VirusTotal query error: {exc}")

    try:
        payload = json.loads(raw.decode("utf-8", errors="ignore"))
    except Exception:
        return _empty_result("error_parse", "invalid VirusTotal JSON response")

    stats = (
        payload.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    if not isinstance(stats, dict):
        stats = {}
    positives = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = 0
    for value in stats.values():
        try:
            total += int(value)
        except (TypeError, ValueError):
            continue

    if positives >= max(1, int(malicious_threshold)):
        status = "malicious"
    elif positives > 0:
        status = "suspicious"
    else:
        status = "clean"

    result = {
        "ok": True,
        "status": status,
        "positives": positives,
        "total": total,
        "sha256": file_hash,
        "message": "",
        "cached": False,
    }
    _write_cache(file_hash, result)
    return result


def check_file_path(
    file_path: Path,
    *,
    api_key: str,
    malicious_threshold: int = 5,
    timeout_sec: int = 10,
) -> dict[str, Any]:
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return _empty_result("not_found", "file path not found")
    try:
        file_hash = sha256_file(path)
    except Exception as exc:
        return _empty_result("error_hashing", f"cannot hash file: {exc}")

    result = query_hash(
        file_hash,
        api_key=api_key,
        malicious_threshold=malicious_threshold,
        timeout_sec=timeout_sec,
    )
    result["sha256"] = file_hash
    return result
