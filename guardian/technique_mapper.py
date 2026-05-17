#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


TECHNIQUE_DEFS = [
    {
        "id": "T1574.001",
        "name": "Hijack Execution Flow: DLL Side-Loading",
        "keywords": [
            "winmm proxy export pattern",
            "partial winmm proxy export pattern",
            "proxydllregisterserver",
            "dllregisterserver",
            "runmalware",
            "sideload",
            "notepad++.exe",
            "npp.exe",
            "winmm.dll",
        ],
        "ioc_contains": [
            ("behavior", "winmm_proxy_exports="),
            ("export", "dllregisterserver"),
            ("export", "runmalware"),
            ("string", "runmalware"),
            ("host_process", "notepad++.exe"),
            ("host_process", "npp.exe"),
            ("loaded_module_name", "winmm.dll"),
            ("module_path_class", "user_writable"),
            ("process_chain", "notepad++.exe -> winmm.dll"),
        ],
    },
    {
        "id": "T1218.011",
        "name": "System Binary Proxy Execution: Rundll32",
        "keywords": ["rundll32.exe", "runmalware", "dllregisterserver"],
        "ioc_contains": [
            ("string", "rundll32.exe"),
            ("process_name", "rundll32.exe"),
            ("execution_command", "rundll32.exe"),
            ("process_cmdline", "rundll32.exe"),
        ],
    },
    {
        "id": "T1547.001",
        "name": "Registry Run Keys / Startup Folder",
        "keywords": [
            "startup",
            "csidl_startup",
            "systemupdate.vbs",
            "syscheck.vbs",
            "setresilientpersistence",
        ],
        "ioc_contains": [
            ("string", "startup"),
            ("string", "csidl_startup"),
            ("string", "systemupdate.vbs"),
            ("string", "syscheck.vbs"),
        ],
    },
    {
        "id": "T1140",
        "name": "Deobfuscate/Decode Files or Information",
        "keywords": ["cryptdecrypt", "cryptimportkey", "cryptsetkeyparam"],
        "ioc_contains": [
            ("string", "cryptdecrypt"),
            ("string", "cryptimportkey"),
            ("string", "cryptsetkeyparam"),
        ],
    },
    {
        "id": "T1027.013",
        "name": "Obfuscated Files/Information: Encrypted/Encoded File",
        "keywords": ["ciphertext", "kp_iv", "encrypted payload", "daylakey"],
        "ioc_contains": [
            ("string", "ciphertext"),
            ("string", "kp_iv"),
            ("string", "daylakey"),
        ],
    },
    {
        "id": "T1620",
        "name": "Reflective Code Loading",
        "keywords": ["ntprotectvirtualmemory", "virtualprotect", "in memory", "shellcode"],
        "ioc_contains": [
            ("string", "ntprotectvirtualmemory"),
            ("string", "virtualprotect"),
        ],
    },
]


def infer_techniques(
    path: Path,
    reasons: list[str] | None,
    iocs: list[dict[str, str]] | None,
    score: int,
) -> list[dict[str, object]]:
    if int(score) <= 0:
        return []

    reasons = reasons or []
    iocs = iocs or []
    reason_blob = " | ".join(str(r).strip().lower() for r in reasons if str(r).strip())
    normalized_iocs: list[tuple[str, str]] = []
    for row in iocs:
        if not isinstance(row, dict):
            continue
        ioc_type = str(row.get("type", "")).strip().lower()
        value = str(row.get("value", "")).strip().lower()
        if not ioc_type or not value:
            continue
        normalized_iocs.append((ioc_type, value))

    path_name = path.name.lower()
    results: list[dict[str, object]] = []
    for rule in TECHNIQUE_DEFS:
        rule_score = 0
        evidence: list[str] = []

        for token in rule.get("keywords", []):
            needle = str(token).strip().lower()
            if needle and needle in reason_blob:
                rule_score += 1
                evidence.append(f"reason:{needle}")

        for ioc_type, contains in rule.get("ioc_contains", []):
            t = str(ioc_type).strip().lower()
            needle = str(contains).strip().lower()
            if not t or not needle:
                continue
            if any((ioc_t == t and needle in ioc_v) for ioc_t, ioc_v in normalized_iocs):
                rule_score += 2
                evidence.append(f"ioc:{t}:{needle}")

        # Extra bias for classic side-loading filename pattern.
        if rule["id"] == "T1574.001" and path_name == "winmm.dll":
            rule_score += 2
            evidence.append("path:winmm.dll")

        if rule_score < 2:
            continue

        confidence = min(1.0, round(rule_score / 8.0, 3))
        results.append(
            {
                "id": rule["id"],
                "name": rule["name"],
                "confidence": confidence,
                "evidence": evidence[:6],
                "score": rule_score,
            }
        )

    results.sort(key=lambda row: float(row.get("score", 0.0)), reverse=True)
    for row in results:
        row.pop("score", None)
    return results[:6]
