# Guardian (MVP)

Guardian is a local Windows host-based detector that watches download/temp folders in realtime, scores suspicious files, and blocks by quarantine when risk is high.

## What it can do

- Realtime watch on directories (`ReadDirectoryChangesW`).
- Detect suspicious `.dll/.exe/.zip/.vbs` based on:
  - IOC strings.
  - PE export heuristics (proxy-style `winmm` exports).
  - Known bad hashes (if you add them in `rules.json`).
- Scan `.zip` archives for embedded suspicious DLLs.
- Block automatically by:
  - Killing process that maps to the exact suspicious executable path.
  - Moving detected file to `quarantine/`.
  - Stopping common LOLBins (`rundll32`, `regsvr32`, `fodhelper`) when a bad DLL is found.
- Log every alert/block event to JSONL.
- Extract IOC set per scan (hash, suspicious strings, exports, signature info when available).
- Classify likely malware type from local IOC/reason evidence (for example `trojan`, `ransomware`, `worm` when signals exist).
- Map matched evidence to ATT&CK techniques for reporting (`T1574.001`, `T1218.011`, `T1547.001`, ...).

## Files

- `guardian.py`: main detector.
- `dashboard.py`: local web UI for detections/quarantine.
- `rules.json`: detection rules and scoring threshold.
- `logs/detections.jsonl`: output event log (created automatically).
- `quarantine/`: blocked files (created automatically).

## Quick start

Run in alert-only mode first:

```powershell
python .\guardian\guardian.py --dry-run --scan-existing --verbose
```

Run in blocking mode:

```powershell
python .\guardian\guardian.py --scan-existing
```

Custom watch paths:

```powershell
python .\guardian\guardian.py --watch "$env:USERPROFILE\Downloads" --watch "$env:TEMP"
```

## Web UI

Run dashboard:

```powershell
python .\guardian\dashboard.py --open-browser
```

Manual URL: `http://127.0.0.1:8787`

From dashboard:

- `Start Monitor`: starts realtime detector (`scan-existing`) directly from UI.
- `Stop Monitor`: stops realtime detector.
- `Clear History`: clears detection history log and empties events list on dashboard.
- `Scan path`: scan one file immediately.
- `Import folder`: click `Browse...` to open Windows folder picker, then scan recursively (including subfolders).
- Optional on both scan modes: enable `block if malicious` to quarantine immediately.
- Scan responses and dashboard events include:
  - extracted IOC list,
  - likely malware type + confidence score.

## Detector evaluation (for grading evidence)

Run quantitative detector evaluation for DLL sideloading:

```powershell
python .\guardian\evaluate_sideload_detector.py
```

Default dataset manifest:

- `guardian/eval_manifest_sideload.json`
- includes malicious PoC sample + benign control samples.

Generated reports:

- `guardian/logs/eval_sideload_report.json`
- `guardian/logs/eval_sideload_report.md`

## Rule tuning

Edit `rules.json`:

- `known_sha256`: add exact sample hashes for immediate block.
- `suspicious_strings`: add/remove IOC strings.
- `critical_string_groups`: each full group matched adds strong score.
- `min_winmm_export_matches`: export pattern sensitivity.
- `block_threshold`: score required to block.

Recommended flow:

1. Run `--dry-run` for a few days.
2. Review `logs/detections.jsonl`.
3. Tune false positives in `rules.json`.
4. Enable blocking mode.

## Notes

- This is an MVP behavior/static detector, not a kernel EDR.
- If malware is fully memory-only, disk-only monitoring has blind spots.
- For production hardening, combine with WDAC/AppLocker and Sysmon correlation.
