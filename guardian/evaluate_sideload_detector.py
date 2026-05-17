#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

from guardian import ScanRules, evaluate_file_detailed
from technique_mapper import infer_techniques


DEFAULT_RULES = Path(__file__).resolve().parent / "rules.json"
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "eval_manifest_sideload.json"
DEFAULT_OUTPUT_JSON = Path(__file__).resolve().parent / "logs" / "eval_sideload_report.json"
DEFAULT_OUTPUT_MD = Path(__file__).resolve().parent / "logs" / "eval_sideload_report.md"


def _resolve_path(raw: str, base_dir: Path) -> Path:
    expanded = os.path.expandvars(str(raw))
    p = Path(expanded)
    if not p.is_absolute():
        p = (base_dir / p).resolve()
    else:
        p = p.resolve()
    return p


def _safe_div(a: float, b: float) -> float:
    if b == 0:
        return 0.0
    return a / b


def _load_manifest(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        samples = payload.get("samples", [])
        if isinstance(samples, list):
            return [row for row in samples if isinstance(row, dict)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def _as_list_of_str(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        s = str(item).strip()
        if s:
            out.append(s)
    return out


def evaluate_manifest(
    rules: ScanRules,
    manifest_path: Path,
    threshold: int | None = None,
) -> dict:
    rows = _load_manifest(manifest_path)
    base_dir = manifest_path.parent
    block_threshold = rules.block_threshold if threshold is None else max(1, int(threshold))

    tp = fp = tn = fn = 0
    skipped = 0
    technique_expect_total = 0
    technique_expect_hit = 0
    sample_results: list[dict] = []

    for idx, row in enumerate(rows, start=1):
        raw_path = str(row.get("path", "")).strip()
        label = str(row.get("label", "")).strip().lower()
        required = bool(row.get("required", False))
        sample_id = str(row.get("id", f"sample-{idx}")).strip() or f"sample-{idx}"
        notes = str(row.get("notes", "")).strip()
        expected_techniques = _as_list_of_str(row.get("expected_techniques", []))
        if label not in {"malicious", "benign"}:
            skipped += 1
            sample_results.append(
                {
                    "id": sample_id,
                    "status": "skipped",
                    "reason": f"invalid label '{label}'",
                    "path": raw_path,
                }
            )
            continue

        if not raw_path:
            skipped += 1
            sample_results.append(
                {
                    "id": sample_id,
                    "status": "skipped",
                    "reason": "missing path",
                    "path": raw_path,
                }
            )
            continue

        path = _resolve_path(raw_path, base_dir)
        if not path.exists() or not path.is_file():
            if required:
                sample_results.append(
                    {
                        "id": sample_id,
                        "status": "error",
                        "reason": "required sample missing",
                        "path": str(path),
                    }
                )
            else:
                skipped += 1
                sample_results.append(
                    {
                        "id": sample_id,
                        "status": "skipped",
                        "reason": "sample missing",
                        "path": str(path),
                    }
                )
            continue

        result = evaluate_file_detailed(path, rules)
        is_malicious_pred = int(result.score) >= block_threshold
        is_malicious_exp = label == "malicious"

        if is_malicious_pred and is_malicious_exp:
            tp += 1
        elif is_malicious_pred and not is_malicious_exp:
            fp += 1
        elif (not is_malicious_pred) and (not is_malicious_exp):
            tn += 1
        else:
            fn += 1

        techniques = infer_techniques(
            path=path,
            reasons=result.reasons,
            iocs=result.iocs,
            score=result.score,
        )
        detected_ids = {str(item.get("id", "")).strip() for item in techniques if isinstance(item, dict)}
        expected_ids = {item.strip() for item in expected_techniques if item.strip()}
        technique_hit = True
        if expected_ids:
            technique_expect_total += 1
            technique_hit = expected_ids.issubset(detected_ids)
            if technique_hit:
                technique_expect_hit += 1

        sample_results.append(
            {
                "id": sample_id,
                "status": "ok",
                "path": str(path),
                "notes": notes,
                "label": label,
                "expected_malicious": is_malicious_exp,
                "pred_malicious": is_malicious_pred,
                "score": int(result.score),
                "sha256": result.sha256,
                "reasons": result.reasons[:6],
                "techniques": techniques,
                "expected_techniques": sorted(expected_ids),
                "technique_match": technique_hit,
            }
        )

    evaluated = tp + fp + tn + fn
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall) if precision and recall else 0.0
    accuracy = _safe_div(tp + tn, evaluated)
    technique_recall = _safe_div(technique_expect_hit, technique_expect_total)

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "manifest_path": str(manifest_path),
        "block_threshold": block_threshold,
        "counts": {
            "evaluated": evaluated,
            "skipped": skipped,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        },
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "technique_recall": round(technique_recall, 4),
        },
        "technique_checks": {
            "expected": technique_expect_total,
            "matched": technique_expect_hit,
        },
        "samples": sample_results,
    }


def render_markdown(report: dict) -> str:
    counts = report.get("counts", {})
    metrics = report.get("metrics", {})
    lines: list[str] = []
    lines.append("# Sideload Detector Evaluation")
    lines.append("")
    lines.append(f"- Generated: `{report.get('generated_at', '-')}`")
    lines.append(f"- Manifest: `{report.get('manifest_path', '-')}`")
    lines.append(f"- Threshold: `{report.get('block_threshold', '-')}`")
    lines.append("")
    lines.append("## Metrics")
    lines.append("")
    lines.append(f"- Evaluated: `{counts.get('evaluated', 0)}`")
    lines.append(f"- Skipped: `{counts.get('skipped', 0)}`")
    lines.append(f"- TP/FP/TN/FN: `{counts.get('tp', 0)}/{counts.get('fp', 0)}/{counts.get('tn', 0)}/{counts.get('fn', 0)}`")
    lines.append(f"- Precision: `{metrics.get('precision', 0.0)}`")
    lines.append(f"- Recall: `{metrics.get('recall', 0.0)}`")
    lines.append(f"- F1: `{metrics.get('f1', 0.0)}`")
    lines.append(f"- Accuracy: `{metrics.get('accuracy', 0.0)}`")
    lines.append(f"- Technique recall: `{metrics.get('technique_recall', 0.0)}`")
    lines.append("")
    lines.append("## Samples")
    lines.append("")
    for sample in report.get("samples", []):
        if not isinstance(sample, dict):
            continue
        sid = sample.get("id", "sample")
        status = sample.get("status", "unknown")
        path = sample.get("path", "-")
        lines.append(f"- `{sid}` | status=`{status}` | path=`{path}`")
        if status != "ok":
            reason = sample.get("reason", "")
            if reason:
                lines.append(f"  - reason: `{reason}`")
            continue
        lines.append(
            "  - "
            + f"label=`{sample.get('label')}`, "
            + f"pred_malicious=`{sample.get('pred_malicious')}`, "
            + f"score=`{sample.get('score')}`, "
            + f"technique_match=`{sample.get('technique_match')}`"
        )
        techniques = sample.get("techniques", [])
        if isinstance(techniques, list) and techniques:
            ids = []
            for t in techniques:
                if isinstance(t, dict):
                    tid = str(t.get("id", "")).strip()
                    if tid:
                        ids.append(tid)
            if ids:
                lines.append(f"  - techniques: `{', '.join(ids)}`")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate DLL sideloading detector quality.")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="Path to rules.json")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="Path to evaluation manifest JSON.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Override malicious threshold score (default: rules block_threshold).",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=DEFAULT_OUTPUT_JSON,
        help="Output JSON report path.",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=DEFAULT_OUTPUT_MD,
        help="Output markdown report path.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rules_path = args.rules.expanduser().resolve()
    manifest_path = args.manifest.expanduser().resolve()
    output_json = args.output_json.expanduser().resolve()
    output_md = args.output_md.expanduser().resolve()

    if not rules_path.exists():
        print(f"rules not found: {rules_path}")
        return 2
    if not manifest_path.exists():
        print(f"manifest not found: {manifest_path}")
        return 2

    rules = ScanRules.from_json(rules_path)
    report = evaluate_manifest(rules=rules, manifest_path=manifest_path, threshold=args.threshold)

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    output_md.write_text(render_markdown(report), encoding="utf-8")

    metrics = report.get("metrics", {})
    counts = report.get("counts", {})
    print(f"evaluated={counts.get('evaluated', 0)} skipped={counts.get('skipped', 0)}")
    print(
        "precision={precision} recall={recall} f1={f1} accuracy={accuracy} technique_recall={technique_recall}".format(
            precision=metrics.get("precision", 0.0),
            recall=metrics.get("recall", 0.0),
            f1=metrics.get("f1", 0.0),
            accuracy=metrics.get("accuracy", 0.0),
            technique_recall=metrics.get("technique_recall", 0.0),
        )
    )
    print(f"json_report={output_json}")
    print(f"md_report={output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

