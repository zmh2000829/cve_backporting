"""历史结果迁移与读取。"""

import json
from pathlib import Path

from core.report_schema import REPORT_SCHEMA_VERSION
from services.reporting import prepare_analyze_json, prepare_validate_json


def detect_report_mode(payload: dict) -> str:
    if not isinstance(payload, dict):
        return ""
    if payload.get("mode") in {"analyze", "validate", "batch-validate"}:
        return payload.get("mode")
    if "overall_pass" in payload or "known_fix" in payload or "checks" in payload:
        return "validate"
    if "is_vulnerable" in payload or "is_fixed" in payload or "dry_run_clean" in payload:
        return "analyze"
    return ""


def normalize_report(payload: dict) -> dict:
    if not isinstance(payload, dict):
        return {}

    if payload.get("schema_version") == REPORT_SCHEMA_VERSION:
        return dict(payload)

    mode = detect_report_mode(payload)
    if mode == "validate":
        return prepare_validate_json(payload)
    if mode == "analyze":
        return prepare_analyze_json(payload)

    return dict(payload)


def load_report(path: str) -> dict:
    report_path = Path(path)
    with report_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return normalize_report(payload)
