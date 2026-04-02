#!/usr/bin/env python3
"""报告 schema / 历史兼容 / golden fixtures 回归。"""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from commands.validate import _prepare_batch_validate_json
from core.output_serializers import aggregate_batch_validate_summary
from services.history_loader import normalize_report
from services.reporting import prepare_analyze_json, prepare_validate_json


FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def _load_json(*parts):
    with (FIXTURE_ROOT.joinpath(*parts)).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _assert_subset(testcase: unittest.TestCase, actual, expected, path="root"):
    if isinstance(expected, dict):
        testcase.assertIsInstance(actual, dict, path)
        for key, value in expected.items():
            testcase.assertIn(key, actual, f"{path}.{key} missing")
            _assert_subset(testcase, actual[key], value, f"{path}.{key}")
        return
    if isinstance(expected, list):
        testcase.assertIsInstance(actual, list, path)
        testcase.assertGreaterEqual(len(actual), len(expected), path)
        for index, value in enumerate(expected):
            _assert_subset(testcase, actual[index], value, f"{path}[{index}]")
        return
    testcase.assertEqual(actual, expected, path)


class ReportSchemaRegressionTests(unittest.TestCase):
    def test_prepare_analyze_json_matches_fixed_case_golden(self):
        raw = _load_json("golden", "analyze_fixed_public.input.json")
        expected = _load_json("golden", "analyze_fixed_public.expected.json")
        actual = prepare_analyze_json(raw)
        _assert_subset(self, actual, expected)

    def test_prepare_validate_json_matches_l4_case_golden(self):
        raw = _load_json("golden", "validate_l4_public.input.json")
        expected = _load_json("golden", "validate_l4_public.expected.json")
        actual = prepare_validate_json(raw)
        _assert_subset(self, actual, expected)

    def test_history_loader_normalizes_legacy_reports(self):
        analyze_legacy = _load_json("history", "analyze_fixed_legacy.json")
        validate_legacy = _load_json("history", "validate_legacy.json")

        analyze_report = normalize_report(analyze_legacy)
        validate_report = normalize_report(validate_legacy)

        self.assertEqual(analyze_report["schema_version"], "result-schema-v2")
        self.assertEqual(analyze_report["summary"]["status"]["state"], "not_applicable")
        self.assertEqual(validate_report["schema_version"], "result-schema-v2")
        self.assertEqual(validate_report["summary"]["status"]["state"], "complete")
        self.assertEqual(
            validate_report["technical_details"]["result_status"]["error_code"],
            "validation_mismatch",
        )

    def test_batch_report_tracks_incomplete_reasons(self):
        complete = prepare_validate_json(_load_json("golden", "validate_l4_public.input.json"))
        incomplete = prepare_validate_json({
            "cve_id": "CVE-2023-46838",
            "target_version": "5.10-hulk",
            "known_fix": "deadbeef",
            "overall_pass": False,
            "summary": "CVE上游数据不完整(MITRE无fix commit), 无法验证",
            "result_status": {
                "state": "incomplete",
                "error_code": "missing_upstream_fix",
                "user_message": "上游 CVE 情报缺少稳定的 fix commit，当前无法完成验证。",
                "technical_detail": "result.cve_info 为 None 或 fix_commit_id 为空。",
                "retryable": True,
                "incomplete_reason": "missing_fix_commit",
                "evidence_refs": ["CVE-2023-46838"],
            },
        })

        batch_summary = aggregate_batch_validate_summary([complete, incomplete])
        report = _prepare_batch_validate_json(
            "5.10-hulk",
            workers=2,
            total_cves=2,
            total_patches=2,
            skipped=0,
            p2_enabled=True,
            batch_summary=batch_summary,
            strategy_summary={},
            passed_list=[],
            failed_list=[],
            error_list=[],
            cve_results=[complete, incomplete],
        )
        expected = _load_json("golden", "batch_public.expected.json")
        _assert_subset(self, report, expected)


if __name__ == "__main__":
    unittest.main()
