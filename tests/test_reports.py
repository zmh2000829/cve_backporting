#!/usr/bin/env python3
"""报告 schema / 历史兼容 / golden fixtures 回归。"""

import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from commands.validate import _prepare_batch_validate_json
from core.output_serializers import aggregate_batch_validate_summary
from services.history_loader import normalize_report
from services.batch_xlsx import build_batch_validate_xlsx_rows, write_batch_validate_xlsx
from services.reporting import prepare_analyze_json, prepare_validate_json
from services.output_support import (
    build_repo_traceability,
    ensure_case_output_dir,
    ensure_mode_output_dir,
    sanitize_path_component,
)


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

    def test_prepare_validate_json_includes_checklist_traceability_and_artifacts(self):
        report = prepare_validate_json({
            "cve_id": "CVE-2024-99999",
            "target_version": "5.10-hulk",
            "known_fix": "deadbeefcafebabe",
            "overall_pass": True,
            "summary": "验证通过",
            "level_decision": {
                "level": "L4",
                "base_level": "L1",
                "review_mode": "manual-approval",
                "rule_hits": [],
            },
            "validation_details": {
                "rule_profile": "default",
                "rule_version": "v2",
                "manual_review_checklist": [
                    "重点核对字段/数据路径",
                    "完成关键路径编译与回归验证",
                ],
            },
            "traceability": {
                "generated_at": "2026-04-03T10:00:00+08:00",
                "target_repo": {
                    "head_commit": "abc123",
                    "head_commit_time": "2026-04-03T09:55:00+08:00",
                },
                "policy": {
                    "profile": "default",
                    "rule_version": "v2",
                    "rule_switches": {"special_risk_rules_enabled": True},
                },
                "data_sources": ["target_repo", "known_fix_local"],
            },
            "artifacts": {
                "run_id": "20260403_100000",
                "output_dir": "/tmp/out/20260403_100000/validate/CVE-2024-99999",
                "report_file": "/tmp/out/20260403_100000/validate/CVE-2024-99999/report.json",
            },
        })

        self.assertEqual(report["manual_review_checklist"][0], "重点核对字段/数据路径")
        self.assertEqual(report["summary"]["manual_review_checklist"][1], "完成关键路径编译与回归验证")
        self.assertEqual(report["traceability"]["policy"]["profile"], "default")
        self.assertEqual(report["traceability"]["schema_version"], "result-schema-v2")
        self.assertEqual(report["artifacts"]["run_id"], "20260403_100000")
        self.assertEqual(
            report["technical_details"]["manual_review_checklist"][0],
            "重点核对字段/数据路径",
        )

    def test_prepare_validate_json_includes_accuracy_recalibration(self):
        report = prepare_validate_json({
            "cve_id": "CVE-2024-88888",
            "target_version": "5.10-hulk",
            "known_fix": "deadbeefcafebabe",
            "overall_pass": True,
            "summary": "验证通过",
            "level_decision": {
                "level": "L1",
                "base_level": "L1",
                "base_method": "verified-direct-exact",
                "review_mode": "llm-review",
                "rule_hits": [],
            },
            "validation_details": {
                "rule_profile": "default",
                "rule_version": "v2",
                "decision_skeleton": {
                    "conclusion": {
                        "direct_backport": {"status": "direct", "summary": "补丁可直接回移"},
                        "prerequisite": {"status": "independent", "summary": "无关联补丁"},
                        "risk": {"status": "low", "summary": "低风险"},
                        "final": {"level": "L1", "base_level": "L1"},
                    }
                },
            },
            "generated_vs_real": {
                "verdict": "identical",
                "core_similarity": 1.0,
                "compare_source": "adapted_patch",
            },
            "accuracy_recalibration": {
                "applied": True,
                "reason": "Validate 准确度校正: generated_vs_real 为 deterministic exact match，按 verified-direct-exact 重新评估级别。",
                "original_level": "L3",
                "adjusted_level": "L1",
            },
        })

        self.assertEqual(report["summary"]["level_recalibration"]["状态"], "已校正")
        self.assertEqual(report["summary"]["level_recalibration"]["原级别"], "L3")
        self.assertEqual(report["technical_details"]["accuracy_recalibration"]["adjusted_level"], "L1")

    def test_prepare_validate_json_keeps_primary_and_solution_set_quality_separate(self):
        report = prepare_validate_json({
            "cve_id": "CVE-2024-77777",
            "target_version": "5.10-hulk",
            "known_fix": "deadbeefcafebabe",
            "overall_pass": True,
            "summary": "验证通过",
            "generated_vs_real": {
                "verdict": "identical",
                "core_similarity": 1.0,
                "compare_source": "adapted_patch",
                "compare_scope": "primary_fix",
            },
            "solution_set_vs_real": {
                "verdict": "different",
                "core_similarity": 0.35,
                "compare_source": "predicted_solution_set",
                "compare_scope": "solution_set",
            },
        })

        self.assertEqual(report["summary"]["patch_quality"]["工具补丁与真实修复关系"], "identical")
        self.assertEqual(report["summary"]["solution_set_quality"]["工具预测解集与实际解集关系"], "different")
        self.assertEqual(report["technical_details"]["solution_set_vs_real"]["compare_scope"], "solution_set")


class OutputSupportRegressionTests(unittest.TestCase):
    class _FakeGitMgr:
        def run_git(self, cmd, target_version, timeout=10):
            if cmd[:3] == ["git", "rev-parse", "HEAD"]:
                return "abc1234567890fedcba\n"
            if cmd[:4] == ["git", "rev-parse", "--abbrev-ref", "HEAD"]:
                return "stable/5.10\n"
            if cmd[:4] == ["git", "log", "-1", "--format=%cI"]:
                return "2026-04-03T09:55:00+08:00\n"
            if cmd[:4] == ["git", "remote", "get-url", "origin"]:
                return "git@example.com:kernel/linux.git\n"
            return ""

    def test_output_layout_helpers_use_run_mode_scope_layout(self):
        root = tempfile.mkdtemp(prefix="out-layout-")
        try:
            case_dir = ensure_case_output_dir(root, "20260403_100000", "validate", "CVE-2024-26633")
            mode_dir = ensure_mode_output_dir(root, "20260403_100000", "batch-validate", "5.10/hulk")
            self.assertTrue(os.path.isdir(case_dir))
            self.assertTrue(os.path.isdir(mode_dir))
            self.assertTrue(case_dir.endswith("/20260403_100000/validate/CVE-2024-26633"))
            self.assertTrue(mode_dir.endswith("/20260403_100000/batch-validate/5.10_hulk"))
            self.assertEqual(sanitize_path_component("  "), "unknown")
        finally:
            shutil.rmtree(root)

    def test_build_repo_traceability_collects_head_snapshot(self):
        config = type("Cfg", (), {
            "repositories": {
                "5.10-hulk": {
                    "path": "/repo/linux",
                    "branch": "stable/5.10",
                }
            }
        })()
        trace = build_repo_traceability(config, self._FakeGitMgr(), "5.10-hulk")
        self.assertEqual(trace["path"], "/repo/linux")
        self.assertEqual(trace["configured_branch"], "stable/5.10")
        self.assertEqual(trace["current_branch"], "stable/5.10")
        self.assertEqual(trace["head_commit_short"], "abc123456789")
        self.assertEqual(trace["head_commit_time"], "2026-04-03T09:55:00+08:00")


class BatchXlsxRegressionTests(unittest.TestCase):
    def _sample_results(self):
        return [
            {
                "cve_id": "CVE-EXACT-UPGRADED",
                "known_fix": "aaa111bbb222ccc333",
                "summary": "补丁完全一致，但规则升级",
                "dryrun_detail": {"apply_method": "strict"},
                "level_decision": {
                    "level": "L3",
                    "base_level": "L0",
                    "rule_hits": [
                        {"rule_id": "prerequisite_required", "severity": "high", "level_floor": "L3"},
                    ],
                },
                "generated_vs_real": {
                    "verdict": "identical",
                    "core_similarity": 1.0,
                    "deterministic_exact_match": True,
                },
                "validation_details": {
                    "strategy_buckets": {"dependency_bucket": "required"},
                    "special_risk_report": {
                        "summary": {
                            "triggered_sections": ["locking_sync"],
                            "has_critical_structure_change": True,
                        }
                    },
                },
                "result_status": {"state": "complete"},
            },
            {
                "cve_id": "CVE-FAILED",
                "known_fix": "ddd444eee555",
                "summary": "核心差异较大",
                "dryrun_detail": {"apply_method": "regenerated"},
                "level_decision": {"level": "L1", "base_level": "L1", "rule_hits": []},
                "generated_vs_real": {
                    "verdict": "different",
                    "core_similarity": 0.25,
                    "deterministic_exact_match": False,
                },
                "result_status": {"state": "complete"},
            },
            {
                "cve_id": "CVE-ACCEPTABLE",
                "known_fix": "fff666",
                "summary": "语义本质相同",
                "dryrun_detail": {"apply_method": "3way"},
                "level_decision": {"level": "L1", "base_level": "L1", "rule_hits": []},
                "generated_vs_real": {
                    "verdict": "essentially_same",
                    "core_similarity": 0.95,
                    "deterministic_exact_match": False,
                },
                "result_status": {"state": "complete"},
            },
        ]

    def test_batch_xlsx_rows_separate_exact_promotion_and_failure(self):
        rows = build_batch_validate_xlsx_rows(self._sample_results())

        exact = rows[0]
        failed = rows[1]
        acceptable = rows[2]

        self.assertEqual(exact["主补丁状态"], "完全一致")
        self.assertEqual(exact["是否完全一致"], "是")
        self.assertEqual(exact["是否升级"], "是")
        self.assertEqual(exact["升级路径"], "L0->L3")
        self.assertIn("prerequisite_required->L3", exact["升级规则"])
        self.assertEqual(failed["是否失败"], "是")
        self.assertEqual(acceptable["主补丁状态"], "本质相同")
        self.assertEqual(acceptable["是否失败"], "否")

    def test_batch_xlsx_writer_creates_expected_workbook_parts(self):
        tmpdir = tempfile.mkdtemp(prefix="batch-xlsx-")
        try:
            path = os.path.join(tmpdir, "batch_validate_summary.xlsx")
            write_batch_validate_xlsx(
                path,
                self._sample_results(),
                "5.10-hulk",
                batch_summary={"promotion_summary": {"promotion_matrix": {"L0->L3": 1}}},
                generated_at="2026-04-21T15:00:00+08:00",
            )
            self.assertTrue(os.path.exists(path))
            with zipfile.ZipFile(path) as zf:
                names = set(zf.namelist())
                self.assertIn("xl/workbook.xml", names)
                self.assertIn("xl/worksheets/sheet1.xml", names)
                self.assertIn("xl/worksheets/sheet5.xml", names)
                workbook = zf.read("xl/workbook.xml").decode("utf-8")
                detail = zf.read("xl/worksheets/sheet2.xml").decode("utf-8")
                summary = zf.read("xl/worksheets/sheet1.xml").decode("utf-8")
            self.assertIn("总览", workbook)
            self.assertIn("全部明细", workbook)
            self.assertIn("完全一致", workbook)
            self.assertIn("有升级", workbook)
            self.assertIn("失败", workbook)
            self.assertIn("CVE-EXACT-UPGRADED", detail)
            self.assertIn("CVE-FAILED", detail)
            self.assertIn("L0-&gt;L3", summary)
        finally:
            shutil.rmtree(tmpdir)


if __name__ == "__main__":
    unittest.main()
