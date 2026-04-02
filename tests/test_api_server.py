#!/usr/bin/env python3
"""API server 结构化错误与结果状态回归。"""

import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api_server


class APIServerErrorShapeTests(unittest.TestCase):
    def test_error_body_uses_unified_error_shape(self):
        body = api_server._error_body(
            "invalid_request",
            "missing cve_id",
            technical_detail="missing cve_id",
            retryable=False,
            status_code=400,
        )
        self.assertFalse(body["ok"])
        self.assertEqual(body["status_code"], 400)
        self.assertEqual(body["error"]["state"], "error")
        self.assertEqual(body["error"]["error_code"], "invalid_request")
        self.assertEqual(body["error"]["user_message"], "missing cve_id")
        self.assertFalse(body["error"]["retryable"])

    def test_validate_handler_keeps_result_status(self):
        config = SimpleNamespace(policy=SimpleNamespace(special_risk_rules_enabled=True))
        original = api_server.cli._run_single_validate
        try:
            def fake_run_single_validate(cfg, cve_id, target, known_fix, known_prereqs, **kwargs):
                return {
                    "cve_id": cve_id,
                    "target_version": target,
                    "known_fix": known_fix,
                    "overall_pass": False,
                    "summary": "CVE上游数据不完整(MITRE无fix commit), 无法验证",
                    "result_status": {
                        "state": "incomplete",
                        "error_code": "missing_upstream_fix",
                        "user_message": "上游 CVE 情报缺少稳定的 fix commit，当前无法完成验证。",
                        "technical_detail": "result.cve_info 为 None 或 fix_commit_id 为空。",
                        "retryable": True,
                        "incomplete_reason": "missing_fix_commit",
                        "evidence_refs": [cve_id],
                    },
                    "validation_details": {
                        "strategy_buckets": {"dependency_bucket": "independent"},
                        "special_risk_report": {"summary": {"triggered_sections": [], "has_critical_structure_change": False}},
                    },
                }

            api_server.cli._run_single_validate = fake_run_single_validate
            result = api_server._default_validate_handler({
                "target_version": "5.10-hulk",
                "cve_id": "CVE-TEST-2",
                "known_fix": "deadbeef",
            }, config)
        finally:
            api_server.cli._run_single_validate = original

        self.assertEqual(result["result_status"]["state"], "incomplete")
        self.assertEqual(result["result_status"]["incomplete_reason"], "missing_fix_commit")


if __name__ == "__main__":
    unittest.main()
