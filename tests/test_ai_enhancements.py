#!/usr/bin/env python3
"""AI advisory and patch generation regression tests."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ai_assistant import AIAssistant
from core.ai_patch_generator import AIPatchGenerator
from core.config import ConfigLoader
from core.llm_client import LLMClient
from core.models import DryRunResult, PatchInfo
from core.policy_engine import PolicyEngine
from core.config import AIConfig, PolicyConfig


class _FakeLLM:
    enabled = True
    provider = "glm"
    model = "GLM-5"
    _max_tokens = 4000

    def __init__(self):
        self.prompts = []

    def chat_json(self, prompt, **kwargs):
        self.prompts.append(prompt)
        if "dependency_triage" in prompt:
            return {
                "decision": "background",
                "confidence": 0.77,
                "summary": "候选缺少直接语义依赖，建议作为背景线索。",
                "evidence_lines": ["score only weak"],
            }
        if "risk_semantic_explainer" in prompt:
            return {
                "decision": "attention",
                "confidence": 0.68,
                "summary": "风险需要人工核对，但不能单独证明必须升档。",
                "evidence_lines": ["ctx->state"],
            }
        return {
            "decision": "likely_low_signal",
            "confidence": 0.81,
            "summary": "普通条件变化，暂未看到锁或生命周期语义。",
            "evidence_lines": ["if (ctx->active)"],
        }

    def chat(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return """```diff
diff --git a/foo.c b/foo.c
--- a/foo.c
+++ b/foo.c
@@ -1,1 +1,1 @@
-old();
+new();
```"""


class _JsonFallbackLLM(LLMClient):
    def __init__(self):
        super().__init__()
        self.enabled = True
        self._provider = "glm"
        self._model = "GLM-5"
        self._base_url = "http://glm5.local:8888/v1"
        self._api_key = "test"
        self.calls = []

    def _call(self, messages, *, temperature, max_tokens, response_format=None):
        self.calls.append(response_format)
        if response_format:
            raise RuntimeError("response_format unsupported")
        return "```json\n{'decision':'uncertain','confidence':0.4,'summary':'ok','evidence_lines':[],}\n```"


class AIEnhancementTests(unittest.TestCase):
    def test_glm_api_key_can_come_from_provider_specific_env(self):
        old = os.environ.get("GLM_API_KEY")
        os.environ["GLM_API_KEY"] = "test-glm-key"
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml", delete=False) as handle:
                handle.write(
                    "llm:\n"
                    "  enabled: true\n"
                    "  provider: glm\n"
                    "  api_key: ${GLM_API_KEY}\n"
                    "  base_url: http://glm5.local:8888/v1\n"
                    "  model: GLM-5\n"
                    "ai:\n"
                    "  mode: advisory\n"
                    "  enable_low_signal_adjudication: true\n"
                )
                path = handle.name
            try:
                cfg = ConfigLoader.load(path)
                client = LLMClient(cfg.llm)
            finally:
                os.unlink(path)
        finally:
            if old is None:
                os.environ.pop("GLM_API_KEY", None)
            else:
                os.environ["GLM_API_KEY"] = old

        self.assertTrue(client.enabled)
        self.assertEqual(client.provider, "glm")
        self.assertEqual(client.model, "GLM-5")

    def test_chat_json_tolerates_common_model_wrappers(self):
        client = LLMClient()

        parsed = client._parse_json_object(
            "下面是结果：\n```json\n{\"decision\":\"likely_low_signal\",\"confidence\":0.8,\"summary\":\"ok\",\"evidence_lines\":[]}\n```\n请参考。"
        )
        self.assertEqual(parsed["decision"], "likely_low_signal")

        parsed = client._parse_json_object(
            "{'decision':'uncertain','confidence':0.2,'summary':'ok','evidence_lines':[],}"
        )
        self.assertEqual(parsed["decision"], "uncertain")

        parsed = client._parse_json_object(
            '{"decision":"attention","confidence":0.7,"summary":"ok","raw":{"nested":true}}'
        )
        self.assertEqual(parsed["decision"], "attention")

    def test_chat_json_retries_without_response_format_when_provider_rejects_it(self):
        client = _JsonFallbackLLM()
        parsed = client.chat_json("return json", system="json only")

        self.assertEqual(parsed["decision"], "uncertain")
        self.assertEqual(client.calls[0], {"type": "json_object"})
        self.assertIsNone(client.calls[1])

    def test_ai_assistant_outputs_advisory_evidence_without_changing_policy(self):
        diff = """diff --git a/foo.c b/foo.c
--- a/foo.c
+++ b/foo.c
@@ -1,2 +1,2 @@
-if (ctx->ready)
+if (ctx->active)
"""
        patch = PatchInfo(commit_id="deadbeef", subject="condition tweak", diff_code=diff, modified_files=["foo.c"])
        details = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False).evaluate(
            patch,
            DryRunResult(applies_cleanly=True, apply_method="strict"),
            git_mgr=object(),
            target_version="5.10",
        )
        assistant = AIAssistant(
            _FakeLLM(),
            AIConfig(
                mode="advisory",
                enable_low_signal_adjudication=True,
                enable_risk_explainer=True,
            ),
        )

        evidence = assistant.enhance_accuracy(
            patch=patch,
            validation_details=details,
            prerequisite_patches=[],
            dependency_details=None,
        )

        self.assertTrue(evidence["enabled"])
        self.assertEqual(evidence["mode"], "advisory")
        self.assertTrue(evidence["tasks"])
        self.assertFalse(any(t.get("used_for_final_decision") for t in evidence["tasks"]))
        self.assertTrue(evidence["summary"])

    def test_ai_patch_generator_uses_unified_llm_client_and_reports_delta(self):
        generator = AIPatchGenerator(_FakeLLM())
        report = generator.generate_patch_with_report(
            "diff --git a/foo.c b/foo.c\n--- a/foo.c\n+++ b/foo.c\n@@ -1,1 +1,1 @@\n-old();\n+new();\n",
            "old();\n",
            {"hunks": [{"severity": "L4", "reason": "conflict"}]},
            "foo.c",
        )

        self.assertEqual(report["status"], "success")
        self.assertIn("diff --git", report["patch"])
        self.assertGreaterEqual(report["semantic_delta"]["preserved_added_count"], 1)

    def test_ai_generated_apply_method_stays_high_risk(self):
        diff = """diff --git a/foo.c b/foo.c
--- a/foo.c
+++ b/foo.c
@@ -1,1 +1,1 @@
-old();
+new();
"""
        fake_git = type(
            "FakeGit",
            (),
            {"run_git": lambda self, cmd, target_version, timeout=15: "int f(void) { return 0; }\n"},
        )()
        details = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=True).evaluate(
            PatchInfo(commit_id="deadbeef", subject="ai candidate", diff_code=diff, modified_files=["foo.c"]),
            DryRunResult(applies_cleanly=True, apply_method="ai-generated"),
            git_mgr=fake_git,
            target_version="5.10",
        )

        self.assertEqual(details.level_decision.base_method, "ai-generated")
        self.assertEqual(details.level_decision.base_level, "L5")
        self.assertTrue(any("AI" in item for item in details.manual_review_checklist))


if __name__ == "__main__":
    unittest.main()
