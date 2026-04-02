#!/usr/bin/env python3
"""策略引擎回归：基线 DryRun + rules/ 抬升、关键结构、调用链牵连、L1 API 启发式、profile 预设。"""

import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api_server
import cli
from core.config import PolicyConfig, POLICY_PROFILE_PRESETS
from core.models import DependencyAnalysisDetails, DryRunResult, PatchInfo, PrerequisitePatch
from core.output_serializers import aggregate_batch_validate_summary
from core.policy_engine import PolicyEngine


class _MockGit:
    """按 HEAD:path 返回固定 C 源码，用于调用图。"""

    def __init__(self, files: dict):
        self.files = files

    def run_git(self, cmd, target_version, timeout=15):
        if len(cmd) >= 3 and cmd[0] == "git" and cmd[1] == "show":
            spec = cmd[2]
            if spec.startswith("HEAD:"):
                path = spec[5:]
                return self.files.get(path)
        return None


def _patch(diff: str, files=None, subject="t") -> PatchInfo:
    paths = files or []
    return PatchInfo(
        commit_id="deadbeef",
        subject=subject,
        diff_code=diff,
        modified_files=paths,
    )


class PolicyEngineRegressionTests(unittest.TestCase):
    def test_l0_strict_harmless_when_no_rules(self):
        diff = """diff --git a/x.c b/x.c
@@ -1,2 +1,2 @@
- int a = 1;
+ int a = 2;
"""
        p = _patch(diff, ["x.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        eng = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False)
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        self.assertIsNotNone(vd.level_decision)
        self.assertEqual(vd.level_decision.level, "L0")
        self.assertEqual(vd.level_decision.base_level, "L0")
        self.assertTrue(vd.level_decision.harmless)
        self.assertIn("L0", vd.level_decision.strategy)
        self.assertTrue(any(h.get("rule_id") == "direct_backport_candidate" for h in vd.level_decision.rule_hits))
        self.assertEqual(vd.strategy_buckets.get("dependency_bucket"), "independent")
        self.assertEqual(vd.decision_skeleton["conclusion"]["direct_backport"]["status"], "direct")
        self.assertIn("admission_rules", vd.decision_skeleton["evidence"])

    def test_strict_critical_structure_promotes_out_of_l0(self):
        diff = """diff --git a/lock.c b/lock.c
@@ -1,2 +1,2 @@
 void f(void) {
-    mutex_lock(&a);
+    mutex_lock(&b);
}
"""
        p = _patch(diff, ["lock.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        eng = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False)
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        self.assertEqual(vd.level_decision.base_level, "L0")
        self.assertEqual(vd.level_decision.level, "L3")
        self.assertFalse(vd.level_decision.harmless)
        self.assertTrue(any("mutex" in m.lower() or "关键" in m for m in vd.warnings))
        self.assertIn("b", vd.decision_skeleton["evidence"]["lock_objects"])
        self.assertEqual(vd.decision_skeleton["conclusion"]["risk"]["status"], "high")

    def test_plain_struct_pointer_change_does_not_trigger_critical_structure_rule(self):
        diff = """diff --git a/foo.c b/foo.c
@@ -1,2 +1,2 @@
-struct foo *ctx = old;
+struct foo *ctx = new;
"""
        p = _patch(diff, ["foo.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        eng = PolicyEngine(
            PolicyConfig(profile="default", high_impact_single_line_rules_enabled=False),
            llm_enabled=False,
        )
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        rule_ids = {hit["rule_id"] for hit in vd.level_decision.rule_hits}
        self.assertEqual(vd.level_decision.level, "L0")
        self.assertNotIn("critical_structures", rule_ids)
        self.assertNotIn("single_line_high_impact", rule_ids)
        self.assertFalse(vd.special_risk_report["summary"]["has_critical_structure_change"])

    def test_large_change_warning(self):
        body = "\n".join(f"- old{i}\n+ new{i}" for i in range(50))
        diff = f"diff --git a/big.c b/big.c\n@@\n{body}\n"
        p = _patch(diff, ["big.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        eng = PolicyEngine(
            PolicyConfig(profile="default", large_change_line_threshold=30),
            llm_enabled=False,
        )
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        self.assertEqual(vd.level_decision.level, "L2")
        self.assertFalse(vd.level_decision.harmless)
        self.assertTrue(any("改动较大" in w for w in vd.warnings))

    def test_call_chain_fanout_cross_file(self):
        a_c = """int helper(void) {
    return 1;
}
int foo(void) {
    helper();
    return 0;
}
"""
        b_c = """void bar(void) {
    foo();
}
void baz(void) {
    foo();
}
"""
        diff = """diff --git a/a.c b/a.c
@@ -1,5 +1,5 @@ void foo(void) {
 int foo(void) {
-    return 0;
+    return 1;
 }
"""
        p = _patch(diff, ["a.c", "b.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="context-C1")
        git = _MockGit({"a.c": a_c, "b.c": b_c})
        eng = PolicyEngine(
            PolicyConfig(profile="default", call_chain_fanout_threshold=2),
            llm_enabled=False,
        )
        vd = eng.evaluate(p, dr, git, "5.10")
        self.assertEqual(vd.level_decision.base_level, "L1")
        self.assertEqual(vd.level_decision.level, "L2")
        impacts = {fi.function: fi for fi in vd.function_impacts}
        self.assertIn("foo", impacts)
        self.assertGreaterEqual(len(impacts["foo"].callers) + len(impacts["foo"].callees), 2)
        self.assertTrue(any("扩散" in w or "调用链" in w for w in vd.warnings))

    def test_member_access_pseudo_call_does_not_create_call_chain_edge(self):
        a_c = """int changed(struct ops *ops, void *ctx) {
    ops->helper(ctx);
    return 0;
}
"""
        b_c = """int helper(void) {
    return 0;
}
"""
        diff = """diff --git a/a.c b/a.c
@@ -1,3 +1,3 @@ int changed(struct ops *ops, void *ctx) {
-    return 0;
+    return 1;
 }
"""
        p = _patch(diff, ["a.c", "b.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        git = _MockGit({"a.c": a_c, "b.c": b_c})
        eng = PolicyEngine(
            PolicyConfig(profile="default", high_impact_single_line_rules_enabled=False),
            llm_enabled=False,
        )
        vd = eng.evaluate(p, dr, git, "5.10")
        rule_ids = {hit["rule_id"] for hit in vd.level_decision.rule_hits}
        self.assertEqual(vd.level_decision.level, "L0")
        self.assertNotIn("call_chain_propagation", rule_ids)
        self.assertNotIn("call_chain_fanout", rule_ids)
        impacts = {fi.function: fi for fi in vd.function_impacts}
        self.assertIn("changed", impacts)
        self.assertEqual(impacts["changed"].callers, [])
        self.assertEqual(impacts["changed"].callees, [])

    def test_l1_api_surface_signature_hint(self):
        diff = """diff --git a/f.c b/f.c
@@ -1,2 +1,2 @@
-int frob(int x) {
+int frob(int x, int y) {
     return x;
 }
"""
        p = _patch(diff, ["f.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="context-C1")
        eng = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False)
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        self.assertEqual(vd.level_decision.level, "L2")
        self.assertEqual(vd.level_decision.review_mode, "targeted-review")
        self.assertTrue(any("签名" in w or "入参" in w or "调用点" in w for w in vd.warnings))

    def test_l1_api_surface_disabled(self):
        diff = """diff --git a/f.c b/f.c
@@ -1,2 +1,2 @@
-int frob(int x) {
+int frob(int x, int y) {
     return x;
 }
"""
        p = _patch(diff, ["f.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="context-C1")
        eng = PolicyEngine(
            PolicyConfig(profile="default", l1_api_surface_rules_enabled=False),
            llm_enabled=False,
        )
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        self.assertFalse(any(h.get("rule_id") == "l1_api_surface" for h in (vd.level_decision.rule_hits or [])))

    def test_critical_call_chain_propagation_promotes_to_l4(self):
        a_c = """int helper(void) {
    return 1;
}
int foo(void) {
    helper();
    return 0;
}
"""
        b_c = """void bar(void) {
    foo();
}
"""
        diff = """diff --git a/a.c b/a.c
@@ -1,5 +1,5 @@ int foo(void) {
-    mutex_lock(&old_lock);
+    mutex_lock(&new_lock);
 }
"""
        p = _patch(diff, ["a.c", "b.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        git = _MockGit({"a.c": a_c, "b.c": b_c})
        eng = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False)
        vd = eng.evaluate(p, dr, git, "5.10")
        self.assertEqual(vd.level_decision.base_level, "L0")
        self.assertEqual(vd.level_decision.level, "L4")
        self.assertTrue(any(h.get("rule_id") == "call_chain_propagation" for h in vd.level_decision.rule_hits))

    def test_prerequisite_required_promotes_to_l3(self):
        diff = """diff --git a/a.c b/a.c
@@ -1,2 +1,2 @@
-int x = 1;
+int x = 2;
"""
        p = _patch(diff, ["a.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        prereqs = [PrerequisitePatch(commit_id="abc123456789", subject="prep", grade="strong")]
        vd = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False).evaluate(
            p,
            dr,
            _MockGit({}),
            "any",
            prerequisite_patches=prereqs,
            dependency_details=DependencyAnalysisDetails(candidate_count=4, strong_count=1),
        )
        self.assertEqual(vd.level_decision.level, "L3")
        self.assertTrue(any(h.get("rule_id") == "prerequisite_required" for h in vd.level_decision.rule_hits))
        self.assertEqual(vd.strategy_buckets.get("dependency_bucket"), "required")
        self.assertTrue(any(h.get("rule_class") == "direct_backport_veto" for h in vd.level_decision.rule_hits))
        self.assertEqual(vd.decision_skeleton["conclusion"]["prerequisite"]["status"], "required")

    def test_independent_patch_rule_when_no_prereq(self):
        diff = """diff --git a/a.c b/a.c
@@ -1,2 +1,2 @@
-int x = 1;
+int x = 2;
"""
        p = _patch(diff, ["a.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        vd = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False).evaluate(
            p,
            dr,
            _MockGit({}),
            "any",
            prerequisite_patches=[],
            dependency_details=DependencyAnalysisDetails(candidate_count=3, strong_count=0, medium_count=0, weak_count=1),
        )
        self.assertTrue(any(h.get("rule_id") == "independent_patch" for h in vd.level_decision.rule_hits))
        self.assertTrue(any("关联补丁判断" in s for s in vd.workflow_steps))
        self.assertEqual(vd.strategy_buckets.get("dependency_bucket"), "independent")
        self.assertEqual(vd.decision_skeleton["conclusion"]["prerequisite"]["status"], "independent")

    def test_single_line_high_impact_rule(self):
        diff = """diff --git a/lock.c b/lock.c
@@ -1,2 +1,2 @@
-if (!mutex_trylock(&foo))
+if (!mutex_lock_interruptible(&foo))
"""
        p = _patch(diff, ["lock.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        vd = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False).evaluate(
            p, dr, _MockGit({}), "any"
        )
        self.assertEqual(vd.level_decision.level, "L3")
        self.assertTrue(any(h.get("rule_id") == "single_line_high_impact" for h in vd.level_decision.rule_hits))
        risk_evidence = vd.decision_skeleton["evidence"]
        self.assertIn("foo", risk_evidence["lock_objects"])
        self.assertTrue(any(h.get("rule_class") == "risk_profile" for h in vd.level_decision.rule_hits))

    def test_risk_markers_capture_fields_states_and_error_nodes(self):
        diff = """diff --git a/net.c b/net.c
@@ -1,5 +1,5 @@
-if (ctx->state == OLD_STATE)
+if (ctx->state == NEW_STATE)
-    return -EINVAL;
+    goto err_unlock;
"""
        p = _patch(diff, ["net.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="context-C1")
        vd = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False).evaluate(
            p, dr, _MockGit({}), "any"
        )
        evidence = vd.decision_skeleton["evidence"]
        self.assertIn("ctx->state", evidence["fields"])
        self.assertTrue(any("state" in item.lower() for item in evidence["state_points"]))
        self.assertTrue(any("err_unlock" in item for item in evidence["error_path_nodes"]))

    def test_profile_conservative_presets_exist(self):
        self.assertIn("conservative", POLICY_PROFILE_PRESETS)
        self.assertLess(
            POLICY_PROFILE_PRESETS["conservative"]["large_change_line_threshold"],
            POLICY_PROFILE_PRESETS["aggressive"]["large_change_line_threshold"],
        )

    def test_l5_unknown_method_low_confidence(self):
        p = _patch("- x\n+ y\n", ["z.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="")
        eng = PolicyEngine(PolicyConfig(), llm_enabled=False)
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        self.assertEqual(vd.level_decision.level, "L5")
        self.assertEqual(vd.level_decision.confidence, "low")

    def test_l5_when_dryrun_missing(self):
        p = _patch("- x\n+ y\n", ["z.c"])
        eng = PolicyEngine(PolicyConfig(profile="balanced"), llm_enabled=False)
        vd = eng.evaluate(p, None, _MockGit({}), "any")
        self.assertEqual(vd.level_decision.level, "L5")
        self.assertEqual(vd.level_decision.confidence, "low")
        self.assertEqual(vd.rule_version, "v2")

    def test_empty_patch_keeps_v2_schema_and_profile(self):
        eng = PolicyEngine(PolicyConfig(profile="conservative"), llm_enabled=False)
        vd = eng.evaluate(None, None, _MockGit({}), "any")
        self.assertIsNone(vd.level_decision)
        self.assertEqual(vd.rule_version, "v2")
        self.assertEqual(vd.rule_profile, "conservative")
        self.assertIn("fix_patch 为空", vd.warnings)

    def test_p2_special_risk_report_and_rules(self):
        diff = """diff --git a/drivers/foo.c b/drivers/foo.c
--- a/drivers/foo.c
+++ b/drivers/foo.c
@@ -10,7 +10,12 @@ static int foo_update(struct foo *foo)
-    if (foo->state)
+    mutex_lock(&foo->lock);
+    if (!foo->state)
+        goto err_unlock;
+    foo->status = -EINVAL;
+    mutex_unlock(&foo->lock);
+err_unlock:
+    return -EINVAL;
"""
        p = _patch(diff, ["drivers/foo.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        eng = PolicyEngine(
            PolicyConfig(
                profile="default",
                special_risk_rules_enabled=True,
                prerequisite_rules_enabled=False,
                direct_backport_rules_enabled=False,
                large_change_rules_enabled=False,
                call_chain_rules_enabled=False,
                critical_structure_rules_enabled=False,
                l1_api_surface_rules_enabled=False,
                high_impact_single_line_rules_enabled=False,
            ),
            llm_enabled=False,
        )
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        self.assertEqual(vd.rule_version, "v2")
        self.assertTrue(vd.special_risk_report["enabled"])
        self.assertIn("locking_sync", vd.special_risk_report["summary"]["triggered_sections"])
        self.assertIn("state_machine_control_flow", vd.special_risk_report["summary"]["triggered_sections"])
        self.assertIn("error_path", vd.special_risk_report["summary"]["triggered_sections"])
        rule_ids = {hit["rule_id"] for hit in vd.level_decision.rule_hits}
        self.assertIn("p2_locking_sync", rule_ids)
        self.assertIn("p2_state_machine_control_flow", rule_ids)
        self.assertIn("p2_error_path", rule_ids)

    def test_p2_can_be_disabled(self):
        diff = """diff --git a/drivers/foo.c b/drivers/foo.c
--- a/drivers/foo.c
+++ b/drivers/foo.c
@@ -1,3 +1,4 @@
+mutex_lock(&foo->lock);
"""
        p = _patch(diff, ["drivers/foo.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        vd = PolicyEngine(
            PolicyConfig(
                profile="default",
                special_risk_rules_enabled=False,
                prerequisite_rules_enabled=False,
                direct_backport_rules_enabled=False,
                large_change_rules_enabled=False,
                call_chain_rules_enabled=False,
                critical_structure_rules_enabled=False,
                l1_api_surface_rules_enabled=False,
                high_impact_single_line_rules_enabled=False,
            ),
            llm_enabled=False,
        ).evaluate(p, dr, _MockGit({}), "any")
        self.assertFalse(vd.special_risk_report["enabled"])
        rule_ids = {hit["rule_id"] for hit in vd.level_decision.rule_hits}
        self.assertFalse(any(rule_id.startswith("p2_") for rule_id in rule_ids))

    def test_p2_state_machine_ignores_syntax_only_error_return_change(self):
        diff = """diff --git a/foo.c b/foo.c
@@ -1,3 +1,3 @@
-if (ret)
-    return -EINVAL;
+if (ret)
+    return -EAGAIN;
"""
        p = _patch(diff, ["foo.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        vd = PolicyEngine(
            PolicyConfig(profile="default", high_impact_single_line_rules_enabled=False),
            llm_enabled=False,
        ).evaluate(p, dr, _MockGit({}), "any")
        rule_ids = {hit["rule_id"] for hit in vd.level_decision.rule_hits}
        self.assertEqual(vd.level_decision.level, "L2")
        self.assertNotIn("p2_state_machine_control_flow", rule_ids)
        self.assertIn("p2_error_path", rule_ids)
        self.assertFalse(vd.special_risk_report["sections"]["state_machine_control_flow"]["triggered"])

    def test_batch_summary_counts(self):
        summary = aggregate_batch_validate_summary([
            {
                "cve_id": "CVE-1",
                "level_decision": {"level": "L0", "base_level": "L0"},
                "generated_vs_real": {"verdict": "identical", "deterministic_exact_match": True},
                "validation_details": {
                    "strategy_buckets": {"dependency_bucket": "independent"},
                    "special_risk_report": {
                        "summary": {
                            "triggered_sections": ["locking_sync"],
                            "has_critical_structure_change": True,
                        }
                    },
                },
            },
            {
                "cve_id": "CVE-2",
                "level_decision": {"level": "L3", "base_level": "L1"},
                "generated_vs_real": {"verdict": "different", "deterministic_exact_match": False},
                "validation_details": {
                    "strategy_buckets": {"dependency_bucket": "required"},
                    "special_risk_report": {
                        "summary": {
                            "triggered_sections": ["error_path"],
                            "has_critical_structure_change": False,
                        }
                    },
                },
            },
        ])
        self.assertEqual(summary["l0_l5"]["current_level_distribution"]["L0"], 1)
        self.assertEqual(summary["l0_l5"]["current_level_distribution"]["L3"], 1)
        self.assertEqual(summary["deterministic_exact_match"]["count"], 1)
        self.assertEqual(summary["critical_structure_change"]["count"], 1)
        self.assertEqual(summary["manual_prerequisite_analysis"]["count"], 1)

    def test_batch_summary_accepts_friendly_validate_json(self):
        friendly = cli._prepare_validate_json({
            "cve_id": "CVE-1",
            "target_version": "5.10-hulk",
            "level_decision": {"level": "L4", "base_level": "L0", "base_method": "strict"},
            "l0_l5": {"current_level": "L4", "base_level": "L0"},
            "generated_vs_real": {"verdict": "identical", "deterministic_exact_match": True},
            "validation_details": {
                "strategy_buckets": {"dependency_bucket": "required"},
                "special_risk_report": {
                    "summary": {
                        "triggered_sections": ["state_machine_control_flow"],
                        "has_critical_structure_change": True,
                    }
                },
            },
        })
        summary = aggregate_batch_validate_summary([friendly])
        self.assertEqual(summary["l0_l5"]["current_level_distribution"]["L4"], 1)
        self.assertEqual(summary["l0_l5"]["base_level_distribution"]["L0"], 1)
        self.assertEqual(summary["deterministic_exact_match"]["count"], 1)
        self.assertEqual(summary["critical_structure_change"]["count"], 1)
        self.assertEqual(summary["manual_prerequisite_analysis"]["count"], 1)


class APIServerRegressionTests(unittest.TestCase):
    def test_validate_handler_applies_p2_override(self):
        config = SimpleNamespace(policy=SimpleNamespace(special_risk_rules_enabled=True))
        original = api_server.cli._run_single_validate
        try:
            def fake_run_single_validate(cfg, cve_id, target, known_fix, known_prereqs, **kwargs):
                self.assertFalse(cfg.policy.special_risk_rules_enabled)
                return {
                    "cve_id": cve_id,
                    "target_version": target,
                    "known_fix": known_fix,
                    "level_decision": {"level": "L2", "base_level": "L0", "base_method": "strict"},
                    "validation_details": {
                        "strategy_buckets": {"dependency_bucket": "independent"},
                        "special_risk_report": {"summary": {"triggered_sections": [], "has_critical_structure_change": False}},
                    },
                    "generated_vs_real": {"verdict": "identical", "deterministic_exact_match": True},
                }

            api_server.cli._run_single_validate = fake_run_single_validate
            result = api_server._default_validate_handler({
                "target_version": "5.10-hulk",
                "cve_id": "CVE-TEST-1",
                "known_fix": "deadbeef",
                "p2_enabled": False,
            }, config)
        finally:
            api_server.cli._run_single_validate = original

        self.assertFalse(result["p2_enabled"])
        self.assertEqual(result["l0_l5"]["current_level"], "L2")

    def test_batch_validate_handler_returns_batch_summary(self):
        config = SimpleNamespace(policy=SimpleNamespace(special_risk_rules_enabled=True))
        original_make_git_mgr = api_server.cli._make_git_mgr
        original_run_single_validate = api_server.cli._run_single_validate
        original_prepare_validate_json = api_server.cli._prepare_validate_json
        try:
            api_server.cli._make_git_mgr = lambda cfg, target: object()

            def fake_run_single_validate(cfg, cve_id, target, known_fix, known_prereqs, **kwargs):
                return {
                    "cve_id": cve_id,
                    "target_version": target,
                    "known_fix": known_fix,
                    "level_decision": {"level": "L0", "base_level": "L0", "base_method": "strict"},
                    "validation_details": {
                        "strategy_buckets": {
                            "dependency_bucket": "required" if known_prereqs else "independent",
                        },
                        "special_risk_report": {
                            "summary": {
                                "triggered_sections": ["locking_sync"] if known_prereqs else [],
                                "has_critical_structure_change": bool(known_prereqs),
                            }
                        },
                    },
                    "generated_vs_real": {
                        "verdict": "identical",
                        "deterministic_exact_match": not known_prereqs,
                    },
                }

            api_server.cli._run_single_validate = fake_run_single_validate
            api_server.cli._prepare_validate_json = lambda result: dict(result)

            result = api_server._default_batch_validate_handler({
                "target": "5.10-hulk",
                "p2_enabled": True,
                "items": [
                    {"cve_id": "CVE-1", "known_fix": "aaa"},
                    {"cve_id": "CVE-2", "known_fix": "bbb", "known_prereqs": ["ccc"]},
                ],
            }, config)
        finally:
            api_server.cli._make_git_mgr = original_make_git_mgr
            api_server.cli._run_single_validate = original_run_single_validate
            api_server.cli._prepare_validate_json = original_prepare_validate_json

        self.assertTrue(result["p2_enabled"])
        self.assertIn("batch_summary", result)
        self.assertEqual(result["batch_summary"]["total"], 2)
        self.assertEqual(result["batch_summary"]["deterministic_exact_match"]["count"], 1)
        self.assertEqual(result["batch_summary"]["critical_structure_change"]["count"], 1)
        self.assertEqual(result["batch_summary"]["manual_prerequisite_analysis"]["count"], 1)


if __name__ == "__main__":
    unittest.main()
