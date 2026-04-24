#!/usr/bin/env python3
"""策略引擎回归：基线 DryRun + rules/ 抬升、关键结构、调用链牵连、L1 API 启发式、profile 预设。"""

import os
import sys
import tempfile
import unittest
import argparse
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api_server
import cli
from commands import analyze as analyze_cmd
from commands.policy_cli import apply_policy_cli_overrides
from commands import validate as validate_cmd
from core.config import Config, PolicyConfig, POLICY_PROFILE_PRESETS
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
    def test_cli_policy_profile_override_changes_runtime_profile(self):
        cfg = Config(policy=PolicyConfig(profile="balanced", special_risk_rules_enabled=True))
        args = SimpleNamespace(policy_profile="conservative", p2_enabled=False)
        out = apply_policy_cli_overrides(cfg, args)
        self.assertEqual(cfg.policy.profile, "balanced")
        self.assertEqual(out.policy.profile, "conservative")
        self.assertEqual(
            out.policy.large_change_line_threshold,
            POLICY_PROFILE_PRESETS["conservative"]["large_change_line_threshold"],
        )
        self.assertEqual(
            out.policy.call_chain_fanout_threshold,
            POLICY_PROFILE_PRESETS["conservative"]["call_chain_fanout_threshold"],
        )
        self.assertFalse(out.policy.special_risk_rules_enabled)

    def test_analyze_cli_accepts_policy_profile_argument(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        analyze_cmd.register(subparsers, argparse.ArgumentParser(add_help=False))
        args = parser.parse_args([
            "analyze",
            "--cve", "CVE-2024-26633",
            "--target", "5.10-hulk",
            "--policy-profile", "conservative",
        ])
        self.assertEqual(args.policy_profile, "conservative")

    def test_validate_cli_accepts_policy_profile_argument(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        validate_cmd.register(subparsers, argparse.ArgumentParser(add_help=False))
        args = parser.parse_args([
            "validate",
            "--cve", "CVE-2024-26633",
            "--target", "5.10-hulk",
            "--known-fix", "deadbeef",
            "--policy-profile", "balanced",
        ])
        self.assertEqual(args.policy_profile, "balanced")

    def test_batch_validate_cli_accepts_xlsx_argument(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        validate_cmd.register(subparsers, argparse.ArgumentParser(add_help=False))
        args = parser.parse_args([
            "batch-validate",
            "--file", "cves.json",
            "--target", "5.10-hulk",
            "--xlsx",
        ])
        self.assertTrue(args.xlsx)

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

    def test_l0_direct_backport_candidate_allows_plain_field_assignment(self):
        diff = """diff --git a/x.c b/x.c
@@ -1,2 +1,2 @@
- ctx->limit = old;
+ ctx->limit = new;
"""
        p = _patch(diff, ["x.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        eng = PolicyEngine(
            PolicyConfig(
                profile="default",
                prerequisite_rules_enabled=False,
                large_change_rules_enabled=False,
                call_chain_rules_enabled=False,
                critical_structure_rules_enabled=False,
                special_risk_rules_enabled=False,
                l1_api_surface_rules_enabled=False,
                high_impact_single_line_rules_enabled=False,
            ),
            llm_enabled=False,
        )
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        rule_ids = {hit["rule_id"] for hit in vd.level_decision.rule_hits}
        self.assertEqual(vd.level_decision.level, "L0")
        self.assertIn("direct_backport_candidate", rule_ids)
        self.assertEqual(vd.decision_skeleton["conclusion"]["direct_backport"]["status"], "direct")

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

    def test_l1_function_call_statement_does_not_trigger_api_surface(self):
        diff = """diff --git a/f.c b/f.c
@@ -1,3 +1,3 @@ int frob(int x) {
-    ret = helper(old);
+    ret = helper(new);
     return ret;
 }
"""
        p = _patch(diff, ["f.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="context-C1")
        eng = PolicyEngine(
            PolicyConfig(
                profile="default",
                prerequisite_rules_enabled=False,
                large_change_rules_enabled=False,
                call_chain_rules_enabled=False,
                critical_structure_rules_enabled=False,
                special_risk_rules_enabled=False,
                high_impact_single_line_rules_enabled=False,
            ),
            llm_enabled=False,
        )
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        rule_ids = {hit["rule_id"] for hit in vd.level_decision.rule_hits}
        self.assertEqual(vd.level_decision.level, "L1")
        self.assertNotIn("l1_api_surface", rule_ids)

    def test_generic_uppercase_condition_does_not_trigger_state_machine(self):
        diff = """diff --git a/f.c b/f.c
@@ -1,3 +1,3 @@ int frob(int rc) {
-    if (rc == FOO_READY)
+    if (rc == BAR_READY)
         return 0;
 }
"""
        p = _patch(diff, ["f.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        eng = PolicyEngine(
            PolicyConfig(
                profile="default",
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
        rule_ids = {hit["rule_id"] for hit in vd.level_decision.rule_hits}
        self.assertEqual(vd.level_decision.level, "L0")
        self.assertNotIn("p2_state_machine_control_flow", rule_ids)

    def test_plain_member_condition_does_not_trigger_single_line_high_impact(self):
        diff = """diff --git a/f.c b/f.c
@@ -1,3 +1,3 @@ int frob(struct foo *ctx) {
-    if (ctx->ready)
+    if (ctx->active)
         return 0;
 }
"""
        p = _patch(diff, ["f.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        eng = PolicyEngine(
            PolicyConfig(
                profile="default",
                prerequisite_rules_enabled=False,
                direct_backport_rules_enabled=False,
                large_change_rules_enabled=False,
                call_chain_rules_enabled=False,
                critical_structure_rules_enabled=False,
                special_risk_rules_enabled=False,
                l1_api_surface_rules_enabled=False,
            ),
            llm_enabled=False,
        )
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        rule_ids = {hit["rule_id"] for hit in vd.level_decision.rule_hits}
        self.assertEqual(vd.level_decision.level, "L0")
        self.assertNotIn("single_line_high_impact", rule_ids)

    def test_l1_comment_drift_is_sampled_as_light_drift(self):
        diff = """diff --git a/f.c b/f.c
@@ -1,2 +1,2 @@ int frob(int x) {
-    /* old comment */
+    /* updated comment */
 }
"""
        p = _patch(diff, ["f.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="context-C1")
        eng = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False)
        vd = eng.evaluate(p, dr, _MockGit({"f.c": "int frob(int x) {\n    return x;\n}\n"}), "any")
        rule_hits = {hit["rule_id"]: hit for hit in vd.level_decision.rule_hits}
        self.assertEqual(vd.level_decision.level, "L1")
        self.assertIn("l1_light_drift_sample", rule_hits)
        self.assertIn("comment_only", rule_hits["l1_light_drift_sample"]["evidence"]["categories"])

    def test_l1_local_variable_rename_is_sampled_as_light_drift(self):
        diff = """diff --git a/f.c b/f.c
@@ -1,4 +1,4 @@ int frob(int x) {
-    int oldv = x + 1;
-    return oldv;
+    int newv = x + 1;
+    return newv;
 }
"""
        p = _patch(diff, ["f.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="context-C1")
        eng = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False)
        vd = eng.evaluate(p, dr, _MockGit({"f.c": "int frob(int x) {\n    return x;\n}\n"}), "any")
        rule_hits = {hit["rule_id"]: hit for hit in vd.level_decision.rule_hits}
        self.assertEqual(vd.level_decision.level, "L1")
        self.assertIn("l1_light_drift_sample", rule_hits)
        self.assertIn("local_variable_rename", rule_hits["l1_light_drift_sample"]["evidence"]["categories"])
        self.assertIn("oldv->newv", rule_hits["l1_light_drift_sample"]["evidence"]["rename_pairs"])

    def test_l1_clean_context_drift_allows_direct_backport(self):
        diff = """diff --git a/f.c b/f.c
@@ -1,2 +1,2 @@
- value = old;
+ value = new;
"""
        p = _patch(diff, ["f.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="context-C1")
        eng = PolicyEngine(
            PolicyConfig(
                profile="default",
                large_change_rules_enabled=False,
                call_chain_rules_enabled=False,
                critical_structure_rules_enabled=False,
                special_risk_rules_enabled=False,
                l1_api_surface_rules_enabled=False,
                high_impact_single_line_rules_enabled=False,
            ),
            llm_enabled=False,
        )
        vd = eng.evaluate(p, dr, _MockGit({"f.c": "int f(void) {\n    return 0;\n}\n"}), "any")
        self.assertEqual(vd.level_decision.level, "L1")
        self.assertEqual(vd.decision_skeleton["conclusion"]["direct_backport"]["status"], "direct")
        self.assertEqual(vd.decision_skeleton["conclusion"]["risk"]["status"], "low")
        self.assertEqual(vd.manual_review_checklist, [])

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
        self.assertTrue(vd.manual_review_checklist)

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
        self.assertIn("balanced", POLICY_PROFILE_PRESETS)
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

    def test_verified_direct_defaults_to_l3_not_l5(self):
        p = _patch("- x\n+ y\n", ["z.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="verified-direct")
        eng = PolicyEngine(PolicyConfig(), llm_enabled=False)
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        self.assertEqual(vd.level_decision.base_level, "L3")
        self.assertEqual(vd.level_decision.level, "L3")
        self.assertEqual(vd.level_decision.review_mode, "focused-review")

    def test_validate_exact_match_recalibrates_verified_direct_to_l1(self):
        p = _patch("- x\n+ y\n", ["z.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="verified-direct")
        eng = PolicyEngine(PolicyConfig(), llm_enabled=False)
        vd = eng.evaluate(p, dr, _MockGit({}), "any")
        result = SimpleNamespace(
            fix_patch=p,
            dry_run=dr,
            level_decision=vd.level_decision,
            prerequisite_patches=[],
            dependency_details=DependencyAnalysisDetails(),
            validation_details=vd,
            function_impacts=vd.function_impacts,
        )
        recalibration = cli._maybe_recalibrate_validate_level_from_accuracy(
            result,
            {
                "verdict": "identical",
                "deterministic_exact_match": True,
                "compare_scope": "single_fix",
            },
            eng,
            _MockGit({}),
            "any",
        )
        self.assertTrue(recalibration.get("applied"))
        self.assertEqual(recalibration.get("original_level"), "L3")
        self.assertEqual(recalibration.get("adjusted_level"), "L1")
        self.assertEqual(result.level_decision.base_method, "verified-direct-exact")
        self.assertEqual(result.level_decision.level, "L1")
        self.assertEqual(
            result.validation_details.decision_skeleton["conclusion"]["direct_backport"]["status"],
            "direct",
        )
        self.assertTrue(
            any("Validate 准确度校正" in step for step in result.validation_details.workflow_steps)
        )

    def test_l5_when_dryrun_missing(self):
        p = _patch("- x\n+ y\n", ["z.c"])
        eng = PolicyEngine(PolicyConfig(profile="balanced"), llm_enabled=False)
        vd = eng.evaluate(p, None, _MockGit({}), "any")
        self.assertEqual(vd.level_decision.level, "L5")
        self.assertEqual(vd.level_decision.confidence, "low")
        self.assertEqual(vd.rule_version, "v2")

    def test_missing_intro_uncertain_blocks_l0(self):
        p = _patch("diff --git a/z.c b/z.c\n--- a/z.c\n+++ b/z.c\n@@ -1,1 +1,1 @@\n- old();\n+ new();\n", ["z.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        dep = DependencyAnalysisDetails(
            candidate_count=0,
            strong_count=0,
            medium_count=0,
            weak_count=0,
            intro_verdict="uncertain",
            intro_strategy="missing_intro_patch_probe_uncertain_assume",
            intro_confidence=0.2,
        )
        eng = PolicyEngine(PolicyConfig(profile="balanced"), llm_enabled=False)
        vd = eng.evaluate(p, dr, _MockGit({}), "any", dependency_details=dep)
        self.assertEqual(vd.level_decision.base_level, "L0")
        self.assertEqual(vd.level_decision.level, "L1")
        self.assertTrue(any(hit.get("rule_id") == "missing_intro_uncertain" for hit in vd.level_decision.rule_hits))

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

    def test_p2_lifecycle_does_not_promote_bare_goto_err_without_resource_ops(self):
        diff = """diff --git a/foo.c b/foo.c
@@ -1,4 +1,7 @@ int f(int ret) {
-    return 0;
+    if (ret)
+        goto err;
+    return 0;
+err:
+    return -EINVAL;
 }
"""
        p = _patch(diff, ["foo.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        vd = PolicyEngine(
            PolicyConfig(profile="default", high_impact_single_line_rules_enabled=False),
            llm_enabled=False,
        ).evaluate(p, dr, _MockGit({}), "any")
        rule_ids = {hit["rule_id"] for hit in vd.level_decision.rule_hits}
        self.assertNotIn("p2_lifecycle_resource", rule_ids)
        self.assertIn("p2_error_path", rule_ids)
        self.assertEqual(vd.level_decision.level, "L2")
        self.assertFalse(vd.special_risk_report["sections"]["lifecycle_resource"]["triggered"])

    def test_p2_struct_field_ignores_same_field_value_change(self):
        diff = """diff --git a/foo.c b/foo.c
@@ -1,2 +1,2 @@ int f(struct foo *ctx) {
-    ctx->limit = old;
+    ctx->limit = new;
 }
"""
        p = _patch(diff, ["foo.c"])
        dr = DryRunResult(applies_cleanly=True, apply_method="strict")
        vd = PolicyEngine(
            PolicyConfig(profile="default", high_impact_single_line_rules_enabled=False),
            llm_enabled=False,
        ).evaluate(p, dr, _MockGit({}), "any")
        rule_ids = {hit["rule_id"] for hit in vd.level_decision.rule_hits}
        self.assertNotIn("p2_struct_field_data_path", rule_ids)
        self.assertEqual(vd.level_decision.level, "L0")
        self.assertFalse(vd.special_risk_report["sections"]["struct_field_data_path"]["triggered"])

    def test_batch_summary_counts(self):
        summary = aggregate_batch_validate_summary([
            {
                "cve_id": "CVE-1",
                "overall_pass": True,
                "dryrun_detail": {"apply_method": "strict"},
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
                "overall_pass": False,
                "dryrun_detail": {
                    "apply_method": "regenerated",
                    "apply_attempts": [{"method": "regenerated-zero/unidiff-zero", "success": "yes"}],
                },
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
        self.assertEqual(summary["promotion_summary"]["promoted_count"], 1)
        self.assertEqual(summary["strategy_effectiveness"]["counts"]["Strict"], 1)
        self.assertEqual(summary["strategy_effectiveness"]["counts"]["Zero-Context"], 1)
        self.assertEqual(summary["level_accuracy"]["final_levels"]["L0"]["pass_rate"], 1.0)
        self.assertEqual(summary["level_accuracy"]["final_levels"]["L3"]["total"], 1)

    def test_batch_summary_tracks_promotion_rules(self):
        summary = aggregate_batch_validate_summary([
            {
                "cve_id": "CVE-1",
                "level_decision": {
                    "level": "L3",
                    "base_level": "L0",
                    "rule_hits": [
                        {"rule_id": "p2_lifecycle_resource", "severity": "warn", "level_floor": "L2"},
                        {"rule_id": "prerequisite_required", "severity": "high", "level_floor": "L3"},
                    ],
                },
                "validation_details": {"strategy_buckets": {"dependency_bucket": "required"}},
            }
        ])
        self.assertEqual(summary["promotion_summary"]["promotion_matrix"]["L0->L3"], 1)
        self.assertEqual(summary["promotion_summary"]["top_promotion_rules"]["p2_lifecycle_resource"], 1)
        self.assertEqual(summary["promotion_summary"]["top_promotion_rules"]["prerequisite_required"], 1)

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
        self.assertEqual(summary["strategy_effectiveness"]["counts"]["Unresolved"], 1)

    def test_batch_summary_keeps_primary_accuracy_and_tracks_solution_set_separately(self):
        summary = aggregate_batch_validate_summary([
            {
                "cve_id": "CVE-1",
                "level_decision": {"level": "L1", "base_level": "L1"},
                "generated_vs_real": {"verdict": "identical", "deterministic_exact_match": True},
                "solution_set_vs_real": {"verdict": "different", "deterministic_exact_match": False},
                "validation_details": {
                    "strategy_buckets": {"dependency_bucket": "recommended"},
                    "special_risk_report": {"summary": {"triggered_sections": [], "has_critical_structure_change": False}},
                },
            },
        ])
        self.assertEqual(summary["verdict_distribution"]["identical"], 1)
        self.assertEqual(summary["deterministic_exact_match"]["count"], 1)
        self.assertEqual(summary["solution_set_verdict_distribution"]["different"], 1)
        self.assertEqual(summary["solution_set_deterministic_exact_match"]["count"], 0)
        self.assertEqual(summary["solution_set_deterministic_exact_match"]["case_count"], 1)

    def test_batch_case_bucket_uses_primary_patch_accuracy(self):
        tmpdir = tempfile.mkdtemp(prefix="batch-case-")
        try:
            runtime = SimpleNamespace(
                _run_single_validate=lambda *args, **kwargs: {
                    "cve_id": "CVE-1",
                    "generated_vs_real": {
                        "verdict": "identical",
                        "core_similarity": 1.0,
                        "deterministic_exact_match": True,
                    },
                    "solution_set_vs_real": {
                        "verdict": "different",
                        "core_similarity": 0.3,
                        "deterministic_exact_match": False,
                    },
                    "dryrun_detail": {"has_adapted_patch": True, "apply_method": "verified-direct"},
                    "validation_details": {
                        "strategy_buckets": {"dependency_bucket": "recommended"},
                        "special_risk_report": {"summary": {"triggered_sections": [], "has_critical_structure_change": False}},
                    },
                    "analysis_framework": {
                        "conclusion": {
                            "direct_backport": {"status": "review"},
                            "prerequisite": {"status": "recommended"},
                            "risk": {"status": "attention"},
                        }
                    },
                    "result_status": {"state": "complete"},
                    "summary": "主补丁准确，但整套解集不完整",
                    "tool_prereqs": [],
                }
            )
            config = SimpleNamespace(output=SimpleNamespace(output_dir=tmpdir))
            group = {
                "primary_fix": {"commit": "aaa111", "subject": "fix"},
                "prereq_fixes": [],
                "all_fixes": [{"commit": "aaa111"}, {"commit": "bbb222"}],
            }
            case_out = validate_cmd._execute_batch_validate_case(
                runtime, config, "5.10-hulk", "CVE-1", group, git_mgr=object(), run_id="run1"
            )
        finally:
            import shutil
            shutil.rmtree(tmpdir)

        self.assertEqual(case_out["bucket"], "passed")
        self.assertEqual(case_out["verdict"], "identical")
        self.assertEqual(case_out["item"]["solution_set_verdict"], "different")

    def test_find_rollback_commit_uses_earliest_fix_or_prereq(self):
        class _Git:
            @staticmethod
            def run_git_rc(cmd, rv, timeout=30):
                commit = cmd[3]
                earliest = cmd[4]
                order = {"aaa111": 1, "bbb222": 2, "ccc333": 3}
                return 0 if order[commit] <= order[earliest] else 1

        rollback = cli._find_rollback_commit(_Git(), "5.10-hulk", ["bbb222", "ccc333"], ["aaa111"])
        self.assertEqual(rollback, "aaa111~1")

    def test_compare_generated_vs_real_tracks_repeated_file_sections(self):
        generated = """diff --git a/foo.c b/foo.c
@@ -1,2 +1,2 @@
-old_a
+new_a
diff --git a/foo.c b/foo.c
@@ -5,2 +5,2 @@
-old_b
+new_b
"""
        actual = """diff --git a/foo.c b/foo.c
@@ -1,2 +1,2 @@
-old_a
+alt_a
diff --git a/foo.c b/foo.c
@@ -5,2 +5,2 @@
-old_b
+new_b
"""
        comparison = cli._compare_generated_vs_real(generated, actual)
        self.assertNotEqual(comparison["verdict"], "identical")
        self.assertLess(comparison["core_similarity"], 1.0)


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

    def test_validate_handler_accepts_known_fixes_array(self):
        config = SimpleNamespace(policy=SimpleNamespace(special_risk_rules_enabled=True))
        original = api_server.cli._run_single_validate
        try:
            def fake_run_single_validate(cfg, cve_id, target, known_fix, known_prereqs, **kwargs):
                self.assertEqual(known_fix, "aaa111")
                self.assertEqual(kwargs.get("known_fixes"), ["aaa111", "bbb222"])
                return {
                    "cve_id": cve_id,
                    "target_version": target,
                    "known_fix": known_fix,
                    "known_fix_commits": kwargs.get("known_fixes"),
                    "level_decision": {"level": "L1", "base_level": "L1", "base_method": "context-C1"},
                    "validation_details": {
                        "strategy_buckets": {"dependency_bucket": "independent"},
                        "special_risk_report": {"summary": {"triggered_sections": [], "has_critical_structure_change": False}},
                    },
                    "generated_vs_real": {"verdict": "essentially_same", "deterministic_exact_match": False},
                }

            api_server.cli._run_single_validate = fake_run_single_validate
            result = api_server._default_validate_handler({
                "target_version": "5.10-hulk",
                "cve_id": "CVE-TEST-LIST",
                "known_fixes": ["aaa111", "bbb222"],
            }, config)
        finally:
            api_server.cli._run_single_validate = original

        self.assertEqual(result["known_fix_commits"], ["aaa111", "bbb222"])
        self.assertEqual(result["l0_l5"]["current_level"], "L1")

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
