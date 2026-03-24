#!/usr/bin/env python3
"""策略引擎回归：L0–L5 映射、关键结构、大改动、扇出、L1 API 启发式、profile 预设。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import PolicyConfig, POLICY_PROFILE_PRESETS
from core.models import DryRunResult, PatchInfo
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
        self.assertTrue(vd.level_decision.harmless)
        self.assertIn("L0", vd.level_decision.strategy)

    def test_l0_not_harmless_on_critical_structure(self):
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
        self.assertEqual(vd.level_decision.level, "L0")
        self.assertFalse(vd.level_decision.harmless)
        self.assertTrue(any("mutex" in m.lower() or "关键" in m for m in vd.warnings))

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
        impacts = {fi.function: fi for fi in vd.function_impacts}
        self.assertIn("foo", impacts)
        self.assertGreaterEqual(len(impacts["foo"].callers) + len(impacts["foo"].callees), 2)
        self.assertTrue(any("扩散" in w or "调用链" in w for w in vd.warnings))

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
        self.assertEqual(vd.level_decision.level, "L1")
        self.assertTrue(any("签名" in w or "L1" in w or "调用点" in w for w in vd.warnings))

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


if __name__ == "__main__":
    unittest.main()
