#!/usr/bin/env python3
"""搜索 profile / near-miss 与函数解析可靠性回归。"""

import os
import sys
import argparse
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.analysis import AnalysisAgent
from commands import analyze as analyze_cmd
from commands.policy_cli import apply_policy_cli_overrides
from core.config import ConfigLoader, PolicyConfig, SearchConfig
from core.function_analyzer import FunctionAnalyzer
from core.models import DryRunResult, GitCommit, PatchInfo
from core.policy_engine import PolicyEngine


class _SearchGit:
    def __init__(self, *, subject_commits=None, file_commits=None, diffs=None):
        self.subject_commits = subject_commits or []
        self.file_commits = file_commits or []
        self.diffs = diffs or {}
        self.last_error = {}

    def check_commit_existence(self, commit_id, target_version):
        return "not_found", None

    def search_by_subject(self, subject, rv, limit=20):
        return self.subject_commits[:limit]

    def search_by_keywords(self, keywords, rv, limit=50):
        return []

    def search_by_files(self, files, rv, limit=100, after_ts=0, no_merges=False):
        return self.file_commits[:limit]

    def get_commit_diff(self, commit_id, rv):
        return self.diffs.get(commit_id)


class SearchProfileTests(unittest.TestCase):
    def test_analyze_cli_accepts_search_profile_argument(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        analyze_cmd.register(subparsers, argparse.ArgumentParser(add_help=False))
        args = parser.parse_args([
            "analyze",
            "--cve", "CVE-2024-26633",
            "--target", "5.10-hulk",
            "--search-profile", "aggressive",
        ])
        self.assertEqual(args.search_profile, "aggressive")

    def test_cli_search_profile_override_changes_runtime_search_profile(self):
        cfg = ConfigLoader.load("__missing_config_for_test__.yaml")
        args = argparse.Namespace(policy_profile=None, p2_enabled=None, search_profile="aggressive")
        out = apply_policy_cli_overrides(cfg, args)
        self.assertEqual(cfg.search.profile, "balanced")
        self.assertEqual(out.search.profile, "aggressive")
        self.assertEqual(out.search.subject_candidate_limit, 20)

    def test_config_loader_merges_search_profile_presets(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".yaml", delete=False) as handle:
            handle.write("search:\n  profile: aggressive\n  diff_threshold: 0.66\n")
            path = handle.name
        try:
            cfg = ConfigLoader.load(path)
        finally:
            os.unlink(path)

        self.assertEqual(cfg.search.profile, "aggressive")
        self.assertEqual(cfg.search.subject_candidate_limit, 20)
        self.assertEqual(cfg.search.diff_threshold, 0.66)

    def test_subject_near_miss_explains_below_threshold(self):
        candidate = GitCommit(
            commit_id="abc123456789",
            subject="fix race in driver bar",
        )
        agent = AnalysisAgent(
            _SearchGit(subject_commits=[candidate]),
            search_config=SearchConfig(profile="conservative", subject_threshold=0.90),
        )

        result = agent.search(
            "deadbeef",
            "fix race in driver foo",
            "",
            "5.10",
        )

        self.assertFalse(result.found)
        self.assertEqual(result.failure.reason, "below_threshold")
        self.assertEqual(result.failure.level, "L2")
        self.assertEqual(result.search_profile["subject_threshold"], 0.90)
        self.assertTrue(result.near_misses)
        self.assertEqual(result.near_misses[0]["failure_reason"], "below_threshold")
        self.assertGreater(result.near_misses[0]["threshold_delta"], 0)

    def test_aggressive_subject_profile_can_recall_same_candidate(self):
        candidate = GitCommit(
            commit_id="abc123456789",
            subject="fix race in driver bar",
        )
        agent = AnalysisAgent(
            _SearchGit(subject_commits=[candidate]),
            search_config=SearchConfig(profile="aggressive", subject_threshold=0.80),
        )

        result = agent.search(
            "deadbeef",
            "fix race in driver foo",
            "",
            "5.10",
        )

        self.assertTrue(result.found)
        self.assertEqual(result.strategy, "subject_match")
        self.assertEqual(result.search_profile["profile"], "aggressive")

    def test_diff_near_miss_records_threshold_delta_and_failure_reason(self):
        source_diff = """diff --git a/foo.c b/foo.c
--- a/foo.c
+++ b/foo.c
@@ -1,1 +1,1 @@
- old
+ new
"""
        target_diff = """diff --git a/foo.c b/foo.c
--- a/foo.c
+++ b/foo.c
@@ -1,1 +1,1 @@
- abc
+ other
"""
        candidate = GitCommit(
            commit_id="feedface1234",
            subject="unrelated subsystem cleanup",
        )
        agent = AnalysisAgent(
            _SearchGit(
                file_commits=[candidate],
                diffs={candidate.commit_id: target_diff},
            ),
            search_config=SearchConfig(profile="balanced", diff_threshold=0.70),
        )

        result = agent.search(
            "deadbeef",
            "fix race in driver foo",
            source_diff,
            "5.10",
        )

        self.assertFalse(result.found)
        self.assertEqual(result.failure.reason, "below_threshold")
        self.assertEqual(result.failure.level, "L3")
        self.assertTrue(result.candidates)
        self.assertEqual(result.candidates[0]["failure_reason"], "below_threshold")
        self.assertGreater(result.candidates[0]["threshold_delta"], 0)


class FunctionAnalyzerReliabilityTests(unittest.TestCase):
    def test_multiline_signature_long_function_and_indirect_call_handling(self):
        filler = "\n".join(f"    value += {i};" for i in range(120))
        code = f"""static inline int
target_func(
    struct foo *ctx,
    int value)
{{
    bar(value);
    (*ctx->cb)(value);
{filler}
    ctx->value = value;
    return value;
}}

int after(void)
{{
    return 0;
}}

int caller(struct foo *ctx)
{{
    return target_func(ctx, 1);
}}
"""
        lines = code.splitlines()
        changed_line = next(i + 1 for i, line in enumerate(lines) if "ctx->value = value" in line)
        diff = f"""diff --git a/foo.c b/foo.c
--- a/foo.c
+++ b/foo.c
@@ -{changed_line},1 +{changed_line},1 @@
-    ctx->value = old;
+    ctx->value = value;
"""

        analyzer = FunctionAnalyzer()
        funcs = {fn.name: fn for fn in analyzer.extract_functions(code, "foo.c")}
        self.assertIn("target_func", funcs)
        self.assertIn("after", funcs)
        self.assertIn("caller", funcs)
        self.assertGreater(funcs["target_func"].end_line, funcs["target_func"].line_number + 100)
        self.assertLess(funcs["target_func"].end_line, funcs["after"].line_number)

        body, _ = analyzer.extract_function_body(lines, funcs["target_func"].line_number - 1)
        self.assertEqual(analyzer.extract_callees(body), ["bar"])
        self.assertEqual(analyzer.extract_indirect_calls(body), ["cb"])

        impact = analyzer.analyze_patch_impact(diff, code, "foo.c")
        modified = {fn.name for fn in impact["modified_functions"]}
        self.assertIn("target_func", modified)
        self.assertNotIn("after", modified)
        affected = {fn.name for fn in impact["affected_functions"]}
        self.assertIn("caller", affected)


class LowLevelNegativeSampleTests(unittest.TestCase):
    def test_low_signal_if_only_change_does_not_trigger_single_line_high_impact(self):
        diff = """diff --git a/foo.c b/foo.c
--- a/foo.c
+++ b/foo.c
@@ -1,2 +1,2 @@
-if (ret)
+if (rc)
"""
        patch = PatchInfo(commit_id="deadbeef", subject="rename local condition", diff_code=diff, modified_files=["foo.c"])
        dryrun = DryRunResult(applies_cleanly=True, apply_method="strict")
        details = PolicyEngine(PolicyConfig(profile="default"), llm_enabled=False).evaluate(
            patch,
            dryrun,
            git_mgr=object(),
            target_version="5.10",
        )

        rule_ids = {hit.get("rule_id") for hit in details.level_decision.rule_hits}
        self.assertNotIn("single_line_high_impact", rule_ids)
        self.assertEqual(details.level_decision.level, "L0")


if __name__ == "__main__":
    unittest.main()
