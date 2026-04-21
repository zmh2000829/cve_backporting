#!/usr/bin/env python3
"""Dependency Agent 语义证据回归。"""

import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.dependency import DependencyAgent
from core.models import CveInfo, PatchInfo


class _MockDependencyGit:
    def __init__(self, commits, diffs):
        self.commits = commits
        self.diffs = diffs

    def search_by_files(self, files, target_version, limit=50, after_ts=0, no_merges=True):
        return list(self.commits)

    def get_commit_diff(self, commit_id, target_version):
        return self.diffs.get(commit_id, "")

    def find_commit_by_id(self, commit_id, target_version):
        for item in self.commits:
            if item.commit_id == commit_id:
                return {"timestamp": item.timestamp}
        return None


class DependencyEvidenceTests(unittest.TestCase):
    def test_prerequisite_patch_captures_shared_field_lock_and_state_evidence(self):
        fix_patch = PatchInfo(
            commit_id="fixdeadbeef",
            subject="fix",
            diff_code="""diff --git a/net/foo.c b/net/foo.c
@@ -1,4 +1,5 @@
-    spin_lock(&ctx->lock);
+    spin_lock(&ctx->lock);
-    if (ctx->state == OLD_STATE)
+    if (ctx->state == NEW_STATE)
+        ctx->status = NEW_STATE;
""",
            modified_files=["net/foo.c"],
        )
        candidate = SimpleNamespace(
            commit_id="abc123456789",
            subject="prep state and lock",
            author="tester",
            timestamp=100,
        )
        candidate_diff = """diff --git a/net/foo.c b/net/foo.c
@@ -10,4 +10,5 @@
-    spin_lock(&ctx->lock);
+    spin_lock(&ctx->lock);
-    ctx->status = OLD_STATE;
+    ctx->status = NEW_STATE;
+    if (ctx->state)
"""
        agent = DependencyAgent(
            _MockDependencyGit([candidate], {candidate.commit_id: candidate_diff})
        )

        result = agent.analyze(
            fix_patch,
            CveInfo(cve_id="CVE-TEST-DEP"),
            target_version="5.10-hulk",
        )

        prereqs = result["prerequisite_patches"]
        self.assertEqual(len(prereqs), 1)
        patch = prereqs[0]
        self.assertIn("ctx->lock", patch.shared_lock_domains)
        self.assertIn("ctx->state", patch.shared_fields)
        self.assertIn("ctx->status", patch.shared_state_points)
        self.assertTrue(patch.evidence_lines)

        details = result["analysis_details"]
        self.assertGreaterEqual(details.semantic_overlap_summary["shared_lock_domains"], 1)
        self.assertGreaterEqual(details.semantic_overlap_summary["shared_fields"], 1)
        self.assertGreaterEqual(details.semantic_overlap_summary["shared_state_points"], 1)
        self.assertTrue(details.prerequisite_evidence_samples)

    def test_weak_same_function_candidates_do_not_become_prerequisites(self):
        fix_patch = PatchInfo(
            commit_id="fixdeadbeef",
            subject="fix",
            diff_code="""diff --git a/drivers/foo.c b/drivers/foo.c
--- a/drivers/foo.c
+++ b/drivers/foo.c
@@ -1,1 +1,1 @@ foo_worker {
-    value = old;
+    value = new;
""",
            modified_files=["drivers/foo.c"],
        )
        commits = [
            SimpleNamespace(
                commit_id=f"weak{i:02d}abcdef",
                subject=f"background cleanup {i}",
                author="tester",
                timestamp=100 + i,
            )
            for i in range(15)
        ]
        diffs = {
            c.commit_id: f"""diff --git a/drivers/foo.c b/drivers/foo.c
--- a/drivers/foo.c
+++ b/drivers/foo.c
@@ -{100 + i},1 +{100 + i},1 @@ foo_worker {{
-    tmp = {i};
+    tmp = {i + 1};
"""
            for i, c in enumerate(commits)
        }
        agent = DependencyAgent(_MockDependencyGit(commits, diffs))

        result = agent.analyze(
            fix_patch,
            CveInfo(cve_id="CVE-TEST-WEAK"),
            target_version="5.10-hulk",
        )

        self.assertEqual(result["prerequisite_patches"], [])
        details = result["analysis_details"]
        self.assertEqual(details.strong_count, 0)
        self.assertEqual(details.medium_count, 0)
        self.assertEqual(details.weak_count, 15)
        self.assertIn("weak 候选仅作为背景线索", details.no_prerequisite_reason)

    def test_actionable_prerequisites_are_capped(self):
        fix_patch = PatchInfo(
            commit_id="fixdeadbeef",
            subject="fix",
            diff_code="""diff --git a/drivers/foo.c b/drivers/foo.c
--- a/drivers/foo.c
+++ b/drivers/foo.c
@@ -20,1 +20,1 @@ foo_worker {
-    if (ctx->limit)
+    if (ctx->limit && ready)
""",
            modified_files=["drivers/foo.c"],
        )
        commits = [
            SimpleNamespace(
                commit_id=f"medium{i:02d}abcdef",
                subject=f"prep ctx limit {i}",
                author="tester",
                timestamp=100 + i,
            )
            for i in range(12)
        ]
        diffs = {
            c.commit_id: f"""diff --git a/drivers/foo.c b/drivers/foo.c
--- a/drivers/foo.c
+++ b/drivers/foo.c
@@ -20,1 +20,1 @@ foo_worker {{
-    if (ctx->limit == {i})
+    if (ctx->limit == {i + 1})
"""
            for i, c in enumerate(commits)
        }
        agent = DependencyAgent(_MockDependencyGit(commits, diffs))

        result = agent.analyze(
            fix_patch,
            CveInfo(cve_id="CVE-TEST-CAP"),
            target_version="5.10-hulk",
        )

        prereqs = result["prerequisite_patches"]
        self.assertEqual(len(prereqs), 10)
        self.assertTrue(all(p.grade == "medium" for p in prereqs))
        self.assertEqual(result["analysis_details"].medium_count, 10)


if __name__ == "__main__":
    unittest.main()
