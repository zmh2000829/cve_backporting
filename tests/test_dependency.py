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


if __name__ == "__main__":
    unittest.main()
