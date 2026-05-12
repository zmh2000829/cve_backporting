#!/usr/bin/env python3
"""DryRun regression tests for Android hunk drift."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.dryrun import DryRunAgent
from core.git_manager import GitRepoManager
from core.models import PatchInfo


def _git(cwd: Path, *args: str):
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )


class DryRunAndroidSemanticTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        _git(self.root, "init")
        _git(self.root, "config", "user.email", "test@example.com")
        _git(self.root, "config", "user.name", "Tester")
        self.file_path = Path("services/core/java/com/android/server/wm/ActivityTaskManagerService.java")
        full_path = self.root / self.file_path
        full_path.parent.mkdir(parents=True)
        full_path.write_text(self._target_before(), encoding="utf-8")
        _git(self.root, "add", str(self.file_path))
        _git(self.root, "commit", "-m", "target before")
        self.git_mgr = GitRepoManager(
            {"android": {"path": str(self.root), "branch": "HEAD"}},
            use_cache=False,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_removed_code_line_is_not_dropped_when_upstream_removed_comments_are_absent(self):
        patch = PatchInfo(
            commit_id="a" * 40,
            subject="Fix BAL identity for next matching activity",
            diff_code=self._community_patch(),
            modified_files=[str(self.file_path)],
        )

        result = DryRunAgent(self.git_mgr).check_adaptive(patch, "android")

        self.assertTrue(result.applies_cleanly, result.error_output)
        self.assertIn(
            "-            options.getOptions(r).setAvoidMoveToFront();",
            result.adapted_patch,
        )
        self.assertIn(
            "+            // launchedFromUid of the calling activity represents the app that launches it.",
            result.adapted_patch,
        )
        self.assertIn("+                .setRealCallingUid(origCallingUid)", result.adapted_patch)

    def _target_before(self):
        return """package com.android.server.wm;

class ActivityTaskManagerService {
    void startNextMatchingActivity() {
        if (resultTo != null) {
            resultTo.removeResultsLocked(r, resultWho, requestCode);
        }

        final long origId = Binder.clearCallingIdentity();
        // TODO(b/64750076): Check if calling pid should really be -1.
        try {
            if (options == null) {
                options = new SafeActivityOptions(ActivityOptions.makeBasic());
            }
            options.getOptions(r).setAvoidMoveToFront();
            final int res = getActivityStartController()
                .obtainStarter(intent, "startNextMatchingActivity")
                .setCaller(r.app.getThread())
                .setResultTo(resultTo)
                .setResultWho(resultWho)
                .setRequestCode(requestCode)
                .setCallingUid(r.launchedFromUid)
                .setCallingPackage(r.launchedFromPackage)
                .setCallingFeatureId(r.launchedFromFeatureId)
                .setRealCallingPid(-1)
                .setRealCallingUid(r.launchedFromUid)
                .setActivityOptions(options)
                .execute();
            r.finishing = wasFinishing;
        } finally {
            Binder.restoreCallingIdentity(origId);
        }
    }
}
"""

    def _community_patch(self):
        path = self.file_path
        return f"""diff --git a/{path} b/{path}
--- a/{path}
+++ b/{path}
@@ -6,19 +6,23 @@
             resultTo.removeResultsLocked(r, resultWho, requestCode);
         }}
 
+        final int origCallingUid = Binder.getCallingUid();
+        final int origCallingPid = Binder.getCallingPid();
         final long origId = Binder.clearCallingIdentity();
         // TODO(b/64750076): Check if calling pid should really be -1.
         try {{
             if (options == null) {{
                 options = new SafeActivityOptions(ActivityOptions.makeBasic());
             }}
-            // Fixes b/230492947
-
-            // Prevents background activity launch through #startNextMatchingActivity
-            // An activity going into the background could still go back to the foreground
-            // if the intent used matches both:
-            // - the activity in the background
-            // - a second activity.
-            options.getOptions(r).setAvoidMoveToFront();
+            // launchedFromUid of the calling activity represents the app that launches it.
+            // It may have BAL privileges (i.e. the Launcher App). Using its identity to
+            // launch to launch next matching activity causes BAL.
+            // Change the realCallingUid to the calling activity's uid.
+            // In ActivityStarter, when caller is set, the callingUid and callingPid are
+            // ignored. So now both callingUid and realCallingUid is set to the caller app.
             final int res = getActivityStartController()
                 .obtainStarter(intent, "startNextMatchingActivity")
                 .setCaller(r.app.getThread())
@@ -25,8 +29,8 @@
                 .setCallingUid(r.launchedFromUid)
                 .setCallingPackage(r.launchedFromPackage)
                 .setCallingFeatureId(r.launchedFromFeatureId)
-                .setRealCallingPid(-1)
-                .setRealCallingUid(r.launchedFromUid)
+                .setRealCallingPid(origCallingPid)
+                .setRealCallingUid(origCallingUid)
                 .setActivityOptions(options)
                 .execute();
             r.finishing = wasFinishing;
"""


if __name__ == "__main__":
    unittest.main()
