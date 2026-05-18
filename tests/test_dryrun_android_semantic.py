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
        self.assertIn("+            // Fixes b/230492947 b/337726734", result.adapted_patch)
        self.assertIn(
            "+            // Prevents background activity launch through #startNextMatchingActivity",
            result.adapted_patch,
        )
        self.assertIn("+                .setRealCallingUid(origCallingUid)", result.adapted_patch)
        self.assertNotIn("+                        .setRealCallingUid(origCallingUid)", result.adapted_patch)

        checked = DryRunAgent(self.git_mgr)._apply_check(
            result.adapted_patch,
            str(self.root),
            [],
        )
        self.assertTrue(checked.applies_cleanly, checked.error_output)

    def test_repeated_removed_line_uses_surrounding_context_not_first_global_match(self):
        file_path = Path("core/java/android/content/ContentProvider.java")
        full_path = self.root / file_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(self._content_provider_before(), encoding="utf-8")
        _git(self.root, "add", str(file_path))
        _git(self.root, "commit", "-m", "content provider before")

        patch = PatchInfo(
            commit_id="b" * 40,
            subject="Validate content provider file modes",
            diff_code=self._content_provider_patch(file_path),
            modified_files=[str(file_path)],
        )

        result = DryRunAgent(self.git_mgr).check_adaptive(patch, "android")

        self.assertTrue(result.applies_cleanly, result.error_output)
        self.assertEqual(result.adapted_patch.count(
            "+            enforceFilePermission(attributionSource, uri, updatedMode);"), 2)
        self.assertNotIn(
            "+            enforceFilePermission(attributionSource, uri, updatedMode);\n"
            "+            enforceFilePermission(attributionSource, uri, updatedMode);",
            result.adapted_patch,
        )
        self.assertIn(
            "+                        uri, updatedMode, CancellationSignal.fromTransport(cancellationSignal));",
            result.adapted_patch,
        )
        self.assertIn("+        private String validateFileMode(String mode) {", result.adapted_patch)

        checked = DryRunAgent(self.git_mgr)._apply_check(
            result.adapted_patch,
            str(self.root),
            [],
        )
        self.assertTrue(checked.applies_cleanly, checked.error_output)

    def test_comment_only_fix_note_is_preserved_when_old_note_is_absent(self):
        file_path = Path("core/java/android/content/CommentOnly.java")
        full_path = self.root / file_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(
            """class CommentOnly {
    void open() {
        enforceFilePermission(attributionSource, uri, mode);
        traceBegin(TRACE_TAG_DATABASE, "openFile: ", uri.getAuthority());
    }
}
""",
            encoding="utf-8",
        )
        _git(self.root, "add", str(file_path))
        _git(self.root, "commit", "-m", "comment only target")

        patch = PatchInfo(
            commit_id="c" * 40,
            subject="Preserve security fix note",
            diff_code=f"""diff --git a/{file_path} b/{file_path}
--- a/{file_path}
+++ b/{file_path}
@@ -1,6 +1,7 @@
 class CommentOnly {{
     void open() {{
-        // Old upstream-only note
+        // Fixes b/123456789: sanitize mode before permission check.
         enforceFilePermission(attributionSource, uri, mode);
         traceBegin(TRACE_TAG_DATABASE, "openFile: ", uri.getAuthority());
     }}
""",
            modified_files=[str(file_path)],
        )

        result = DryRunAgent(self.git_mgr).check_adaptive(patch, "android")

        self.assertTrue(result.applies_cleanly, result.error_output)
        self.assertIn(
            "+        // Fixes b/123456789: sanitize mode before permission check.",
            result.adapted_patch,
        )
        checked = DryRunAgent(self.git_mgr)._apply_check(
            result.adapted_patch,
            str(self.root),
            [],
        )
        self.assertTrue(checked.applies_cleanly, checked.error_output)

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
+
+            // Fixes b/230492947 b/337726734
+            // Prevents background activity launch through #startNextMatchingActivity
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

    def _content_provider_before(self):
        return """package android.content;

public abstract class ContentProvider {
    private class Transport {
        public ParcelFileDescriptor openFile(AttributionSource attributionSource, Uri uri,
                String mode, ICancellationSignal cancellationSignal)
                throws FileNotFoundException {
            uri = validateIncomingUri(uri);
            uri = maybeGetUriWithoutUserId(uri);
            enforceFilePermission(attributionSource, uri, mode);
            traceBegin(TRACE_TAG_DATABASE, "openFile: ", uri.getAuthority());
            final AttributionSource original = setCallingAttributionSource(
                    attributionSource);
            try {
                return mInterface.openFile(
                        uri, mode, CancellationSignal.fromTransport(cancellationSignal));
            } catch (RemoteException e) {
                throw e.rethrowAsRuntimeException();
            } finally {
                setCallingAttributionSource(original);
            }
        }

        public AssetFileDescriptor openAssetFile(AttributionSource attributionSource, Uri uri,
                String mode, ICancellationSignal cancellationSignal)
                throws FileNotFoundException {
            uri = validateIncomingUri(uri);
            uri = maybeGetUriWithoutUserId(uri);
            enforceFilePermission(attributionSource, uri, mode);
            traceBegin(TRACE_TAG_DATABASE, "openAssetFile: ", uri.getAuthority());
            final AttributionSource original = setCallingAttributionSource(
                    attributionSource);
            try {
                return mInterface.openAssetFile(
                        uri, mode, CancellationSignal.fromTransport(cancellationSignal));
            } catch (RemoteException e) {
                throw e.rethrowAsRuntimeException();
            } finally {
                setCallingAttributionSource(original);
            }
        }

        @Override
        public int checkUriPermission(@NonNull AttributionSource attributionSource, Uri uri,
                int uid, int modeFlags) {
            return 0;
        }
    }
}
"""

    def _content_provider_patch(self, path):
        return f"""diff --git a/{path} b/{path}
--- a/{path}
+++ b/{path}
@@ -8,13 +8,14 @@
             uri = validateIncomingUri(uri);
             uri = maybeGetUriWithoutUserId(uri);
-            enforceFilePermission(attributionSource, uri, mode);
+            final String updatedMode = validateFileMode(mode);
+            enforceFilePermission(attributionSource, uri, updatedMode);
             traceBegin(TRACE_TAG_DATABASE, "openFile: ", uri.getAuthority());
             final AttributionSource original = setCallingAttributionSource(
                     attributionSource);
             try {{
                 return mInterface.openFile(
-                        uri, mode, CancellationSignal.fromTransport(cancellationSignal));
+                        uri, updatedMode, CancellationSignal.fromTransport(cancellationSignal));
             }} catch (RemoteException e) {{
                 throw e.rethrowAsRuntimeException();
             }} finally {{
@@ -27,13 +28,14 @@
             uri = validateIncomingUri(uri);
             uri = maybeGetUriWithoutUserId(uri);
-            enforceFilePermission(attributionSource, uri, mode);
+            final String updatedMode = validateFileMode(mode);
+            enforceFilePermission(attributionSource, uri, updatedMode);
             traceBegin(TRACE_TAG_DATABASE, "openAssetFile: ", uri.getAuthority());
             final AttributionSource original = setCallingAttributionSource(
                     attributionSource);
             try {{
                 return mInterface.openAssetFile(
-                        uri, mode, CancellationSignal.fromTransport(cancellationSignal));
+                        uri, updatedMode, CancellationSignal.fromTransport(cancellationSignal));
             }} catch (RemoteException e) {{
                 throw e.rethrowAsRuntimeException();
             }} finally {{
@@ -42,6 +44,25 @@
             }}
         }}
 
+        private String validateFileMode(String mode) {{
+            // We currently only support the following modes: r, w, wt, wa, rw, rwt
+            // Note: ideally, we should check against the allowed modes and throw a
+            // SecurityException if the mode doesn't match any of them but to avoid app compat
+            // issues, we're silently dropping bits which allow modifying files when the write bit
+            // is not specified.
+            if (mode != null && mode.indexOf('w') == -1) {{
+                // Don't allow truncation without write
+                if (mode.indexOf('t') != -1) {{
+                    mode = mode.replace("t", "");
+                }}
+                // Don't allow appending without write
+                if (mode.indexOf('a') != -1) {{
+                    mode = mode.replace("a", "");
+                }}
+            }}
+            return mode;
+        }}
+
         @Override
         public int checkUriPermission(@NonNull AttributionSource attributionSource, Uri uri,
                 int uid, int modeFlags) {{
"""


if __name__ == "__main__":
    unittest.main()
