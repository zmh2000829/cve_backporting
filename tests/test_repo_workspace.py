#!/usr/bin/env python3
"""Android repo workspace routing tests."""

import os
import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.dryrun import DryRunAgent
from agents.crawler import CrawlerAgent
from core.git_manager import GitRepoManager
from core.models import PatchInfo


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return result.stdout


class RepoWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / ".repo").mkdir()
        (self.root / "frameworks/base").mkdir(parents=True)
        (self.root / "system/core").mkdir(parents=True)
        (self.root / ".repo/manifest.xml").write_text(
            """<manifest>
  <default revision="HEAD" remote="aosp" />
  <project name="platform/frameworks/base" path="frameworks/base" />
  <project name="platform/system/core" path="system/core" />
</manifest>
""",
            encoding="utf-8",
        )
        self.base = self.root / "frameworks/base"
        self.core = self.root / "system/core"
        self.base_commit = self._init_project(self.base, "foo.c", "int f(void) { return 1; }\n")
        self.core_commit = self._init_project(self.core, "init.c", "int g(void) { return 2; }\n")
        self.git_mgr = GitRepoManager(
            {"android": {"type": "repo", "path": str(self.root), "manifest": ".repo/manifest.xml", "branch": "HEAD"}},
            use_cache=False,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _init_project(self, path: Path, filename: str, content: str) -> str:
        _git(path, "init")
        _git(path, "config", "user.email", "test@example.com")
        _git(path, "config", "user.name", "Tester")
        (path / filename).write_text(content, encoding="utf-8")
        _git(path, "add", filename)
        _git(path, "commit", "-m", f"add {filename}")
        return _git(path, "rev-parse", "HEAD").strip()

    def test_git_manager_routes_file_and_diff_to_repo_project(self):
        content = self.git_mgr.get_file_content("frameworks/base/foo.c", "android")
        self.assertIn("return 1", content)

        commits = self.git_mgr.search_by_files(["frameworks/base/foo.c"], "android", limit=5)
        self.assertTrue(commits)
        self.assertEqual(getattr(commits[0], "project_path", ""), "frameworks/base")

        diff = self.git_mgr.get_commit_diff(self.base_commit, "android", project_path="frameworks/base")
        self.assertIn("diff --git a/frameworks/base/foo.c b/frameworks/base/foo.c", diff)

        raw = self.git_mgr.run_git(["git", "show", "--format=", self.base_commit], "android")
        self.assertIn("int f(void)", raw)

    def test_dryrun_applies_android_repo_patch_inside_project(self):
        diff = """diff --git a/frameworks/base/foo.c b/frameworks/base/foo.c
--- a/frameworks/base/foo.c
+++ b/frameworks/base/foo.c
@@ -1 +1 @@
-int f(void) { return 1; }
+int f(void) { return 3; }
"""
        result = DryRunAgent(self.git_mgr).check_adaptive(
            PatchInfo(commit_id="abc", subject="change foo", diff_code=diff, modified_files=["frameworks/base/foo.c"]),
            "android",
        )
        self.assertTrue(result.applies_cleanly, result.error_output)
        self.assertEqual(result.apply_method, "strict")

    def test_manifest_includes_are_loaded_recursively(self):
        root = Path(tempfile.mkdtemp(dir=self.root))
        (root / ".repo").mkdir(parents=True)
        (root / "manifest_store/android").mkdir(parents=True)
        (root / "manifest_store/hisi").mkdir(parents=True)
        (root / ".repo/manifest.xml").write_text(
            """<manifest>
  <default revision="main" remote="origin" />
  <include name="android/common.xml" />
  <include name="hisi/system.xml" />
</manifest>
""",
            encoding="utf-8",
        )
        (root / "manifest_store/android/common.xml").write_text(
            """<manifest>
  <project name="platform/frameworks/base" path="frameworks/base" />
</manifest>
""",
            encoding="utf-8",
        )
        (root / "manifest_store/hisi/system.xml").write_text(
            """<manifest>
  <project name="vendor/hisi/system" path="vendor/hisi/system" revision="dev" />
</manifest>
""",
            encoding="utf-8",
        )
        mgr = GitRepoManager(
            {"android-inc": {
                "type": "repo",
                "path": str(root),
                "manifest": ".repo/manifest.xml",
                "manifest_include_dirs": ["manifest_store"],
            }},
            use_cache=False,
        )

        projects = mgr.list_repo_projects("android-inc")
        paths = {p.norm_path: p for p in projects}
        self.assertIn("frameworks/base", paths)
        self.assertIn("vendor/hisi/system", paths)
        self.assertEqual(paths["frameworks/base"].revision, "main")
        self.assertEqual(paths["vendor/hisi/system"].revision, "dev")

    def test_build_cache_can_use_repo_projects_bare_git_dir(self):
        root = Path(tempfile.mkdtemp(dir=self.root))
        (root / ".repo/projects/frameworks").mkdir(parents=True)
        (root / ".repo").mkdir(exist_ok=True)
        (root / ".repo/manifest.xml").write_text(
            """<manifest>
  <default revision="main" remote="origin" />
  <project name="platform/frameworks/base" path="frameworks/base" revision="main" />
</manifest>
""",
            encoding="utf-8",
        )
        src = root / "src-base"
        src.mkdir()
        _git(src, "init")
        _git(src, "config", "user.email", "test@example.com")
        _git(src, "config", "user.name", "Tester")
        (src / "foo.c").write_text("int f(void) { return 1; }\n", encoding="utf-8")
        _git(src, "add", "foo.c")
        _git(src, "commit", "-m", "add foo")
        _git(src, "branch", "-M", "main")
        bare = root / ".repo/projects/frameworks/base.git"
        subprocess.run(
            ["git", "clone", "--bare", str(src), str(bare)],
            check=True, capture_output=True, text=True,
        )
        mgr = GitRepoManager(
            {"android-bare": {"type": "repo", "path": str(root), "manifest": ".repo/manifest.xml"}},
            use_cache=True,
            cache_db_path=str(root / "cache.db"),
        )

        self.assertEqual(mgr.count_commits("android-bare"), 1)
        mgr.build_commit_cache("android-bare")
        self.assertEqual(mgr.get_cache_count("android-bare"), 1)

    def test_crawler_fetches_android_googlesource_project_and_prefixes_paths(self):
        commit = "a" * 40
        diff = """diff --git a/foo.c b/foo.c
--- a/foo.c
+++ b/foo.c
@@ -1 +1 @@
-int f(void) { return 1; }
+int f(void) { return 3; }
"""

        class Resp:
            def __init__(self, status_code, text):
                self.status_code = status_code
                self.text = text

        class FakeSession:
            def __init__(self):
                self.headers = {}
                self.urls = []

            def get(self, url, **_kwargs):
                self.urls.append(url)
                if url.endswith("?format=JSON"):
                    return Resp(200, ")]}'\n" + json.dumps({
                        "message": "Fix foo\n\nBody",
                        "author": {"name": "Tester", "email": "test@example.com", "time": "now"},
                        "tree_diff": [{"old_path": "foo.c", "new_path": "foo.c"}],
                    }))
                return Resp(200, base64.b64encode(diff.encode("utf-8")).decode("ascii"))

        crawler = CrawlerAgent(git_mgr=self.git_mgr)
        fake = FakeSession()
        crawler.session = fake

        patch = crawler.fetch_patch(
            commit,
            target_version="android",
            source_repo="platform/frameworks/base",
        )

        self.assertIsNotNone(patch)
        self.assertIn(
            "https://android.googlesource.com/platform/frameworks/base/+/" + commit,
            fake.urls[0],
        )
        self.assertEqual(patch.modified_files, ["frameworks/base/foo.c"])
        self.assertIn("diff --git a/frameworks/base/foo.c b/frameworks/base/foo.c", patch.diff_code)

    def test_repo_validate_worktree_is_created_for_commit_project(self):
        wt = Path(tempfile.mkdtemp(dir=self.root))
        rollback = f"{self.base_commit}~0"
        self.assertTrue(self.git_mgr.create_worktree("android", rollback, str(wt)))
        try:
            self.assertTrue((wt / "frameworks/base/foo.c").exists())
            mgr = GitRepoManager(
                {"android": {"type": "repo", "path": str(wt), "manifest": ".repo/manifest.xml", "branch": "HEAD"}},
                use_cache=False,
            )
            content = mgr.get_file_content("frameworks/base/foo.c", "android")
            self.assertIn("return 1", content)
        finally:
            self.git_mgr.remove_worktree("android", str(wt))


if __name__ == "__main__":
    unittest.main()
