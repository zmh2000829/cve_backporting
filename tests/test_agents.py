#!/usr/bin/env python3
"""
Agent 测试套件

用法:
  python -m tests.test_agents                         # 全部测试
  python -m tests.test_agents CVE-2024-26633          # 测试单个CVE
  python -m tests.test_agents mainline                # Mainline识别
  python -m tests.test_agents full CVE-2024-26633     # 端到端分析
  python -m tests.test_agents dryrun CVE-2024-26633   # Dry-run测试
  python -m tests.test_agents repos                   # 列出仓库
  python -m tests.test_agents build-cache <repo> [N]  # 构建缓存
"""

import sys
import os
import json
import logging
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import ConfigLoader
from core.git_manager import GitRepoManager
from agents.crawler import CrawlerAgent
from agents.analysis import AnalysisAgent
from agents.dependency import DependencyAgent
from agents.dryrun import DryRunAgent
from pipeline import Pipeline
from services.history_loader import detect_report_mode

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_config = None
_FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def _cfg():
    global _config
    if _config is None:
        p = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")
        _config = ConfigLoader.load(p)
    return _config


def _git_mgr(rv: str = None) -> GitRepoManager:
    c = _cfg()
    rcs = {k: {"path": v["path"], "branch": v.get("branch")} for k, v in c.repositories.items()}
    return GitRepoManager(rcs, use_cache=True)


def _default_repo() -> str:
    repos = list(_cfg().repositories.keys())
    return repos[0] if repos else ""


def _save(name: str, data):
    d = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    print(f"  保存: {p}")


class AgentSmokeDiscoveryTests(unittest.TestCase):
    def test_history_fixtures_are_present(self):
        self.assertTrue((_FIXTURE_ROOT / "history" / "analyze_fixed_legacy.json").exists())
        self.assertTrue((_FIXTURE_ROOT / "history" / "validate_legacy.json").exists())

    def test_detect_report_mode_for_legacy_examples(self):
        with (_FIXTURE_ROOT / "history" / "analyze_fixed_legacy.json").open("r", encoding="utf-8") as handle:
            analyze_payload = json.load(handle)
        with (_FIXTURE_ROOT / "history" / "validate_legacy.json").open("r", encoding="utf-8") as handle:
            validate_payload = json.load(handle)

        self.assertEqual(detect_report_mode(analyze_payload), "analyze")
        self.assertEqual(detect_report_mode(validate_payload), "validate")


# ─── Tests ───────────────────────────────────────────────────────────

def test_crawler(cve_id: str = "CVE-2024-26633"):
    """测试 Crawler Agent"""
    print(f"\n{'=' * 70}")
    print(f"[Crawler Agent] 获取 {cve_id}")
    print(f"{'=' * 70}")

    crawler = CrawlerAgent()
    cve = crawler.fetch_cve(cve_id)
    if not cve:
        print("  FAIL: 获取失败")
        return False

    print(f"  描述: {cve.description[:120]}...")
    print(f"  严重程度: {cve.severity}")
    print(f"  Mainline fix: {cve.mainline_fix_commit[:12] if cve.mainline_fix_commit else 'N/A'}")
    print(f"  引入commit: {cve.introduced_commit_id or '未知'}")
    print(f"  Fix commits: {len(cve.fix_commits)}")

    if cve.version_commit_mapping:
        print(f"  版本映射:")
        for ver in sorted(cve.version_commit_mapping):
            c = cve.version_commit_mapping[ver]
            ml = " [MAINLINE]" if ver == cve.mainline_version else ""
            print(f"    {ver:15s} -> {c[:12]}{ml}")

    if cve.fix_commit_id:
        patch = crawler.fetch_patch(cve.fix_commit_id)
        if patch:
            print(f"  Patch: {patch.subject}")
            print(f"  Files: {patch.modified_files}")

    _save(f"crawler_{cve_id.replace('-', '_')}.json", {
        "cve_id": cve.cve_id,
        "mainline_fix": cve.mainline_fix_commit,
        "version_mapping": cve.version_commit_mapping,
    })
    print("  PASS")
    return True


def test_mainline():
    """Mainline commit 识别准确性 (CVE-2025-40198)"""
    print(f"\n{'=' * 70}")
    print("[Crawler Agent] Mainline识别 (CVE-2025-40198)")
    print(f"{'=' * 70}")

    expected_ml = "8ecb790ea8c3fc69e77bace57f14cf0d7c177bd8"
    expected_ver = "6.18"

    crawler = CrawlerAgent()
    cve = crawler.fetch_cve("CVE-2025-40198")
    if not cve:
        print("  FAIL: 获取失败")
        return False

    ok = 0
    if cve.mainline_fix_commit[:12] == expected_ml[:12]:
        print(f"  PASS mainline_commit: {cve.mainline_fix_commit[:12]}")
        ok += 1
    else:
        print(f"  FAIL mainline_commit: {cve.mainline_fix_commit[:12]} != {expected_ml[:12]}")

    if cve.mainline_version == expected_ver:
        print(f"  PASS mainline_version: {cve.mainline_version}")
        ok += 1
    else:
        print(f"  FAIL mainline_version: {cve.mainline_version} != {expected_ver}")

    print(f"  Score: {ok}/2")
    return ok == 2


def test_analysis(commit_id: str, repo: str = None):
    """测试 Analysis Agent"""
    repo = repo or _default_repo()
    if not repo:
        print("  SKIP: 未配置仓库")
        return False

    print(f"\n{'=' * 70}")
    print(f"[Analysis Agent] 搜索 {commit_id[:12]} in {repo}")
    print(f"{'=' * 70}")

    crawler = CrawlerAgent()
    mgr = _git_mgr(repo)
    agent = AnalysisAgent(mgr)

    patch = crawler.fetch_patch(commit_id)
    sr = agent.search(
        commit_id,
        patch.subject if patch else "",
        patch.diff_code if patch else "",
        repo,
    )
    if sr.found:
        print(f"  FOUND: {sr.target_commit[:12]} via {sr.strategy} ({sr.confidence:.0%})")
    else:
        print(f"  NOT FOUND")
        for c in sr.candidates[:3]:
            sim = c.get("similarity", c.get("confidence", 0))
            print(f"    候选: {c.get('commit_id', '')[:12]} ({sim:.0%})")
    return sr.found


def test_dryrun(cve_id: str, repo: str = None):
    """测试 DryRun Agent"""
    repo = repo or _default_repo()
    if not repo:
        print("  SKIP: 未配置仓库")
        return False

    print(f"\n{'=' * 70}")
    print(f"[DryRun Agent] {cve_id} -> {repo}")
    print(f"{'=' * 70}")

    crawler = CrawlerAgent()
    cve = crawler.fetch_cve(cve_id)
    if not cve or not cve.fix_commit_id:
        print("  SKIP: 无fix commit")
        return False

    patch = crawler.fetch_patch(cve.fix_commit_id)
    if not patch:
        print("  SKIP: 无patch")
        return False

    mgr = _git_mgr(repo)
    agent = DryRunAgent(mgr)
    dr = agent.check(patch, repo)

    if dr.applies_cleanly:
        print("  结果: 可以干净应用")
    else:
        print(f"  结果: 无法应用")
        if dr.conflicting_files:
            print(f"  冲突文件: {dr.conflicting_files}")
        if dr.error_output:
            print(f"  错误: {dr.error_output[:300]}")
    if dr.stat_output:
        print(f"  统计:\n{dr.stat_output}")

    return True


def test_full(cve_id: str, repo: str = None):
    """端到端 Pipeline 测试"""
    repo = repo or _default_repo()
    if not repo:
        print("  SKIP: 未配置仓库")
        return False

    print(f"\n{'=' * 70}")
    print(f"[Pipeline] {cve_id} -> {repo}")
    print(f"{'=' * 70}")

    mgr = _git_mgr(repo)
    pipe = Pipeline(mgr)
    result = pipe.analyze(cve_id, repo)
    print(Pipeline.format_report(result))

    _save(f"pipeline_{cve_id.replace('-', '_')}.json", {
        "cve_id": result.cve_id,
        "is_vulnerable": result.is_vulnerable,
        "is_fixed": result.is_fixed,
        "dry_run_clean": result.dry_run.applies_cleanly if result.dry_run else None,
        "recommendations": result.recommendations,
    })
    return True


# ─── CLI ─────────────────────────────────────────────────────────────

def cmd_repos():
    c = _cfg()
    if not c.repositories:
        print("未配置仓库")
        return
    mgr = _git_mgr()
    for name, info in c.repositories.items():
        cnt = mgr.get_cache_count(name)
        print(f"  {name}: {info.get('path')} (分支: {info.get('branch')}, 缓存: {cnt})")


def cmd_build_cache(repo: str, n: int = None):
    mgr = _git_mgr(repo)
    mgr.build_commit_cache(repo, n)
    print(f"  完成: {mgr.get_cache_count(repo)} commits")


def main():
    args = sys.argv[1:]
    if not args:
        ok = test_crawler("CVE-2024-26633") and test_mainline()
        if _default_repo():
            ok &= test_full("CVE-2024-26633")
        print(f"\n{'=' * 70}")
        print(f"测试{'全部通过' if ok else '部分失败'}")
        return

    cmd = args[0]
    if cmd == "repos":
        cmd_repos()
    elif cmd == "build-cache":
        r = args[1] if len(args) > 1 else _default_repo()
        n = None if len(args) <= 2 or args[2].lower() == "all" else int(args[2])
        cmd_build_cache(r, n)
    elif cmd == "mainline":
        test_mainline()
    elif cmd == "full":
        test_full(args[1] if len(args) > 1 else "CVE-2024-26633", args[2] if len(args) > 2 else None)
    elif cmd == "dryrun":
        test_dryrun(args[1] if len(args) > 1 else "CVE-2024-26633", args[2] if len(args) > 2 else None)
    elif cmd == "search":
        if len(args) > 1:
            test_analysis(args[1], args[2] if len(args) > 2 else None)
        else:
            print("用法: test_agents.py search <commit_id> [repo]")
    elif cmd.startswith("CVE-"):
        test_crawler(cmd)
    else:
        print(f"未知: {cmd}\n{__doc__}")


if __name__ == "__main__":
    main()
