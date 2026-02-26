#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE补丁回溯工具测试套件
可作为测试运行，也可作为CLI使用

用法:
  python tests/test_crawl_cve.py                          # 运行完整测试
  python tests/test_crawl_cve.py CVE-2024-26633           # 测试单个CVE
  python tests/test_crawl_cve.py mainline                 # 测试mainline识别
  python tests/test_crawl_cve.py full CVE-2024-26633      # 端到端分析
  python tests/test_crawl_cve.py repos                    # 列出仓库
  python tests/test_crawl_cve.py build-cache <repo> [N]   # 构建缓存
"""

import sys
import os
import json
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crawl_cve_patch import CveFetcher, CveInfo
from config_loader import ConfigLoader
from git_repo_manager import GitRepoManager
from enhanced_cve_analyzer import BackportAnalyzer

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ─── 配置辅助 ────────────────────────────────────────────────────────

_config = None


def _load_config():
    global _config
    if _config is None:
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")
        _config = ConfigLoader.load(path)
    return _config


def _make_git_mgr(repo_version: str = None) -> GitRepoManager:
    config = _load_config()
    repo_configs = {
        k: {"path": v["path"], "branch": v.get("branch")}
        for k, v in config.repositories.items()
    }
    return GitRepoManager(repo_configs, use_cache=True)


def _default_repo() -> str:
    repos = list(_load_config().repositories.keys())
    return repos[0] if repos else ""


def _save_result(filename: str, data):
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    print(f"  结果已保存: {path}")


# ─── 测试: CVE信息获取 ───────────────────────────────────────────────

def test_fetch_cve(cve_id: str = "CVE-2024-26633"):
    """测试从MITRE API获取CVE信息"""
    print(f"\n{'='*70}")
    print(f"测试CVE信息获取: {cve_id}")
    print(f"{'='*70}")

    fetcher = CveFetcher()
    cve = fetcher.fetch_cve(cve_id)

    if not cve:
        print(f"  FAIL: 获取 {cve_id} 失败")
        return False

    print(f"  描述: {cve.description[:120]}...")
    print(f"  严重程度: {cve.severity}")
    print(f"  Mainline fix: {cve.mainline_fix_commit[:12] if cve.mainline_fix_commit else 'N/A'}")
    print(f"  Mainline版本: {cve.mainline_version or 'N/A'}")
    print(f"  引入commit: {cve.introduced_commit_id or '未知'}")
    print(f"  Fix commits: {len(cve.fix_commits)}")

    if cve.version_commit_mapping:
        print(f"  版本映射:")
        for ver in sorted(cve.version_commit_mapping):
            c = cve.version_commit_mapping[ver]
            ml = " [MAINLINE]" if ver == cve.mainline_version else ""
            print(f"    {ver:15s} -> {c[:12]}{ml}")

    # 获取patch
    if cve.fix_commit_id:
        patch = fetcher.fetch_patch(cve.fix_commit_id)
        if patch:
            print(f"  Patch subject: {patch.subject}")
            print(f"  Patch files: {patch.modified_files}")
        else:
            print(f"  WARN: 获取patch失败")

    _save_result(f"cve_{cve_id.replace('-', '_')}.json", {
        "cve_id": cve.cve_id,
        "mainline_fix": cve.mainline_fix_commit,
        "mainline_version": cve.mainline_version,
        "version_mapping": cve.version_commit_mapping,
        "fix_commits": cve.fix_commits,
        "introduced": cve.introduced_commit_id,
    })
    print(f"  PASS")
    return True


# ─── 测试: Mainline Commit 识别 ─────────────────────────────────────

def test_mainline_identification():
    """使用CVE-2025-40198验证mainline commit识别准确性"""
    print(f"\n{'='*70}")
    print(f"测试Mainline Commit识别 (CVE-2025-40198)")
    print(f"{'='*70}")

    expected = {
        "mainline_commit": "8ecb790ea8c3fc69e77bace57f14cf0d7c177bd8",
        "mainline_version": "6.18",
        "version_mapping": {
            "5.4.301": "7bf46ff83a0ef11836e38ebd72cdc5107209342d",
            "5.10.246": "b2bac84fde28fb6a88817b8b761abda17a1d300b",
            "6.1.158": "e651294218d2684302ee5ed95ccf381646f3e5b4",
            "6.6.114": "01829af7656b56d83682b3491265d583d502e502",
            "6.12.54": "2a0cf438320cdb783e0378570744c0ef0d83e934",
            "6.17.4": "a6e94557cd05adc82fae0400f6e17745563e5412",
            "6.18": "8ecb790ea8c3fc69e77bace57f14cf0d7c177bd8",
        },
    }

    fetcher = CveFetcher()
    cve = fetcher.fetch_cve("CVE-2025-40198")

    if not cve:
        print("  FAIL: 获取CVE失败")
        return False

    score = 0
    total = 4

    # Check 1: mainline commit
    if cve.mainline_fix_commit[:12] == expected["mainline_commit"][:12]:
        print(f"  PASS mainline_commit: {cve.mainline_fix_commit[:12]}")
        score += 1
    else:
        print(f"  FAIL mainline_commit: got {cve.mainline_fix_commit[:12]}, "
              f"want {expected['mainline_commit'][:12]}")

    # Check 2: mainline version
    if cve.mainline_version == expected["mainline_version"]:
        print(f"  PASS mainline_version: {cve.mainline_version}")
        score += 1
    else:
        print(f"  FAIL mainline_version: got {cve.mainline_version}, "
              f"want {expected['mainline_version']}")

    # Check 3: version mapping
    mapping_ok = 0
    for ver, exp_commit in expected["version_mapping"].items():
        actual = cve.version_commit_mapping.get(ver, "")
        if actual[:12] == exp_commit[:12]:
            mapping_ok += 1
        else:
            print(f"  FAIL mapping {ver}: got {actual[:12]}, want {exp_commit[:12]}")

    if mapping_ok == len(expected["version_mapping"]):
        print(f"  PASS version_mapping: {mapping_ok}/{len(expected['version_mapping'])}")
        score += 1
    else:
        print(f"  PARTIAL version_mapping: {mapping_ok}/{len(expected['version_mapping'])}")

    # Check 4: fix_commit_id == mainline_commit
    if cve.fix_commit_id and cve.fix_commit_id[:12] == expected["mainline_commit"][:12]:
        print(f"  PASS fix_commit_id == mainline_commit")
        score += 1
    else:
        print(f"  FAIL fix_commit_id: got {cve.fix_commit_id[:12] if cve.fix_commit_id else 'N/A'}")

    print(f"\n  Score: {score}/{total}")
    return score == total


# ─── 测试: 目标仓库搜索 ─────────────────────────────────────────────

def test_repo_search(commit_id: str, repo: str = None):
    """测试在目标仓库中搜索commit"""
    repo = repo or _default_repo()
    if not repo:
        print("  SKIP: 未配置仓库")
        return False

    print(f"\n{'='*70}")
    print(f"测试仓库搜索: {commit_id[:12]} in {repo}")
    print(f"{'='*70}")

    mgr = _make_git_mgr(repo)

    # L1: ID match
    print(f"  [L1] 精确ID匹配...")
    exact = mgr.find_commit_by_id(commit_id, repo)
    if exact:
        print(f"  FOUND: {exact['commit_id'][:12]} - {exact['subject'][:60]}")
        return True

    # L2: keyword search
    fetcher = CveFetcher()
    patch = fetcher.fetch_patch(commit_id)
    if patch and patch.subject:
        print(f"  [L2] Subject搜索: {patch.subject[:60]}")
        from enhanced_patch_matcher import extract_keywords, subject_similarity
        keywords = extract_keywords(patch.subject)
        if keywords:
            candidates = mgr.search_by_keywords(keywords, repo, limit=10)
            for c in candidates[:5]:
                sim = subject_similarity(patch.subject, c.subject)
                marker = " <--" if sim > 0.85 else ""
                print(f"    {c.commit_id[:12]} [{sim:.0%}] {c.subject[:50]}{marker}")

    print(f"  NOT FOUND")
    return False


# ─── 测试: 端到端分析 ────────────────────────────────────────────────

def test_full_analysis(cve_id: str, repo: str = None):
    """端到端CVE分析"""
    repo = repo or _default_repo()
    if not repo:
        print("  SKIP: 未配置仓库")
        return False

    print(f"\n{'='*70}")
    print(f"端到端分析: {cve_id} -> {repo}")
    print(f"{'='*70}")

    fetcher = CveFetcher()
    mgr = _make_git_mgr(repo)
    analyzer = BackportAnalyzer(fetcher, mgr)

    result = analyzer.analyze(cve_id, repo)
    report = BackportAnalyzer.format_report(result)
    print(report)

    _save_result(f"analysis_{cve_id.replace('-', '_')}.json", {
        "cve_id": result.cve_id,
        "target_version": result.target_version,
        "is_vulnerable": result.is_vulnerable,
        "is_fixed": result.is_fixed,
        "introduced_search": {
            "found": result.introduced_search.found if result.introduced_search else False,
            "strategy": result.introduced_search.strategy if result.introduced_search else "",
            "confidence": result.introduced_search.confidence if result.introduced_search else 0,
            "target_commit": result.introduced_search.target_commit if result.introduced_search else "",
        },
        "fix_search": {
            "found": result.fix_search.found if result.fix_search else False,
            "strategy": result.fix_search.strategy if result.fix_search else "",
            "confidence": result.fix_search.confidence if result.fix_search else 0,
            "target_commit": result.fix_search.target_commit if result.fix_search else "",
        },
        "prerequisite_patches": result.prerequisite_patches,
        "recommendations": result.recommendations,
    })

    return True


# ─── CLI: 仓库管理 ──────────────────────────────────────────────────

def cmd_list_repos():
    """列出配置的仓库及缓存状态"""
    config = _load_config()
    if not config.repositories:
        print("未配置仓库. 请编辑 config.yaml")
        return

    mgr = _make_git_mgr()
    print(f"\n配置的仓库:")
    print("-" * 60)
    for name, info in config.repositories.items():
        path = info.get("path", "N/A")
        branch = info.get("branch", "N/A")
        exists = os.path.exists(path)
        count = mgr.get_cache_count(name)
        status = f"路径{'存在' if exists else '不存在'}, 缓存: {count} commits"
        print(f"  {name}")
        print(f"    路径: {path}")
        print(f"    分支: {branch}")
        print(f"    状态: {status}")


def cmd_build_cache(repo: str, max_commits: int = None):
    """构建缓存"""
    print(f"\n构建缓存: {repo}, 数量: {max_commits or '全部'}")
    print("-" * 60)
    mgr = _make_git_mgr(repo)
    mgr.build_commit_cache(repo, max_commits)
    count = mgr.get_cache_count(repo)
    print(f"  完成: {count} commits")


# ─── 主入口 ──────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    if not args:
        print("运行完整测试套件...\n")
        ok = True
        ok &= test_fetch_cve("CVE-2024-26633")
        ok &= test_mainline_identification()
        if _default_repo():
            ok &= test_full_analysis("CVE-2024-26633")
        print(f"\n{'='*70}")
        print(f"测试{'全部通过' if ok else '部分失败'}")
        return

    cmd = args[0]

    if cmd == "repos":
        cmd_list_repos()
    elif cmd == "build-cache":
        repo = args[1] if len(args) > 1 else _default_repo()
        max_c = None
        if len(args) > 2:
            max_c = None if args[2].lower() == "all" else int(args[2])
        cmd_build_cache(repo, max_c)
    elif cmd == "mainline":
        test_mainline_identification()
    elif cmd == "full":
        cve_id = args[1] if len(args) > 1 else "CVE-2024-26633"
        repo = args[2] if len(args) > 2 else None
        test_full_analysis(cve_id, repo)
    elif cmd == "search":
        commit_id = args[1] if len(args) > 1 else ""
        repo = args[2] if len(args) > 2 else None
        if commit_id:
            test_repo_search(commit_id, repo)
        else:
            print("用法: python test_crawl_cve.py search <commit_id> [repo]")
    elif cmd.startswith("CVE-"):
        test_fetch_cve(cmd)
    else:
        print(f"未知命令: {cmd}")
        print(__doc__)


if __name__ == "__main__":
    main()
