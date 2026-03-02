"""
Pipeline 编排器
串联四个Agent完成端到端CVE补丁回溯分析：
  Crawler -> Analysis -> Dependency -> DryRun
"""

import logging
from typing import Optional, Callable

from core.models import AnalysisResult
from core.git_manager import GitRepoManager
from agents.crawler import CrawlerAgent
from agents.analysis import AnalysisAgent
from agents.dependency import DependencyAgent
from agents.dryrun import DryRunAgent

logger = logging.getLogger(__name__)

# UI 回调协议: on_stage(key, status, detail)
StageCB = Optional[Callable[[str, str, str], None]]

STAGES = [
    ("crawler_cve",  "Crawler  │ 获取CVE信息"),
    ("crawler_patch", "Crawler  │ 获取修复补丁"),
    ("analysis_intro", "Analysis │ 搜索引入commit"),
    ("analysis_fix",  "Analysis │ 搜索修复commit"),
    ("analysis_bp",   "Analysis │ 检查stable backport"),
    ("dependency",    "Dependency│ 前置依赖分析"),
    ("dryrun",        "DryRun   │ 补丁试应用"),
]


class Pipeline:
    """CVE补丁回溯分析流水线"""

    def __init__(self, git_mgr: GitRepoManager, api_timeout: int = 30):
        self.crawler = CrawlerAgent(api_timeout=api_timeout, git_mgr=git_mgr)
        self.analysis = AnalysisAgent(git_mgr)
        self.dependency = DependencyAgent(git_mgr)
        self.dryrun = DryRunAgent(git_mgr)
        self.git_mgr = git_mgr

    def analyze(self, cve_id: str, target_version: str,
                enable_dryrun: bool = True,
                on_stage: StageCB = None) -> AnalysisResult:
        result = AnalysisResult(cve_id=cve_id, target_version=target_version)

        def _cb(key, status, detail=""):
            if on_stage:
                on_stage(key, status, detail)

        # ── Step 1: Crawler - CVE ────────────────────────────────────
        _cb("crawler_cve", "running")
        cve_info = self.crawler.fetch_cve(cve_id)
        if not cve_info or not cve_info.fix_commit_id:
            _cb("crawler_cve", "fail", "无法获取CVE信息")
            result.recommendations.append(f"无法获取 {cve_id} 的修复commit信息")
            return result
        result.cve_info = cve_info
        ml = cve_info.mainline_fix_commit[:12] if cve_info.mainline_fix_commit else "N/A"
        _cb("crawler_cve", "success",
            f"mainline={ml} ({cve_info.mainline_version or 'N/A'}), "
            f"{len(cve_info.fix_commits)} fix, {len(cve_info.introduced_commits)} intro")

        # ── Step 2: Crawler - Patch ──────────────────────────────────
        _cb("crawler_patch", "running")
        fix_patch = self.crawler.fetch_patch(cve_info.fix_commit_id, target_version)
        if not fix_patch:
            _cb("crawler_patch", "fail", "获取补丁失败 (远程+本地均不可用)")
            result.recommendations.append("无法获取修复补丁内容 (googlesource不可达且本地仓库无此commit)")
            return result
        result.fix_patch = fix_patch
        _cb("crawler_patch", "success",
            f"{fix_patch.subject[:50]}  ({len(fix_patch.modified_files)} files)")

        # ── Step 3: Analysis - 引入commit (启用包含度匹配) ─────────────
        if cve_info.introduced_commit_id:
            _cb("analysis_intro", "running")
            intro_patch = self.crawler.fetch_patch(cve_info.introduced_commit_id, target_version)
            result.introduced_search = self.analysis.search(
                cve_info.introduced_commit_id,
                intro_patch.subject if intro_patch else "",
                intro_patch.diff_code if intro_patch else "",
                target_version,
                use_containment=True,
            )
            result.is_vulnerable = result.introduced_search.found
            if result.is_vulnerable:
                _cb("analysis_intro", "success",
                    f"命中 {result.introduced_search.target_commit[:12]} "
                    f"via {result.introduced_search.strategy}")
                result.recommendations.append(
                    f"目标仓库包含漏洞引入commit ({result.introduced_search.target_commit[:12]})")
            else:
                _cb("analysis_intro", "warn", "未找到, 可能不受影响")
                result.recommendations.append("未找到漏洞引入commit, 可能不受影响(建议人工确认)")
        else:
            _cb("analysis_intro", "skip", "无引入commit信息")
            result.is_vulnerable = True

        # ── Step 4: Analysis - 修复commit ────────────────────────────
        _cb("analysis_fix", "running")
        result.fix_search = self.analysis.search(
            cve_info.fix_commit_id, fix_patch.subject,
            fix_patch.diff_code, target_version,
        )
        result.is_fixed = result.fix_search.found

        if result.is_fixed:
            _cb("analysis_fix", "success",
                f"已合入 {result.fix_search.target_commit[:12]} "
                f"({result.fix_search.confidence:.0%}) via {result.fix_search.strategy}")
            result.recommendations.append(
                f"修复补丁已合入 ({result.fix_search.target_commit[:12]}), "
                f"置信度 {result.fix_search.confidence:.0%}")
            _cb("analysis_bp", "skip", "已修复")
            _cb("dependency", "skip", "已修复")
            _cb("dryrun", "skip", "已修复")
            return result

        _cb("analysis_fix", "warn", "未合入")

        # 尝试stable backport
        _cb("analysis_bp", "running")
        bp = self._try_stable_backport(cve_info, target_version)
        if bp:
            result.is_fixed = True
            result.fix_search = bp
            _cb("analysis_bp", "success", f"backport已合入 {bp.target_commit[:12]}")
            result.recommendations.append(f"stable backport已合入 ({bp.target_commit[:12]})")
            _cb("dependency", "skip", "已修复")
            _cb("dryrun", "skip", "已修复")
            return result
        _cb("analysis_bp", "warn", "无可用backport")

        # ── Step 5: Dependency ───────────────────────────────────────
        _cb("dependency", "running")
        dep = self.dependency.analyze(
            fix_patch, cve_info, target_version,
            fix_search=result.fix_search,
            intro_search=result.introduced_search,
        )
        result.prerequisite_patches = dep["prerequisite_patches"]
        result.conflict_files = dep["conflict_files"]
        result.recommendations.extend(dep["recommendations"])
        n_pre = len(result.prerequisite_patches)
        if n_pre > 0:
            n_s = sum(1 for p in result.prerequisite_patches if p.grade == "strong")
            n_m = sum(1 for p in result.prerequisite_patches if p.grade == "medium")
            parts = []
            if n_s:
                parts.append(f"{n_s}强")
            if n_m:
                parts.append(f"{n_m}中")
            parts.append(f"共{n_pre}个")
            _cb("dependency", "success", " / ".join(parts))
        else:
            _cb("dependency", "warn", "无前置依赖")

        # ── Step 6: DryRun ───────────────────────────────────────────
        if enable_dryrun:
            _cb("dryrun", "running")
            result.dry_run = self.dryrun.check(fix_patch, target_version)
            if result.dry_run.applies_cleanly:
                _cb("dryrun", "success", "可以干净应用")
                result.recommendations.append("Dry-run: 补丁可以干净应用")
            else:
                nc = len(result.dry_run.conflicting_files)
                cf = ", ".join(result.dry_run.conflicting_files[:3])
                # 尝试3-way
                dr3 = self.dryrun.check_with_3way(fix_patch, target_version)
                if dr3.applies_cleanly:
                    result.dry_run = dr3
                    _cb("dryrun", "success", "3-way merge成功")
                    result.recommendations.append("Dry-run: 3-way merge可以成功应用")
                else:
                    _cb("dryrun", "fail", f"{nc} 个文件冲突: {cf}")
                    result.recommendations.append(f"Dry-run: 补丁无法直接应用, {nc} 个文件冲突")
        else:
            _cb("dryrun", "skip", "已跳过")

        not_merged = f"修复补丁 {cve_info.fix_commit_id[:12]} 未合入"
        result.recommendations.insert(0, not_merged)

        return result

    def _try_stable_backport(self, cve_info, tv: str):
        for ver in cve_info.version_commit_mapping:
            if ver.startswith("5.10"):
                bp_cid = cve_info.version_commit_mapping[ver]
                if bp_cid != cve_info.fix_commit_id:
                    bp_patch = self.crawler.fetch_patch(bp_cid, tv)
                    if bp_patch:
                        sr = self.analysis.search(bp_cid, bp_patch.subject,
                                                   bp_patch.diff_code, tv)
                        if sr.found:
                            return sr
        return None
