"""
Pipeline 编排器
串联四个Agent完成端到端CVE补丁回溯分析：
  Crawler -> Analysis -> Dependency -> DryRun
"""

import logging
from typing import Optional, Callable

from core.models import AnalysisResult
from core.git_manager import GitRepoManager
from core.matcher import PathMapper
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

    def __init__(self, git_mgr: GitRepoManager, api_timeout: int = 30,
                 path_mappings: list = None):
        pm = PathMapper(path_mappings) if path_mappings else PathMapper()
        self.crawler = CrawlerAgent(api_timeout=api_timeout, git_mgr=git_mgr)
        self.analysis = AnalysisAgent(git_mgr, path_mapper=pm)
        self.dependency = DependencyAgent(git_mgr, path_mapper=pm)
        self.dryrun = DryRunAgent(git_mgr, path_mapper=pm)
        self.git_mgr = git_mgr

    def analyze(self, cve_id: str, target_version: str,
                enable_dryrun: bool = True,
                on_stage: StageCB = None,
                cve_info=None) -> AnalysisResult:
        result = AnalysisResult(cve_id=cve_id, target_version=target_version)

        def _cb(key, status, detail=""):
            if on_stage:
                on_stage(key, status, detail)

        # ── Step 1: Crawler - CVE ────────────────────────────────────
        _cb("crawler_cve", "running")
        prefer_local = cve_info is not None and cve_info.fix_commit_id
        if prefer_local:
            logger.info("[Pipeline] 使用预提供的 CveInfo, 跳过 MITRE 爬取")
        else:
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
        fix_patch = self.crawler.fetch_patch(
            cve_info.fix_commit_id, target_version,
            local_first=prefer_local)
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
            intro_patch = self.crawler.fetch_patch(
                cve_info.introduced_commit_id, target_version,
                local_first=prefer_local)
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

        # ── Step 6: DryRun (多级自适应) ──────────────────────────────
        if enable_dryrun:
            _cb("dryrun", "running")
            # 优先使用 stable backport 补丁 (路径和 context 更匹配目标分支)
            dryrun_patch = fix_patch
            bp_patch = self._find_stable_patch(cve_info, target_version)
            if bp_patch and bp_patch.diff_code:
                dryrun_patch = bp_patch
                logger.info("[Pipeline] DryRun 使用 stable backport 补丁: %s",
                            bp_patch.commit_id[:12])
            result.dry_run = self.dryrun.check_adaptive(
                dryrun_patch, target_version)
            dr = result.dry_run
            if dr.applies_cleanly:
                method_labels = {
                    "strict": "可以干净应用",
                    "context-C1": "上下文偏移已适配 (-C1)",
                    "3way": "3-way merge成功",
                    "regenerated": "上下文重生成成功",
                    "conflict-adapted": "冲突已适配 (需人工审查)",
                }
                label = method_labels.get(dr.apply_method, dr.apply_method)
                if dr.apply_method == "strict":
                    _cb("dryrun", "success", label)
                else:
                    _cb("dryrun", "success", f"{label}")
                result.recommendations.append(f"Dry-run: {label}")
                if dr.adapted_patch:
                    result.recommendations.append(
                        "已生成适配后的补丁 (原始改动不变, 仅更新 context lines)")
            else:
                nc = len(dr.conflicting_files)
                nh = len(dr.conflict_hunks)
                cf = ", ".join(dr.conflicting_files[:3])
                if nh:
                    sev_counts = {}
                    for h in dr.conflict_hunks:
                        s = h.get("severity", "L3")
                        sev_counts[s] = sev_counts.get(s, 0) + 1
                    sev_str = " / ".join(
                        f"{v}×{k}" for k, v in sorted(sev_counts.items()))
                    _cb("dryrun", "fail",
                        f"{nc} 文件冲突, {nh} hunk 已分析 ({sev_str})")
                    result.recommendations.append(
                        f"Dry-run: {nc} 个文件冲突, "
                        f"冲突分析: {sev_str}")
                else:
                    _cb("dryrun", "fail", f"{nc} 个文件冲突: {cf}")
                    result.recommendations.append(
                        f"Dry-run: 补丁无法直接应用, {nc} 个文件冲突")
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

    def _find_stable_patch(self, cve_info, tv: str):
        """
        查找最匹配目标分支的 stable backport 补丁。
        从 version_commit_mapping 中按版本距离排序, 优先选最近的 backport。
        """
        import re as _re

        # 从 tv (如 "5.10-hulk") 提取 major.minor 前缀
        m = _re.match(r"(\d+\.\d+)", tv)
        target_prefix = m.group(1) if m else ""

        # 精确匹配: 找 5.10.x 的 backport
        if target_prefix:
            for ver in sorted(cve_info.version_commit_mapping.keys(),
                              reverse=True):
                if ver.startswith(target_prefix):
                    bp_cid = cve_info.version_commit_mapping[ver]
                    if bp_cid != cve_info.fix_commit_id:
                        patch = self.crawler.fetch_patch(bp_cid, tv)
                        if patch and patch.diff_code:
                            return patch

        # 回退: 找最近的低版本 backport (如 5.10 没有则用 5.15/5.4)
        for ver in sorted(cve_info.version_commit_mapping.keys()):
            bp_cid = cve_info.version_commit_mapping[ver]
            if bp_cid != cve_info.fix_commit_id:
                patch = self.crawler.fetch_patch(bp_cid, tv)
                if patch and patch.diff_code:
                    return patch
        return None
