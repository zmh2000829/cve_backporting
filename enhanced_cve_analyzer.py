#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE补丁回溯分析器
核心流程：
1. 从MITRE获取CVE信息 → 识别mainline fix/introduced commit
2. 三级搜索定位目标仓库中的对应commit（ID → Subject → Diff）
3. 判定修复状态 + 前置依赖分析
"""

import re
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from crawl_cve_patch import CveFetcher, CveInfo, PatchInfo
from git_repo_manager import GitRepoManager, GitCommit
from enhanced_patch_matcher import (
    CommitInfo, CommitMatcher, DependencyAnalyzer, MatchResult,
    extract_keywords, extract_files_from_diff, extract_functions_from_diff,
    subject_similarity, normalize_subject,
)

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """commit搜索结果"""
    found: bool = False
    strategy: str = "none"
    confidence: float = 0.0
    target_commit: str = ""
    target_subject: str = ""
    candidates: List[Dict] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """CVE分析结果"""
    cve_id: str
    target_version: str
    cve_info: Optional[CveInfo] = None
    fix_patch: Optional[PatchInfo] = None
    introduced_search: Optional[SearchResult] = None
    fix_search: Optional[SearchResult] = None
    is_vulnerable: bool = False
    is_fixed: bool = False
    prerequisite_patches: List[Dict] = field(default_factory=list)
    conflict_files: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class BackportAnalyzer:
    """
    CVE补丁回溯分析器
    不依赖AI模块，纯逻辑分析
    """

    def __init__(self, fetcher: CveFetcher, git_mgr: GitRepoManager):
        self.fetcher = fetcher
        self.git_mgr = git_mgr
        self.matcher = CommitMatcher()

    # ─── 主入口 ──────────────────────────────────────────────────────

    def analyze(self, cve_id: str, target_version: str) -> AnalysisResult:
        """
        完整CVE分析流程
        """
        result = AnalysisResult(cve_id=cve_id, target_version=target_version)

        # Step 1: 获取CVE信息
        logger.info("=" * 70)
        logger.info("[Step 1] 获取 %s 的CVE信息", cve_id)
        cve_info = self.fetcher.fetch_cve(cve_id)
        if not cve_info or not cve_info.fix_commit_id:
            result.recommendations.append(f"无法获取 {cve_id} 的修复commit信息")
            return result
        result.cve_info = cve_info

        logger.info("  Mainline fix: %s (%s)",
                     cve_info.mainline_fix_commit[:12] if cve_info.mainline_fix_commit else "N/A",
                     cve_info.mainline_version or "N/A")
        logger.info("  Introduced: %s", cve_info.introduced_commit_id or "未知")

        # Step 2: 获取mainline fix patch
        logger.info("[Step 2] 获取mainline修复补丁内容")
        fix_patch = self.fetcher.fetch_patch(cve_info.fix_commit_id)
        if not fix_patch:
            result.recommendations.append("无法获取修复补丁内容")
            return result
        result.fix_patch = fix_patch

        # Step 3: 检查问题引入commit是否在目标仓库
        if cve_info.introduced_commit_id:
            logger.info("[Step 3] 搜索问题引入commit: %s", cve_info.introduced_commit_id[:12])
            intro_patch = self.fetcher.fetch_patch(cve_info.introduced_commit_id)
            intro_subject = intro_patch.subject if intro_patch else ""
            intro_diff = intro_patch.diff_code if intro_patch else ""

            result.introduced_search = self._search_commit(
                cve_info.introduced_commit_id, intro_subject, intro_diff, target_version
            )
            result.is_vulnerable = result.introduced_search.found
            if result.is_vulnerable:
                logger.info("  目标仓库包含漏洞引入commit -> 受影响")
                result.recommendations.append(
                    f"目标仓库包含漏洞引入commit ({result.introduced_search.target_commit[:12]}), 需要修复"
                )
            else:
                logger.info("  目标仓库中未找到漏洞引入commit")
                result.recommendations.append("未找到漏洞引入commit, 可能不受影响(建议人工确认)")
        else:
            logger.info("[Step 3] 无引入commit信息, 基于5.10版本假定受影响")
            result.is_vulnerable = True

        # Step 4: 检查修复补丁是否已合入
        logger.info("[Step 4] 搜索修复补丁: %s", cve_info.fix_commit_id[:12])
        result.fix_search = self._search_commit(
            cve_info.fix_commit_id, fix_patch.subject, fix_patch.diff_code, target_version
        )
        result.is_fixed = result.fix_search.found

        if result.is_fixed:
            logger.info("  修复补丁已合入: %s (置信度: %.0f%%)",
                        result.fix_search.target_commit[:12], result.fix_search.confidence * 100)
            result.recommendations.append(
                f"修复补丁已合入 ({result.fix_search.target_commit[:12]}), "
                f"置信度 {result.fix_search.confidence:.0%}"
            )
            return result

        logger.info("  修复补丁未合入")

        # Step 5: 也检查stable backport版本(5.10.x)是否已合入
        backport_commit = cve_info.version_commit_mapping.get(
            self._find_closest_version(cve_info.version_commit_mapping, "5.10")
        )
        if backport_commit and backport_commit != cve_info.fix_commit_id:
            logger.info("[Step 5] 检查5.10 stable backport: %s", backport_commit[:12])
            bp_patch = self.fetcher.fetch_patch(backport_commit)
            if bp_patch:
                bp_search = self._search_commit(
                    backport_commit, bp_patch.subject, bp_patch.diff_code, target_version
                )
                if bp_search.found:
                    result.is_fixed = True
                    result.fix_search = bp_search
                    result.recommendations.append(
                        f"5.10 stable backport已合入 ({bp_search.target_commit[:12]})"
                    )
                    return result

        # Step 6: 依赖分析
        logger.info("[Step 6] 分析前置依赖补丁")
        self._analyze_prerequisites(result, target_version)

        return result

    # ─── 三级搜索 ────────────────────────────────────────────────────

    def _search_commit(self, commit_id: str, subject: str,
                       diff_code: str, target_version: str) -> SearchResult:
        """
        三级搜索策略定位目标仓库中的commit
        Level 1: 精确 commit ID
        Level 2: 语义 subject 匹配 (含 [backport] 变体)
        Level 3: 代码 diff 匹配
        """
        sr = SearchResult()

        # Level 1: ID精确匹配
        logger.info("  [L1] 精确ID匹配: %s", commit_id[:12])
        exact = self.git_mgr.find_commit_by_id(commit_id, target_version)
        if exact:
            sr.found = True
            sr.strategy = "exact_id"
            sr.confidence = 1.0
            sr.target_commit = exact["commit_id"]
            sr.target_subject = exact["subject"]
            logger.info("  [L1] 找到: %s", exact["commit_id"][:12])
            return sr

        if not subject:
            logger.info("  [L1] 无subject信息, 跳过L2/L3")
            return sr

        # Level 2: Subject语义匹配
        logger.info("  [L2] Subject语义匹配: %s", subject[:60])
        sr = self._search_by_subject(commit_id, subject, target_version)
        if sr.found:
            return sr

        # Level 3: Diff代码匹配
        if diff_code:
            files = extract_files_from_diff(diff_code)
            if files:
                logger.info("  [L3] Diff代码匹配 (文件: %s)", ", ".join(files[:3]))
                sr = self._search_by_diff(commit_id, subject, diff_code, files, target_version)
                if sr.found:
                    return sr

        return sr

    def _search_by_subject(self, commit_id: str, subject: str,
                           target_version: str) -> SearchResult:
        """Level 2: 基于subject搜索"""
        sr = SearchResult()
        norm_subj = normalize_subject(subject)

        # 策略2a: 精确subject搜索
        candidates = self.git_mgr.search_by_subject(norm_subj, target_version, limit=10)

        # 策略2b: 关键词搜索
        if not candidates:
            keywords = extract_keywords(subject)
            if keywords:
                candidates = self.git_mgr.search_by_keywords(keywords, target_version, limit=30)

        if not candidates:
            return sr

        # 计算相似度
        best_match = None
        best_sim = 0.0
        all_candidates = []

        for c in candidates:
            sim = subject_similarity(subject, c.subject)
            all_candidates.append({
                "commit_id": c.commit_id,
                "subject": c.subject,
                "similarity": sim,
            })
            if sim > best_sim:
                best_sim = sim
                best_match = c

        sr.candidates = sorted(all_candidates, key=lambda x: x["similarity"], reverse=True)[:5]

        if best_match and best_sim >= 0.85:
            sr.found = True
            sr.strategy = "subject_match"
            sr.confidence = best_sim
            sr.target_commit = best_match.commit_id
            sr.target_subject = best_match.subject
            logger.info("  [L2] 找到: %s (相似度: %.0f%%)", best_match.commit_id[:12], best_sim * 100)

        return sr

    def _search_by_diff(self, commit_id: str, subject: str,
                        diff_code: str, files: List[str],
                        target_version: str) -> SearchResult:
        """Level 3: 基于diff搜索"""
        sr = SearchResult()

        file_commits = self.git_mgr.search_by_files(files[:3], target_version, limit=50)
        if not file_commits:
            return sr

        source = CommitInfo(
            commit_id=commit_id,
            subject=subject,
            diff_code=diff_code,
            modified_files=files,
        )

        targets = []
        for gc in file_commits:
            diff = self.git_mgr.get_commit_diff(gc.commit_id, target_version)
            targets.append(CommitInfo(
                commit_id=gc.commit_id,
                subject=gc.subject,
                diff_code=diff or "",
                modified_files=extract_files_from_diff(diff or ""),
            ))

        matches = self.matcher.match_comprehensive(source, targets)
        if matches and matches[0].confidence >= 0.70:
            best = matches[0]
            sr.found = True
            sr.strategy = f"diff_match ({best.match_type})"
            sr.confidence = best.confidence
            sr.target_commit = best.target_commit
            sr.target_subject = best.details.get("target_subject", "")
            sr.candidates = [
                {"commit_id": m.target_commit, "confidence": m.confidence, "type": m.match_type}
                for m in matches[:5]
            ]
            logger.info("  [L3] 找到: %s (置信度: %.0f%%)", best.target_commit[:12], best.confidence * 100)

        return sr

    # ─── 前置依赖分析 ────────────────────────────────────────────────

    def _analyze_prerequisites(self, result: AnalysisResult, target_version: str):
        """
        分析修复补丁的前置依赖：
        对比mainline修复补丁修改的文件/行号，查找目标仓库中的差异
        """
        if not result.fix_patch:
            return

        fix_files = result.fix_patch.modified_files
        if not fix_files:
            result.recommendations.append("修复补丁未合入, 补丁无文件修改信息, 无法分析依赖")
            return

        logger.info("  分析修改文件的中间补丁: %s", ", ".join(fix_files[:5]))

        # 在mainline中查找fix之前修改相同文件的commits
        # （用mainline仓库的patch内容中的Fixes:标签等信息）
        fix_commit_id = result.cve_info.fix_commit_id
        fix_msg = result.fix_patch.commit_msg or ""

        # 从Fixes:标签提取
        fixes_commits = re.findall(r"Fixes:\s*([0-9a-f]{7,40})", fix_msg)
        if fixes_commits:
            logger.info("  Fixes标签引用: %s", ", ".join(c[:12] for c in fixes_commits))

        # 在目标仓库中查找修改同文件的近期commits（可能是缺失的前置依赖）
        intervening = self.git_mgr.search_by_files(fix_files[:3], target_version, limit=20)

        prereqs = []
        for c in intervening:
            # 排除已找到的commit
            if result.fix_search and c.commit_id[:12] == result.fix_search.target_commit[:12]:
                continue
            if result.introduced_search and result.introduced_search.target_commit:
                if c.commit_id[:12] == result.introduced_search.target_commit[:12]:
                    continue

            prereqs.append({
                "commit_id": c.commit_id,
                "subject": c.subject,
                "timestamp": c.timestamp,
            })

        result.conflict_files = fix_files
        result.prerequisite_patches = prereqs[:10]

        not_merged_msg = f"修复补丁 {fix_commit_id[:12]} 未合入"
        if prereqs:
            not_merged_msg += f", 发现 {len(prereqs)} 个修改相同文件的commits需要review"
        result.recommendations.append(not_merged_msg)

    # ─── 工具方法 ────────────────────────────────────────────────────

    @staticmethod
    def _find_closest_version(mapping: Dict[str, str], prefix: str) -> Optional[str]:
        """从版本映射中找最接近prefix的版本"""
        for ver in mapping:
            if ver.startswith(prefix):
                return ver
        return None

    # ─── 报告生成 ────────────────────────────────────────────────────

    @staticmethod
    def format_report(result: AnalysisResult) -> str:
        """生成人类可读的分析报告"""
        lines = [
            f"# CVE补丁回溯分析报告: {result.cve_id}",
            f"目标版本: {result.target_version}",
            "",
        ]

        if result.cve_info:
            lines.append(f"## CVE信息")
            lines.append(f"- 描述: {result.cve_info.description[:200]}")
            lines.append(f"- 严重程度: {result.cve_info.severity}")
            lines.append(f"- Mainline fix: {result.cve_info.mainline_fix_commit[:12] if result.cve_info.mainline_fix_commit else 'N/A'}")
            lines.append(f"- 引入commit: {result.cve_info.introduced_commit_id or '未知'}")
            lines.append("")

        if result.fix_patch:
            lines.append(f"## 修复补丁")
            lines.append(f"- Subject: {result.fix_patch.subject}")
            lines.append(f"- 修改文件: {', '.join(result.fix_patch.modified_files[:5])}")
            lines.append("")

        lines.append(f"## 状态")
        lines.append(f"- 是否受影响: {'是' if result.is_vulnerable else '未确认'}")
        lines.append(f"- 是否已修复: {'是' if result.is_fixed else '否'}")
        lines.append("")

        if result.introduced_search and result.introduced_search.found:
            sr = result.introduced_search
            lines.append(f"## 漏洞引入commit定位")
            lines.append(f"- 目标仓库commit: {sr.target_commit[:12]}")
            lines.append(f"- 策略: {sr.strategy}")
            lines.append(f"- 置信度: {sr.confidence:.0%}")
            lines.append("")

        if result.fix_search:
            sr = result.fix_search
            lines.append(f"## 修复补丁定位")
            if sr.found:
                lines.append(f"- 目标仓库commit: {sr.target_commit[:12]}")
                lines.append(f"- 策略: {sr.strategy}")
                lines.append(f"- 置信度: {sr.confidence:.0%}")
            else:
                lines.append(f"- 状态: 未找到/未合入")
                if sr.candidates:
                    lines.append(f"- 最接近的候选:")
                    for c in sr.candidates[:3]:
                        lines.append(f"  - {c.get('commit_id', '')[:12]} "
                                     f"(相似度: {c.get('similarity', c.get('confidence', 0)):.0%})")
            lines.append("")

        if result.prerequisite_patches:
            lines.append(f"## 前置依赖补丁 ({len(result.prerequisite_patches)} 个)")
            for p in result.prerequisite_patches:
                lines.append(f"- {p['commit_id'][:12]} {p['subject'][:60]}")
            lines.append("")

        if result.recommendations:
            lines.append(f"## 建议")
            for r in result.recommendations:
                lines.append(f"- {r}")

        return "\n".join(lines)


# 向后兼容
EnhancedCVEAnalyzer = BackportAnalyzer
