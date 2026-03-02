"""
Dependency Agent
分析修复补丁的前置依赖：
  - 时间窗口限制 (引入commit → HEAD)
  - Hunk 级行范围重叠分析
  - 三级依赖分类 (强/中/弱)
  - Fixes: 标签链追踪
"""

import re
import logging
from typing import Dict, List, Optional

from core.models import PatchInfo, CveInfo, SearchResult, PrerequisitePatch
from core.git_manager import GitRepoManager
from core.matcher import (
    PathMapper, extract_files_from_diff, extract_functions_from_diff,
    extract_hunks_from_diff, compute_hunk_overlap,
)

logger = logging.getLogger(__name__)

ADJACENT_MARGIN = 50


class DependencyAgent:
    """前置依赖分析Agent"""

    def __init__(self, git_mgr: GitRepoManager, path_mapper: PathMapper = None):
        self.git_mgr = git_mgr
        self.path_mapper = path_mapper or PathMapper()

    def analyze(self, fix_patch: PatchInfo, cve_info: CveInfo,
                target_version: str,
                fix_search: Optional[SearchResult] = None,
                intro_search: Optional[SearchResult] = None) -> Dict:
        result = {
            "prerequisite_patches": [],
            "conflict_files": [],
            "fixes_refs": [],
            "recommendations": [],
        }

        files = fix_patch.modified_files
        if not files:
            result["recommendations"].append("补丁无文件修改信息, 无法分析依赖")
            return result

        search_files = self.path_mapper.expand_files(files) if self.path_mapper.has_rules else files
        if len(search_files) > len(files):
            logger.info("[Dependency] 路径映射: %s → +%d 等价路径",
                        ", ".join(files[:3]), len(search_files) - len(files))

        logger.info("[Dependency] 分析修改文件: %s", ", ".join(files[:5]))
        result["conflict_files"] = files

        # Fixes: 标签链
        fix_msg = fix_patch.commit_msg or ""
        fixes_refs = re.findall(r"Fixes:\s*([0-9a-f]{7,40})", fix_msg)
        if fixes_refs:
            result["fixes_refs"] = fixes_refs
            logger.info("[Dependency] Fixes引用: %s", ", ".join(c[:12] for c in fixes_refs))

        # 确定时间窗口起点
        after_ts = 0
        if intro_search and intro_search.target_commit:
            info = self.git_mgr.find_commit_by_id(intro_search.target_commit, target_version)
            if info and info.get("timestamp"):
                after_ts = info["timestamp"]
                logger.info("[Dependency] 时间窗口: 从引入commit时间 %d 开始", after_ts)

        # 查找修改同文件的 commit (排除 merge, 限定时间窗口, 含路径映射)
        intervening = self.git_mgr.search_by_files(
            search_files[:8], target_version, limit=50,
            after_ts=after_ts, no_merges=True,
        )

        # 排除已知 commit
        skip_ids = set()
        if fix_search and fix_search.target_commit:
            skip_ids.add(fix_search.target_commit[:12])
        if intro_search and intro_search.target_commit:
            skip_ids.add(intro_search.target_commit[:12])
        for ref in fixes_refs:
            skip_ids.add(ref[:12])

        intervening = [c for c in intervening if c.commit_id[:12] not in skip_ids]

        if not intervening:
            result["recommendations"].append("时间窗口内无修改同文件的其他commit")
            return result

        # 提取 fix patch 的 hunk 和函数信息
        fix_hunks = extract_hunks_from_diff(fix_patch.diff_code) if fix_patch.diff_code else []
        fix_funcs = set(extract_functions_from_diff(fix_patch.diff_code)) if fix_patch.diff_code else set()

        logger.info("[Dependency] fix patch: %d hunks, %d funcs, %d 候选commit",
                    len(fix_hunks), len(fix_funcs), len(intervening))

        # 逐个分析候选
        prereqs: List[PrerequisitePatch] = []
        for c in intervening:
            diff = self.git_mgr.get_commit_diff(c.commit_id, target_version)
            if not diff:
                continue

            c_hunks = extract_hunks_from_diff(diff)
            c_funcs = set(extract_functions_from_diff(diff))

            # 文件数过多的大重构 commit → 降权
            c_files = extract_files_from_diff(diff)
            if len(c_files) > 20:
                continue

            # Hunk 重叠分析
            direct_overlaps, adjacent_overlaps = (0, 0)
            if fix_hunks and c_hunks:
                direct_overlaps, adjacent_overlaps = compute_hunk_overlap(
                    fix_hunks, c_hunks, margin=ADJACENT_MARGIN)

            # 函数重叠
            func_overlap = sorted(fix_funcs & c_funcs) if fix_funcs and c_funcs else []

            # 评分
            score = 0.0
            score += min(direct_overlaps * 0.3, 0.6)
            score += min(adjacent_overlaps * 0.1, 0.2)
            score += min(len(func_overlap) * 0.15, 0.3)

            if score < 0.05 and not func_overlap and direct_overlaps == 0:
                continue

            # 分级
            if (direct_overlaps > 0 and func_overlap) or score >= 0.5:
                grade = "strong"
            elif direct_overlaps > 0 or adjacent_overlaps > 0 or score >= 0.2:
                grade = "medium"
            else:
                grade = "weak"

            prereqs.append(PrerequisitePatch(
                commit_id=c.commit_id,
                subject=c.subject,
                author=c.author,
                timestamp=c.timestamp,
                grade=grade,
                score=round(score, 3),
                overlap_funcs=func_overlap,
                overlap_hunks=direct_overlaps,
                adjacent_hunks=adjacent_overlaps,
            ))

        # 按 score 降序, strong 优先
        grade_order = {"strong": 0, "medium": 1, "weak": 2}
        prereqs.sort(key=lambda p: (grade_order.get(p.grade, 9), -p.score))

        result["prerequisite_patches"] = prereqs

        # 统计
        n_strong = sum(1 for p in prereqs if p.grade == "strong")
        n_medium = sum(1 for p in prereqs if p.grade == "medium")
        n_weak = sum(1 for p in prereqs if p.grade == "weak")

        if prereqs:
            parts = []
            if n_strong:
                parts.append(f"{n_strong} 个强依赖")
            if n_medium:
                parts.append(f"{n_medium} 个中依赖")
            if n_weak:
                parts.append(f"{n_weak} 个弱依赖")
            result["recommendations"].append(
                f"发现前置依赖: {', '.join(parts)}, 建议按顺序 review")
            if n_strong > 0:
                strong_list = [p for p in prereqs if p.grade == "strong"]
                result["recommendations"].append(
                    f"强依赖 commit 建议优先合入: " +
                    ", ".join(p.commit_id[:12] for p in strong_list[:5]))

        return result
