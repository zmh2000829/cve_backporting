"""
Dependency Agent
分析修复补丁的前置依赖：
  - 从 Fixes: 标签提取引用关系
  - 在目标仓库中查找修改同文件/函数的中间提交
  - 构建依赖图并拓扑排序
"""

import re
import logging
from typing import Dict, List, Optional

from core.models import PatchInfo, CveInfo, SearchResult
from core.git_manager import GitRepoManager
from core.matcher import (
    CommitInfo, DependencyGraph,
    extract_files_from_diff, extract_functions_from_diff,
)

logger = logging.getLogger(__name__)


class DependencyAgent:
    """前置依赖分析Agent"""

    def __init__(self, git_mgr: GitRepoManager):
        self.git_mgr = git_mgr

    def analyze(self, fix_patch: PatchInfo, cve_info: CveInfo,
                target_version: str,
                fix_search: Optional[SearchResult] = None,
                intro_search: Optional[SearchResult] = None) -> Dict:
        """
        分析修复补丁的前置依赖

        Returns:
            {
                "prerequisite_patches": [...],
                "conflict_files": [...],
                "fixes_refs": [...],
                "recommendations": [...]
            }
        """
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

        logger.info("[Dependency] 分析修改文件: %s", ", ".join(files[:5]))
        result["conflict_files"] = files

        # Fixes: 标签
        fix_msg = fix_patch.commit_msg or ""
        fixes_refs = re.findall(r"Fixes:\s*([0-9a-f]{7,40})", fix_msg)
        if fixes_refs:
            result["fixes_refs"] = fixes_refs
            logger.info("[Dependency] Fixes引用: %s", ", ".join(c[:12] for c in fixes_refs))

        # 查找修改同文件的近期commits
        intervening = self.git_mgr.search_by_files(files[:3], target_version, limit=20)

        skip_ids = set()
        if fix_search and fix_search.target_commit:
            skip_ids.add(fix_search.target_commit[:12])
        if intro_search and intro_search.target_commit:
            skip_ids.add(intro_search.target_commit[:12])

        prereqs = []
        for c in intervening:
            if c.commit_id[:12] in skip_ids:
                continue
            prereqs.append({
                "commit_id": c.commit_id,
                "subject": c.subject,
                "timestamp": c.timestamp,
            })

        result["prerequisite_patches"] = prereqs[:10]

        # 强依赖评分（修改相同函数的commit权重更高）
        if fix_patch.diff_code:
            fix_funcs = set(extract_functions_from_diff(fix_patch.diff_code))
            if fix_funcs:
                for p in result["prerequisite_patches"]:
                    diff = self.git_mgr.get_commit_diff(p["commit_id"], target_version)
                    if diff:
                        p_funcs = set(extract_functions_from_diff(diff))
                        overlap = fix_funcs & p_funcs
                        p["func_overlap"] = sorted(overlap)
                        p["is_strong"] = len(overlap) > 0

        if prereqs:
            result["recommendations"].append(
                f"发现 {len(prereqs)} 个修改相同文件的commits需要review")

        return result
