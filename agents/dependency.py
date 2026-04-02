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
LOCK_PATTERNS = [
    re.compile(r"\b(?:spin_lock(?:_[A-Za-z0-9_]+)?|spin_unlock(?:_[A-Za-z0-9_]+)?|"
               r"mutex_lock|mutex_unlock|mutex_trylock|mutex_lock_interruptible|"
               r"read_lock|write_lock|down_[A-Za-z0-9_]+|up_[A-Za-z0-9_]+)\s*\(\s*&?([A-Za-z_][\w>\.\-]*)"),
    re.compile(r"\b(?:rcu_assign_pointer|rcu_dereference|refcount_inc|refcount_dec|"
               r"kref_get|kref_put)\s*\(\s*&?([A-Za-z_][\w>\.\-]*)"),
]
FIELD_PATTERN = re.compile(r"\b[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w+)+")
STATE_PATTERN = re.compile(
    r"\b([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w+)*"
    r"(?:->|\.)?(?:state|status|mode|flags?|enabled|disabled|phase|step))\b",
    re.IGNORECASE,
)


class DependencyAgent:
    """前置依赖分析Agent"""

    def __init__(self, git_mgr: GitRepoManager, path_mapper: PathMapper = None):
        self.git_mgr = git_mgr
        self.path_mapper = path_mapper or PathMapper()

    def _changed_bodies(self, diff_text: str) -> List[str]:
        return [
            line[1:].strip()
            for line in (diff_text or "").splitlines()
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
        ]

    def _normalize_object_name(self, value: str) -> str:
        text = (value or "").strip()
        text = re.sub(r"^\(.*?\)", "", text).strip()
        text = text.lstrip("&*").strip()
        return text[:80]

    def _extract_semantic_markers(self, diff_text: str) -> Dict[str, List[str]]:
        fields: List[str] = []
        locks: List[str] = []
        states: List[str] = []

        def _append_unique(bucket: List[str], value: str):
            if value and value not in bucket:
                bucket.append(value)

        for body in self._changed_bodies(diff_text):
            for pattern in LOCK_PATTERNS:
                for match in pattern.finditer(body):
                    _append_unique(locks, self._normalize_object_name(match.group(1)))
            for match in FIELD_PATTERN.finditer(body):
                _append_unique(fields, match.group(0))
            for match in STATE_PATTERN.finditer(body):
                _append_unique(states, match.group(1))

        return {
            "fields": fields,
            "locks": locks,
            "states": states,
        }

    def _collect_evidence_lines(
        self,
        diff_text: str,
        *,
        fields: List[str],
        locks: List[str],
        states: List[str],
        limit: int = 6,
    ) -> List[str]:
        terms = [item for item in (fields or []) + (locks or []) + (states or []) if item]
        if not terms:
            return []
        evidence: List[str] = []
        for body in self._changed_bodies(diff_text):
            if any(term in body for term in terms):
                if body not in evidence:
                    evidence.append(body)
            if len(evidence) >= limit:
                break
        return evidence[:limit]

    def analyze(self, fix_patch: PatchInfo, cve_info: CveInfo,
                target_version: str,
                fix_search: Optional[SearchResult] = None,
                intro_search: Optional[SearchResult] = None) -> Dict:
        from core.models import DependencyAnalysisDetails
        from datetime import datetime
        
        result = {
            "prerequisite_patches": [],
            "conflict_files": [],
            "fixes_refs": [],
            "recommendations": [],
            "analysis_details": None,
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
        time_window_start = "仓库初始"
        if intro_search and intro_search.target_commit:
            info = self.git_mgr.find_commit_by_id(intro_search.target_commit, target_version)
            if info and info.get("timestamp"):
                after_ts = info["timestamp"]
                time_window_start = datetime.fromtimestamp(after_ts).strftime("%Y-%m-%d %H:%M:%S")
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
            # 无前置依赖场景：生成详细分析说明
            details = DependencyAnalysisDetails(
                candidate_count=0,
                strong_count=0,
                medium_count=0,
                weak_count=0,
                time_window_start=time_window_start,
                time_window_end="HEAD",
                analysis_files=files,
                analysis_scope=f"时间窗口内修改同文件的 commit (排除 merge)",
                no_prerequisite_reason="时间窗口内无其他 commit 修改相同文件",
                confidence_level="high",
                boundary_statement=f"仅对 {target_version} 分支当前状态成立",
                dryrun_baseline_passed=False,
                dryrun_method="",
                analysis_narrative=[
                    "Step 1: 建候选集 — 在时间窗口内搜索修改同文件的 commit",
                    "  结果: 0 个候选 commit (无其他修改)",
                    "Step 2: 空集基线 DryRun — 不带任何前置补丁直接应用修复补丁",
                    "  待 DryRun Agent 验证...",
                    "Step 3: 结论 — 无硬前置依赖",
                    "  置信度: 高 (候选集为空，无需隔离实验)",
                ],
                manual_review_checklist=[
                    "确认修复补丁的 DryRun 结果（strict/fuzz/3way 中至少一个通过）",
                    "检查是否引入新 struct 字段或 API 变更（可能有隐性依赖）",
                    "验证关键路径编译和单测通过",
                ],
            )
            result["analysis_details"] = details
            result["recommendations"].append("时间窗口内无修改同文件的其他commit")
            return result

        # 提取 fix patch 的 hunk 和函数信息
        fix_hunks = extract_hunks_from_diff(fix_patch.diff_code) if fix_patch.diff_code else []
        fix_funcs = set(extract_functions_from_diff(fix_patch.diff_code)) if fix_patch.diff_code else set()
        fix_markers = self._extract_semantic_markers(fix_patch.diff_code or "")

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
            c_markers = self._extract_semantic_markers(diff)

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
            shared_fields = sorted(set(fix_markers["fields"]) & set(c_markers["fields"]))
            shared_locks = sorted(set(fix_markers["locks"]) & set(c_markers["locks"]))
            shared_states = sorted(set(fix_markers["states"]) & set(c_markers["states"]))

            # 评分
            score = 0.0
            score += min(direct_overlaps * 0.3, 0.6)
            score += min(adjacent_overlaps * 0.1, 0.2)
            score += min(len(func_overlap) * 0.15, 0.3)
            score += min(len(shared_fields) * 0.08, 0.24)
            score += min(len(shared_locks) * 0.18, 0.36)
            score += min(len(shared_states) * 0.12, 0.24)

            if score < 0.05 and not func_overlap and direct_overlaps == 0 and not (shared_fields or shared_locks or shared_states):
                continue

            # 分级
            if (direct_overlaps > 0 and (func_overlap or shared_fields or shared_locks or shared_states)) or score >= 0.5:
                grade = "strong"
            elif direct_overlaps > 0 or adjacent_overlaps > 0 or func_overlap or shared_fields or shared_locks or shared_states or score >= 0.2:
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
                shared_fields=shared_fields[:8],
                shared_lock_domains=shared_locks[:8],
                shared_state_points=shared_states[:8],
                evidence_lines=self._collect_evidence_lines(
                    diff,
                    fields=shared_fields,
                    locks=shared_locks,
                    states=shared_states,
                ),
            ))

        # 按 score 降序, strong 优先
        grade_order = {"strong": 0, "medium": 1, "weak": 2}
        prereqs.sort(key=lambda p: (grade_order.get(p.grade, 9), -p.score))

        result["prerequisite_patches"] = prereqs

        # 统计
        n_strong = sum(1 for p in prereqs if p.grade == "strong")
        n_medium = sum(1 for p in prereqs if p.grade == "medium")
        n_weak = sum(1 for p in prereqs if p.grade == "weak")
        semantic_overlap_summary = {
            "shared_fields": sum(1 for p in prereqs if p.shared_fields),
            "shared_lock_domains": sum(1 for p in prereqs if p.shared_lock_domains),
            "shared_state_points": sum(1 for p in prereqs if p.shared_state_points),
        }
        evidence_samples = [
            {
                "commit_id": p.commit_id,
                "grade": p.grade,
                "shared_fields": p.shared_fields[:4],
                "shared_lock_domains": p.shared_lock_domains[:4],
                "shared_state_points": p.shared_state_points[:4],
            }
            for p in prereqs[:5]
            if p.shared_fields or p.shared_lock_domains or p.shared_state_points
        ]

        # 生成分析详情
        if len(prereqs) == 0:
            # 无前置依赖场景
            confidence = "high"
            reason = "候选集中无 strong/medium 依赖，仅有 weak 依赖可忽略"
            narrative = [
                f"Step 1: 建候选集 — 在时间窗口内搜索修改同文件的 commit",
                f"  结果: {len(intervening)} 个候选 commit",
                f"Step 2: 依赖分级 — 按 hunk 重叠、函数交集、评分分级",
                f"  strong: {n_strong}, medium: {n_medium}, weak: {n_weak}",
                f"Step 3: 结论 — 无硬前置依赖",
                f"  置信度: {confidence} (无 strong/medium 依赖)",
            ]
        else:
            confidence = "high" if n_strong > 0 else ("medium" if n_medium > 0 else "low")
            evidence_parts = []
            if semantic_overlap_summary["shared_lock_domains"]:
                evidence_parts.append(f"{semantic_overlap_summary['shared_lock_domains']} 个共享锁域")
            if semantic_overlap_summary["shared_fields"]:
                evidence_parts.append(f"{semantic_overlap_summary['shared_fields']} 个共享字段域")
            if semantic_overlap_summary["shared_state_points"]:
                evidence_parts.append(f"{semantic_overlap_summary['shared_state_points']} 个共享状态点")
            reason = f"发现 {n_strong} 个强依赖、{n_medium} 个中依赖"
            if evidence_parts:
                reason += "；证据包含 " + " / ".join(evidence_parts)
            narrative = [
                f"Step 1: 建候选集 — 在时间窗口内搜索修改同文件的 commit",
                f"  结果: {len(intervening)} 个候选 commit",
                f"Step 2: 依赖分级 — 按 hunk 重叠、函数交集、评分分级",
                f"  strong: {n_strong}, medium: {n_medium}, weak: {n_weak}",
                (
                    "Step 2.5: 语义域交集 — 继续核对共享字段/锁域/状态点"
                    f"  结果: 锁域={semantic_overlap_summary['shared_lock_domains']},"
                    f" 字段={semantic_overlap_summary['shared_fields']},"
                    f" 状态点={semantic_overlap_summary['shared_state_points']}"
                ),
                f"Step 3: 最小集合隔离 — 确定必须前置的最小集合",
                f"  建议优先合入 strong 依赖: {', '.join(p.commit_id[:12] for p in prereqs[:3] if p.grade == 'strong')}",
            ]

        details = DependencyAnalysisDetails(
            candidate_count=len(intervening),
            strong_count=n_strong,
            medium_count=n_medium,
            weak_count=n_weak,
            time_window_start=time_window_start,
            time_window_end="HEAD",
            analysis_files=files,
            analysis_scope=f"时间窗口内修改同文件的 commit (排除 merge, 限制 50 个)",
            no_prerequisite_reason=reason if len(prereqs) == 0 else "",
            confidence_level=confidence,
            boundary_statement=f"仅对 {target_version} 分支当前状态成立",
            dryrun_baseline_passed=False,
            dryrun_method="",
            analysis_narrative=narrative,
            manual_review_checklist=[
                "确认修复补丁的 DryRun 结果（strict/fuzz/3way 中至少一个通过）",
                "检查是否引入新 struct 字段或 API 变更（可能有隐性依赖）",
                "验证关键路径编译和单测通过",
                "优先核对共享字段、共享锁域和共享状态迁移点是否来自前置补丁",
                "对于 strong 依赖，建议按顺序 review 并优先合入",
            ] if len(prereqs) > 0 else [
                "确认修复补丁的 DryRun 结果（strict/fuzz/3way 中至少一个通过）",
                "检查是否引入新 struct 字段或 API 变更（可能有隐性依赖）",
                "验证关键路径编译和单测通过",
            ],
            semantic_overlap_summary=semantic_overlap_summary,
            prerequisite_evidence_samples=evidence_samples,
        )
        result["analysis_details"] = details

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
