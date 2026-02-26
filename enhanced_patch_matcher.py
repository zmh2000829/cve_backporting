#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
补丁匹配与依赖分析模块
核心功能：
1. 多维度commit匹配（ID、subject、diff、文件路径）
2. 语义相似度计算
3. 依赖图构建与拓扑排序
"""

import re
import difflib
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


@dataclass
class CommitInfo:
    """commit信息"""
    commit_id: str
    subject: str
    commit_msg: str = ""
    diff_code: str = ""
    modified_files: List[str] = field(default_factory=list)
    modified_functions: List[str] = field(default_factory=list)
    author: str = ""
    timestamp: int = 0

    def __hash__(self):
        return hash(self.commit_id)


@dataclass
class MatchResult:
    """匹配结果"""
    target_commit: str
    source_commit: str
    confidence: float
    match_type: str
    details: Dict = field(default_factory=dict)


# ─── 工具函数 ────────────────────────────────────────────────────────

_BACKPORT_PREFIXES = [
    "[backport]", "[stable]", "backport:", "stable:",
    "[patch]", "cherry-pick", "cherry pick",
]


def normalize_subject(subject: str) -> str:
    """标准化subject：小写、去除backport前缀"""
    s = subject.lower().strip()
    for prefix in _BACKPORT_PREFIXES:
        if s.startswith(prefix.lower()):
            s = s[len(prefix):].strip()
            break
    return re.sub(r"^[\s\-:]+", "", s)


def extract_files_from_diff(diff_code: str) -> List[str]:
    """从diff中提取修改的文件列表"""
    files = set()
    for line in diff_code.split("\n"):
        if line.startswith("---") or line.startswith("+++"):
            m = re.search(r"[+-]{3}\s+[ab]/(.*?)(?:\s|$)", line)
            if m and m.group(1) != "/dev/null":
                files.add(m.group(1))
    return sorted(files)


def extract_functions_from_diff(diff_code: str) -> List[str]:
    """从diff中提取修改的函数名"""
    funcs = set()
    for m in re.finditer(r"@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@\s*(.+?)(?:\s*\{|$)", diff_code):
        name = m.group(1).strip()
        if name:
            funcs.add(name)
    for m in re.finditer(r"^\+\s*(?:static\s+)?(?:inline\s+)?(?:\w+\s+)+(\w+)\s*\(", diff_code, re.MULTILINE):
        funcs.add(m.group(1))
    return sorted(funcs)


def extract_keywords(subject: str, max_count: int = 5) -> List[str]:
    """从subject中提取搜索关键词"""
    stopwords = {"a", "an", "the", "in", "on", "at", "to", "for", "of", "with", "by",
                 "and", "or", "not", "is", "it", "this", "that", "from", "fix", "add"}
    words = re.findall(r"\w+", normalize_subject(subject))
    return [w for w in words if len(w) > 2 and w not in stopwords][:max_count]


# ─── 相似度计算 ──────────────────────────────────────────────────────

def subject_similarity(s1: str, s2: str) -> float:
    """计算两个subject的相似度（标准化后用SequenceMatcher）"""
    return difflib.SequenceMatcher(None, normalize_subject(s1), normalize_subject(s2)).ratio()


def diff_similarity(diff1: str, diff2: str) -> float:
    """计算两个diff的相似度（忽略行号，只比较实际修改）"""
    def extract_changes(diff: str) -> List[str]:
        return [
            line[1:].strip()
            for line in diff.split("\n")
            if (line.startswith("+") or line.startswith("-"))
            and not line.startswith(("+++", "---"))
            and line[1:].strip()
        ]

    c1, c2 = extract_changes(diff1), extract_changes(diff2)
    if not c1 or not c2:
        return 0.0
    return difflib.SequenceMatcher(None, c1, c2).ratio()


def file_similarity(files1: List[str], files2: List[str]) -> float:
    """修改文件列表的Jaccard相似度（仅比较文件名）"""
    if not files1 or not files2:
        return 0.0
    names1 = {f.split("/")[-1] for f in files1}
    names2 = {f.split("/")[-1] for f in files2}
    inter = len(names1 & names2)
    union = len(names1 | names2)
    return inter / union if union else 0.0


# ─── CommitMatcher ───────────────────────────────────────────────────

class CommitMatcher:
    """多维度commit匹配器"""

    def match_by_subject(self, source: CommitInfo, targets: List[CommitInfo],
                         threshold: float = 0.85) -> List[MatchResult]:
        results = []
        for t in targets:
            sim = subject_similarity(source.subject, t.subject)
            if sim >= threshold:
                results.append(MatchResult(
                    target_commit=t.commit_id,
                    source_commit=source.commit_id,
                    confidence=sim,
                    match_type="subject_similarity",
                    details={"source_subject": source.subject, "target_subject": t.subject},
                ))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results

    def match_by_diff(self, source: CommitInfo, targets: List[CommitInfo],
                      threshold: float = 0.70) -> List[MatchResult]:
        results = []
        src_files = source.modified_files or extract_files_from_diff(source.diff_code)

        for t in targets:
            tgt_files = t.modified_files or extract_files_from_diff(t.diff_code)
            fsim = file_similarity(src_files, tgt_files)
            if fsim < 0.3:
                continue
            dsim = diff_similarity(source.diff_code, t.diff_code)
            combined = fsim * 0.4 + dsim * 0.6
            if combined >= threshold:
                results.append(MatchResult(
                    target_commit=t.commit_id,
                    source_commit=source.commit_id,
                    confidence=combined,
                    match_type="diff_similarity",
                    details={"file_sim": fsim, "diff_sim": dsim},
                ))
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results

    def match_comprehensive(self, source: CommitInfo,
                            targets: List[CommitInfo]) -> List[MatchResult]:
        """综合匹配：先ID精确 -> subject -> diff"""
        # Level 1: ID匹配
        for t in targets:
            if source.commit_id[:12] == t.commit_id[:12]:
                return [MatchResult(
                    target_commit=t.commit_id, source_commit=source.commit_id,
                    confidence=1.0, match_type="exact_id",
                    details={"target_subject": t.subject},
                )]

        # Level 2: Subject匹配
        subj_matches = self.match_by_subject(source, targets, threshold=0.85)
        if subj_matches and subj_matches[0].confidence >= 0.95:
            return subj_matches

        # Level 3: Diff匹配
        diff_matches = self.match_by_diff(source, targets, threshold=0.70)

        # 合并去重
        seen = {}
        for m in subj_matches + diff_matches:
            if m.target_commit not in seen or m.confidence > seen[m.target_commit].confidence:
                seen[m.target_commit] = m
        final = sorted(seen.values(), key=lambda x: x.confidence, reverse=True)
        return final


# ─── DependencyAnalyzer ──────────────────────────────────────────────

class DependencyAnalyzer:
    """补丁依赖关系分析"""

    def __init__(self):
        self.graph: Dict[str, Set[str]] = defaultdict(set)
        self.reverse: Dict[str, Set[str]] = defaultdict(set)

    def add_dependency(self, patch: str, depends_on: str):
        self.graph[patch].add(depends_on)
        self.reverse[depends_on].add(patch)

    def find_dependencies(self, fix: CommitInfo,
                          candidates: List[CommitInfo]) -> Dict[str, float]:
        """分析fix_commit对candidates的依赖强度"""
        deps = {}
        fix_files = set(fix.modified_files or extract_files_from_diff(fix.diff_code))
        fix_funcs = set(fix.modified_functions or extract_functions_from_diff(fix.diff_code))

        for c in candidates:
            if c.commit_id == fix.commit_id:
                continue
            if fix.timestamp > 0 and c.timestamp > 0 and c.timestamp >= fix.timestamp:
                continue

            c_files = set(c.modified_files or extract_files_from_diff(c.diff_code))
            c_funcs = set(c.modified_functions or extract_functions_from_diff(c.diff_code))

            file_overlap = len(fix_files & c_files) / len(fix_files) if fix_files else 0
            func_overlap = len(fix_funcs & c_funcs) / len(fix_funcs) if fix_funcs else 0
            score = file_overlap * 0.6 + func_overlap * 0.4

            if score > 0.3:
                deps[c.commit_id] = score

        return deps

    def topological_sort(self, patches: List[str]) -> List[str]:
        """拓扑排序：返回合入顺序"""
        in_degree = {p: 0 for p in patches}
        for p in patches:
            for dep in self.graph[p]:
                if dep in in_degree:
                    in_degree[p] += 1

        queue = deque(p for p in patches if in_degree[p] == 0)
        result = []
        while queue:
            cur = queue.popleft()
            result.append(cur)
            for dep in self.reverse[cur]:
                if dep in in_degree:
                    in_degree[dep] -= 1
                    if in_degree[dep] == 0:
                        queue.append(dep)

        if len(result) != len(patches):
            logger.warning("依赖图中存在环")
        return result

    def get_all_dependencies(self, patch: str, visited: Set[str] = None) -> Set[str]:
        """递归获取所有依赖（含传递依赖）"""
        if visited is None:
            visited = set()
        if patch in visited:
            return set()
        visited.add(patch)
        all_deps = set(self.graph[patch])
        for dep in list(self.graph[patch]):
            all_deps.update(self.get_all_dependencies(dep, visited))
        return all_deps
