"""相似度匹配与依赖图算法"""

import re
import difflib
import logging
from typing import Dict, List, Set
from dataclasses import field
from collections import defaultdict, deque
from core.models import CommitInfo, MatchResult

logger = logging.getLogger(__name__)

_BACKPORT_PREFIXES = [
    "[backport]", "[stable]", "backport:", "stable:",
    "[patch]", "cherry-pick", "cherry pick",
]


def normalize_subject(subject: str) -> str:
    s = subject.lower().strip()
    for prefix in _BACKPORT_PREFIXES:
        if s.startswith(prefix.lower()):
            s = s[len(prefix):].strip()
            break
    return re.sub(r"^[\s\-:]+", "", s)


def extract_files_from_diff(diff: str) -> List[str]:
    files = set()
    for line in diff.split("\n"):
        if line.startswith("---") or line.startswith("+++"):
            m = re.search(r"[+-]{3}\s+[ab]/(.*?)(?:\s|$)", line)
            if m and m.group(1) != "/dev/null":
                files.add(m.group(1))
    return sorted(files)


def extract_functions_from_diff(diff: str) -> List[str]:
    funcs = set()
    for m in re.finditer(r"@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@\s*(.+?)(?:\s*\{|$)", diff):
        n = m.group(1).strip()
        if n:
            funcs.add(n)
    return sorted(funcs)


def extract_hunks_from_diff(diff: str) -> List[Dict]:
    """从 diff 中提取每个 hunk 的文件路径和行范围"""
    hunks = []
    current_file = ""
    for line in diff.split("\n"):
        if line.startswith("diff --git"):
            m = re.search(r"a/(.*?)\s+b/", line)
            if m:
                current_file = m.group(1)
        elif line.startswith("--- a/"):
            current_file = line[6:].strip()
        elif line.startswith("@@"):
            m = re.match(r"@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@", line)
            if m and current_file:
                old_start = int(m.group(1))
                old_count = int(m.group(2)) if m.group(2) else 1
                new_start = int(m.group(3))
                new_count = int(m.group(4)) if m.group(4) else 1
                hunks.append({
                    "file": current_file,
                    "old_start": old_start, "old_end": old_start + old_count,
                    "new_start": new_start, "new_end": new_start + new_count,
                })
    return hunks


def compute_hunk_overlap(hunks_a: List[Dict], hunks_b: List[Dict],
                         margin: int = 50) -> tuple:
    """
    比较两组 hunk 的重叠关系。
    Returns: (direct_overlaps, adjacent_overlaps)
      direct_overlaps: 行范围直接相交的 hunk 对数
      adjacent_overlaps: 行范围在 margin 行内相邻的 hunk 对数
    """
    direct = 0
    adjacent = 0
    for ha in hunks_a:
        for hb in hunks_b:
            if ha["file"] != hb["file"]:
                continue
            a_start, a_end = ha["new_start"], ha["new_end"]
            b_start, b_end = hb["new_start"], hb["new_end"]
            if a_start <= b_end and b_start <= a_end:
                direct += 1
            elif (a_start - margin <= b_end and b_start - margin <= a_end):
                adjacent += 1
    return direct, adjacent


def extract_keywords(subject: str, max_count: int = 5) -> List[str]:
    stops = {"a", "an", "the", "in", "on", "at", "to", "for", "of", "with", "by",
             "and", "or", "not", "is", "it", "this", "that", "from", "fix", "add"}
    words = re.findall(r"\w+", normalize_subject(subject))
    return [w for w in words if len(w) > 2 and w not in stops][:max_count]


def subject_similarity(s1: str, s2: str) -> float:
    return difflib.SequenceMatcher(None, normalize_subject(s1), normalize_subject(s2)).ratio()


def diff_similarity(d1: str, d2: str) -> float:
    def changes(d):
        return [l[1:].strip() for l in d.split("\n")
                if (l.startswith("+") or l.startswith("-"))
                and not l.startswith(("+++", "---")) and l[1:].strip()]
    c1, c2 = changes(d1), changes(d2)
    if not c1 or not c2:
        return 0.0
    return difflib.SequenceMatcher(None, c1, c2).ratio()


def _extract_change_lines(diff: str):
    """提取 diff 中的 +/- 变更行，分别返回 added 和 removed（去前缀、去空白行、去短行噪声）"""
    added, removed = [], []
    for line in diff.split("\n"):
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            s = line[1:].strip()
            if len(s) >= 4:
                added.append(s)
        elif line.startswith("-"):
            s = line[1:].strip()
            if len(s) >= 4:
                removed.append(s)
    return added, removed


def diff_containment(source_diff: str, target_diff: str) -> float:
    """
    计算 source_diff 的改动在 target_diff 中的包含度 (0.0~1.0)。
    不对称：衡量 "target 包含了多少 source 的改动"。
    适用于本地仓库把社区多个 patch 合并为一个 commit 的场景。
    """
    from collections import Counter

    src_add, src_rem = _extract_change_lines(source_diff)
    tgt_add, tgt_rem = _extract_change_lines(target_diff)

    total = len(src_add) + len(src_rem)
    if total == 0:
        return 0.0

    tgt_add_bag = Counter(tgt_add)
    tgt_rem_bag = Counter(tgt_rem)

    matched = 0
    for line in src_add:
        if tgt_add_bag[line] > 0:
            matched += 1
            tgt_add_bag[line] -= 1
    for line in src_rem:
        if tgt_rem_bag[line] > 0:
            matched += 1
            tgt_rem_bag[line] -= 1

    return matched / total


def file_similarity(f1: List[str], f2: List[str]) -> float:
    if not f1 or not f2:
        return 0.0
    n1 = {f.split("/")[-1] for f in f1}
    n2 = {f.split("/")[-1] for f in f2}
    return len(n1 & n2) / len(n1 | n2) if (n1 | n2) else 0.0


class CommitMatcher:
    def match_by_subject(self, src: CommitInfo, tgts: List[CommitInfo],
                         threshold: float = 0.85) -> List[MatchResult]:
        res = []
        for t in tgts:
            s = subject_similarity(src.subject, t.subject)
            if s >= threshold:
                res.append(MatchResult(target_commit=t.commit_id, source_commit=src.commit_id,
                                       confidence=s, match_type="subject_similarity",
                                       details={"source_subject": src.subject, "target_subject": t.subject}))
        res.sort(key=lambda x: x.confidence, reverse=True)
        return res

    def match_by_diff(self, src: CommitInfo, tgts: List[CommitInfo],
                      threshold: float = 0.70,
                      use_containment: bool = False) -> List[MatchResult]:
        """
        use_containment=True:  引入commit搜索模式，启用包含度检测 (squash场景)
        use_containment=False: 修复commit搜索模式，仅用双向相似度
        """
        res = []
        sf = src.modified_files or extract_files_from_diff(src.diff_code)
        for t in tgts:
            tf = t.modified_files or extract_files_from_diff(t.diff_code)
            fs = file_similarity(sf, tf)
            if fs < 0.3:
                continue

            ds = diff_similarity(src.diff_code, t.diff_code)

            if use_containment:
                dc = diff_containment(src.diff_code, t.diff_code)
                if dc >= ds:
                    score = fs * 0.3 + dc * 0.7
                    mtype = "diff_containment"
                else:
                    score = fs * 0.4 + ds * 0.6
                    mtype = "diff_similarity"
            else:
                dc = 0.0
                score = fs * 0.4 + ds * 0.6
                mtype = "diff_similarity"

            if score >= threshold:
                details = {"file_sim": fs, "diff_sim": ds}
                if use_containment:
                    details["diff_containment"] = dc
                res.append(MatchResult(
                    target_commit=t.commit_id, source_commit=src.commit_id,
                    confidence=score, match_type=mtype, details=details))
        res.sort(key=lambda x: x.confidence, reverse=True)
        return res

    def match_comprehensive(self, src: CommitInfo, tgts: List[CommitInfo],
                            use_containment: bool = False) -> List[MatchResult]:
        for t in tgts:
            if src.commit_id[:12] == t.commit_id[:12]:
                return [MatchResult(target_commit=t.commit_id, source_commit=src.commit_id,
                                     confidence=1.0, match_type="exact_id",
                                     details={"target_subject": t.subject})]
        subj = self.match_by_subject(src, tgts, 0.85)
        if subj and subj[0].confidence >= 0.95:
            return subj
        diff = self.match_by_diff(src, tgts, 0.70, use_containment=use_containment)
        seen = {}
        for m in subj + diff:
            if m.target_commit not in seen or m.confidence > seen[m.target_commit].confidence:
                seen[m.target_commit] = m
        return sorted(seen.values(), key=lambda x: x.confidence, reverse=True)


class DependencyGraph:
    def __init__(self):
        self.graph: Dict[str, Set[str]] = defaultdict(set)
        self.reverse: Dict[str, Set[str]] = defaultdict(set)

    def add(self, patch: str, depends_on: str):
        self.graph[patch].add(depends_on)
        self.reverse[depends_on].add(patch)

    def topological_sort(self, patches: List[str]) -> List[str]:
        ind = {p: 0 for p in patches}
        for p in patches:
            for d in self.graph[p]:
                if d in ind:
                    ind[p] += 1
        q = deque(p for p in patches if ind[p] == 0)
        res = []
        while q:
            cur = q.popleft()
            res.append(cur)
            for d in self.reverse[cur]:
                if d in ind:
                    ind[d] -= 1
                    if ind[d] == 0:
                        q.append(d)
        return res
