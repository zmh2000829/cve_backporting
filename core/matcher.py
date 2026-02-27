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
                      threshold: float = 0.70) -> List[MatchResult]:
        res = []
        sf = src.modified_files or extract_files_from_diff(src.diff_code)
        for t in tgts:
            tf = t.modified_files or extract_files_from_diff(t.diff_code)
            fs = file_similarity(sf, tf)
            if fs < 0.3:
                continue
            ds = diff_similarity(src.diff_code, t.diff_code)
            combined = fs * 0.4 + ds * 0.6
            if combined >= threshold:
                res.append(MatchResult(target_commit=t.commit_id, source_commit=src.commit_id,
                                       confidence=combined, match_type="diff_similarity",
                                       details={"file_sim": fs, "diff_sim": ds}))
        res.sort(key=lambda x: x.confidence, reverse=True)
        return res

    def match_comprehensive(self, src: CommitInfo, tgts: List[CommitInfo]) -> List[MatchResult]:
        for t in tgts:
            if src.commit_id[:12] == t.commit_id[:12]:
                return [MatchResult(target_commit=t.commit_id, source_commit=src.commit_id,
                                     confidence=1.0, match_type="exact_id",
                                     details={"target_subject": t.subject})]
        subj = self.match_by_subject(src, tgts, 0.85)
        if subj and subj[0].confidence >= 0.95:
            return subj
        diff = self.match_by_diff(src, tgts, 0.70)
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
