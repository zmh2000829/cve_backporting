"""所有共享数据模型"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class CveInfo:
    """CVE漏洞信息"""
    cve_id: str
    description: str = ""
    severity: str = "unknown"
    introduced_commits: List[Dict] = field(default_factory=list)
    fix_commits: List[Dict] = field(default_factory=list)
    mainline_fix_commit: str = ""
    mainline_version: str = ""
    version_commit_mapping: Dict[str, str] = field(default_factory=dict)

    @property
    def introduced_commit_id(self) -> Optional[str]:
        return self.introduced_commits[0]["commit_id"] if self.introduced_commits else None

    @property
    def fix_commit_id(self) -> Optional[str]:
        return self.mainline_fix_commit or (
            self.fix_commits[0]["commit_id"] if self.fix_commits else None
        )


@dataclass
class PatchInfo:
    """补丁内容"""
    commit_id: str
    subject: str = ""
    commit_msg: str = ""
    author: str = ""
    date: str = ""
    diff_code: str = ""
    modified_files: List[str] = field(default_factory=list)


@dataclass
class GitCommit:
    """Git commit记录"""
    commit_id: str
    subject: str
    commit_msg: str = ""
    author: str = ""
    timestamp: int = 0
    diff_code: str = ""
    modified_files: List[str] = field(default_factory=list)


@dataclass
class CommitInfo:
    """用于匹配的commit详情"""
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


@dataclass
class SearchResult:
    """commit搜索结果"""
    found: bool = False
    strategy: str = "none"
    confidence: float = 0.0
    target_commit: str = ""
    target_subject: str = ""
    candidates: List[Dict] = field(default_factory=list)
    steps: List["SearchStep"] = field(default_factory=list)


@dataclass
class StrategyResult:
    """单个搜索策略的结果"""
    level: str           # "L1", "L2", "L3"
    name: str            # "ID精确匹配", "Subject语义匹配", "Diff代码匹配"
    found: bool = False
    confidence: float = 0.0
    target_commit: str = ""
    target_subject: str = ""
    detail: str = ""
    candidates: List[Dict] = field(default_factory=list)
    elapsed: float = 0.0


@dataclass
class MultiStrategyResult:
    """多策略综合搜索结果"""
    commit_id: str
    subject: str = ""
    author: str = ""
    modified_files: List[str] = field(default_factory=list)
    strategies: List[StrategyResult] = field(default_factory=list)

    @property
    def is_present(self) -> bool:
        return any(s.found for s in self.strategies)

    @property
    def best(self) -> Optional["StrategyResult"]:
        found = [s for s in self.strategies if s.found]
        return max(found, key=lambda s: s.confidence) if found else None

    @property
    def verdict(self) -> str:
        b = self.best
        if not b:
            return "未找到"
        return f"{b.target_commit[:12]} via {b.level} ({b.confidence:.0%})"


@dataclass
class SearchStep:
    """搜索过程中单个级别的记录"""
    level: str              # "L1", "L2", "L3"
    status: str = "skip"    # "hit", "miss", "skip"
    detail: str = ""
    elapsed: float = 0.0


@dataclass
class PrerequisitePatch:
    """前置依赖补丁"""
    commit_id: str
    subject: str
    author: str = ""
    timestamp: int = 0
    grade: str = "weak"         # "strong", "medium", "weak"
    score: float = 0.0
    overlap_funcs: List[str] = field(default_factory=list)
    overlap_hunks: int = 0      # 重叠 hunk 数量
    adjacent_hunks: int = 0     # 相邻 hunk 数量


@dataclass
class DryRunResult:
    """Dry-run 试应用结果"""
    applies_cleanly: bool = False
    conflicting_files: List[str] = field(default_factory=list)
    conflict_details: List[Dict] = field(default_factory=list)
    error_output: str = ""
    stat_output: str = ""
    patch_file: str = ""


@dataclass
class AnalysisResult:
    """CVE完整分析结果"""
    cve_id: str
    target_version: str
    cve_info: Optional[CveInfo] = None
    fix_patch: Optional[PatchInfo] = None
    introduced_search: Optional[SearchResult] = None
    fix_search: Optional[SearchResult] = None
    is_vulnerable: bool = False
    is_fixed: bool = False
    prerequisite_patches: List[PrerequisitePatch] = field(default_factory=list)
    conflict_files: List[str] = field(default_factory=list)
    dry_run: Optional[DryRunResult] = None
    recommendations: List[str] = field(default_factory=list)
