"""所有共享数据模型"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


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
class LevelDecision:
    """L0-L5 级别判定结果"""
    level: str = "L5"                    # L0/L1/L2/L3/L4/L5
    base_level: str = "L5"               # DryRun 基线级别（规则抬升前）
    base_method: str = ""                # DryRun 成功方法
    strategy: str = ""                    # 使用的策略说明
    review_mode: str = ""                 # auto-pass / llm-review / manual-approval ...
    next_action: str = ""                 # 下一步建议动作
    harmless: bool = False                 # 是否可判定为无害变更
    confidence: str = "medium"            # high/medium/low
    reason: str = ""                      # 判定理由
    warnings: List[str] = field(default_factory=list)  # 风险告警
    rule_hits: List[Dict[str, Any]] = field(default_factory=list)  # 命中的规则明细


@dataclass
class FunctionImpact:
    """函数调用/被调用影响分析"""
    function: str = ""
    callers: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)
    impact_score: float = 0.0
    warnings: List[str] = field(default_factory=list)


@dataclass
class ValidationDetails:
    """validate 过程细节（用于可审计输出）"""
    workflow_steps: List[str] = field(default_factory=list)
    level_decision: Optional[LevelDecision] = None
    function_impacts: List[FunctionImpact] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    rule_profile: str = "default"
    rule_version: str = "v2"


@dataclass
class DependencyAnalysisDetails:
    """前置依赖分析详情（用于"无前置"场景的详细说明）"""
    candidate_count: int = 0                    # 候选 commit 总数
    strong_count: int = 0                       # strong 依赖数
    medium_count: int = 0                       # medium 依赖数
    weak_count: int = 0                         # weak 依赖数
    time_window_start: str = ""                 # 时间窗口起点 (引入 commit 时间)
    time_window_end: str = ""                   # 时间窗口终点 (HEAD)
    analysis_files: List[str] = field(default_factory=list)  # 分析的文件列表
    analysis_scope: str = ""                    # 分析范围描述
    no_prerequisite_reason: str = ""            # 无前置的原因说明
    confidence_level: str = "medium"            # 结论置信度: high/medium/low
    boundary_statement: str = ""                # 边界声明 (仅对当前分支/配置成立)
    dryrun_baseline_passed: bool = False        # 空集基线 DryRun 是否通过
    dryrun_method: str = ""                     # DryRun 通过的方法 (strict/fuzz/3way/etc)
    analysis_narrative: List[str] = field(default_factory=list)  # 拟人化分析过程 (5-6 条)
    manual_review_checklist: List[str] = field(default_factory=list)  # 人工审查清单


@dataclass
class DryRunResult:
    """Dry-run 试应用结果"""
    applies_cleanly: bool = False
    apply_method: str = ""          # "strict" / "context-C1" / "3way" / "regenerated" / ""
    conflicting_files: List[str] = field(default_factory=list)
    conflict_details: List[Dict] = field(default_factory=list)
    conflict_hunks: List[Dict] = field(default_factory=list)  # 逐hunk冲突分析
    error_output: str = ""
    stat_output: str = ""
    patch_file: str = ""
    adapted_patch: str = ""         # 上下文重生成/冲突适配后的补丁内容
    search_reports: List[Dict] = field(default_factory=list)  # 详细搜索过程报告
    apply_attempts: List[Dict[str, str]] = field(default_factory=list)  # 每次 apply 尝试轨迹


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
    dependency_details: Optional["DependencyAnalysisDetails"] = None  # v2.0 新增：依赖分析详情
    level_decision: Optional[LevelDecision] = None
    function_impacts: List[FunctionImpact] = field(default_factory=list)
    validation_details: Optional[ValidationDetails] = None


# ── v2.0 深度分析模型 ─────────────────────────────────────────────


@dataclass
class CommunityDiscussion:
    """社区讨论记录 (lore.kernel.org / bugzilla / CVE 引用)"""
    source: str = ""              # "lore" / "bugzilla" / "cve_ref"
    url: str = ""
    title: str = ""
    date: str = ""
    author: str = ""
    snippet: str = ""             # 关键内容摘要 (确定性截取或 LLM 摘要)
    relevance: str = ""           # "direct_fix" / "discussion" / "related"


@dataclass
class VulnAnalysis:
    """漏洞深度分析"""
    vuln_type: str = ""           # "UAF" / "OOB" / "NULL_deref" / "race" / ...
    severity: str = ""            # "critical" / "high" / "medium" / "low"
    cvss_score: float = 0.0
    affected_subsystem: str = ""
    affected_functions: List[str] = field(default_factory=list)
    root_cause: str = ""          # 技术根因描述
    trigger_path: str = ""        # 触发路径
    exploit_conditions: str = ""  # 利用条件
    impact_description: str = ""  # 影响描述
    detection_method: str = ""    # 漏洞判断方法
    llm_enhanced: bool = False    # 是否经过 LLM 增强


@dataclass
class CodeReviewItem:
    """代码检视条目"""
    category: str = ""        # "lock" / "refcount" / "null_check" / "overflow" /
                              # "error_handling" / "race_condition"
    location: str = ""        # "file:function:line"
    description: str = ""
    severity: str = "info"    # "critical" / "warning" / "info"


@dataclass
class PatchReview:
    """修复补丁逻辑分析"""
    fix_summary: str = ""                 # 修复补丁做了什么
    trigger_analysis: str = ""            # 原始漏洞如何触发
    prevention_mechanism: str = ""        # 修复方案如何预防
    modified_functions: List[str] = field(default_factory=list)
    call_topology: Dict = field(default_factory=dict)  # {func: [callers/callees]}
    data_structures: List[Dict] = field(default_factory=list)  # 涉及的锁/结构体
    code_review_items: List[CodeReviewItem] = field(default_factory=list)
    security_patterns: List[str] = field(default_factory=list)  # 检测到的安全模式
    llm_enhanced: bool = False


@dataclass
class PostPatch:
    """后置关联补丁"""
    commit_id: str = ""
    subject: str = ""
    relation: str = ""        # "followup_fix" / "same_function" / "same_subsystem"
    description: str = ""


@dataclass
class RiskBenefitScore:
    """风险收益量化评分 — 每个维度附带等级标签和详细文字解释"""
    merge_complexity: float = 0.0
    merge_complexity_detail: str = ""
    regression_risk: float = 0.0
    regression_risk_detail: str = ""
    change_scope: float = 0.0
    change_scope_detail: str = ""
    security_benefit: float = 0.0
    security_benefit_detail: str = ""
    overall_score: float = 0.0
    overall_detail: str = ""
    factors: List[str] = field(default_factory=list)


@dataclass
class MergeRecommendation:
    """合入建议"""
    action: str = ""                  # "merge" / "merge_with_prereqs" /
                                      # "manual_review" / "skip"
    confidence: float = 0.0
    summary: str = ""                 # 综合建议
    dependency_analysis: str = ""     # 关联补丁完整分析
    prerequisite_actions: List[str] = field(default_factory=list)
    review_checklist: List[str] = field(default_factory=list)
    risk_benefit: Optional[RiskBenefitScore] = None
    llm_enhanced: bool = False


@dataclass
class AnalysisResultV2:
    """v2.0 深度分析结果 (扩展 AnalysisResult)"""
    base: Optional[AnalysisResult] = None   # v1 基础分析结果
    community: List[CommunityDiscussion] = field(default_factory=list)
    vuln_analysis: Optional[VulnAnalysis] = None
    patch_review: Optional[PatchReview] = None
    post_patches: List[PostPatch] = field(default_factory=list)
    merge_recommendation: Optional[MergeRecommendation] = None

    def to_dict(self) -> Dict:
        """序列化为 JSON 友好的 dict"""
        import dataclasses
        d: Dict = {}
        if self.base:
            d["cve_id"] = self.base.cve_id
            d["target_version"] = self.base.target_version
        if self.community:
            d["community_discussions"] = [
                dataclasses.asdict(c) for c in self.community
            ]
        if self.vuln_analysis:
            d["vuln_analysis"] = dataclasses.asdict(self.vuln_analysis)
        if self.patch_review:
            d["patch_review"] = dataclasses.asdict(self.patch_review)
        if self.post_patches:
            d["post_patches"] = [
                dataclasses.asdict(p) for p in self.post_patches
            ]
        if self.merge_recommendation:
            d["merge_recommendation"] = dataclasses.asdict(
                self.merge_recommendation
            )
        return d
