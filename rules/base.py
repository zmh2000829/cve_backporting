"""规则与级别策略的基础抽象。"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.models import (
    DependencyAnalysisDetails,
    DryRunResult,
    FunctionImpact,
    PatchInfo,
    PrerequisitePatch,
)


@dataclass
class RuleContext:
    patch: PatchInfo
    dryrun: Optional[DryRunResult]
    function_impacts: List[FunctionImpact]
    changed_lines: int
    hunk_count: int
    prerequisite_patches: List[PrerequisitePatch] = field(default_factory=list)
    dependency_details: Optional[DependencyAnalysisDetails] = None
    critical_structure_hits: List[str] = field(default_factory=list)
    special_risk_report: Dict = field(default_factory=dict)
    risk_markers: Dict[str, List[str]] = field(default_factory=dict)
    llm_enabled: bool = False
    base_level: str = "L5"
    base_method: str = ""


class PolicyRule:
    rule_id = "base"
    name = "BaseRule"
    severity = "info"
    rule_class = "risk_profile"
    rule_scope = "risk"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        raise NotImplementedError


class RuleRegistry:
    def __init__(self):
        self.rules: List[PolicyRule] = []

    def register(self, rule: PolicyRule):
        self.rules.append(rule)

    def evaluate(self, ctx: RuleContext) -> List[Dict]:
        hits = []
        for rule in self.rules:
            try:
                out = rule.evaluate(ctx)
                if out:
                    out.setdefault("rule_class", getattr(rule, "rule_class", "risk_profile"))
                    out.setdefault("rule_scope", getattr(rule, "rule_scope", "risk"))
                    hits.append(out)
            except Exception as exc:
                hits.append({
                    "rule_id": f"{rule.rule_id}_error",
                    "name": rule.name,
                    "severity": "warn",
                    "rule_class": getattr(rule, "rule_class", "risk_profile"),
                    "rule_scope": getattr(rule, "rule_scope", "risk"),
                    "level_floor": "L2",
                    "message": f"规则异常: {exc}",
                    "evidence": {},
                })
        return hits


@dataclass
class LevelPolicy:
    level: str
    methods: List[str] = field(default_factory=list)
    strategy: str = ""
    review_mode: str = "manual-review"
    next_action: str = ""
    harmless_allowed: bool = False
    confidence_with_llm: str = "medium"
    confidence_without_llm: str = "medium"


class LevelPolicyRegistry:
    def __init__(self):
        self._policies: Dict[str, LevelPolicy] = {}
        self._method_to_level: Dict[str, str] = {}

    def register(self, policy: LevelPolicy):
        self._policies[policy.level] = policy
        for method in policy.methods:
            self._method_to_level[method] = policy.level

    def get(self, level: str) -> Optional[LevelPolicy]:
        return self._policies.get(level)

    def resolve_base_level(self, method: str) -> str:
        return self._method_to_level.get(method or "", "L5")
