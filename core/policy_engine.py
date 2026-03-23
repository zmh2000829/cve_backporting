"""策略分级与可插拔规则引擎"""

import importlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.function_analyzer import FunctionAnalyzer
from core.matcher import extract_hunks_from_diff
from core.models import LevelDecision, FunctionImpact, ValidationDetails, PatchInfo, DryRunResult


@dataclass
class RuleContext:
    patch: PatchInfo
    dryrun: Optional[DryRunResult]
    function_impacts: List[FunctionImpact]
    changed_lines: int
    hunk_count: int
    critical_structure_hits: List[str] = field(default_factory=list)


class PolicyRule:
    rule_id = "base"
    name = "BaseRule"
    severity = "info"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        raise NotImplementedError


class LargeChangeRule(PolicyRule):
    rule_id = "large_change"
    name = "Large Change Warning"
    severity = "warn"

    def __init__(self, line_threshold: int, hunk_threshold: int):
        self.line_threshold = line_threshold
        self.hunk_threshold = hunk_threshold

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        if ctx.changed_lines >= self.line_threshold or ctx.hunk_count >= self.hunk_threshold:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "message": f"改动较大: {ctx.changed_lines} 行, {ctx.hunk_count} hunk",
                "evidence": {"changed_lines": ctx.changed_lines, "hunk_count": ctx.hunk_count},
            }
        return None


class CriticalStructureRule(PolicyRule):
    rule_id = "critical_structures"
    name = "Critical Structures Changed"
    severity = "high"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        if not ctx.critical_structure_hits:
            return None
        uniq = sorted(set(ctx.critical_structure_hits))
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "message": "检测到关键结构/锁变更: " + ", ".join(uniq[:6]),
            "evidence": {"keywords": uniq},
        }


class CallChainFanoutRule(PolicyRule):
    rule_id = "call_chain_fanout"
    name = "Call Chain Fanout Warning"
    severity = "warn"

    def __init__(self, fanout_threshold: int):
        self.fanout_threshold = fanout_threshold

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        risky = [fi for fi in ctx.function_impacts if (len(fi.callers) + len(fi.callees)) >= self.fanout_threshold]
        if not risky:
            return None
        top = sorted(risky, key=lambda x: len(x.callers) + len(x.callees), reverse=True)[0]
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "message": f"调用链扩散较大: {top.function} callers={len(top.callers)} callees={len(top.callees)}",
            "evidence": {"function": top.function, "callers": top.callers[:8], "callees": top.callees[:8]},
        }


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
                    hits.append(out)
            except Exception as e:
                hits.append({"rule_id": f"{rule.rule_id}_error", "name": rule.name, "severity": "warn", "message": f"规则异常: {e}", "evidence": {}})
        return hits


class PolicyEngine:
    def __init__(self, config=None, llm_enabled: bool = False):
        self.config = config
        self.llm_enabled = llm_enabled
        self.fa = FunctionAnalyzer()
        self.registry = RuleRegistry()
        self._register_default_rules()
        self._load_extra_rules()

    def _register_default_rules(self):
        lt = getattr(self.config, "large_change_line_threshold", 80) if self.config else 80
        ht = getattr(self.config, "large_hunk_threshold", 8) if self.config else 8
        ft = getattr(self.config, "call_chain_fanout_threshold", 6) if self.config else 6
        self.registry.register(LargeChangeRule(lt, ht))
        self.registry.register(CriticalStructureRule())
        self.registry.register(CallChainFanoutRule(ft))

    def _load_extra_rules(self):
        if not self.config:
            return
        for mod in (getattr(self.config, "extra_rule_modules", []) or []):
            try:
                m = importlib.import_module(mod)
                if hasattr(m, "register_rules"):
                    m.register_rules(self.registry)
                elif hasattr(m, "RULES"):
                    for r in getattr(m, "RULES"):
                        self.registry.register(r)
            except Exception:
                continue

    def evaluate(self, patch: Optional[PatchInfo], dryrun: Optional[DryRunResult], git_mgr, target_version: str, path_mapper=None) -> ValidationDetails:
        if not patch:
            return ValidationDetails(workflow_steps=["无补丁数据，跳过策略分级"], warnings=["fix_patch 为空"], rule_profile="default", rule_version="v1")

        changed = self._count_changed_lines(patch.diff_code or "")
        hunks = len(extract_hunks_from_diff(patch.diff_code or ""))
        funcs = self._extract_modified_function_names(patch.diff_code or "")
        impacts = self._analyze_function_impacts(patch, funcs, git_mgr, target_version, path_mapper)
        critical_hits = self._scan_critical_structure_hits(patch.diff_code or "")

        ctx = RuleContext(patch=patch, dryrun=dryrun, function_impacts=impacts, changed_lines=changed, hunk_count=hunks, critical_structure_hits=critical_hits)
        rule_hits = self.registry.evaluate(ctx)
        level_decision = self._decide_level(dryrun, rule_hits)

        steps = [
            f"级别判定: {level_decision.level} ({level_decision.strategy})",
            f"变更规模: {changed} 行, {hunks} hunk, {len(funcs)} 函数",
            f"调用链影响函数: {len(impacts)}",
            f"规则命中: {len(rule_hits)}",
        ]
        warnings = [h["message"] for h in rule_hits if h.get("severity") in ("warn", "high")]

        return ValidationDetails(
            workflow_steps=steps,
            level_decision=level_decision,
            function_impacts=impacts,
            warnings=warnings,
            rule_profile=getattr(self.config, "profile", "default") if self.config else "default",
            rule_version="v1",
        )

    def _decide_level(self, dryrun: Optional[DryRunResult], rule_hits: List[Dict]) -> LevelDecision:
        method = (dryrun.apply_method if dryrun else "") or ""
        m2l = {
            "strict": "L0", "ignore-ws": "L1", "context-C1": "L1", "C1-ignore-ws": "L1",
            "3way": "L2", "regenerated": "L3", "conflict-adapted": "L4", "verified-direct": "L5",
        }
        level = m2l.get(method, "L5")
        high = [h for h in rule_hits if h.get("severity") == "high"]
        warn = [h for h in rule_hits if h.get("severity") == "warn"]

        if level == "L0":
            strategy, conf = "严格匹配", "high"
        elif level == "L1":
            strategy, conf = "轻度上下文/空白适配", ("high" if self.llm_enabled else "medium")
        elif level == "L2":
            strategy, conf = "3-way 合并", "medium"
        elif level == "L3":
            strategy, conf = "上下文重生成", "medium"
        elif level == "L4":
            strategy, conf = "冲突适配", "low"
        else:
            strategy, conf = "高级适配路径", "low"

        harmless = (level == "L0" and not high and not warn)
        warnings = [h["message"] for h in rule_hits if h.get("severity") in ("warn", "high")]
        reason = f"DryRun={method or 'none'} -> {level}; 规则命中 {len(rule_hits)}"

        return LevelDecision(level=level, strategy=strategy, harmless=harmless, confidence=conf, reason=reason, warnings=warnings, rule_hits=rule_hits)

    def _extract_modified_function_names(self, diff_text: str) -> List[str]:
        funcs = set()
        for m in re.finditer(r'@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@\s*(.+)', diff_text):
            sig = m.group(1).strip()
            fm = re.search(r'\b([a-zA-Z_]\w{2,})\s*\(', sig)
            if fm:
                funcs.add(fm.group(1))
        return sorted(funcs)

    def _analyze_function_impacts(self, patch: PatchInfo, modified_funcs: List[str], git_mgr, target_version: str, path_mapper=None) -> List[FunctionImpact]:
        if not modified_funcs:
            return []
        topo_all: Dict[str, Dict] = {}
        for fpath in (patch.modified_files or [])[:8]:
            content = self._get_file_content(git_mgr, target_version, fpath, path_mapper)
            if not content:
                continue
            topo_all.update(self.fa.build_call_topology(content, fpath))

        impacts: List[FunctionImpact] = []
        fanout_t = getattr(self.config, "call_chain_fanout_threshold", 6) if self.config else 6
        for fn in modified_funcs:
            info = topo_all.get(fn)
            if not info:
                continue
            callers = info.get("callers", []) or []
            callees = info.get("callees", []) or []
            fanout = len(callers) + len(callees)
            warns = []
            if fanout >= fanout_t:
                warns.append(f"{fn} 调用链影响较大: callers={len(callers)}, callees={len(callees)}")
            impacts.append(FunctionImpact(function=fn, callers=callers[:12], callees=callees[:12], impact_score=round(min(fanout / 10.0, 1.0), 3), warnings=warns))
        return impacts

    def _count_changed_lines(self, diff_text: str) -> int:
        n = 0
        for l in diff_text.split("\n"):
            if l.startswith(("+++", "---")):
                continue
            if l.startswith(("+", "-")):
                n += 1
        return n

    def _scan_critical_structure_hits(self, diff_text: str) -> List[str]:
        kws = getattr(self.config, "critical_structure_keywords", None) or ["spin_lock", "mutex", "rcu", "refcount", "kref", "atomic", "struct"]
        changes = [l[1:].strip() for l in diff_text.split("\n") if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
        hits = []
        for c in changes:
            for kw in kws:
                if kw in c:
                    hits.append(kw)
        return hits

    def _get_file_content(self, git_mgr, target_version: str, fpath: str, path_mapper=None) -> Optional[str]:
        out = git_mgr.run_git(["git", "show", f"HEAD:{fpath}"], target_version, timeout=15)
        if out is not None:
            return out
        if path_mapper:
            for alt in path_mapper.translate(fpath):
                if alt == fpath:
                    continue
                out = git_mgr.run_git(["git", "show", f"HEAD:{alt}"], target_version, timeout=15)
                if out is not None:
                    return out
        return None
