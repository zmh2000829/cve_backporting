"""策略分级与可插拔规则引擎。"""

import importlib
import inspect
import re
from typing import Dict, List, Optional

from core.function_analyzer import FunctionAnalyzer
from core.matcher import extract_hunks_from_diff
from core.models import DryRunResult, FunctionImpact, LevelDecision, PatchInfo, ValidationDetails
from rules.base import LevelPolicyRegistry, RuleContext, RuleRegistry
from rules.level_policies import derive_final_level, effective_level_floor, level_rank


BUILTIN_POLICY_MODULES = (
    "rules.level_policies",
    "rules.default_rules",
)


class PolicyEngine:
    def __init__(self, config=None, llm_enabled: bool = False):
        self.config = config
        self.llm_enabled = llm_enabled
        self.fa = FunctionAnalyzer()
        self.rule_registry = RuleRegistry()
        self.level_registry = LevelPolicyRegistry()
        self._load_policy_modules(BUILTIN_POLICY_MODULES)
        self._load_policy_modules(getattr(self.config, "extra_rule_modules", []) or [])

    def _load_policy_modules(self, modules):
        for mod_name in modules:
            try:
                module = importlib.import_module(mod_name)
            except Exception:
                continue
            self._register_policy_module(module)

    def _register_policy_module(self, module):
        register_levels = getattr(module, "register_level_policies", None)
        if callable(register_levels):
            self._invoke_registrar(register_levels, self.level_registry)

        for policy in getattr(module, "LEVEL_POLICIES", []) or []:
            self.level_registry.register(policy)

        register_rules = getattr(module, "register_rules", None)
        if callable(register_rules):
            self._invoke_registrar(register_rules, self.rule_registry)

        for rule in getattr(module, "RULES", []) or []:
            self.rule_registry.register(rule)

    def _invoke_registrar(self, registrar, registry):
        try:
            param_count = len(inspect.signature(registrar).parameters)
        except (TypeError, ValueError):
            param_count = 1
        if param_count >= 2:
            registrar(registry, self.config)
        else:
            registrar(registry)

    def evaluate(self, patch: Optional[PatchInfo], dryrun: Optional[DryRunResult], git_mgr, target_version: str, path_mapper=None) -> ValidationDetails:
        if not patch:
            return ValidationDetails(
                workflow_steps=["无补丁数据，跳过策略分级"],
                warnings=["fix_patch 为空"],
                rule_profile=getattr(self.config, "profile", "default") if self.config else "default",
                rule_version="v2",
            )

        base_method = (dryrun.apply_method if dryrun else "") or ""
        base_level = self.level_registry.resolve_base_level(base_method)
        changed = self._count_changed_lines(patch.diff_code or "")
        hunks = len(extract_hunks_from_diff(patch.diff_code or ""))
        funcs = self._extract_modified_function_names(patch.diff_code or "")
        impacts = self._analyze_function_impacts(patch, funcs, git_mgr, target_version, path_mapper)
        critical_hits = self._scan_critical_structure_hits(patch.diff_code or "")

        ctx = RuleContext(
            patch=patch,
            dryrun=dryrun,
            function_impacts=impacts,
            changed_lines=changed,
            hunk_count=hunks,
            critical_structure_hits=critical_hits,
            llm_enabled=self.llm_enabled,
            base_level=base_level,
            base_method=base_method,
        )
        rule_hits = self.rule_registry.evaluate(ctx)
        level_decision = self._decide_level(base_method, base_level, rule_hits)

        cross_n = getattr(self, "_last_cross_file_count", 0)
        steps = [
            f"DryRun 基线: {base_level} ({base_method or 'none'})",
            f"最终场景: {level_decision.level} ({level_decision.review_mode})",
            f"变更规模: {changed} 行, {hunks} hunk, {len(funcs)} 函数",
            f"调用链影响函数: {len(impacts)}（跨文件合并源文件 {cross_n} 个）",
            f"规则命中: {len(rule_hits)}",
        ]
        warnings = [hit["message"] for hit in rule_hits if hit.get("severity") in ("warn", "high")]

        return ValidationDetails(
            workflow_steps=steps,
            level_decision=level_decision,
            function_impacts=impacts,
            warnings=warnings,
            rule_profile=getattr(self.config, "profile", "default") if self.config else "default",
            rule_version="v2",
        )

    def _decide_level(self, base_method: str, base_level: str, rule_hits: List[Dict]) -> LevelDecision:
        final_level = derive_final_level(base_level, rule_hits)
        policy = self.level_registry.get(final_level) or self.level_registry.get("L5")
        high = [hit for hit in rule_hits if hit.get("severity") == "high"]
        warn = [hit for hit in rule_hits if hit.get("severity") == "warn"]
        warnings = [hit["message"] for hit in rule_hits if hit.get("severity") in ("warn", "high")]

        harmful_promotions = []
        for hit in rule_hits:
            floor = effective_level_floor(hit)
            if level_rank(floor) > level_rank(base_level):
                harmful_promotions.append(f"{hit.get('rule_id', 'unknown')}→{floor}")
        promotion_reason = "；".join(harmful_promotions[:4]) if harmful_promotions else "无规则抬升"

        confidence = "low"
        strategy = ""
        review_mode = ""
        next_action = ""
        harmless = False
        if policy:
            confidence = policy.confidence_with_llm if self.llm_enabled else policy.confidence_without_llm
            strategy = policy.strategy
            review_mode = policy.review_mode
            next_action = policy.next_action
            harmless = final_level == "L0" and policy.harmless_allowed and not high and not warn

        reason = (
            f"DryRun 基线={base_level}（method={base_method or 'none'}）；"
            f"规则抬升={promotion_reason}；"
            f"命中规则 {len(rule_hits)}（high={len(high)}, warn={len(warn)}）。"
            f"仅最终 L0 且无 warn/high 命中时才判定 harmless。"
        )

        return LevelDecision(
            level=final_level,
            base_level=base_level,
            base_method=base_method,
            strategy=strategy,
            review_mode=review_mode,
            next_action=next_action,
            harmless=harmless,
            confidence=confidence,
            reason=reason,
            warnings=warnings,
            rule_hits=rule_hits,
        )

    def _extract_modified_function_names(self, diff_text: str) -> List[str]:
        funcs = set()
        for match in re.finditer(r"@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@\s*(.+)", diff_text):
            sig = match.group(1).strip()
            func_match = re.search(r"\b([a-zA-Z_]\w{2,})\s*\(", sig)
            if func_match:
                funcs.add(func_match.group(1))
        return sorted(funcs)

    def _analyze_function_impacts(self, patch: PatchInfo, modified_funcs: List[str], git_mgr, target_version: str, path_mapper=None) -> List[FunctionImpact]:
        self._last_cross_file_count = 0
        if not modified_funcs:
            return []

        pairs: List[tuple] = []
        for fpath in (patch.modified_files or [])[:8]:
            content = self._get_file_content(git_mgr, target_version, fpath, path_mapper)
            if content:
                pairs.append((fpath, content))
        self._last_cross_file_count = len(pairs)
        if not pairs:
            return []

        global_names = set()
        for fpath, content in pairs:
            for fn in self.fa.extract_functions(content, fpath):
                global_names.add(fn.name)

        callees_of, callers_of = self.fa.build_cross_file_call_graph(pairs, global_names)

        impacts: List[FunctionImpact] = []
        fanout_threshold = getattr(self.config, "call_chain_fanout_threshold", 6) if self.config else 6
        for fn in modified_funcs:
            if fn not in callees_of:
                continue
            callers = callers_of.get(fn, []) or []
            callees = callees_of.get(fn, []) or []
            fanout = len(callers) + len(callees)
            warns = []
            if fanout >= fanout_threshold:
                warns.append(f"{fn} 调用链影响较大: callers={len(callers)}, callees={len(callees)}")
            if fanout > 0:
                warns.append(f"{fn} 存在调用/被调用牵连: callers={len(callers)}, callees={len(callees)}")
            if len(pairs) > 1 and fanout > 0:
                warns.append(f"{fn} 已在 {len(pairs)} 个修改文件范围内做跨文件符号牵连分析")
            impacts.append(
                FunctionImpact(
                    function=fn,
                    callers=callers[:12],
                    callees=callees[:12],
                    impact_score=round(min(fanout / 10.0, 1.0), 3),
                    warnings=warns,
                )
            )
        return impacts

    def _count_changed_lines(self, diff_text: str) -> int:
        count = 0
        for line in diff_text.split("\n"):
            if line.startswith(("+++", "---")):
                continue
            if line.startswith(("+", "-")):
                count += 1
        return count

    def _scan_critical_structure_hits(self, diff_text: str) -> List[str]:
        keywords = getattr(self.config, "critical_structure_keywords", None) or [
            "spin_lock", "mutex", "rcu", "refcount", "kref", "atomic", "struct",
        ]
        changes = [
            line[1:].strip()
            for line in diff_text.split("\n")
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
        ]
        hits = []
        for change in changes:
            for keyword in keywords:
                if keyword in change:
                    hits.append(keyword)
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
