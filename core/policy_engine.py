"""策略分级与可插拔规则引擎。"""

import importlib
import inspect
import re
from typing import Any, Dict, List, Optional

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

    def evaluate(
        self,
        patch: Optional[PatchInfo],
        dryrun: Optional[DryRunResult],
        git_mgr,
        target_version: str,
        path_mapper=None,
        prerequisite_patches=None,
        dependency_details=None,
    ) -> ValidationDetails:
        if not patch:
            return ValidationDetails(
                workflow_steps=["无补丁数据，跳过策略分级"],
                warnings=["fix_patch 为空"],
                rule_profile=getattr(self.config, "profile", "default") if self.config else "default",
                rule_version="v2",
                special_risk_report={"enabled": bool(getattr(self.config, "special_risk_rules_enabled", True)) if self.config else True},
                strategy_buckets={},
            )

        base_method = (dryrun.apply_method if dryrun else "") or ""
        base_level = self.level_registry.resolve_base_level(base_method)
        changed = self._count_changed_lines(patch.diff_code or "")
        hunks = len(extract_hunks_from_diff(patch.diff_code or ""))
        funcs = self._extract_modified_function_names(patch.diff_code or "")
        impacts = self._analyze_function_impacts(patch, funcs, git_mgr, target_version, path_mapper)
        critical_hits = self._scan_critical_structure_hits(patch.diff_code or "")
        special_risk_report = self._build_special_risk_report(patch.diff_code or "")
        risk_markers = self._extract_risk_markers(patch.diff_code or "")

        ctx = RuleContext(
            patch=patch,
            dryrun=dryrun,
            function_impacts=impacts,
            changed_lines=changed,
            hunk_count=hunks,
            prerequisite_patches=list(prerequisite_patches or []),
            dependency_details=dependency_details,
            critical_structure_hits=critical_hits,
            special_risk_report=special_risk_report,
            risk_markers=risk_markers,
            llm_enabled=self.llm_enabled,
            base_level=base_level,
            base_method=base_method,
        )
        rule_hits = self.rule_registry.evaluate(ctx)
        level_decision = self._decide_level(base_method, base_level, rule_hits)

        cross_n = getattr(self, "_last_cross_file_count", 0)
        prereq_summary = self._summarize_prerequisites(prerequisite_patches, dependency_details)
        direct_summary = self._summarize_direct_backport(level_decision, rule_hits, prerequisite_patches)
        impact_summary = self._summarize_impact_focus(rule_hits, impacts, critical_hits, special_risk_report)
        special_risk_summary = self._summarize_special_risk(special_risk_report)
        steps = [
            f"DryRun 基线: {base_level} ({base_method or 'none'})",
            f"最终场景: {level_decision.level} ({level_decision.review_mode})",
            f"直接回合判断: {direct_summary}",
            f"关联补丁判断: {prereq_summary}",
            f"变更规模: {changed} 行, {hunks} hunk, {len(funcs)} 函数",
            f"调用链影响函数: {len(impacts)}（跨文件合并源文件 {cross_n} 个）",
            f"高影响关注: {impact_summary}",
            f"P2 专项分析: {special_risk_summary}",
            f"规则命中: {len(rule_hits)}",
        ]
        warnings = [hit["message"] for hit in rule_hits if hit.get("severity") in ("warn", "high")]
        strategy_buckets = self._build_strategy_buckets(level_decision, rule_hits, prerequisite_patches, special_risk_report)
        decision_skeleton = self._build_decision_skeleton(
            steps, level_decision, rule_hits, prerequisite_patches, impacts, critical_hits, risk_markers, special_risk_report
        )
        manual_review_checklist = self._build_manual_review_checklist(
            level_decision,
            rule_hits,
            prerequisite_patches,
            impacts,
            risk_markers,
            special_risk_report,
            dependency_details,
            base_method,
        )
        strategy_buckets = self._build_strategy_buckets(level_decision, rule_hits, prerequisite_patches, special_risk_report)

        return ValidationDetails(
            workflow_steps=steps,
            level_decision=level_decision,
            function_impacts=impacts,
            special_risk_report=special_risk_report,
            warnings=warnings,
            rule_profile=getattr(self.config, "profile", "default") if self.config else "default",
            rule_version="v2",
            strategy_buckets=strategy_buckets,
            decision_skeleton=decision_skeleton,
            manual_review_checklist=manual_review_checklist,
        )

    def _summarize_prerequisites(self, prerequisite_patches, dependency_details) -> str:
        prereqs = list(prerequisite_patches or [])
        semantic_labels = []
        if any(getattr(p, "shared_lock_domains", None) for p in prereqs):
            semantic_labels.append("共享锁域")
        if any(getattr(p, "shared_fields", None) for p in prereqs):
            semantic_labels.append("共享字段")
        if any(getattr(p, "shared_state_points", None) for p in prereqs):
            semantic_labels.append("状态迁移点")
        semantic_suffix = f"；证据集中在{' / '.join(semantic_labels)}" if semantic_labels else ""
        if prereqs:
            strong = sum(1 for p in prereqs if getattr(p, "grade", "") == "strong")
            medium = sum(1 for p in prereqs if getattr(p, "grade", "") == "medium")
            if strong:
                return f"存在 {strong} 个强依赖前置补丁，不能忽略关联补丁{semantic_suffix}"
            if medium:
                return f"存在 {medium} 个中等依赖，建议一并核对关联补丁{semantic_suffix}"
            return f"仅发现 {len(prereqs)} 个弱关联补丁，可按需复核{semantic_suffix}"
        if dependency_details is not None:
            reason = getattr(dependency_details, "no_prerequisite_reason", "")
            if reason:
                return f"未发现强/中依赖，可不优先考虑关联补丁；{reason}"
            return "未发现强/中依赖，可不优先考虑关联补丁"
        return "暂无依赖分析证据"

    def _summarize_direct_backport(self, level_decision: LevelDecision, rule_hits: List[Dict], prerequisite_patches) -> str:
        prereqs = list(prerequisite_patches or [])
        rule_ids = {hit.get("rule_id") for hit in (rule_hits or [])}
        veto_classes = {
            self._classify_rule_class(hit)
            for hit in (rule_hits or [])
            if self._classify_rule_class(hit) in ("low_level_veto", "direct_backport_veto", "risk_profile")
        }
        if "direct_backport_candidate" in rule_ids and not prereqs and level_decision.level == "L0":
            return "满足直接回合条件"
        if level_decision.level == "L1" and level_decision.base_level == "L1" and not prereqs and not veto_classes:
            if "l1_light_drift_sample" in rule_ids:
                return "补丁可直接回移，当前仅见轻微漂移样本；建议保留最小编译/回归验证"
            return "补丁可直接回移，当前仅见上下文/空白漂移，没有额外否决信号"
        if "l1_light_drift_sample" in rule_ids and not prereqs and level_decision.level == "L1":
            return "补丁主体接近可直回，当前漂移主要是注释/日志/等价宏/局部变量命名这类轻微样本"
        if "prerequisite_required" in rule_ids:
            return "不能直接回合，需先处理强依赖补丁"
        if level_decision.level in ("L0", "L1") and not prereqs:
            return "补丁主体接近可直回，但需结合规则证据确认"
        return "不建议直接回合，需先审查风险或依赖"

    def _summarize_impact_focus(
        self,
        rule_hits: List[Dict],
        impacts: List[FunctionImpact],
        critical_hits: List[str],
        special_risk_report: Dict[str, Any],
    ) -> str:
        highlights = []
        for hit in rule_hits or []:
            rule_id = hit.get("rule_id")
            if rule_id == "single_line_high_impact":
                highlights.append("单行高影响变更")
            elif rule_id == "critical_structures":
                highlights.append("关键结构/锁/引用计数")
            elif rule_id.startswith("p2_"):
                highlights.append("P2 专项高风险语义")
            elif rule_id in ("call_chain_propagation", "call_chain_fanout"):
                highlights.append("调用链扩散")
            elif rule_id == "l1_api_surface":
                highlights.append("函数签名/入参/返回路径")
        if not highlights:
            sections = ((special_risk_report or {}).get("summary") or {}).get("triggered_sections", [])
            if sections:
                highlights.append("专项命中: " + "/".join(sections[:3]))
        if not highlights and critical_hits:
            highlights.append("关键结构关键词")
        if not highlights and impacts:
            top = sorted(impacts, key=lambda x: x.impact_score, reverse=True)[0]
            if top.impact_score > 0:
                highlights.append(f"函数 {top.function} 的调用链影响")
        return "、".join(dict.fromkeys(highlights)) if highlights else "未发现额外高影响信号"

    def _summarize_special_risk(self, special_risk_report: Dict[str, Any]) -> str:
        if not special_risk_report:
            return "未输出专项分析"
        if not special_risk_report.get("enabled", True):
            return "已禁用"
        summary = special_risk_report.get("summary") or {}
        sections = summary.get("triggered_sections") or []
        if not sections:
            return "未命中锁/生命周期/状态机/字段/错误路径专项信号"
        labels = {
            "locking_sync": "锁与同步",
            "lifecycle_resource": "生命周期",
            "state_machine_control_flow": "状态机/控制流",
            "struct_field_data_path": "结构体字段",
            "error_path": "错误路径",
        }
        cn = [labels.get(item, item) for item in sections]
        return f"命中 {len(sections)} 类: {' / '.join(cn[:5])}"

    def _has_material_impacts(self, impacts: List[FunctionImpact]) -> bool:
        for impact in impacts or []:
            if (impact.impact_score or 0) > 0:
                return True
            if impact.callers or impact.callees or impact.warnings:
                return True
        return False

    def _can_direct_backport_low_drift(
        self,
        level_decision: LevelDecision,
        low_level_veto_hits: List[Dict],
        direct_backport_veto_hits: List[Dict],
        risk_hits: List[Dict],
        prereqs,
        impacts: List[FunctionImpact],
        critical_hits: List[str],
    ) -> bool:
        if list(prereqs or []):
            return False
        if level_decision.level != "L1" or level_decision.base_level != "L1":
            return False
        if low_level_veto_hits or direct_backport_veto_hits or risk_hits:
            return False
        if critical_hits or self._has_material_impacts(impacts):
            return False
        return True

    def _build_manual_review_checklist(
        self,
        level_decision: LevelDecision,
        rule_hits: List[Dict],
        prerequisite_patches,
        impacts: List[FunctionImpact],
        risk_markers: Dict[str, List[str]],
        special_risk_report: Dict[str, Any],
        dependency_details,
        base_method: str,
    ) -> List[str]:
        prereqs = list(prerequisite_patches or [])
        needs_manual = (
            level_decision.level in ("L2", "L3", "L4", "L5")
            or bool(prereqs)
            or any(hit.get("severity") in ("warn", "high") for hit in (rule_hits or []))
            or base_method in ("regenerated", "conflict-adapted", "verified-direct")
        )
        if not needs_manual:
            return []

        out = []
        seen = set()

        def _push(text: str):
            item = str(text or "").strip()
            if not item or item in seen:
                return
            seen.add(item)
            out.append(item)

        for item in getattr(dependency_details, "manual_review_checklist", []) or []:
            _push(item)

        _push("先对照上游 hunk 与目标分支代码，确认不是上下文漂移或错误落点导致的误判")

        lock_objects = list((risk_markers or {}).get("lock_objects", []) or [])
        fields = list((risk_markers or {}).get("fields", []) or [])
        state_points = list((risk_markers or {}).get("state_points", []) or [])
        error_path_nodes = list((risk_markers or {}).get("error_path_nodes", []) or [])
        top_functions = [
            impact.function
            for impact in sorted(impacts or [], key=lambda item: item.impact_score, reverse=True)
            if impact.function and ((impact.impact_score or 0) > 0 or impact.callers or impact.callees or impact.warnings)
        ]

        if fields:
            _push("重点核对字段/数据路径: " + " / ".join(fields[:4]))
        if lock_objects:
            _push("重点核对锁对象与保护域: " + " / ".join(lock_objects[:4]))
        if state_points:
            _push("重点核对状态点与状态迁移: " + " / ".join(state_points[:4]))
        if error_path_nodes:
            _push("重点核对错误路径与清理顺序: " + " / ".join(error_path_nodes[:4]))
        if top_functions:
            _push("检查调用链影响函数: " + " / ".join(top_functions[:4]))

        sections = ((special_risk_report or {}).get("summary") or {}).get("triggered_sections", [])
        if sections:
            _push("锁/生命周期/状态机/字段/错误路径专项已命中，需逐项核对证据与目标分支实现是否一致")

        strong = [p for p in prereqs if getattr(p, "grade", "") == "strong"]
        medium = [p for p in prereqs if getattr(p, "grade", "") == "medium"]
        if strong or medium:
            ordered = [p.commit_id[:12] for p in strong[:3]] + [p.commit_id[:12] for p in medium[:2]]
            _push("按 strong/medium 顺序复核关联补丁: " + ", ".join(ordered))

        if base_method in ("regenerated", "conflict-adapted", "verified-direct"):
            _push("当前补丁经过重建/冲突适配/verified-direct 路径，需逐 hunk 复核生成结果与目标分支代码")

        _push("完成关键路径编译、最小功能回归和错误路径回归验证")
        return out[:8]

    def _build_strategy_buckets(
        self,
        level_decision: LevelDecision,
        rule_hits: List[Dict],
        prerequisite_patches,
        special_risk_report: Dict[str, Any],
    ) -> Dict:
        rule_type_counter: Dict[str, int] = {}
        rule_class_counter: Dict[str, int] = {}
        for hit in rule_hits or []:
            rule_type = self._classify_rule_type(hit.get("rule_id", ""))
            rule_type_counter[rule_type] = rule_type_counter.get(rule_type, 0) + 1
            rule_class = self._classify_rule_class(hit)
            rule_class_counter[rule_class] = rule_class_counter.get(rule_class, 0) + 1

        prereqs = list(prerequisite_patches or [])
        strong = sum(1 for p in prereqs if getattr(p, "grade", "") == "strong")
        medium = sum(1 for p in prereqs if getattr(p, "grade", "") == "medium")
        weak = sum(1 for p in prereqs if getattr(p, "grade", "") not in ("strong", "medium"))
        if strong:
            dependency_bucket = "required"
        elif medium:
            dependency_bucket = "recommended"
        elif weak:
            dependency_bucket = "weak_only"
        else:
            dependency_bucket = "independent"

        special_summary = (special_risk_report or {}).get("summary") or {}

        return {
            "level": level_decision.level,
            "base_level": level_decision.base_level,
            "rule_type_bucket": sorted(rule_type_counter.items()),
            "rule_class_bucket": sorted(rule_class_counter.items()),
            "dependency_bucket": dependency_bucket,
            "special_risk_enabled": bool((special_risk_report or {}).get("enabled", True)),
            "special_risk_sections": list(special_summary.get("triggered_sections") or []),
            "critical_structure_change": bool(special_summary.get("has_critical_structure_change")),
            "dependency_counts": {
                "strong": strong,
                "medium": medium,
                "weak": weak,
                "total": len(prereqs),
            },
        }

    def _classify_rule_type(self, rule_id: str) -> str:
        if rule_id.startswith("prerequisite_") or rule_id == "independent_patch":
            return "dependency"
        if rule_id in ("direct_backport_candidate",):
            return "direct_backport"
        if rule_id in ("large_change",):
            return "change_size"
        if rule_id in ("call_chain_propagation", "call_chain_fanout"):
            return "call_chain"
        if rule_id in ("critical_structures",):
            return "critical_structure"
        if rule_id.startswith("p2_"):
            return "special_risk"
        if rule_id in ("l1_api_surface",):
            return "api_surface"
        if rule_id in ("single_line_high_impact",):
            return "high_impact_single_line"
        return "other"

    def _classify_rule_class(self, hit: Dict) -> str:
        rule_class = (hit or {}).get("rule_class", "")
        if rule_class in ("admission", "low_level_veto", "direct_backport_veto", "risk_profile"):
            return rule_class
        return "risk_profile"

    def _compact_rule_hit(self, hit: Dict) -> Dict:
        evidence = (hit or {}).get("evidence", {}) or {}
        return {
            "rule_id": hit.get("rule_id", ""),
            "rule_class": self._classify_rule_class(hit),
            "rule_scope": hit.get("rule_scope", ""),
            "severity": hit.get("severity", ""),
            "level_floor": hit.get("level_floor", ""),
            "message": hit.get("message", ""),
            "evidence": evidence,
        }

    def _build_decision_skeleton(
        self,
        steps: List[str],
        level_decision: LevelDecision,
        rule_hits: List[Dict],
        prerequisite_patches,
        impacts: List[FunctionImpact],
        critical_hits: List[str],
        risk_markers: Dict[str, List[str]],
        special_risk_report: Dict[str, Any],
    ) -> Dict:
        prereqs = list(prerequisite_patches or [])
        admission_hits = [
            self._compact_rule_hit(hit)
            for hit in (rule_hits or [])
            if self._classify_rule_class(hit) == "admission"
        ]
        low_level_veto_hits = [
            self._compact_rule_hit(hit)
            for hit in (rule_hits or [])
            if self._classify_rule_class(hit) == "low_level_veto"
        ]
        direct_backport_veto_hits = [
            self._compact_rule_hit(hit)
            for hit in (rule_hits or [])
            if self._classify_rule_class(hit) == "direct_backport_veto"
        ]
        risk_hits = [
            self._compact_rule_hit(hit)
            for hit in (rule_hits or [])
            if self._classify_rule_class(hit) == "risk_profile"
        ]

        strong = sum(1 for p in prereqs if getattr(p, "grade", "") == "strong")
        medium = sum(1 for p in prereqs if getattr(p, "grade", "") == "medium")
        weak = sum(1 for p in prereqs if getattr(p, "grade", "") not in ("strong", "medium"))
        material_impacts = self._has_material_impacts(impacts)
        l1_direct_ok = self._can_direct_backport_low_drift(
            level_decision,
            low_level_veto_hits,
            direct_backport_veto_hits,
            risk_hits,
            prereqs,
            impacts,
            critical_hits,
        )

        if level_decision.level == "L0" and admission_hits and not low_level_veto_hits and not direct_backport_veto_hits and not prereqs:
            direct_status = "direct"
        elif l1_direct_ok:
            direct_status = "direct"
        elif not prereqs and level_decision.level in ("L0", "L1"):
            direct_status = "review"
        else:
            direct_status = "blocked"

        if strong:
            prereq_status = "required"
        elif medium:
            prereq_status = "recommended"
        elif weak:
            prereq_status = "weak_only"
        else:
            prereq_status = "independent"

        if critical_hits or any(hit.get("severity") == "high" for hit in risk_hits):
            risk_status = "high"
        elif risk_hits or low_level_veto_hits or direct_backport_veto_hits or material_impacts:
            risk_status = "attention"
        else:
            risk_status = "low"

        return {
            "process": {
                "workflow_steps": list(steps or []),
                "base_level": level_decision.base_level,
                "base_method": level_decision.base_method,
                "final_level": level_decision.level,
            },
            "evidence": {
                "admission_rules": admission_hits,
                "low_level_veto_rules": low_level_veto_hits,
                "direct_backport_veto_rules": direct_backport_veto_hits,
                "risk_profile_rules": risk_hits,
                "prerequisite_patches": [
                    {
                        "commit_id": p.commit_id,
                        "subject": p.subject,
                        "grade": getattr(p, "grade", ""),
                        "score": getattr(p, "score", 0.0),
                        "shared_fields": list(getattr(p, "shared_fields", []) or [])[:6],
                        "shared_lock_domains": list(getattr(p, "shared_lock_domains", []) or [])[:6],
                        "shared_state_points": list(getattr(p, "shared_state_points", []) or [])[:6],
                        "evidence_lines": list(getattr(p, "evidence_lines", []) or [])[:4],
                    }
                    for p in prereqs[:8]
                ],
                "critical_structure_hits": sorted(set(critical_hits))[:12],
                "lock_objects": risk_markers.get("lock_objects", [])[:12],
                "fields": risk_markers.get("fields", [])[:12],
                "state_points": risk_markers.get("state_points", [])[:12],
                "error_path_nodes": risk_markers.get("error_path_nodes", [])[:12],
                "special_risk_report": special_risk_report,
                "function_impacts": [
                    {
                        "function": fi.function,
                        "impact_score": fi.impact_score,
                        "callers": fi.callers[:8],
                        "callees": fi.callees[:8],
                        "warnings": fi.warnings[:6],
                    }
                    for fi in sorted(impacts, key=lambda item: item.impact_score, reverse=True)[:8]
                ],
            },
            "conclusion": {
                "direct_backport": {
                    "status": direct_status,
                    "summary": self._summarize_direct_backport(level_decision, rule_hits, prereqs),
                },
                "prerequisite": {
                    "status": prereq_status,
                    "summary": self._summarize_prerequisites(prereqs, None if prereqs else True),
                    "counts": {
                        "strong": strong,
                        "medium": medium,
                        "weak": weak,
                        "total": len(prereqs),
                    },
                },
                "risk": {
                    "status": risk_status,
                    "summary": self._summarize_impact_focus(rule_hits, impacts, critical_hits, special_risk_report),
                },
                "final": {
                    "level": level_decision.level,
                    "base_level": level_decision.base_level,
                    "review_mode": level_decision.review_mode,
                    "next_action": level_decision.next_action,
                    "harmless": level_decision.harmless,
                    "reason": level_decision.reason,
                },
            },
        }

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
                if self._match_critical_keyword(change, keyword):
                    hits.append(keyword)
        return hits

    def _match_critical_keyword(self, change: str, keyword: str) -> bool:
        text = (change or "").strip()
        if not text:
            return False

        if keyword == "struct":
            return bool(
                re.search(r"^\s*struct\s+[A-Za-z_]\w*\s*\{", text)
                or re.search(r"\b(sizeof|offsetof|container_of)\s*\(", text)
            )
        if keyword == "mutex":
            return bool(re.search(r"\bmutex(?:_[A-Za-z0-9_]+)?\b", text))
        if keyword == "spin_lock":
            return bool(re.search(r"\bspin_lock(?:_[A-Za-z0-9_]+)?\b", text))
        if keyword == "rcu":
            return bool(re.search(r"\brcu(?:_[A-Za-z0-9_]+)?\b", text))
        if keyword == "refcount":
            return bool(re.search(r"\brefcount(?:_[A-Za-z0-9_]+)?\b", text))
        if keyword == "kref":
            return bool(re.search(r"\bkref(?:_[A-Za-z0-9_]+)?\b", text))
        if keyword == "atomic":
            return bool(re.search(r"\batomic(?:64|long)?(?:_[A-Za-z0-9_]+)?\b", text))
        return bool(re.search(rf"\b{re.escape(keyword)}\b", text))

    def _extract_risk_markers(self, diff_text: str) -> Dict[str, List[str]]:
        lock_objects = []
        fields = []
        state_points = []
        error_path_nodes = []

        changes = [
            line[1:].strip()
            for line in diff_text.split("\n")
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
        ]

        lock_patterns = [
            re.compile(r"\b(?:spin_lock|spin_unlock|mutex_lock|mutex_unlock|mutex_trylock|mutex_lock_interruptible|read_lock|write_lock|down_write|up_write)\s*\(\s*&?([a-zA-Z_][\w>\.\-]*)"),
            re.compile(r"\b(?:rcu_assign_pointer|rcu_dereference|refcount_inc|refcount_dec|kref_get|kref_put)\s*\(\s*&?([a-zA-Z_][\w>\.\-]*)"),
        ]
        field_pattern = re.compile(r"(?:\b[a-zA-Z_]\w*(?:->|\.)[a-zA-Z_]\w*(?:->|\.)*[a-zA-Z_]\w*)")
        state_pattern = re.compile(r"\b([a-zA-Z_]\w*(?:state|status|mode|phase|flag|flags))\b", re.IGNORECASE)
        error_patterns = [
            re.compile(r"\bgoto\s+([a-zA-Z_]\w*)"),
            re.compile(r"\breturn\s+(-[A-Z0-9_]+|NULL|ERR_PTR\([^)]+\)|PTR_ERR\([^)]+\))"),
            re.compile(r"\b(IS_ERR|PTR_ERR|ERR_PTR|WARN_ON|BUG_ON)\b"),
        ]

        def _append_unique(bucket, value):
            if value and value not in bucket:
                bucket.append(value)

        for change in changes:
            for pattern in lock_patterns:
                for match in pattern.finditer(change):
                    _append_unique(lock_objects, match.group(1))
            for match in field_pattern.finditer(change):
                _append_unique(fields, match.group(0))
            for match in state_pattern.finditer(change):
                _append_unique(state_points, match.group(1))
            for pattern in error_patterns:
                for match in pattern.finditer(change):
                    node = match.group(1)
                    if node:
                        _append_unique(error_path_nodes, node)
            if "goto err" in change or "goto out" in change:
                _append_unique(error_path_nodes, change)
            if re.search(r"\bif\s*\(", change) and ("return" in change or "goto" in change):
                _append_unique(state_points, change)

        return {
            "lock_objects": lock_objects,
            "fields": fields,
            "state_points": state_points,
            "error_path_nodes": error_path_nodes,
        }

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

    def _build_special_risk_report(self, diff_text: str) -> Dict[str, Any]:
        enabled = bool(getattr(self.config, "special_risk_rules_enabled", True)) if self.config else True
        if not enabled:
            return {
                "enabled": False,
                "summary": {
                    "triggered_sections": [],
                    "high_risk_sections": [],
                    "has_critical_structure_change": False,
                },
                "sections": {},
            }

        entries = self._collect_diff_entries(diff_text)
        hunk_groups: Dict[str, List[Dict[str, Any]]] = {}
        for entry in entries:
            hunk_groups.setdefault(entry["hunk_key"], []).append(entry)

        sections = {
            "locking_sync": self._analyze_locking_sync(entries, hunk_groups),
            "lifecycle_resource": self._analyze_lifecycle_resource(entries),
            "state_machine_control_flow": self._analyze_state_machine(entries, hunk_groups),
            "struct_field_data_path": self._analyze_struct_field_data_path(entries, hunk_groups),
            "error_path": self._analyze_error_path(entries),
        }
        triggered_sections = [name for name, section in sections.items() if section.get("triggered")]
        high_risk_sections = [name for name, section in sections.items() if section.get("risk") == "high"]
        has_critical_structure_change = any(
            sections.get(name, {}).get("triggered")
            for name in ("locking_sync", "lifecycle_resource", "struct_field_data_path")
        )
        return {
            "enabled": True,
            "summary": {
                "triggered_sections": triggered_sections,
                "high_risk_sections": high_risk_sections,
                "has_critical_structure_change": has_critical_structure_change,
            },
            "sections": sections,
        }

    def _collect_diff_entries(self, diff_text: str) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        current_file = ""
        current_hunk = ""
        current_func = ""
        current_struct = ""
        hunk_index = 0

        for raw in (diff_text or "").splitlines():
            if raw.startswith("diff --git"):
                match = re.search(r" b/(.+)$", raw)
                current_file = match.group(1) if match else current_file
                current_hunk = ""
                current_func = ""
                current_struct = ""
                hunk_index = 0
                continue
            if raw.startswith("@@"):
                current_hunk = raw
                current_func = self._extract_function_name_from_hunk(raw)
                current_struct = ""
                hunk_index += 1
                continue
            if raw.startswith(("index ", "new file mode", "deleted file mode", "similarity index", "rename ")):
                continue
            if raw.startswith(("+++", "---")):
                continue

            marker = raw[0] if raw else ""
            body = raw[1:] if marker in (" ", "+", "-") else raw
            stripped = body.strip()

            struct_match = re.match(r"^\s*struct\s+([A-Za-z_]\w*)\s*\{", body)
            if struct_match:
                current_struct = struct_match.group(1)
            elif re.match(r"^\s*};\s*$", body):
                current_struct = ""

            if marker not in ("+", "-"):
                continue
            if not stripped:
                continue

            entries.append({
                "sign": marker,
                "body": stripped,
                "file": current_file,
                "hunk": current_hunk,
                "function": current_func,
                "struct": current_struct,
                "hunk_key": f"{current_file}#{hunk_index}",
            })
        return entries

    def _extract_function_name_from_hunk(self, hunk_header: str) -> str:
        match = re.search(r"@@.*@@\s*(.+)$", hunk_header or "")
        if not match:
            return ""
        sig = match.group(1).strip()
        func_match = re.search(r"\b([A-Za-z_]\w*)\s*\(", sig)
        return func_match.group(1) if func_match else ""

    def _extract_member_paths(self, body: str) -> List[str]:
        pattern = re.compile(r"\b[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w+)+")
        return sorted(set(pattern.findall(body or "")))

    def _normalize_object_name(self, value: str) -> str:
        text = (value or "").strip()
        text = re.sub(r"^\(.*?\)", "", text).strip()
        text = text.lstrip("&*").strip()
        return text[:80]

    def _truncate_list(self, values: List[str], limit: int = 8) -> List[str]:
        return list(dict.fromkeys([v for v in values if v]))[:limit]

    def _analyze_locking_sync(self, entries: List[Dict[str, Any]], hunk_groups: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        lock_re = re.compile(
            r"\b(spin_lock(?:_[A-Za-z0-9_]+)?|spin_unlock(?:_[A-Za-z0-9_]+)?|"
            r"mutex_lock|mutex_unlock|mutex_trylock|rcu_read_lock|rcu_read_unlock|"
            r"synchronize_rcu|read_lock|read_unlock|write_lock|write_unlock|"
            r"down_[A-Za-z0-9_]+|up_[A-Za-z0-9_]+)\s*\(([^)]*)\)"
        )
        lock_objects: List[str] = []
        operation_changes: List[str] = []
        protected_data: List[str] = []
        sync_order_clues: List[str] = []
        evidence: List[str] = []
        has_added = False
        has_removed = False
        lock_hunks = set()

        for entry in entries:
            match = lock_re.search(entry["body"])
            if not match:
                continue
            op = match.group(1)
            arg0 = match.group(2).split(",", 1)[0].strip()
            obj = self._normalize_object_name(arg0)
            if obj:
                lock_objects.append(obj)
            operation_changes.append(f"{entry['sign']}{op}")
            evidence.append(entry["body"])
            lock_hunks.add(entry["hunk_key"])
            has_added = has_added or entry["sign"] == "+"
            has_removed = has_removed or entry["sign"] == "-"

        for hunk_key in lock_hunks:
            group = hunk_groups.get(hunk_key, [])
            member_paths = []
            for entry in group:
                member_paths.extend(self._extract_member_paths(entry["body"]))
            protected_data.extend(member_paths)
            if any(item["sign"] == "+" for item in group) and any(item["sign"] == "-" for item in group):
                sync_order_clues.append(group[0].get("function") or group[0].get("file") or hunk_key)

        triggered = bool(operation_changes)
        return {
            "triggered": triggered,
            "risk": "high" if triggered else "none",
            "lock_objects": self._truncate_list(lock_objects),
            "operation_changes": self._truncate_list(operation_changes, 12),
            "protected_data_objects": self._truncate_list(protected_data, 12),
            "sync_order_changes": self._truncate_list(sync_order_clues),
            "summary": (
                f"检测到 {len(operation_changes)} 处锁/同步操作变更"
                + ("，同时存在加锁/解锁增删" if has_added and has_removed else "")
            ) if triggered else "未检测到锁/同步语义变化",
            "evidence_lines": self._truncate_list(evidence, 6),
        }

    def _analyze_lifecycle_resource(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        lifecycle_re = re.compile(
            r"\b(kmalloc|kzalloc|kvzalloc|alloc|free|kfree|kvfree|get|put|"
            r"refcount_inc|refcount_dec|kref_get|kref_put|init|deinit|destroy|cleanup)\b"
        )
        hold_objects: List[str] = []
        release_sequences: List[str] = []
        rollback_paths: List[str] = []
        categories = set()
        evidence: List[str] = []

        for entry in entries:
            body = entry["body"]
            match = lifecycle_re.search(body)
            if not match:
                if re.search(r"\bgoto\s+(err|out|fail|free|put)\w*\b", body):
                    rollback_paths.append(body)
                    evidence.append(body)
                continue
            token = match.group(1)
            categories.add(token)
            evidence.append(body)
            assign_match = re.match(r"([A-Za-z_]\w*(?:->\w+)?)\s*=\s*\w+", body)
            call_match = re.search(r"\(([^)]*)\)", body)
            obj = ""
            if assign_match:
                obj = assign_match.group(1)
            elif call_match:
                obj = call_match.group(1).split(",", 1)[0].strip()
            obj = self._normalize_object_name(obj)
            if obj:
                hold_objects.append(obj)
            if token in ("free", "kfree", "kvfree", "put", "kref_put", "destroy", "cleanup"):
                release_sequences.append(body)
            if re.search(r"\bgoto\s+(err|out|fail|free|put)\w*\b", body):
                rollback_paths.append(body)

        triggered = bool(categories or rollback_paths)
        return {
            "triggered": triggered,
            "risk": "high" if triggered else "none",
            "categories": self._truncate_list(sorted(categories), 12),
            "ownership_objects": self._truncate_list(hold_objects, 10),
            "release_order_clues": self._truncate_list(release_sequences, 6),
            "rollback_paths": self._truncate_list(rollback_paths, 6),
            "summary": (
                "检测到对象生命周期/资源管理变化，需核对持有关系、释放顺序与错误回滚"
                if triggered else "未检测到明显生命周期变化"
            ),
            "evidence_lines": self._truncate_list(evidence, 6),
        }

    def _analyze_state_machine(self, entries: List[Dict[str, Any]], hunk_groups: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        condition_changes: List[str] = []
        return_changes: List[str] = []
        error_codes: List[str] = []
        state_fields: List[str] = []
        callback_ops: List[str] = []
        semantic_hunks: List[str] = []
        evidence: List[str] = []
        state_re = re.compile(
            r"\b([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w+)*"
            r"(?:->|\.)?(?:state|status|mode|flags?|enabled|disabled|phase|step))\b",
            re.IGNORECASE,
        )
        state_transition_re = re.compile(
            r"\b(?:[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w+)*"
            r"(?:->|\.)?(?:state|status|mode|flags?|enabled|disabled|phase|step))\b"
            r"\s*(?:==|!=|=|\+=|-=|\|\||&&)",
            re.IGNORECASE,
        )
        state_const_re = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")

        for hunk_key, group in hunk_groups.items():
            hunk_conditions: List[str] = []
            hunk_returns: List[str] = []
            hunk_errors: List[str] = []
            hunk_state_fields: List[str] = []
            hunk_callbacks: List[str] = []
            hunk_evidence: List[str] = []
            has_transition = False

            for entry in group:
                body = entry["body"]
                state_hits = state_re.findall(body)
                line_has_transition = bool(state_transition_re.search(body))
                has_state_hint = bool(state_hits) or bool(state_const_re.search(body))
                if re.search(r"^\s*(if|else\s+if|switch)\s*\(", body) and has_state_hint:
                    hunk_conditions.append(body)
                    hunk_evidence.append(body)
                if line_has_transition:
                    has_transition = True
                    hunk_evidence.append(body)
                if re.search(r"\b(return|goto|break|continue)\b", body):
                    if state_hits or line_has_transition or hunk_conditions or hunk_callbacks:
                        hunk_returns.append(body)
                        hunk_evidence.append(body)
                hunk_errors.extend(re.findall(r"-E[A-Z0-9_]+", body))
                hunk_state_fields.extend(state_hits)
                if re.search(r"(?:->ops->|\.ops->|\bops->)", body) and (
                    line_has_transition or has_state_hint or re.search(r"\b(if|switch|return|goto)\b", body)
                ):
                    hunk_callbacks.append(body)
                    hunk_evidence.append(body)

            semantic = bool(
                has_transition
                or (hunk_conditions and (hunk_state_fields or hunk_callbacks or hunk_returns))
                or (hunk_returns and (hunk_state_fields or hunk_conditions or hunk_callbacks or has_transition))
                or (hunk_callbacks and (hunk_conditions or has_transition or hunk_state_fields))
            )
            if not semantic:
                continue

            semantic_hunks.append(hunk_key)
            condition_changes.extend(hunk_conditions)
            return_changes.extend(hunk_returns)
            error_codes.extend(hunk_errors)
            state_fields.extend(hunk_state_fields)
            callback_ops.extend(hunk_callbacks)
            evidence.extend(hunk_evidence)

        triggered = bool(condition_changes or return_changes or state_fields or callback_ops or semantic_hunks)
        high_risk = bool(condition_changes and (state_fields or callback_ops or semantic_hunks))
        return {
            "triggered": triggered,
            "risk": "high" if high_risk else ("warn" if triggered else "none"),
            "condition_changes": self._truncate_list(condition_changes, 6),
            "return_path_changes": self._truncate_list(return_changes, 6),
            "error_codes": self._truncate_list(error_codes, 8),
            "state_fields": self._truncate_list(state_fields, 8),
            "callback_or_ops_changes": self._truncate_list(callback_ops, 6),
            "semantic_hunks": self._truncate_list(semantic_hunks, 6),
            "summary": (
                "检测到条件/返回/状态字段变化，可能影响状态迁移与进入退出条件"
                if triggered else "未检测到明显状态机/控制流专项变化"
            ),
            "evidence_lines": self._truncate_list(evidence, 6),
        }

    def _analyze_struct_field_data_path(self, entries: List[Dict[str, Any]], hunk_groups: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        field_decl_re = re.compile(r"(?:struct\s+\w+\s+)?(?:const\s+)?[A-Za-z_][\w\s\*]+\s+([A-Za-z_]\w*)\s*(?:\[[^\]]+\])?\s*;")
        field_defs: Dict[str, Dict[str, List[str]]] = {}
        access_info: Dict[str, Dict[str, Any]] = {}
        evidence: List[str] = []

        for entry in entries:
            body = entry["body"]
            in_struct = entry.get("struct")
            hunk_group = hunk_groups.get(entry["hunk_key"], [])
            has_lock_context = any(
                re.search(r"\b(lock|unlock|rcu_read_lock|rcu_read_unlock)\b", item["body"])
                for item in hunk_group
            )
            has_error_context = any(
                re.search(r"\b(goto\s+(err|out|fail)|return\s+-E[A-Z0-9_]+)\b", item["body"])
                for item in hunk_group
            )

            if in_struct:
                match = field_decl_re.search(body)
                if match:
                    field_name = match.group(1)
                    bucket = field_defs.setdefault(field_name, {"added": [], "removed": [], "structs": []})
                    bucket["added" if entry["sign"] == "+" else "removed"].append(body)
                    if in_struct:
                        bucket["structs"].append(in_struct)
                    evidence.append(body)

            for path in self._extract_member_paths(body):
                field_name = path.split("->")[-1].split(".")[-1]
                info = access_info.setdefault(field_name, {
                    "field": field_name,
                    "access_paths": set(),
                    "read_functions": set(),
                    "write_functions": set(),
                    "lock_protected": False,
                    "state_related": False,
                    "error_path_related": False,
                })
                info["access_paths"].add(path)
                func_name = entry.get("function") or entry.get("file") or ""
                if "=" in body and path in body.split("=", 1)[0]:
                    info["write_functions"].add(func_name)
                else:
                    info["read_functions"].add(func_name)
                info["lock_protected"] = info["lock_protected"] or has_lock_context
                info["state_related"] = info["state_related"] or bool(re.search(r"\b(state|status|mode|flags?)\b", body))
                info["error_path_related"] = info["error_path_related"] or has_error_context

        field_changes = []
        for field_name, change in field_defs.items():
            change_type = "type_change"
            if change["added"] and not change["removed"]:
                change_type = "added"
            elif change["removed"] and not change["added"]:
                change_type = "removed"
            field_changes.append({
                "field": field_name,
                "change_type": change_type,
                "structs": self._truncate_list(change.get("structs", []), 4),
                "added_lines": self._truncate_list(change.get("added", []), 2),
                "removed_lines": self._truncate_list(change.get("removed", []), 2),
            })

        field_usages = []
        for field_name, info in access_info.items():
            field_usages.append({
                "field": field_name,
                "access_paths": self._truncate_list(sorted(info["access_paths"]), 6),
                "read_functions": self._truncate_list(sorted(info["read_functions"]), 6),
                "write_functions": self._truncate_list(sorted(info["write_functions"]), 6),
                "lock_protected": bool(info["lock_protected"]),
                "state_related": bool(info["state_related"]),
                "error_path_related": bool(info["error_path_related"]),
            })

        triggered = bool(field_changes or field_usages)
        high_risk = bool(field_changes) or any(item["lock_protected"] for item in field_usages)
        return {
            "triggered": triggered,
            "risk": "high" if high_risk else ("warn" if triggered else "none"),
            "field_changes": field_changes[:10],
            "field_usages": field_usages[:12],
            "summary": (
                "检测到结构体字段或数据路径变化，需核对字段定义、读写位置与锁保护域"
                if triggered else "未检测到结构体字段/数据路径专项变化"
            ),
            "evidence_lines": self._truncate_list(evidence, 6),
        }

    def _analyze_error_path(self, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        goto_err: List[str] = []
        cleanup_logic: List[str] = []
        error_codes: List[str] = []
        recovery_changes: List[str] = []
        evidence: List[str] = []

        for entry in entries:
            body = entry["body"]
            hit = False
            if re.search(r"\bgoto\s+(err|out|fail|free|put)\w*\b", body):
                goto_err.append(body)
                hit = True
            if re.search(r"\b(cleanup|free|kfree|put|unlock|release|destroy)\b", body):
                cleanup_logic.append(body)
                hit = True
            codes = re.findall(r"-E[A-Z0-9_]+", body)
            if codes:
                error_codes.extend(codes)
                hit = True
            if re.search(r"\b(reset|restore|rollback|unwind)\b", body):
                recovery_changes.append(body)
                hit = True
            if hit:
                evidence.append(body)

        triggered = bool(goto_err or cleanup_logic or error_codes or recovery_changes)
        return {
            "triggered": triggered,
            "risk": "warn" if triggered else "none",
            "goto_err_paths": self._truncate_list(goto_err, 6),
            "cleanup_changes": self._truncate_list(cleanup_logic, 6),
            "error_codes": self._truncate_list(error_codes, 8),
            "recovery_changes": self._truncate_list(recovery_changes, 6),
            "summary": (
                "检测到错误路径/清理逻辑变化，需确认失败后的状态恢复与清理完整性"
                if triggered else "未检测到错误路径专项变化"
            ),
            "evidence_lines": self._truncate_list(evidence, 6),
        }
