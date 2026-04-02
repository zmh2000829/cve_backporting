"""默认内置规则，承载于 rules/ 目录下以支持插拔式扩展。"""

import re
from typing import Dict, List, Optional

from rules.base import PolicyRule, RuleContext, RuleRegistry


def _changed_bodies(diff_text: str) -> List[str]:
    bodies = []
    for line in (diff_text or "").split("\n"):
        if line.startswith(("+++", "---")):
            continue
        if len(line) >= 2 and line[0] in "+-":
            bodies.append(line[1:].strip())
    return bodies


def _count_params(signature: str) -> int:
    m = re.search(r"\((.*)\)", signature)
    if not m:
        return -1
    inner = m.group(1).strip()
    if not inner or inner == "void":
        return 0
    return len([p for p in inner.split(",") if p.strip()])


def _special_section(ctx: RuleContext, section: str) -> Dict:
    report = getattr(ctx, "special_risk_report", {}) or {}
    return ((report.get("sections") or {}).get(section) or {})


class LargeChangeRule(PolicyRule):
    rule_id = "large_change"
    name = "Large Change Warning"
    severity = "warn"
    rule_class = "low_level_veto"
    rule_scope = "low_level"

    def __init__(self, line_threshold: int, hunk_threshold: int):
        self.line_threshold = line_threshold
        self.hunk_threshold = hunk_threshold

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        if ctx.changed_lines >= self.line_threshold or ctx.hunk_count >= self.hunk_threshold:
            return {
                "rule_id": self.rule_id,
                "name": self.name,
                "severity": self.severity,
                "level_floor": "L2",
                "message": f"改动较大: {ctx.changed_lines} 行, {ctx.hunk_count} hunk",
                "evidence": {
                    "changed_lines": ctx.changed_lines,
                    "hunk_count": ctx.hunk_count,
                    "line_threshold": self.line_threshold,
                    "hunk_threshold": self.hunk_threshold,
                },
            }
        return None


class CriticalStructureRule(PolicyRule):
    rule_id = "critical_structures"
    name = "Critical Structures Changed"
    severity = "high"
    rule_class = "risk_profile"
    rule_scope = "risk"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        if not ctx.critical_structure_hits:
            return None
        uniq = sorted(set(ctx.critical_structure_hits))
        categories = []
        if any(k in uniq for k in ("spin_lock", "mutex", "rcu")):
            categories.append("locking")
        if any(k in uniq for k in ("refcount", "kref", "atomic")):
            categories.append("lifetime")
        if "struct" in uniq:
            categories.append("layout")
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "level_floor": "L3",
            "message": "检测到关键结构/锁变更: " + ", ".join(uniq[:6]),
            "evidence": {
                "keywords": uniq,
                "categories": categories,
                "lock_objects": ctx.risk_markers.get("lock_objects", [])[:8],
                "fields": ctx.risk_markers.get("fields", [])[:8],
                "state_points": ctx.risk_markers.get("state_points", [])[:8],
                "error_path_nodes": ctx.risk_markers.get("error_path_nodes", [])[:8],
            },
        }


class P2LockingSyncRule(PolicyRule):
    rule_id = "p2_locking_sync"
    name = "P2 Locking / Synchronization"
    severity = "high"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        section = _special_section(ctx, "locking_sync")
        if not section.get("triggered"):
            return None
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": "high",
            "level_floor": "L3",
            "message": section.get("summary", "检测到锁与同步语义变化"),
            "evidence": {
                "lock_objects": section.get("lock_objects", []),
                "operation_changes": section.get("operation_changes", []),
                "protected_data_objects": section.get("protected_data_objects", []),
                "sync_order_changes": section.get("sync_order_changes", []),
                "evidence_lines": section.get("evidence_lines", []),
            },
        }


class P2LifecycleResourceRule(PolicyRule):
    rule_id = "p2_lifecycle_resource"
    name = "P2 Lifecycle / Resource"
    severity = "high"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        section = _special_section(ctx, "lifecycle_resource")
        if not section.get("triggered"):
            return None
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": "high",
            "level_floor": "L3",
            "message": section.get("summary", "检测到生命周期/资源管理变化"),
            "evidence": {
                "categories": section.get("categories", []),
                "ownership_objects": section.get("ownership_objects", []),
                "release_order_clues": section.get("release_order_clues", []),
                "rollback_paths": section.get("rollback_paths", []),
                "evidence_lines": section.get("evidence_lines", []),
            },
        }


class P2StateMachineRule(PolicyRule):
    rule_id = "p2_state_machine_control_flow"
    name = "P2 State Machine / Control Flow"
    severity = "warn"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        section = _special_section(ctx, "state_machine_control_flow")
        if not section.get("triggered"):
            return None
        high_risk = section.get("risk") == "high"
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": "high" if high_risk else "warn",
            "level_floor": "L3" if high_risk else "L2",
            "message": section.get("summary", "检测到状态机/控制流变化"),
            "evidence": {
                "condition_changes": section.get("condition_changes", []),
                "return_path_changes": section.get("return_path_changes", []),
                "error_codes": section.get("error_codes", []),
                "state_fields": section.get("state_fields", []),
                "callback_or_ops_changes": section.get("callback_or_ops_changes", []),
                "evidence_lines": section.get("evidence_lines", []),
            },
        }


class P2StructFieldRule(PolicyRule):
    rule_id = "p2_struct_field_data_path"
    name = "P2 Struct Field / Data Path"
    severity = "warn"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        section = _special_section(ctx, "struct_field_data_path")
        if not section.get("triggered"):
            return None
        high_risk = section.get("risk") == "high"
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": "high" if high_risk else "warn",
            "level_floor": "L3" if high_risk else "L2",
            "message": section.get("summary", "检测到结构体字段/数据路径变化"),
            "evidence": {
                "field_changes": section.get("field_changes", []),
                "field_usages": section.get("field_usages", [])[:6],
                "evidence_lines": section.get("evidence_lines", []),
            },
        }


class P2ErrorPathRule(PolicyRule):
    rule_id = "p2_error_path"
    name = "P2 Error Path"
    severity = "warn"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        section = _special_section(ctx, "error_path")
        if not section.get("triggered"):
            return None
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": "warn",
            "level_floor": "L2",
            "message": section.get("summary", "检测到错误路径变化"),
            "evidence": {
                "goto_err_paths": section.get("goto_err_paths", []),
                "cleanup_changes": section.get("cleanup_changes", []),
                "error_codes": section.get("error_codes", []),
                "recovery_changes": section.get("recovery_changes", []),
                "evidence_lines": section.get("evidence_lines", []),
            },
        }


class PrerequisiteRequiredRule(PolicyRule):
    rule_id = "prerequisite_required"
    name = "Strong Prerequisite Required"
    severity = "high"
    rule_class = "direct_backport_veto"
    rule_scope = "direct_backport"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        strong = [p for p in ctx.prerequisite_patches if getattr(p, "grade", "") == "strong"]
        if not strong:
            return None
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "level_floor": "L3",
            "message": f"检测到 {len(strong)} 个强依赖前置补丁，不能忽略关联补丁顺序",
            "evidence": {
                "count": len(strong),
                "commits": [p.commit_id[:12] for p in strong[:6]],
                "subjects": [p.subject for p in strong[:3]],
            },
        }


class PrerequisiteRecommendedRule(PolicyRule):
    rule_id = "prerequisite_recommended"
    name = "Prerequisite Review Recommended"
    severity = "warn"
    rule_class = "direct_backport_veto"
    rule_scope = "direct_backport"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        medium = [p for p in ctx.prerequisite_patches if getattr(p, "grade", "") == "medium"]
        if not medium:
            return None
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "level_floor": "L2",
            "message": f"检测到 {len(medium)} 个中等依赖，建议同时评估关联补丁",
            "evidence": {
                "count": len(medium),
                "commits": [p.commit_id[:12] for p in medium[:6]],
                "subjects": [p.subject for p in medium[:3]],
            },
        }


class IndependentPatchRule(PolicyRule):
    rule_id = "independent_patch"
    name = "Independent Patch Hint"
    severity = "info"
    rule_class = "admission"
    rule_scope = "direct_backport"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        if ctx.prerequisite_patches:
            return None
        if ctx.dependency_details is None:
            return None
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "level_floor": "L0",
            "message": "当前未发现强/中依赖，关联补丁可不作为首要阻塞项",
            "evidence": {
                "candidate_count": getattr(ctx.dependency_details, "candidate_count", 0),
                "strong_count": getattr(ctx.dependency_details, "strong_count", 0),
                "medium_count": getattr(ctx.dependency_details, "medium_count", 0),
                "weak_count": getattr(ctx.dependency_details, "weak_count", 0),
            },
        }


class DirectBackportRule(PolicyRule):
    rule_id = "direct_backport_candidate"
    name = "Direct Backport Candidate"
    severity = "info"
    rule_class = "admission"
    rule_scope = "direct_backport"

    def __init__(self, line_threshold: int, hunk_threshold: int):
        self.line_threshold = line_threshold
        self.hunk_threshold = hunk_threshold

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        max_fanout = max(
            [len(fi.callers) + len(fi.callees) for fi in ctx.function_impacts] or [0]
        )
        if ctx.base_level != "L0":
            return None
        if ctx.prerequisite_patches:
            return None
        if ctx.changed_lines > self.line_threshold or ctx.hunk_count > self.hunk_threshold:
            return None
        if ctx.critical_structure_hits or max_fanout > 0:
            return None
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "level_floor": "L0",
            "message": "满足直接回合候选条件：strict 命中、无前置依赖、改动规模小、无明显调用链牵连",
            "evidence": {
                "base_level": ctx.base_level,
                "changed_lines": ctx.changed_lines,
                "hunk_count": ctx.hunk_count,
                "max_fanout": max_fanout,
                "line_threshold": self.line_threshold,
                "hunk_threshold": self.hunk_threshold,
            },
        }


class CallChainPropagationRule(PolicyRule):
    rule_id = "call_chain_propagation"
    name = "Call Chain Propagation Warning"
    severity = "warn"
    rule_class = "risk_profile"
    rule_scope = "risk"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        risky = []
        for impact in ctx.function_impacts:
            fanout = len(impact.callers) + len(impact.callees)
            if fanout <= 0:
                continue
            risky.append((impact, fanout))
        if not risky:
            return None

        top, fanout = sorted(risky, key=lambda item: item[1], reverse=True)[0]
        has_critical = bool(ctx.critical_structure_hits)
        severity = "high" if has_critical else "warn"
        floor = "L4" if has_critical else "L2"
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": severity,
            "level_floor": floor,
            "message": (
                f"修改函数存在调用/被调用牵连: {top.function} "
                f"callers={len(top.callers)} callees={len(top.callees)}"
            ),
            "evidence": {
                "function": top.function,
                "callers": top.callers[:12],
                "callees": top.callees[:12],
                "fanout": fanout,
                "critical_structure_hits": sorted(set(ctx.critical_structure_hits))[:8],
            },
        }


class CallChainFanoutRule(PolicyRule):
    rule_id = "call_chain_fanout"
    name = "Call Chain Fanout Warning"
    severity = "warn"
    rule_class = "risk_profile"
    rule_scope = "risk"

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
            "level_floor": "L2",
            "message": f"调用链扩散较大: {top.function} callers={len(top.callers)} callees={len(top.callees)}",
            "evidence": {
                "function": top.function,
                "callers": top.callers[:8],
                "callees": top.callees[:8],
                "fanout_threshold": self.fanout_threshold,
            },
        }


class L1APISurfaceRule(PolicyRule):
    """L1 及近似场景：用 diff 启发式提示签名/入参与返回路径变化。"""

    rule_id = "l1_api_surface"
    name = "API Surface / Return-Path Hint"
    severity = "warn"
    rule_class = "low_level_veto"
    rule_scope = "low_level"

    def __init__(self, return_delta_threshold: int = 2):
        self.return_delta_threshold = return_delta_threshold

    def _looks_like_func_sig(self, body: str) -> bool:
        s = body.strip()
        if "(" not in s or ")" not in s:
            return False
        if re.match(r"^(if|for|while|switch|return)\b", s):
            return False
        return bool(re.search(r"\b\w+\s*\(", s))

    def _scan_diff(self, diff_text: str) -> Dict:
        plus_ret = minus_ret = 0
        plus_sigs: List[str] = []
        minus_sigs: List[str] = []
        for line in diff_text.split("\n"):
            if line.startswith("+++") or line.startswith("---"):
                continue
            if len(line) < 2 or line[0] not in "+-":
                continue
            ch, body = line[0], line[1:]
            if ch == "+" and re.search(r"\breturn\b", body):
                plus_ret += 1
            if ch == "-" and re.search(r"\breturn\b", body):
                minus_ret += 1
            body = body.lstrip()
            if ch == "+" and self._looks_like_func_sig(body):
                plus_sigs.append(re.sub(r"\s+", " ", body.strip()))
            if ch == "-" and self._looks_like_func_sig(body):
                minus_sigs.append(re.sub(r"\s+", " ", body.strip()))
        sig_change = bool(plus_sigs and minus_sigs and set(plus_sigs) != set(minus_sigs))
        ret_delta = abs(plus_ret - minus_ret)
        plus_param_counts = [_count_params(sig) for sig in plus_sigs]
        minus_param_counts = [_count_params(sig) for sig in minus_sigs]
        param_count_changed = bool(
            plus_param_counts and minus_param_counts and set(plus_param_counts) != set(minus_param_counts)
        )
        return {
            "sig_change": sig_change,
            "return_delta": ret_delta,
            "plus_return": plus_ret,
            "minus_return": minus_ret,
            "param_count_changed": param_count_changed,
            "plus_param_counts": plus_param_counts,
            "minus_param_counts": minus_param_counts,
        }

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        scan = self._scan_diff(ctx.patch.diff_code or "")
        parts = []
        if scan["sig_change"]:
            parts.append("函数定义/签名行在 diff 中同时增删且文本不一致，可能存在形参、修饰符或 ABI 变化")
        if scan["param_count_changed"]:
            parts.append(
                f"函数入参数量发生变化（-{scan['minus_param_counts'][:2]} / +{scan['plus_param_counts'][:2]}）"
            )
        if scan["return_delta"] >= self.return_delta_threshold:
            parts.append(
                f"return 语句增删差 {scan['return_delta']}（+{scan['plus_return']}/-{scan['minus_return']}），"
                "可能存在返回值语义或错误路径变化"
            )
        if not parts:
            return None

        level_floor = "L2" if scan["param_count_changed"] else ("L1" if ctx.base_level == "L1" else "L2")
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "level_floor": level_floor,
            "message": "；".join(parts) + "。请重点核对调用点、返回路径与 ABI。",
            "evidence": {
                **scan,
                "base_level": ctx.base_level,
                "return_delta_threshold": self.return_delta_threshold,
            },
        }


class SingleLineHighImpactRule(PolicyRule):
    rule_id = "single_line_high_impact"
    name = "Single Line But High Impact"
    severity = "warn"
    rule_class = "risk_profile"
    rule_scope = "risk"

    CATEGORY_PATTERNS = {
        "locking": re.compile(r"\b(spin_lock|spin_unlock|mutex_lock|mutex_unlock|read_lock|write_lock|rcu_|rwlock|down_write|up_write)\b"),
        "lifetime": re.compile(r"\b(refcount|kref|atomic_|kfree|kvfree|kmalloc|kzalloc|list_del|list_add)\b"),
        "control_flow": re.compile(r"\b(if|else|goto|return|break|continue)\b"),
        "error_path": re.compile(r"\b(NULL|ERR_|IS_ERR|PTR_ERR|WARN_ON|BUG_ON)\b"),
        "layout": re.compile(r"\b(sizeof|offsetof|container_of)\b"),
    }

    def __init__(self, max_changed_lines: int):
        self.max_changed_lines = max_changed_lines

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        if ctx.changed_lines == 0 or ctx.changed_lines > self.max_changed_lines:
            return None
        matched_categories = []
        sample_lines = []
        for body in _changed_bodies(ctx.patch.diff_code or ""):
            for name, pattern in self.CATEGORY_PATTERNS.items():
                if pattern.search(body):
                    matched_categories.append(name)
                    if len(sample_lines) < 4:
                        sample_lines.append(body)
        if not matched_categories:
            return None
        uniq = sorted(set(matched_categories))
        high_risk = any(cat in uniq for cat in ("locking", "lifetime", "layout"))
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": "high" if high_risk else self.severity,
            "level_floor": "L3" if high_risk else "L2",
            "message": (
                f"变更行数仅 {ctx.changed_lines} 行，但涉及高敏感语义: {', '.join(uniq)}"
            ),
            "evidence": {
                "changed_lines": ctx.changed_lines,
                "categories": uniq,
                "sample_lines": sample_lines,
                "max_changed_lines": self.max_changed_lines,
                "lock_objects": ctx.risk_markers.get("lock_objects", [])[:8],
                "fields": ctx.risk_markers.get("fields", [])[:8],
                "state_points": ctx.risk_markers.get("state_points", [])[:8],
                "error_path_nodes": ctx.risk_markers.get("error_path_nodes", [])[:8],
            },
        }


def register_rules(registry: RuleRegistry, config=None):
    direct_line_threshold = getattr(config, "direct_backport_line_threshold", 24) if config else 24
    direct_hunk_threshold = getattr(config, "direct_backport_hunk_threshold", 2) if config else 2
    line_threshold = getattr(config, "large_change_line_threshold", 80) if config else 80
    hunk_threshold = getattr(config, "large_hunk_threshold", 8) if config else 8
    fanout_threshold = getattr(config, "call_chain_fanout_threshold", 6) if config else 6
    return_delta = getattr(config, "l1_return_line_delta_threshold", 2) if config else 2
    single_line_max = getattr(config, "single_line_impact_max_changed_lines", 4) if config else 4

    if not config or getattr(config, "prerequisite_rules_enabled", True):
        registry.register(PrerequisiteRequiredRule())
        registry.register(PrerequisiteRecommendedRule())
        registry.register(IndependentPatchRule())

    if not config or getattr(config, "direct_backport_rules_enabled", True):
        registry.register(DirectBackportRule(direct_line_threshold, direct_hunk_threshold))

    if not config or getattr(config, "large_change_rules_enabled", True):
        registry.register(LargeChangeRule(line_threshold, hunk_threshold))

    if not config or getattr(config, "critical_structure_rules_enabled", True):
        registry.register(CriticalStructureRule())

    if not config or getattr(config, "special_risk_rules_enabled", True):
        registry.register(P2LockingSyncRule())
        registry.register(P2LifecycleResourceRule())
        registry.register(P2StateMachineRule())
        registry.register(P2StructFieldRule())
        registry.register(P2ErrorPathRule())

    if not config or getattr(config, "call_chain_rules_enabled", True):
        registry.register(CallChainPropagationRule())
        registry.register(CallChainFanoutRule(fanout_threshold))

    if not config or getattr(config, "l1_api_surface_rules_enabled", True):
        registry.register(L1APISurfaceRule(return_delta))

    if not config or getattr(config, "high_impact_single_line_rules_enabled", True):
        registry.register(SingleLineHighImpactRule(single_line_max))
