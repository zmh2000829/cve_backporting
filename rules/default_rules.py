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


_COMMENT_ONLY_RE = re.compile(r"^\s*(?://|/\*|\*|\*/)")
_LOG_CALL_RE = re.compile(
    r"\b(?:printk|pr_(?:debug|info|notice|warn|err)|"
    r"dev_(?:dbg|info|warn|err)|netdev_(?:dbg|info|warn|err)|trace_[A-Za-z0-9_]+)\s*\("
)
_UPPER_TOKEN_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")
_LOWER_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]*$")
_C_KEYWORDS = {
    "if", "else", "for", "while", "switch", "case", "break", "continue",
    "return", "goto", "sizeof", "struct", "const", "unsigned", "signed",
    "int", "long", "short", "char", "void", "static", "inline", "enum",
}


def _diff_pairs(diff_text: str, max_pairs: int = 6) -> List[tuple]:
    minus_lines = []
    plus_lines = []
    for raw in (diff_text or "").splitlines():
        if raw.startswith(("+++", "---")):
            continue
        if len(raw) < 2 or raw[0] not in "+-":
            continue
        body = raw[1:].strip()
        if raw[0] == "-":
            minus_lines.append(body)
        else:
            plus_lines.append(body)
    if not minus_lines or len(minus_lines) != len(plus_lines) or len(minus_lines) > max_pairs:
        return []
    return list(zip(minus_lines, plus_lines))


def _tokenize_for_rename(text: str) -> List[str]:
    return re.findall(r"[A-Za-z_]\w*|->|==|!=|<=|>=|\|\||&&|[^\s]", text or "")


def _is_local_identifier(tokens: List[str], idx: int) -> bool:
    if idx < 0 or idx >= len(tokens):
        return False
    token = tokens[idx]
    if not _LOWER_IDENT_RE.match(token):
        return False
    if token in _C_KEYWORDS:
        return False
    if idx + 1 < len(tokens) and tokens[idx + 1] == "(":
        return False
    if idx > 0 and tokens[idx - 1] in (".", "->"):
        return False
    return True


def _scan_l1_light_drift(diff_text: str) -> Dict[str, List[str]]:
    changed = _changed_bodies(diff_text)
    pairs = _diff_pairs(diff_text)
    categories: List[str] = []
    rename_pairs: List[str] = []

    if changed and all(_COMMENT_ONLY_RE.match(line) for line in changed):
        categories.append("comment_only")

    if changed and all(_LOG_CALL_RE.search(line) for line in changed):
        categories.append("logging_only")

    if pairs:
        macro_alias = True
        saw_macro_delta = False
        local_rename = True
        local_map = {}
        reverse_map = {}

        for minus_body, plus_body in pairs:
            minus_norm = _UPPER_TOKEN_RE.sub("MACRO", minus_body)
            plus_norm = _UPPER_TOKEN_RE.sub("MACRO", plus_body)
            if minus_norm != plus_norm:
                macro_alias = False
            if minus_body != plus_body and re.search(_UPPER_TOKEN_RE, minus_body) and re.search(_UPPER_TOKEN_RE, plus_body):
                saw_macro_delta = True

            minus_tokens = _tokenize_for_rename(minus_body)
            plus_tokens = _tokenize_for_rename(plus_body)
            if len(minus_tokens) != len(plus_tokens):
                local_rename = False
                continue
            for idx, (minus_tok, plus_tok) in enumerate(zip(minus_tokens, plus_tokens)):
                if minus_tok == plus_tok:
                    continue
                if not (_is_local_identifier(minus_tokens, idx) and _is_local_identifier(plus_tokens, idx)):
                    local_rename = False
                    break
                if local_map.get(minus_tok, plus_tok) != plus_tok or reverse_map.get(plus_tok, minus_tok) != minus_tok:
                    local_rename = False
                    break
                local_map[minus_tok] = plus_tok
                reverse_map[plus_tok] = minus_tok
            if not local_rename:
                break

        if macro_alias and saw_macro_delta:
            categories.append("equivalent_macro_alias")
        if local_rename and local_map:
            categories.append("local_variable_rename")
            rename_pairs = [f"{src}->{dst}" for src, dst in sorted(local_map.items())[:4]]

    return {
        "categories": categories,
        "rename_pairs": rename_pairs,
        "sample_lines": changed[:4],
    }


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
        lock_objects = ctx.risk_markers.get("lock_objects", [])[:8]
        fields = ctx.risk_markers.get("fields", [])[:8]
        state_points = ctx.risk_markers.get("state_points", [])[:8]
        error_path_nodes = ctx.risk_markers.get("error_path_nodes", [])[:8]
        categories = []
        if any(k in uniq for k in ("spin_lock", "mutex", "rcu")):
            categories.append("locking")
        if any(k in uniq for k in ("refcount", "kref", "atomic")):
            categories.append("lifetime")
        if "struct" in uniq:
            categories.append("layout")
        only_generic_struct = set(uniq).issubset({"struct"})
        has_context_markers = bool(lock_objects or fields or state_points or error_path_nodes)
        if only_generic_struct and not has_context_markers:
            return None
        high_risk = any(cat in categories for cat in ("locking", "lifetime"))
        severity = "high" if high_risk else "warn"
        level_floor = "L3" if high_risk else "L2"
        message = "检测到关键结构/锁变更: " + ", ".join(uniq[:6]) if high_risk else "检测到结构体/关键字段相关变更，建议核对数据路径与布局影响"
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": severity,
            "level_floor": level_floor,
            "message": message,
            "evidence": {
                "keywords": uniq,
                "categories": categories,
                "lock_objects": lock_objects,
                "fields": fields,
                "state_points": state_points,
                "error_path_nodes": error_path_nodes,
                "generic_struct_only": only_generic_struct,
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
        condition_changes = section.get("condition_changes", [])
        return_path_changes = section.get("return_path_changes", [])
        state_fields = section.get("state_fields", [])
        callback_or_ops_changes = section.get("callback_or_ops_changes", [])
        low_signal_only = (
            not high_risk
            and not condition_changes
            and not state_fields
            and not callback_or_ops_changes
            and len(return_path_changes) <= 1
        )
        if low_signal_only:
            return None
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": "high" if high_risk else "warn",
            "level_floor": "L3" if high_risk else "L1",
            "message": section.get("summary", "检测到状态机/控制流变化"),
            "evidence": {
                "condition_changes": condition_changes,
                "return_path_changes": return_path_changes,
                "error_codes": section.get("error_codes", []),
                "state_fields": state_fields,
                "callback_or_ops_changes": callback_or_ops_changes,
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
            "level_floor": "L3" if high_risk else "L1",
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
            "level_floor": "L1",
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
        risk_markers = getattr(ctx, "risk_markers", {}) or {}
        special_summary = (getattr(ctx, "special_risk_report", {}) or {}).get("summary") or {}
        semantic_marker_counts = {
            "lock_objects": len(risk_markers.get("lock_objects", []) or []),
            "fields": len(risk_markers.get("fields", []) or []),
            "state_points": len(risk_markers.get("state_points", []) or []),
            "error_path_nodes": len(risk_markers.get("error_path_nodes", []) or []),
        }
        dependency_confidence = getattr(ctx.dependency_details, "confidence_level", "") if ctx.dependency_details else ""
        if ctx.base_level != "L0":
            return None
        if ctx.prerequisite_patches:
            return None
        if ctx.changed_lines > self.line_threshold or ctx.hunk_count > self.hunk_threshold:
            return None
        if ctx.critical_structure_hits or max_fanout > 0:
            return None
        if any(semantic_marker_counts.values()):
            return None
        if special_summary.get("triggered_sections"):
            return None
        if dependency_confidence == "low":
            return None
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "level_floor": "L0",
            "message": "满足直接回合候选条件：strict 命中、无前置依赖、改动规模小、无明显传播且未观察到语义敏感信号",
            "evidence": {
                "base_level": ctx.base_level,
                "changed_lines": ctx.changed_lines,
                "hunk_count": ctx.hunk_count,
                "max_fanout": max_fanout,
                "line_threshold": self.line_threshold,
                "hunk_threshold": self.hunk_threshold,
                "semantic_marker_counts": semantic_marker_counts,
                "special_risk_sections": list(special_summary.get("triggered_sections") or []),
                "dependency_confidence": dependency_confidence,
            },
        }


class L1LightDriftSampleRule(PolicyRule):
    rule_id = "l1_light_drift_sample"
    name = "L1 Light Drift Sample"
    severity = "info"
    rule_class = "admission"
    rule_scope = "low_level"

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        if ctx.base_level != "L1":
            return None
        if ctx.prerequisite_patches or ctx.critical_structure_hits:
            return None
        if any((len(fi.callers) + len(fi.callees)) > 0 for fi in (ctx.function_impacts or [])):
            return None
        summary = (ctx.special_risk_report or {}).get("summary") or {}
        if summary.get("triggered_sections"):
            return None

        scan = _scan_l1_light_drift(ctx.patch.diff_code or "")
        categories = scan.get("categories") or []
        if not categories:
            return None

        labels = {
            "comment_only": "注释漂移",
            "logging_only": "日志文本漂移",
            "equivalent_macro_alias": "等价宏替换",
            "local_variable_rename": "局部变量重命名",
        }
        cn_categories = [labels.get(item, item) for item in categories]
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "level_floor": "L1",
            "message": "当前 L1 漂移主要表现为轻微样本: " + " / ".join(cn_categories[:4]),
            "evidence": {
                "categories": categories,
                "rename_pairs": scan.get("rename_pairs", []),
                "sample_lines": scan.get("sample_lines", []),
            },
        }


class CallChainPropagationRule(PolicyRule):
    rule_id = "call_chain_propagation"
    name = "Call Chain Propagation Warning"
    severity = "warn"
    rule_class = "risk_profile"
    rule_scope = "risk"

    def __init__(self, promotion_min_fanout: int = 2):
        self.promotion_min_fanout = max(1, int(promotion_min_fanout or 1))

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
        if not has_critical and fanout < self.promotion_min_fanout:
            return None
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
                "promotion_min_fanout": self.promotion_min_fanout,
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

        if scan["param_count_changed"] or scan["sig_change"]:
            level_floor = "L2"
        elif scan["return_delta"] >= self.return_delta_threshold:
            level_floor = "L1" if ctx.base_level in ("L0", "L1") else "L2"
        else:
            level_floor = "L1"
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
        "control_flow": re.compile(r"\b(if|else|switch|goto|break|continue)\b"),
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
    call_chain_promotion_min = getattr(config, "call_chain_promotion_min_fanout", 2) if config else 2
    return_delta = getattr(config, "l1_return_line_delta_threshold", 2) if config else 2
    single_line_max = getattr(config, "single_line_impact_max_changed_lines", 4) if config else 4

    if not config or getattr(config, "prerequisite_rules_enabled", True):
        registry.register(PrerequisiteRequiredRule())
        registry.register(PrerequisiteRecommendedRule())
        registry.register(IndependentPatchRule())

    if not config or getattr(config, "direct_backport_rules_enabled", True):
        registry.register(DirectBackportRule(direct_line_threshold, direct_hunk_threshold))
        registry.register(L1LightDriftSampleRule())

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
        registry.register(CallChainPropagationRule(call_chain_promotion_min))
        registry.register(CallChainFanoutRule(fanout_threshold))

    if not config or getattr(config, "l1_api_surface_rules_enabled", True):
        registry.register(L1APISurfaceRule(return_delta))

    if not config or getattr(config, "high_impact_single_line_rules_enabled", True):
        registry.register(SingleLineHighImpactRule(single_line_max))
