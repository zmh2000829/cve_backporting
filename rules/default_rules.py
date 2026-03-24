"""默认内置规则，承载于 rules/ 目录下以支持插拔式扩展。"""

import re
from typing import Dict, List, Optional

from rules.base import PolicyRule, RuleContext, RuleRegistry


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

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        if not ctx.critical_structure_hits:
            return None
        uniq = sorted(set(ctx.critical_structure_hits))
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "level_floor": "L3",
            "message": "检测到关键结构/锁变更: " + ", ".join(uniq[:6]),
            "evidence": {"keywords": uniq},
        }


class CallChainPropagationRule(PolicyRule):
    rule_id = "call_chain_propagation"
    name = "Call Chain Propagation Warning"
    severity = "warn"

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
        return {
            "sig_change": sig_change,
            "return_delta": ret_delta,
            "plus_return": plus_ret,
            "minus_return": minus_ret,
        }

    def evaluate(self, ctx: RuleContext) -> Optional[Dict]:
        scan = self._scan_diff(ctx.patch.diff_code or "")
        parts = []
        if scan["sig_change"]:
            parts.append("函数定义/签名行在 diff 中同时增删且文本不一致，可能存在形参、修饰符或 ABI 变化")
        if scan["return_delta"] >= self.return_delta_threshold:
            parts.append(
                f"return 语句增删差 {scan['return_delta']}（+{scan['plus_return']}/-{scan['minus_return']}），"
                "可能存在返回值语义或错误路径变化"
            )
        if not parts:
            return None

        level_floor = "L1" if ctx.base_level == "L1" else "L2"
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


def register_rules(registry: RuleRegistry, config=None):
    line_threshold = getattr(config, "large_change_line_threshold", 80) if config else 80
    hunk_threshold = getattr(config, "large_hunk_threshold", 8) if config else 8
    fanout_threshold = getattr(config, "call_chain_fanout_threshold", 6) if config else 6
    return_delta = getattr(config, "l1_return_line_delta_threshold", 2) if config else 2

    if not config or getattr(config, "large_change_rules_enabled", True):
        registry.register(LargeChangeRule(line_threshold, hunk_threshold))

    if not config or getattr(config, "critical_structure_rules_enabled", True):
        registry.register(CriticalStructureRule())

    if not config or getattr(config, "call_chain_rules_enabled", True):
        registry.register(CallChainPropagationRule())
        registry.register(CallChainFanoutRule(fanout_threshold))

    if not config or getattr(config, "l1_api_surface_rules_enabled", True):
        registry.register(L1APISurfaceRule(return_delta))
