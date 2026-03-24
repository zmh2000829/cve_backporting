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


class L1APISurfaceRule(PolicyRule):
    """
    L1 及近似场景：用 diff 启发式提示「签名/参数/返回路径」类变更，供人工与 LLM 二次核对。
    不依赖 LLM；与 profile / 插拔规则并存。
    """

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
            b = body.lstrip()
            if ch == "+" and self._looks_like_func_sig(b):
                plus_sigs.append(re.sub(r"\s+", " ", b.strip()))
            if ch == "-" and self._looks_like_func_sig(b):
                minus_sigs.append(re.sub(r"\s+", " ", b.strip()))
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
            parts.append("函数定义/签名行在 diff 中同时增删且文本不一致，可能存在形参、修饰符或可见性变更")
        if scan["return_delta"] >= self.return_delta_threshold:
            parts.append(
                f"return 语句增删差 {scan['return_delta']}（+{scan['plus_return']}/-{scan['minus_return']}），"
                "可能存在返回值语义或错误路径变化"
            )
        if not parts:
            return None
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "message": "；".join(parts) + "。若为 L1 级应用，请重点核对调用点与 ABI。",
            "evidence": scan,
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
        rd = getattr(self.config, "l1_return_line_delta_threshold", 2) if self.config else 2
        self.registry.register(LargeChangeRule(lt, ht))
        self.registry.register(CriticalStructureRule())
        self.registry.register(CallChainFanoutRule(ft))
        if not self.config or getattr(self.config, "l1_api_surface_rules_enabled", True):
            self.registry.register(L1APISurfaceRule(rd))

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

        cross_n = getattr(self, "_last_cross_file_count", 0)
        steps = [
            f"级别判定: {level_decision.level} ({level_decision.strategy})",
            f"变更规模: {changed} 行, {hunks} hunk, {len(funcs)} 函数",
            f"调用链影响函数: {len(impacts)}（跨文件合并源文件 {cross_n} 个）",
            f"规则命中: {len(rule_hits)}",
        ]
        warnings = [h["message"] for h in rule_hits if h.get("severity") in ("warn", "high")]

        return ValidationDetails(
            workflow_steps=steps,
            level_decision=level_decision,
            function_impacts=impacts,
            warnings=warnings,
            rule_profile=getattr(self.config, "profile", "default") if self.config else "default",
            rule_version="v2",
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

        # 分级策略说明：L0 仅在与规则不冲突时可标为无害；L1 依赖上下文/空白容忍，需规则与 LLM 交叉核对
        if level == "L0":
            strategy = (
                "L0 严格文本匹配：补丁与目标行级一致；若无高危/告警规则命中，可视为对运行时语义无额外扰动"
            )
            conf = "high"
        elif level == "L1":
            strategy = (
                "L1 轻度适配（空白或极少上下文漂移）：默认不自动视为无害；"
                "需结合 l1_api_surface 等规则与（可选）LLM 判断是否为单纯入参/格式类调整"
            )
            conf = "high" if self.llm_enabled else "medium"
        elif level == "L2":
            strategy = "L2 三向合并：依赖共同祖先，存在合入语义偏离风险，建议对照主线 hunk"
            conf = "medium"
        elif level == "L3":
            strategy = "L3 上下文重生成：行面已改写，需重点 review 与测试"
            conf = "medium"
        elif level == "L4":
            strategy = "L4 冲突适配：自动化解冲突，人工必审"
            conf = "low"
        else:
            strategy = "L5 验证直应用或其它高级路径：绕过常规 apply 或方法未识别，按最高谨慎度处理"
            conf = "low"

        harmless = level == "L0" and not high and not warn
        warnings = [h["message"] for h in rule_hits if h.get("severity") in ("warn", "high")]
        reason = (
            f"DryRun 方法={method or 'none'} → 级别 {level}；"
            f"规则命中 {len(rule_hits)}（high={len(high)}, warn={len(warn)}）。"
            f"无害标记仅当 L0 且无 high/warn。"
        )

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
        fanout_t = getattr(self.config, "call_chain_fanout_threshold", 6) if self.config else 6
        for fn in modified_funcs:
            if fn not in callees_of:
                continue
            callers = callers_of.get(fn, []) or []
            callees = callees_of.get(fn, []) or []
            fanout = len(callers) + len(callees)
            warns = []
            if fanout >= fanout_t:
                warns.append(f"{fn} 调用链影响较大: callers={len(callers)}, callees={len(callees)}")
            if len(pairs) > 1 and (callers or callees):
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
