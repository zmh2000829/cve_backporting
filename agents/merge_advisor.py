"""
MergeAdvisor Agent — 合入建议与综合检视

确定性层:
  - 规则引擎判定 action (merge / merge_with_prereqs / manual_review / skip)
  - 检视 checklist 生成

LLM 增强层:
  - 综合分析与自然语言建议
"""

import logging
from typing import List, Optional

from core.models import (
    AnalysisResult, AnalysisResultV2,
    VulnAnalysis, PatchReview, MergeRecommendation,
    RiskBenefitScore, PostPatch, CommunityDiscussion,
)
from core.llm_client import LLMClient

logger = logging.getLogger(__name__)


class MergeAdvisorAgent:
    """合入建议生成"""

    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm

    def advise(self, v2: AnalysisResultV2) -> MergeRecommendation:
        """基于 v2 全量分析结果，生成合入建议"""
        rec = MergeRecommendation()
        base = v2.base

        rec.action = self._determine_action(v2)
        rec.confidence = self._calc_confidence(v2)
        rec.risk_benefit = v2.merge_recommendation.risk_benefit if (
            v2.merge_recommendation and v2.merge_recommendation.risk_benefit
        ) else None
        rec.prerequisite_actions = self._build_prereq_actions(v2)
        rec.review_checklist = self._build_checklist(v2)
        rec.dependency_analysis = self._build_dep_analysis(v2)
        rec.summary = self._build_summary(v2, rec)

        if self.llm and self.llm.enabled:
            self._enhance_with_llm(v2, rec)
            rec.llm_enhanced = True

        logger.info("[MergeAdvisor] action=%s, confidence=%.2f",
                    rec.action, rec.confidence)
        return rec

    # ── 规则引擎 ──────────────────────────────────────────────────────

    def _determine_action(self, v2: AnalysisResultV2) -> str:
        base = v2.base
        if not base:
            return "skip"

        if base.is_fixed:
            return "skip"

        dr = base.dry_run
        has_prereqs = any(
            p.grade in ("strong", "medium")
            for p in (base.prerequisite_patches or [])
        )

        if dr and dr.applies_cleanly and not has_prereqs:
            return "merge"
        if dr and dr.applies_cleanly and has_prereqs:
            return "merge_with_prereqs"
        if dr and not dr.applies_cleanly:
            if has_prereqs:
                return "merge_with_prereqs"
            return "manual_review"
        return "manual_review"

    def _calc_confidence(self, v2: AnalysisResultV2) -> float:
        base = v2.base
        if not base:
            return 0.0

        c = 0.5
        dr = base.dry_run
        if dr:
            if dr.applies_cleanly:
                c += 0.3
                if dr.apply_method == "strict":
                    c += 0.1
            else:
                c -= 0.2

        if v2.vuln_analysis and v2.vuln_analysis.llm_enhanced:
            c += 0.05
        if v2.patch_review and v2.patch_review.llm_enhanced:
            c += 0.05

        return max(0.0, min(1.0, c))

    def _build_prereq_actions(self, v2: AnalysisResultV2) -> List[str]:
        actions: List[str] = []
        base = v2.base
        if not base:
            return actions

        strong = [p for p in (base.prerequisite_patches or [])
                  if p.grade == "strong"]
        medium = [p for p in (base.prerequisite_patches or [])
                  if p.grade == "medium"]

        if strong:
            for p in strong[:5]:
                desc = (f"[强依赖] {p.commit_id[:12]} — {p.subject}")
                if p.overlap_funcs:
                    desc += f" (重叠函数: {', '.join(p.overlap_funcs[:3])})"
                if p.overlap_hunks:
                    desc += f" — 与修复补丁有 {p.overlap_hunks} 个重叠代码块"
                actions.append(desc)
        if medium:
            for p in medium[:3]:
                desc = (f"[中依赖] {p.commit_id[:12]} — {p.subject}")
                if p.overlap_funcs:
                    desc += f" (重叠函数: {', '.join(p.overlap_funcs[:3])})"
                actions.append(desc)

        if v2.post_patches:
            followups = [p for p in v2.post_patches
                         if p.relation == "followup_fix"]
            same_func = [p for p in v2.post_patches
                         if p.relation == "same_function"]
            if followups:
                for p in followups[:3]:
                    actions.append(
                        f"[后续修复] {p.commit_id[:12]} — {p.subject}"
                        f" ({p.description})")
            if same_func:
                for p in same_func[:3]:
                    actions.append(
                        f"[同函数修改] {p.commit_id[:12]} — {p.subject}"
                        f" ({p.description})")

        return actions

    def _build_checklist(self, v2: AnalysisResultV2) -> List[str]:
        checks: List[str] = []
        base = v2.base

        if base and base.dry_run:
            if base.dry_run.applies_cleanly:
                checks.append("[低风险] 补丁可自动应用，确认编译通过")
            else:
                checks.append("[需处理] 解决合入冲突并验证修改正确性")

        if v2.patch_review:
            if v2.patch_review.data_structures:
                types = set(d["type"] for d in v2.patch_review.data_structures)
                checks.append(
                    f"[检视] 确认涉及的数据结构 ({', '.join(types)}) 使用正确"
                )
            for item in v2.patch_review.code_review_items:
                if item.severity in ("critical", "warning"):
                    checks.append(f"[{item.severity}] {item.description}")

        if v2.vuln_analysis:
            va = v2.vuln_analysis
            if va.vuln_type != "unknown":
                checks.append(
                    f"[安全] 确认 {va.vuln_type} 类型漏洞已被完整修复"
                )
            if va.detection_method:
                checks.append(f"[验证] {va.detection_method}")

        checks.append("[通用] 运行相关子系统测试用例")
        checks.append("[通用] 检查补丁在目标内核版本的编译兼容性")

        return checks

    def _build_summary(self, v2: AnalysisResultV2,
                       rec: MergeRecommendation) -> str:
        base = v2.base
        if not base:
            return "缺少基础分析数据，无法生成建议。"

        _sev_cn = {"critical": "严重", "high": "高危",
                   "medium": "中危", "low": "低危"}
        _type_cn = {
            "UAF": "Use-After-Free (释放后使用)",
            "OOB": "Out-of-Bounds (越界读写)",
            "NULL_deref": "NULL 指针解引用",
            "race_condition": "竞态条件",
            "integer_overflow": "整数溢出",
            "info_leak": "信息泄露",
            "deadlock": "死锁",
            "privilege_escalation": "权限提升",
            "DoS": "拒绝服务",
        }
        _action_desc = {
            "merge": "建议直接合入该补丁",
            "merge_with_prereqs": "建议合入该补丁，但需先处理前置依赖",
            "manual_review": "该补丁需经人工审查后决定是否合入",
            "skip": "该 CVE 在目标版本中已修复或无需处理",
        }

        parts: List[str] = [
            _action_desc.get(rec.action, rec.action)
        ]

        # CVE + 漏洞信息
        if v2.vuln_analysis:
            va = v2.vuln_analysis
            sev_cn = _sev_cn.get(va.severity, va.severity)
            type_cn = _type_cn.get(va.vuln_type, va.vuln_type)
            parts.append(
                f"该补丁修复 {base.cve_id} ({sev_cn} 严重度，"
                f"{type_cn} 类型漏洞)")
            if va.affected_subsystem and va.affected_subsystem != "unknown":
                parts.append(f"影响 {va.affected_subsystem} 子系统")
        elif base.cve_info:
            sev_cn = _sev_cn.get(
                base.cve_info.severity.lower(),
                base.cve_info.severity)
            parts.append(
                f"该补丁修复 {base.cve_id} ({sev_cn} 严重度)")

        # DryRun 结果
        _method_cn = {
            "strict": "strict 模式直接应用",
            "context-C1": "降低上下文匹配",
            "3way": "三路合并",
            "regenerated": "上下文重生成",
            "conflict-adapted": "冲突适配",
            "verified-direct": "内存级直接验证",
        }
        dr = base.dry_run
        if dr:
            if dr.applies_cleanly:
                method = _method_cn.get(dr.apply_method, dr.apply_method)
                parts.append(
                    f"DryRun 检测显示补丁可通过{method}干净应用")
            else:
                n_cf = len(dr.conflicting_files)
                parts.append(
                    f"DryRun 检测显示补丁存在 {n_cf} 个文件冲突，"
                    f"需手动解决后合入")

        # 关联补丁概要
        prereqs = base.prerequisite_patches or []
        strong = [p for p in prereqs if p.grade == "strong"]
        medium = [p for p in prereqs if p.grade == "medium"]
        post = v2.post_patches or []

        if not prereqs:
            parts.append(
                "无前置依赖补丁，该修复可独立合入目标版本")
        else:
            parts.append(
                f"存在 {len(prereqs)} 个前置补丁"
                f" (强依赖 {len(strong)}，中依赖 {len(medium)})")
            if strong:
                ids = ", ".join(p.commit_id[:12] for p in strong[:3])
                parts.append(f"强依赖补丁 ({ids}) 必须先合入")

        if post:
            n_followup = sum(
                1 for p in post if p.relation == "followup_fix")
            if n_followup:
                parts.append(
                    f"注意: 存在 {n_followup} 个后续修复补丁需一并评估")
        else:
            parts.append("无后续关联补丁，修复在上游是自包含的")

        # 风险收益总结
        rb = rec.risk_benefit
        if rb and rb.overall_detail:
            parts.append(rb.overall_detail)

        return "。".join(parts) + "。"

    # ── 关联补丁分析 ─────────────────────────────────────────────────

    def _build_dep_analysis(self, v2: AnalysisResultV2) -> str:
        """无论有无关联补丁，都给出完整分析与理由"""
        base = v2.base
        if not base:
            return "缺少基础分析数据，无法评估关联补丁"

        prereqs = base.prerequisite_patches or []
        post = v2.post_patches or []
        dr = base.dry_run
        fix = base.fix_patch
        review = v2.patch_review
        lines: List[str] = []

        strong = [p for p in prereqs if p.grade == "strong"]
        medium = [p for p in prereqs if p.grade == "medium"]
        weak = [p for p in prereqs if p.grade == "weak"]

        if not prereqs:
            lines.append("【前置补丁分析】工具未检测到前置依赖补丁")
            reasons: List[str] = []
            if dr and dr.applies_cleanly:
                reasons.append(
                    "修复补丁可在目标内核版本上干净应用，说明补丁所修改"
                    "的代码上下文在目标版本中与上游一致，不存在因前置补丁"
                    "缺失导致的文本冲突")
            if fix and fix.modified_files:
                n_files = len(fix.modified_files)
                if n_files <= 2:
                    reasons.append(
                        f"补丁仅修改 {n_files} 个文件，改动范围集中，"
                        f"被其他补丁依赖的可能性较低")
            has_ds = (review and review.data_structures
                      and len(review.data_structures) > 0)
            if not has_ds:
                reasons.append(
                    "补丁未引入或依赖新的数据结构定义 (如新的 struct 字段、"
                    "新的锁变量等)，无需额外补丁提供结构基础")
            elif has_ds:
                ds_names = [d.get("name", d["type"])
                            for d in review.data_structures[:3]]
                reasons.append(
                    f"虽然补丁涉及数据结构 ({', '.join(ds_names)})，"
                    f"但这些结构在目标版本中已存在，无需前置补丁引入")

            if reasons:
                lines.append("分析依据: " + "；".join(reasons))
            lines.append(
                "结论: 该补丁属于可独立合入的高版本修复补丁，不依赖"
                "其他前置改动，可直接应用到目标版本")
        else:
            lines.append(
                f"【前置补丁分析】检测到 {len(prereqs)} 个关联前置补丁 "
                f"(强依赖 {len(strong)} / 中依赖 {len(medium)} "
                f"/ 弱关联 {len(weak)})")

            if strong:
                lines.append(
                    "强依赖补丁表示修复补丁引用了这些补丁引入的代码、"
                    "数据结构或 API，缺失它们将导致编译失败或语义错误:")
                for p in strong[:5]:
                    desc = f"  • {p.commit_id[:12]} — {p.subject}"
                    extra = []
                    if p.overlap_funcs:
                        extra.append(
                            f"共享函数: {', '.join(p.overlap_funcs[:3])}")
                    if p.overlap_hunks:
                        extra.append(f"{p.overlap_hunks} 个重叠代码块")
                    if p.adjacent_hunks:
                        extra.append(f"{p.adjacent_hunks} 个相邻代码块")
                    if extra:
                        desc += f" ({'; '.join(extra)})"
                    lines.append(desc)

            if medium:
                lines.append(
                    "中依赖补丁修改了相近的代码区域，虽不直接阻断合入，"
                    "但缺失可能导致功能不完整或遗漏相关修复:")
                for p in medium[:3]:
                    desc = f"  • {p.commit_id[:12]} — {p.subject}"
                    if p.overlap_funcs:
                        desc += (
                            f" (重叠函数: "
                            f"{', '.join(p.overlap_funcs[:3])})")
                    lines.append(desc)

            if dr and dr.applies_cleanly:
                lines.append(
                    "注意: 尽管存在前置补丁，修复补丁本身可干净应用。"
                    "这说明前置补丁提供的是编译/运行时依赖 (如数据结构"
                    "定义、API 声明)，而非文本层面的上下文冲突。"
                    "建议先合入前置补丁以保证功能完整性")
            elif dr and not dr.applies_cleanly:
                lines.append(
                    "修复补丁无法干净应用，前置补丁缺失可能是冲突原因"
                    "之一，建议按依赖顺序先合入前置补丁再尝试应用修复补丁")

        # 后置补丁分析
        if post:
            followups = [p for p in post if p.relation == "followup_fix"]
            same_func = [p for p in post if p.relation == "same_function"]
            lines.append(
                f"【后置补丁分析】检测到 {len(post)} 个后置关联补丁")
            if followups:
                lines.append(
                    f"其中 {len(followups)} 个为后续修复 "
                    f"(通过 Fixes: 标签引用本补丁)，"
                    f"表示上游社区发现本修复存在不完善之处并做了追加修正:")
                for p in followups[:3]:
                    lines.append(
                        f"  • {p.commit_id[:12]} — {p.subject}")
                lines.append("建议将这些后续修复一并合入，避免修复不完整")
            if same_func:
                lines.append(
                    f"另有 {len(same_func)} 个补丁修改了同一函数，"
                    f"可能是功能增强或相关的独立修复:")
                for p in same_func[:3]:
                    lines.append(
                        f"  • {p.commit_id[:12]} — {p.subject}"
                        f" ({p.description})")
                lines.append("建议评估这些修改是否影响修复补丁的正确性")
        else:
            lines.append(
                "【后置补丁分析】未检测到后续关联补丁，"
                "说明该修复在上游社区是自包含的，无需额外的追加修正")

        return "\n".join(lines)

    # ── LLM 增强 ─────────────────────────────────────────────────────

    def _enhance_with_llm(self, v2: AnalysisResultV2,
                          rec: MergeRecommendation):
        base = v2.base
        if not base:
            return

        context_parts = [f"CVE: {base.cve_id}"]
        if v2.vuln_analysis:
            va = v2.vuln_analysis
            context_parts.append(f"漏洞类型: {va.vuln_type}")
            context_parts.append(f"严重度: {va.severity}")
            if va.root_cause:
                context_parts.append(f"根因: {va.root_cause}")

        if v2.patch_review:
            pr = v2.patch_review
            if pr.fix_summary:
                context_parts.append(f"修复: {pr.fix_summary}")
            if pr.trigger_analysis:
                context_parts.append(f"触发: {pr.trigger_analysis}")

        context_parts.append(f"规则判定: {rec.action}")
        if rec.risk_benefit:
            rb = rec.risk_benefit
            context_parts.append(
                f"复杂度={rb.merge_complexity:.2f}, "
                f"回归风险={rb.regression_risk:.2f}, "
                f"安全收益={rb.security_benefit:.2f}"
            )

        prompt = (
            "\n".join(context_parts)
            + "\n\n请用 JSON 格式给出合入建议:\n"
            '{\n'
            '  "summary": "一段话综合建议 (3-5 句话)",\n'
            '  "review_additions": ["额外检视要点1", "额外检视要点2"]\n'
            '}\n'
            "请用中文回答。"
        )

        resp = self.llm.chat_json(
            prompt,
            system="你是 Linux 内核补丁合入决策专家。",
            max_tokens=800,
        )
        if resp:
            if resp.get("summary"):
                rec.summary = resp["summary"]
            additions = resp.get("review_additions", [])
            for item in additions:
                if item and item not in rec.review_checklist:
                    rec.review_checklist.append(f"[LLM] {item}")
