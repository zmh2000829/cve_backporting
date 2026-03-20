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
            actions.append(
                f"先合入 {len(strong)} 个强依赖前置补丁: "
                + ", ".join(p.commit_id[:12] for p in strong[:5])
            )
        if medium:
            actions.append(
                f"评估 {len(medium)} 个中依赖前置补丁是否需合入"
            )

        if v2.post_patches:
            followups = [p for p in v2.post_patches
                         if p.relation == "followup_fix"]
            if followups:
                actions.append(
                    f"注意 {len(followups)} 个后续修复补丁需一并评估: "
                    + ", ".join(p.commit_id[:12] for p in followups[:3])
                )

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

        # 前置依赖
        n_strong = sum(1 for p in (base.prerequisite_patches or [])
                       if p.grade == "strong")
        n_medium = sum(1 for p in (base.prerequisite_patches or [])
                       if p.grade == "medium")
        if n_strong:
            parts.append(
                f"存在 {n_strong} 个强依赖前置补丁必须先合入")
        if n_medium:
            parts.append(
                f"另有 {n_medium} 个中等依赖前置补丁建议评估")

        # 后置补丁
        if v2.post_patches:
            n_followup = sum(1 for p in v2.post_patches
                             if p.relation == "followup_fix")
            if n_followup:
                parts.append(
                    f"注意: 存在 {n_followup} 个后续修复补丁"
                    f"需一并评估是否合入")

        # 风险收益总结
        rb = rec.risk_benefit
        if rb and rb.overall_detail:
            parts.append(rb.overall_detail)

        return "。".join(parts) + "。"

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
