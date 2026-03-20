"""
RiskBenefit Analyzer — 风险收益量化评估

确定性层:
  - 合入复杂度 (冲突文件数/hunk 数/前置依赖数)
  - 回归风险 (修改范围/涉及子系统复杂度)
  - 变更范围 (代码行数/文件数)
  - 安全收益 (漏洞严重度/影响面)

LLM 增强层:
  - 综合风险评估
"""

import logging
from typing import Dict, List, Optional

from core.models import (
    AnalysisResult, PatchReview, VulnAnalysis,
    RiskBenefitScore, PostPatch, PatchInfo, CveInfo,
)
from core.git_manager import GitRepoManager
from core.llm_client import LLMClient
from core.matcher import (
    extract_functions_from_diff, extract_hunks_from_diff,
    extract_files_from_diff,
)

logger = logging.getLogger(__name__)


_LEVEL_LABELS = [
    (0.15, "极低"), (0.30, "低"), (0.50, "中"),
    (0.70, "高"), (1.01, "极高"),
]

_VULN_TYPE_CN = {
    "UAF": "Use-After-Free (释放后使用)",
    "OOB": "Out-of-Bounds (越界读写)",
    "NULL_deref": "NULL 指针解引用",
    "race_condition": "竞态条件",
    "integer_overflow": "整数溢出",
    "info_leak": "信息泄露",
    "deadlock": "死锁",
    "privilege_escalation": "权限提升",
    "DoS": "拒绝服务",
    "type_confusion": "类型混淆",
    "memory_leak": "内存泄漏",
}

_VULN_RISK_DESC = {
    "UAF": "该类漏洞允许攻击者通过控制已释放对象的内存布局实现任意代码执行或权限提升",
    "OOB": "该类漏洞可导致内核内存越界访问，攻击者可能借此泄露敏感数据或劫持控制流",
    "NULL_deref": "该类漏洞通常导致内核崩溃 (Oops/Panic)，在某些架构上可能被利用进行权限提升",
    "race_condition": "该类漏洞利用并发时序窗口，复现困难但一旦利用成功可能获得内核任意读写能力",
    "privilege_escalation": "该类漏洞可使非特权用户获取 root 权限，威胁极高",
    "DoS": "该类漏洞可导致内核崩溃或资源耗尽，影响系统可用性",
    "integer_overflow": "该类漏洞可导致后续缓冲区操作使用错误长度，间接引发越界访问",
    "info_leak": "该类漏洞可泄露内核地址或敏感数据，常作为漏洞利用链的一环",
}

_SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}

_METHOD_CN = {
    "strict": "strict 模式 (原始补丁直接应用)",
    "context-C1": "降低上下文模式 (-C1，容忍少量行偏移)",
    "3way": "三路合并模式 (3-way merge)",
    "regenerated": "上下文重生成模式 (重新定位 hunk 上下文)",
    "conflict-adapted": "冲突适配模式 (自动解决部分冲突)",
    "verified-direct": "直接验证模式 (绕过 git apply，内存级验证)",
}


def _level(val: float) -> str:
    for threshold, label in _LEVEL_LABELS:
        if val < threshold:
            return label
    return "极高"


class RiskBenefitAnalyzer:
    """风险收益量化评估 — 每个维度生成等级标签 + 详细文字解释"""

    def __init__(self, git_mgr: GitRepoManager,
                 llm: Optional[LLMClient] = None):
        self.git_mgr = git_mgr
        self.llm = llm

    def analyze(self, base: AnalysisResult,
                vuln: Optional[VulnAnalysis] = None,
                patch_review: Optional[PatchReview] = None) -> RiskBenefitScore:
        """量化风险收益，同时生成详细文字描述"""
        score = RiskBenefitScore()

        score.merge_complexity, score.merge_complexity_detail = (
            self._calc_merge_complexity(base))
        score.regression_risk, score.regression_risk_detail = (
            self._calc_regression_risk(base, patch_review))
        score.change_scope, score.change_scope_detail = (
            self._calc_change_scope(base))
        score.security_benefit, score.security_benefit_detail = (
            self._calc_security_benefit(base, vuln))
        score.overall_score = self._calc_overall(score)
        score.overall_detail = self._build_overall_detail(
            score, base, vuln)
        score.factors = self._explain_factors(score, base, vuln)

        logger.info("[RiskBenefit] complexity=%.2f, regression=%.2f, "
                    "scope=%.2f, benefit=%.2f → overall=%.2f",
                    score.merge_complexity, score.regression_risk,
                    score.change_scope, score.security_benefit,
                    score.overall_score)
        return score

    def find_post_patches(self, fix_patch: PatchInfo, cve_info: CveInfo,
                          target_version: str) -> List[PostPatch]:
        """
        检测后置关联补丁 (fix 之后修改同函数的 commit)。
        通过 Fixes: 标签反查和同函数后续修改检测。
        """
        results: List[PostPatch] = []

        results.extend(
            self._find_fixes_tag_followers(fix_patch, target_version)
        )
        results.extend(
            self._find_same_function_followers(fix_patch, target_version)
        )

        seen = set()
        deduped: List[PostPatch] = []
        for pp in results:
            if pp.commit_id[:12] not in seen:
                seen.add(pp.commit_id[:12])
                deduped.append(pp)
        return deduped[:20]

    # ── 合入复杂度 ──────────────────────────────────────────────────────

    def _calc_merge_complexity(self, base: AnalysisResult):
        c = 0.0
        parts: List[str] = []
        dr = base.dry_run

        if dr:
            if dr.applies_cleanly:
                method_cn = _METHOD_CN.get(dr.apply_method, dr.apply_method)
                parts.append(f"补丁可通过 DryRun {method_cn}干净应用，无文件冲突")
                if dr.apply_method not in ("strict", ""):
                    c += 0.1
                    parts.append(
                        f"注意：应用方式非 strict，"
                        f"说明原始补丁与目标代码存在上下文偏移，"
                        f"已由工具自动适配")
            else:
                c += 0.4
                n_cf = len(dr.conflicting_files)
                cf_str = "、".join(dr.conflicting_files[:3])
                parts.append(
                    f"补丁无法干净应用，存在 {n_cf} 个文件冲突 ({cf_str})")
                c += min(n_cf * 0.1, 0.3)
                if dr.conflict_hunks:
                    n_hard = sum(1 for h in dr.conflict_hunks
                                 if h.get("severity") in ("L1", "L2"))
                    n_total = len(dr.conflict_hunks)
                    c += min(n_hard * 0.1, 0.2)
                    if n_hard:
                        parts.append(
                            f"其中 {n_hard}/{n_total} 个 hunk 为"
                            f"高严重度冲突 (L1/L2)，需人工解决")
                    else:
                        parts.append(
                            f"共 {n_total} 个冲突 hunk，"
                            f"均为低严重度，可能可自动处理")
        else:
            parts.append("未执行 DryRun 检测，无法判断补丁可应用性")

        n_prereq = len(base.prerequisite_patches)
        n_strong = sum(1 for p in base.prerequisite_patches
                       if p.grade == "strong")
        n_medium = sum(1 for p in base.prerequisite_patches
                       if p.grade == "medium")
        c += min(n_strong * 0.15, 0.3)
        c += min((n_prereq - n_strong) * 0.03, 0.1)

        if n_strong:
            ids = ", ".join(p.commit_id[:12] for p in
                            base.prerequisite_patches if p.grade == "strong")
            parts.append(
                f"存在 {n_strong} 个强依赖前置补丁 ({ids})，"
                f"必须先合入才能保证补丁正确性")
        if n_medium:
            parts.append(
                f"另有 {n_medium} 个中等依赖前置补丁，"
                f"建议评估是否需先合入")
        if n_prereq == 0 and dr and dr.applies_cleanly:
            parts.append("无前置依赖，补丁可独立合入")

        val = min(c, 1.0)
        lv = _level(val)
        detail = (
            f"合入复杂度: {lv}。"
            + "".join(f"{s}。" for s in parts)
        )
        return val, detail

    # ── 回归风险 ──────────────────────────────────────────────────────

    def _calc_regression_risk(self, base: AnalysisResult,
                              review: Optional[PatchReview]):
        r = 0.0
        parts: List[str] = []
        n_files = 0
        n_hunks = 0

        if base.fix_patch:
            n_files = len(base.fix_patch.modified_files or [])
            r += min(n_files * 0.05, 0.3)
            file_list = "、".join(
                (base.fix_patch.modified_files or [])[:3])

            if base.fix_patch.diff_code:
                n_hunks = len(extract_hunks_from_diff(
                    base.fix_patch.diff_code))
                r += min(n_hunks * 0.03, 0.2)

            parts.append(
                f"补丁修改 {n_files} 个文件共 {n_hunks} 个代码块 "
                f"(hunk)，涉及文件: {file_list}")

        sync_types: List[str] = []
        if review:
            n_crit = sum(1 for i in review.code_review_items
                         if i.severity == "critical")
            n_warn = sum(1 for i in review.code_review_items
                         if i.severity == "warning")
            r += min(n_crit * 0.15, 0.3)
            r += min(n_warn * 0.05, 0.15)

            if n_crit or n_warn:
                items_desc = []
                for item in review.code_review_items:
                    if item.severity in ("critical", "warning"):
                        items_desc.append(
                            f"{item.severity} 级 — {item.description}")
                parts.append(
                    f"安全检视发现 {n_crit} 项 critical、"
                    f"{n_warn} 项 warning 级条目：" +
                    "；".join(items_desc[:3]))

            for d in review.data_structures:
                if d["type"] in ("spinlock", "mutex", "rcu"):
                    sync_types.append(
                        f"{d['type']}({d.get('name', '')})")
            if sync_types:
                r += 0.1
                parts.append(
                    f"补丁涉及并发同步原语: {', '.join(sync_types[:4])}，"
                    f"并发场景下的回归风险需重点关注")

            if review.modified_functions:
                parts.append(
                    f"修改集中在函数: "
                    f"{', '.join(review.modified_functions[:5])}")

        if not sync_types and n_files <= 2 and n_hunks <= 3:
            parts.append(
                "修改范围小且集中，未涉及高风险并发原语，回归风险可控")

        val = min(r, 1.0)
        lv = _level(val)
        detail = (
            f"回归风险: {lv}。"
            + "".join(f"{s}。" for s in parts)
        )
        return val, detail

    # ── 变更范围 ──────────────────────────────────────────────────────

    def _calc_change_scope(self, base: AnalysisResult):
        s = 0.0
        parts: List[str] = []
        n_files = 0
        n_add = 0
        n_del = 0

        if base.fix_patch and base.fix_patch.diff_code:
            diff = base.fix_patch.diff_code
            n_files = len(extract_files_from_diff(diff))
            for line in diff.split("\n"):
                if line.startswith("+") and not line.startswith("+++"):
                    n_add += 1
                elif line.startswith("-") and not line.startswith("---"):
                    n_del += 1
            s += min(n_files * 0.08, 0.4)
            s += min((n_add + n_del) * 0.002, 0.4)

            parts.append(
                f"补丁涉及 {n_files} 个文件，"
                f"新增 {n_add} 行、删除 {n_del} 行"
                f" (合计变更 {n_add + n_del} 行)")
            if n_files <= 2 and (n_add + n_del) <= 30:
                parts.append(
                    "变更范围较小，属于局部修复性质的补丁")
            elif n_files >= 5 or (n_add + n_del) >= 200:
                parts.append(
                    "变更范围较大，涉及多个文件或大量代码改动，"
                    "需注意对其他功能的潜在影响")
            else:
                parts.append("变更范围适中")
        else:
            parts.append("无补丁 diff 信息，无法评估变更范围")

        val = min(s, 1.0)
        lv = _level(val)
        detail = (
            f"变更范围: {lv}。"
            + "".join(f"{p}。" for p in parts)
        )
        return val, detail

    # ── 安全收益 ──────────────────────────────────────────────────────

    def _calc_security_benefit(self, base: AnalysisResult,
                               vuln: Optional[VulnAnalysis]):
        b = 0.3
        parts: List[str] = []

        if vuln:
            sev_map = {"critical": 0.4, "high": 0.3,
                       "medium": 0.15, "low": 0.05}
            b += sev_map.get(vuln.severity, 0.1)
            vuln_type_bonus = {
                "UAF": 0.15, "race_condition": 0.15,
                "privilege_escalation": 0.2, "OOB": 0.1,
            }
            b += vuln_type_bonus.get(vuln.vuln_type, 0.05)

            sev_cn = _SEV_CN.get(vuln.severity, vuln.severity)
            type_cn = _VULN_TYPE_CN.get(vuln.vuln_type, vuln.vuln_type)
            parts.append(
                f"修复 {type_cn} 类型漏洞，严重度为 {sev_cn}")

            risk_desc = _VULN_RISK_DESC.get(vuln.vuln_type, "")
            if risk_desc:
                parts.append(risk_desc)

            if vuln.severity in ("critical", "high"):
                parts.append("建议优先修复")
            elif vuln.severity == "medium":
                parts.append("建议在版本迭代中修复")
            else:
                parts.append("可根据版本计划安排修复")

        elif base.cve_info:
            sev_map = {"critical": 0.35, "high": 0.25,
                       "medium": 0.1, "low": 0.0}
            sev = base.cve_info.severity.lower()
            b += sev_map.get(sev, 0.1)
            sev_cn = _SEV_CN.get(sev, sev)
            parts.append(
                f"CVE 标注严重度为 {sev_cn}，"
                f"未进行深度漏洞类型分析")
        else:
            parts.append(
                "缺少 CVE 严重度信息，"
                "按安全修复基础收益 (0.30) 计算")

        val = min(b, 1.0)
        benefit_labels = [
            (0.30, "极低"), (0.45, "低"), (0.60, "中"),
            (0.75, "高"), (1.01, "极高"),
        ]
        lv = "极高"
        for threshold, label in benefit_labels:
            if val < threshold:
                lv = label
                break
        detail = (
            f"安全收益: {lv}。"
            + "".join(f"{p}。" for p in parts)
        )
        return val, detail

    # ── 综合评分 ──────────────────────────────────────────────────────

    def _calc_overall(self, score: RiskBenefitScore) -> float:
        benefit = score.security_benefit
        risk = (score.merge_complexity * 0.35 +
                score.regression_risk * 0.35 +
                score.change_scope * 0.30)
        overall = benefit * 0.6 - risk * 0.4
        return max(0.0, min(1.0, overall + 0.5))

    def _build_overall_detail(self, score: RiskBenefitScore,
                              base: AnalysisResult,
                              vuln: Optional[VulnAnalysis]) -> str:
        lv = _level(score.overall_score)
        action_hint = {
            "极高": "强烈建议合入",
            "高": "建议合入",
            "中": "建议评估后合入",
            "低": "合入收益有限，建议审慎评估",
            "极低": "不建议合入或优先级极低",
        }
        parts: List[str] = [
            f"综合评估: {action_hint.get(lv, '待评估')}"
        ]

        if vuln:
            sev_cn = _SEV_CN.get(vuln.severity, vuln.severity)
            type_cn = _VULN_TYPE_CN.get(vuln.vuln_type, vuln.vuln_type)
            parts.append(
                f"该补丁修复一个 {sev_cn} 严重度的 {type_cn} 漏洞")
        elif base.cve_info:
            sev_cn = _SEV_CN.get(
                base.cve_info.severity.lower(),
                base.cve_info.severity)
            parts.append(
                f"该补丁修复一个 {sev_cn} 严重度的安全漏洞")

        comp_lv = _level(score.merge_complexity)
        reg_lv = _level(score.regression_risk)
        ben_labels = [
            (0.30, "极低"), (0.45, "低"), (0.60, "中"),
            (0.75, "高"), (1.01, "极高"),
        ]
        ben_lv = "极高"
        for threshold, label in ben_labels:
            if score.security_benefit < threshold:
                ben_lv = label
                break

        parts.append(
            f"安全收益{ben_lv}，合入复杂度{comp_lv}，"
            f"回归风险{reg_lv}")

        dr = base.dry_run
        if dr:
            if dr.applies_cleanly:
                method_cn = _METHOD_CN.get(dr.apply_method,
                                           dr.apply_method)
                parts.append(f"补丁可干净应用 ({method_cn})")
            else:
                parts.append(
                    f"补丁存在冲突 "
                    f"({len(dr.conflicting_files)} 个文件)，"
                    f"需手动解决")

        n_strong = sum(1 for p in base.prerequisite_patches
                       if p.grade == "strong")
        if n_strong:
            parts.append(
                f"需先合入 {n_strong} 个强依赖前置补丁")

        return "。".join(parts) + "。"

    def _explain_factors(self, score: RiskBenefitScore,
                         base: AnalysisResult,
                         vuln: Optional[VulnAnalysis]) -> List[str]:
        return [
            score.merge_complexity_detail,
            score.regression_risk_detail,
            score.change_scope_detail,
            score.security_benefit_detail,
        ]

    # ── 后置补丁检测 ──────────────────────────────────────────────────

    def _find_fixes_tag_followers(self, fix_patch: PatchInfo,
                                  target_version: str) -> List[PostPatch]:
        """通过 Fixes: 标签反查 (git log --grep) 查找引用本 fix 的后续 commit"""
        results: List[PostPatch] = []
        short_id = fix_patch.commit_id[:12]

        out = self.git_mgr.run_git(
            ["git", "log", "--oneline", "--all", "-20",
             f"--grep=Fixes: {short_id}"],
            target_version,
        )
        if not out:
            return results

        for line in out.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split(None, 1)
            cid = parts[0] if parts else ""
            subj = parts[1] if len(parts) > 1 else ""
            if cid and cid[:12] != short_id:
                results.append(PostPatch(
                    commit_id=cid,
                    subject=subj,
                    relation="followup_fix",
                    description=f"Fixes: 标签引用了 {short_id}",
                ))
        return results

    def _find_same_function_followers(self, fix_patch: PatchInfo,
                                      target_version: str) -> List[PostPatch]:
        """查找 fix 之后修改同函数的 commit"""
        results: List[PostPatch] = []
        if not fix_patch.diff_code:
            return results

        funcs = extract_functions_from_diff(fix_patch.diff_code)
        if not funcs:
            return results

        for fpath in (fix_patch.modified_files or [])[:3]:
            for func_name in funcs[:3]:
                out = self.git_mgr.run_git(
                    ["git", "log", "--oneline", "-5",
                     f"-S{func_name}", "--", fpath],
                    target_version,
                )
                if not out:
                    continue
                for line in out.strip().split("\n"):
                    parts = line.split(None, 1)
                    cid = parts[0] if parts else ""
                    subj = parts[1] if len(parts) > 1 else ""
                    if cid and cid[:12] != fix_patch.commit_id[:12]:
                        results.append(PostPatch(
                            commit_id=cid,
                            subject=subj,
                            relation="same_function",
                            description=f"修改了同函数 {func_name} in {fpath}",
                        ))
        return results
