"""
Pipeline 编排器
串联四个Agent完成端到端CVE补丁回溯分析：
  Crawler -> Analysis -> Dependency -> DryRun
v2.0 扩展: --deep 模式触发深度分析 (Community/Vuln/PatchReview/RiskBenefit/MergeAdvisor)
"""

import logging
from typing import Optional, Callable

from core.models import AnalysisResult, AnalysisResultV2
from core.git_manager import GitRepoManager
from core.matcher import PathMapper
from core.llm_client import LLMClient
from agents.crawler import CrawlerAgent
from agents.analysis import AnalysisAgent
from agents.dependency import DependencyAgent
from agents.dryrun import DryRunAgent
from agents.community import CommunityAgent
from agents.vuln_analysis import VulnAnalysisAgent
from agents.patch_review import PatchReviewAgent
from agents.merge_advisor import MergeAdvisorAgent
from core.risk_benefit import RiskBenefitAnalyzer
from core.policy_engine import PolicyEngine

logger = logging.getLogger(__name__)

# UI 回调协议: on_stage(key, status, detail)
StageCB = Optional[Callable[[str, str, str], None]]

STAGES = [
    ("crawler_cve",  "Crawler  │ 获取CVE信息"),
    ("crawler_patch", "Crawler  │ 获取修复补丁"),
    ("analysis_intro", "Analysis │ 搜索引入commit"),
    ("analysis_fix",  "Analysis │ 搜索修复commit"),
    ("analysis_bp",   "Analysis │ 检查stable backport"),
    ("dependency",    "Dependency│ 前置依赖分析"),
    ("dryrun",        "DryRun   │ 补丁试应用"),
]

STAGES_DEEP = STAGES + [
    ("community",     "Community│ 社区讨论收集"),
    ("vuln_analysis", "VulnAnaly│ 漏洞深度分析"),
    ("patch_review",  "PatchRevw│ 补丁逻辑检视"),
    ("risk_benefit",  "RiskBnft │ 风险收益评估"),
    ("merge_advice",  "Advisor  │ 合入建议生成"),
]


class Pipeline:
    """CVE补丁回溯分析流水线"""

    def __init__(self, git_mgr: GitRepoManager, api_timeout: int = 30,
                 path_mappings: list = None, llm_config=None,
                 policy_config=None):
        pm = PathMapper(path_mappings) if path_mappings else PathMapper()
        self.crawler = CrawlerAgent(api_timeout=api_timeout, git_mgr=git_mgr)
        self.analysis = AnalysisAgent(git_mgr, path_mapper=pm)
        self.dependency = DependencyAgent(git_mgr, path_mapper=pm)
        self.dryrun = DryRunAgent(git_mgr, path_mapper=pm)
        self.git_mgr = git_mgr

        self.llm = LLMClient(llm_config) if llm_config else LLMClient()
        self.community_agent = CommunityAgent(self.llm)
        self.vuln_agent = VulnAnalysisAgent(self.llm)
        self.patch_review_agent = PatchReviewAgent(git_mgr, self.llm)
        self.risk_benefit = RiskBenefitAnalyzer(git_mgr, self.llm)
        self.merge_advisor = MergeAdvisorAgent(self.llm)
        self.policy_engine = PolicyEngine(policy_config, llm_enabled=self.llm.enabled)

    def analyze(self, cve_id: str, target_version: str,
                enable_dryrun: bool = True,
                force_dryrun: bool = False,
                on_stage: StageCB = None,
                cve_info=None) -> AnalysisResult:
        """
        force_dryrun: 即使检测到 fix 已合入也强制执行 DryRun。
        用于 validate 场景 — worktree 在 known_fix~1 但共享 git 对象库
        导致 subject_match 可能误判 fix 已存在。
        """
        result = AnalysisResult(cve_id=cve_id, target_version=target_version)

        def _cb(key, status, detail=""):
            if on_stage:
                on_stage(key, status, detail)

        # ── Step 1: Crawler - CVE ────────────────────────────────────
        _cb("crawler_cve", "running")
        prefer_local = cve_info is not None and cve_info.fix_commit_id
        if prefer_local:
            logger.info("[Pipeline] 使用预提供的 CveInfo, 跳过 MITRE 爬取")
        else:
            cve_info = self.crawler.fetch_cve(cve_id)
        if not cve_info or not cve_info.fix_commit_id:
            _cb("crawler_cve", "fail", "无法获取CVE信息")
            result.recommendations.append(f"无法获取 {cve_id} 的修复commit信息")
            return result
        result.cve_info = cve_info
        ml = cve_info.mainline_fix_commit[:12] if cve_info.mainline_fix_commit else "N/A"
        _cb("crawler_cve", "success",
            f"mainline={ml} ({cve_info.mainline_version or 'N/A'}), "
            f"{len(cve_info.fix_commits)} fix, {len(cve_info.introduced_commits)} intro")

        # ── Step 2: Crawler - Patch ──────────────────────────────────
        _cb("crawler_patch", "running")
        fix_patch = self.crawler.fetch_patch(
            cve_info.fix_commit_id, target_version,
            local_first=prefer_local)
        if not fix_patch:
            _cb("crawler_patch", "fail", "获取补丁失败 (远程+本地均不可用)")
            result.recommendations.append("无法获取修复补丁内容 (googlesource不可达且本地仓库无此commit)")
            return result
        result.fix_patch = fix_patch
        _cb("crawler_patch", "success",
            f"{fix_patch.subject[:50]}  ({len(fix_patch.modified_files)} files)")

        # ── Step 3: Analysis - 引入commit (启用包含度匹配) ─────────────
        if cve_info.introduced_commit_id:
            _cb("analysis_intro", "running")
            intro_patch = self.crawler.fetch_patch(
                cve_info.introduced_commit_id, target_version,
                local_first=prefer_local)
            result.introduced_search = self.analysis.search(
                cve_info.introduced_commit_id,
                intro_patch.subject if intro_patch else "",
                intro_patch.diff_code if intro_patch else "",
                target_version,
                use_containment=True,
            )
            result.is_vulnerable = result.introduced_search.found
            if result.is_vulnerable:
                _cb("analysis_intro", "success",
                    f"命中 {result.introduced_search.target_commit[:12]} "
                    f"via {result.introduced_search.strategy}")
                result.recommendations.append(
                    f"目标仓库包含漏洞引入commit ({result.introduced_search.target_commit[:12]})")
            else:
                _cb("analysis_intro", "warn", "未找到, 可能不受影响")
                result.recommendations.append("未找到漏洞引入commit, 可能不受影响(建议人工确认)")
        else:
            _cb("analysis_intro", "skip", "无引入commit信息")
            result.is_vulnerable = True

        # ── Step 4: Analysis - 修复commit ────────────────────────────
        _cb("analysis_fix", "running")
        result.fix_search = self.analysis.search(
            cve_info.fix_commit_id, fix_patch.subject,
            fix_patch.diff_code, target_version,
        )
        result.is_fixed = result.fix_search.found

        if result.is_fixed:
            _cb("analysis_fix", "success",
                f"已合入 {result.fix_search.target_commit[:12]} "
                f"({result.fix_search.confidence:.0%}) via {result.fix_search.strategy}")
            result.recommendations.append(
                f"修复补丁已合入 ({result.fix_search.target_commit[:12]}), "
                f"置信度 {result.fix_search.confidence:.0%}")
            if not force_dryrun:
                _cb("analysis_bp", "skip", "已修复")
                _cb("dependency", "skip", "已修复")
                _cb("dryrun", "skip", "已修复")
                return result
            logger.info("[Pipeline] fix 已检测到, 但 force_dryrun=True, "
                        "继续执行 DryRun")
            _cb("analysis_bp", "skip", "force-dryrun")
            _cb("dependency", "skip", "force-dryrun")
        else:
            _cb("analysis_fix", "warn", "未合入")

            # 尝试stable backport
            _cb("analysis_bp", "running")
            bp = self._try_stable_backport(cve_info, target_version)
            if bp:
                result.is_fixed = True
                result.fix_search = bp
                _cb("analysis_bp", "success",
                    f"backport已合入 {bp.target_commit[:12]}")
                result.recommendations.append(
                    f"stable backport已合入 ({bp.target_commit[:12]})")
                if not force_dryrun:
                    _cb("dependency", "skip", "已修复")
                    _cb("dryrun", "skip", "已修复")
                    return result
                logger.info("[Pipeline] backport 已检测到, "
                            "但 force_dryrun=True, 继续执行 DryRun")
                _cb("dependency", "skip", "force-dryrun")
            else:
                _cb("analysis_bp", "warn", "无可用backport")

                # ── Step 5: Dependency ───────────────────────────────
                _cb("dependency", "running")
                dep = self.dependency.analyze(
                    fix_patch, cve_info, target_version,
                    fix_search=result.fix_search,
                    intro_search=result.introduced_search,
                )
                result.prerequisite_patches = dep["prerequisite_patches"]
                result.conflict_files = dep["conflict_files"]
                result.recommendations.extend(dep["recommendations"])
                result.dependency_details = dep.get("analysis_details")
                
                n_pre = len(result.prerequisite_patches)
                if n_pre > 0:
                    n_s = sum(1 for p in result.prerequisite_patches
                              if p.grade == "strong")
                    n_m = sum(1 for p in result.prerequisite_patches
                              if p.grade == "medium")
                    parts = []
                    if n_s:
                        parts.append(f"{n_s}强")
                    if n_m:
                        parts.append(f"{n_m}中")
                    parts.append(f"共{n_pre}个")
                    _cb("dependency", "success", " / ".join(parts))
                else:
                    # 无前置依赖场景：显示分析范围
                    if result.dependency_details:
                        scope = f"候选{result.dependency_details.candidate_count}个"
                        _cb("dependency", "success", f"无前置 ({scope})")
                    else:
                        _cb("dependency", "warn", "无前置依赖")

        # ── Step 6: DryRun (多级自适应) ──────────────────────────────
        if enable_dryrun or force_dryrun:
            _cb("dryrun", "running")
            dryrun_patch = fix_patch
            if not result.is_fixed:
                bp_patch = self._find_stable_patch(
                    cve_info, target_version)
                if bp_patch and bp_patch.diff_code:
                    dryrun_patch = bp_patch
                    logger.info(
                        "[Pipeline] DryRun 使用 stable backport: %s",
                        bp_patch.commit_id[:12])
            result.dry_run = self.dryrun.check_adaptive(
                dryrun_patch, target_version)
            dr = result.dry_run
            # 回填 DryRun 结果到依赖分析详情（支持"无前置"场景的证据链）
            if result.dependency_details is not None:
                result.dependency_details.dryrun_baseline_passed = dr.applies_cleanly
                result.dependency_details.dryrun_method = dr.apply_method or ""
                # 更新拟人化叙述中的 DryRun 状态
                narrative = result.dependency_details.analysis_narrative
                for i, line in enumerate(narrative):
                    if "待 DryRun Agent 验证" in line:
                        dryrun_status = (
                            f"通过 ({dr.apply_method})" if dr.applies_cleanly
                            else f"未通过 (冲突 {len(dr.conflicting_files)} 个文件)"
                        )
                        narrative[i] = f"  结果: 空集基线 DryRun {dryrun_status}"
                        break
                # 如果有前置依赖但 DryRun 通过，说明实际无硬前置
                if dr.applies_cleanly and len(result.prerequisite_patches) == 0:
                    result.dependency_details.confidence_level = "high"
                    result.dependency_details.no_prerequisite_reason = (
                        f"空集基线 DryRun 通过 (method={dr.apply_method}), "
                        "确认无硬前置依赖"
                    )
            if dr.applies_cleanly:
                method_labels = {
                    "strict": "可以干净应用",
                    "context-C1": "上下文偏移已适配 (-C1)",
                    "3way": "3-way merge成功",
                    "regenerated": "上下文重生成成功",
                    "conflict-adapted": "冲突已适配 (需人工审查)",
                    "verified-direct": "直接验证成功 (绕过git apply)",
                }
                label = method_labels.get(
                    dr.apply_method, dr.apply_method)
                if dr.apply_method == "strict":
                    _cb("dryrun", "success", label)
                else:
                    _cb("dryrun", "success", f"{label}")
                result.recommendations.append(f"Dry-run: {label}")
                if dr.adapted_patch:
                    result.recommendations.append(
                        "已生成适配后的补丁 "
                        "(原始改动不变, 仅更新 context lines)")
            else:
                nc = len(dr.conflicting_files)
                nh = len(dr.conflict_hunks)
                cf = ", ".join(dr.conflicting_files[:3])
                if nh:
                    sev_counts = {}
                    for h in dr.conflict_hunks:
                        s = h.get("severity", "L3")
                        sev_counts[s] = sev_counts.get(s, 0) + 1
                    sev_str = " / ".join(
                        f"{v}×{k}" for k, v in sorted(
                            sev_counts.items()))
                    _cb("dryrun", "fail",
                        f"{nc} 文件冲突, {nh} hunk 已分析 "
                        f"({sev_str})")
                    result.recommendations.append(
                        f"Dry-run: {nc} 个文件冲突, "
                        f"冲突分析: {sev_str}")
                else:
                    _cb("dryrun", "fail",
                        f"{nc} 个文件冲突: {cf}")
                    result.recommendations.append(
                        f"Dry-run: 补丁无法直接应用, "
                        f"{nc} 个文件冲突")
        else:
            _cb("dryrun", "skip", "已跳过")

        # ── Step 7: 策略分级与规则评估 (L0-L5 + 可插拔规则) ───────────
        try:
            result.validation_details = self.policy_engine.evaluate(
                result.fix_patch,
                result.dry_run,
                self.git_mgr,
                target_version,
                path_mapper=self.analysis.path_mapper,
                prerequisite_patches=result.prerequisite_patches,
                dependency_details=result.dependency_details,
            )
            result.level_decision = result.validation_details.level_decision
            result.function_impacts = result.validation_details.function_impacts

            ld = result.level_decision
            if ld:
                result.recommendations.append(
                    f"策略分级: {ld.level} ({ld.strategy}), 置信度 {ld.confidence}")
                if ld.level == "L0" and ld.harmless:
                    result.recommendations.append(
                        "L0 判定: 变更可视为无害且不影响语义")
                if ld.warnings:
                    result.recommendations.append(
                        f"规则告警 {len(ld.warnings)} 条: {ld.warnings[0]}")
        except Exception as e:
            logger.warning("[Pipeline] PolicyEngine 评估失败: %s", e)

        if not result.is_fixed:
            not_merged = (
                f"修复补丁 {cve_info.fix_commit_id[:12]} 未合入")
            result.recommendations.insert(0, not_merged)

        return result

    def _try_stable_backport(self, cve_info, tv: str):
        for ver in cve_info.version_commit_mapping:
            if ver.startswith("5.10"):
                bp_cid = cve_info.version_commit_mapping[ver]
                if bp_cid != cve_info.fix_commit_id:
                    bp_patch = self.crawler.fetch_patch(bp_cid, tv)
                    if bp_patch:
                        sr = self.analysis.search(bp_cid, bp_patch.subject,
                                                   bp_patch.diff_code, tv)
                        if sr.found:
                            return sr
        return None

    def _find_stable_patch(self, cve_info, tv: str):
        """
        查找最匹配目标分支的 stable backport 补丁。
        从 version_commit_mapping 中按版本距离排序, 优先选最近的 backport。
        """
        import re as _re

        # 从 tv (如 "5.10-hulk") 提取 major.minor 前缀
        m = _re.match(r"(\d+\.\d+)", tv)
        target_prefix = m.group(1) if m else ""

        # 精确匹配: 找 5.10.x 的 backport
        if target_prefix:
            for ver in sorted(cve_info.version_commit_mapping.keys(),
                              reverse=True):
                if ver.startswith(target_prefix):
                    bp_cid = cve_info.version_commit_mapping[ver]
                    if bp_cid != cve_info.fix_commit_id:
                        patch = self.crawler.fetch_patch(bp_cid, tv)
                        if patch and patch.diff_code:
                            return patch

        # 回退: 找最近的低版本 backport (如 5.10 没有则用 5.15/5.4)
        for ver in sorted(cve_info.version_commit_mapping.keys()):
            bp_cid = cve_info.version_commit_mapping[ver]
            if bp_cid != cve_info.fix_commit_id:
                patch = self.crawler.fetch_patch(bp_cid, tv)
                if patch and patch.diff_code:
                    return patch
        return None

    # ── v2.0 深度分析 ─────────────────────────────────────────────────

    def analyze_deep(self, cve_id: str, target_version: str,
                     on_stage: StageCB = None,
                     cve_info=None) -> AnalysisResultV2:
        """
        深度分析: 先执行 v1 基础分析，再依次执行社区/漏洞/检视/风险/建议。
        """
        def _cb(key, status, detail=""):
            if on_stage:
                on_stage(key, status, detail)

        base = self.analyze(cve_id, target_version,
                            enable_dryrun=True,
                            on_stage=on_stage,
                            cve_info=cve_info)

        v2 = AnalysisResultV2(base=base)
        cve = base.cve_info
        fix_patch = base.fix_patch

        # ── Community ─────────────────────────────────────────────
        _cb("community", "running")
        try:
            if cve:
                v2.community = self.community_agent.analyze(cve)
                _cb("community", "success",
                    f"{len(v2.community)} 条讨论")
            else:
                _cb("community", "skip", "无CVE信息")
        except Exception as e:
            logger.error("[Pipeline] Community 分析失败: %s", e)
            _cb("community", "fail", str(e)[:60])

        # ── Vuln Analysis ─────────────────────────────────────────
        _cb("vuln_analysis", "running")
        try:
            if cve:
                v2.vuln_analysis = self.vuln_agent.analyze(cve, fix_patch)
                va = v2.vuln_analysis
                _cb("vuln_analysis", "success",
                    f"{va.vuln_type} ({va.severity})"
                    f"{' +LLM' if va.llm_enhanced else ''}")
            else:
                _cb("vuln_analysis", "skip", "无CVE信息")
        except Exception as e:
            logger.error("[Pipeline] VulnAnalysis 失败: %s", e)
            _cb("vuln_analysis", "fail", str(e)[:60])

        # ── Patch Review ──────────────────────────────────────────
        _cb("patch_review", "running")
        try:
            if fix_patch:
                v2.patch_review = self.patch_review_agent.analyze(
                    fix_patch, target_version
                )
                pr = v2.patch_review
                _cb("patch_review", "success",
                    f"{len(pr.modified_functions)} funcs, "
                    f"{len(pr.code_review_items)} items"
                    f"{' +LLM' if pr.llm_enhanced else ''}")
            else:
                _cb("patch_review", "skip", "无补丁")
        except Exception as e:
            logger.error("[Pipeline] PatchReview 失败: %s", e)
            _cb("patch_review", "fail", str(e)[:60])

        # ── Risk/Benefit + PostPatches ────────────────────────────
        _cb("risk_benefit", "running")
        try:
            rb_score = self.risk_benefit.analyze(
                base, v2.vuln_analysis, v2.patch_review
            )
            if fix_patch and cve:
                v2.post_patches = self.risk_benefit.find_post_patches(
                    fix_patch, cve, target_version
                )
            v2.merge_recommendation = type(
                'MR', (), {'risk_benefit': rb_score}
            )()  # temporary holder
            _cb("risk_benefit", "success",
                f"overall={rb_score.overall_score:.2f}, "
                f"{len(v2.post_patches)} post-patches")
        except Exception as e:
            logger.error("[Pipeline] RiskBenefit 失败: %s", e)
            _cb("risk_benefit", "fail", str(e)[:60])

        # ── Merge Advisor ─────────────────────────────────────────
        _cb("merge_advice", "running")
        try:
            temp_rec = getattr(v2.merge_recommendation, 'risk_benefit', None)
            v2.merge_recommendation = self.merge_advisor.advise(v2)
            if temp_rec and not v2.merge_recommendation.risk_benefit:
                v2.merge_recommendation.risk_benefit = temp_rec
            rec = v2.merge_recommendation
            _cb("merge_advice", "success",
                f"{rec.action} (conf={rec.confidence:.0%})"
                f"{' +LLM' if rec.llm_enhanced else ''}")
        except Exception as e:
            logger.error("[Pipeline] MergeAdvisor 失败: %s", e)
            _cb("merge_advice", "fail", str(e)[:60])

        return v2

    def run_deep_on_base(self, base: AnalysisResult,
                         on_stage: StageCB = None) -> AnalysisResultV2:
        """在已有的 v1 AnalysisResult 上执行 v2 深度分析（不重跑基础分析）"""
        def _cb(key, status, detail=""):
            if on_stage:
                on_stage(key, status, detail)

        v2 = AnalysisResultV2(base=base)
        cve = base.cve_info
        fix_patch = base.fix_patch
        target_version = base.target_version

        _cb("community", "running")
        try:
            if cve:
                v2.community = self.community_agent.analyze(cve)
                _cb("community", "success",
                    f"{len(v2.community)} 条讨论")
            else:
                _cb("community", "skip", "无CVE信息")
        except Exception as e:
            logger.error("[Pipeline] Community 分析失败: %s", e)
            _cb("community", "fail", str(e)[:60])

        _cb("vuln_analysis", "running")
        try:
            if cve:
                v2.vuln_analysis = self.vuln_agent.analyze(cve, fix_patch)
                va = v2.vuln_analysis
                _cb("vuln_analysis", "success",
                    f"{va.vuln_type} ({va.severity})"
                    f"{' +LLM' if va.llm_enhanced else ''}")
            else:
                _cb("vuln_analysis", "skip", "无CVE信息")
        except Exception as e:
            logger.error("[Pipeline] VulnAnalysis 失败: %s", e)
            _cb("vuln_analysis", "fail", str(e)[:60])

        _cb("patch_review", "running")
        try:
            if fix_patch:
                v2.patch_review = self.patch_review_agent.analyze(
                    fix_patch, target_version
                )
                pr = v2.patch_review
                _cb("patch_review", "success",
                    f"{len(pr.modified_functions)} funcs, "
                    f"{len(pr.code_review_items)} items"
                    f"{' +LLM' if pr.llm_enhanced else ''}")
            else:
                _cb("patch_review", "skip", "无补丁")
        except Exception as e:
            logger.error("[Pipeline] PatchReview 失败: %s", e)
            _cb("patch_review", "fail", str(e)[:60])

        _cb("risk_benefit", "running")
        try:
            rb_score = self.risk_benefit.analyze(
                base, v2.vuln_analysis, v2.patch_review
            )
            if fix_patch and cve:
                v2.post_patches = self.risk_benefit.find_post_patches(
                    fix_patch, cve, target_version
                )
            v2.merge_recommendation = type(
                'MR', (), {'risk_benefit': rb_score}
            )()
            _cb("risk_benefit", "success",
                f"overall={rb_score.overall_score:.2f}, "
                f"{len(v2.post_patches)} post-patches")
        except Exception as e:
            logger.error("[Pipeline] RiskBenefit 失败: %s", e)
            _cb("risk_benefit", "fail", str(e)[:60])

        _cb("merge_advice", "running")
        try:
            temp_rec = getattr(v2.merge_recommendation, 'risk_benefit', None)
            v2.merge_recommendation = self.merge_advisor.advise(v2)
            if temp_rec and not v2.merge_recommendation.risk_benefit:
                v2.merge_recommendation.risk_benefit = temp_rec
            rec = v2.merge_recommendation
            _cb("merge_advice", "success",
                f"{rec.action} (conf={rec.confidence:.0%})"
                f"{' +LLM' if rec.llm_enhanced else ''}")
        except Exception as e:
            logger.error("[Pipeline] MergeAdvisor 失败: %s", e)
            _cb("merge_advice", "fail", str(e)[:60])

        return v2
