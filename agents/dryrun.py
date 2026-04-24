"""
Dry-Run Agent — 多级补丁试应用 + 逐 hunk 冲突分析

多级策略:
  Level 0 - strict:           git apply --check
  Level 1 - context-C1:       git apply --check -C1
  Level 2 - 3way:             git apply --check --3way
  Direct-verify:              完全绕过 git apply, Python 内存中
                              定位 → 验证 → 修改 → difflib 生成 diff
  Level 3 - regenerated:      从目标文件重建 context (核心 +/- 不变)
  Level 3.5 - zero-context:   零上下文重建, 消除 context 行匹配问题
  Level 4 - conflict-adapted: 用目标文件实际行替换 - 行, 保留 + 行
  AI suggestion:              失败后可选生成候选 diff, 必须再通过 git apply --check

核心定位:
  _locate_hunk → (change_pos, n_remove):
    change_pos = 变更点在目标文件中的行号
    n_remove   = 需删除的行数 (纯添加 hunk 为 0)

  定位策略:
    1. 精确序列匹配 (removed 或 context)
    2. 锚点行定位 (before-ctx 最后一行 / after-ctx 第一行)
    3. 函数名作用域搜索
    4. 行号提示 ± 窗口 (含跨 hunk 偏移传播)
    5. 全局逐行模糊匹配
    6. 分段 context (before / after 独立搜索)
    7. 逐行投票 (起始位置众数)

  补丁重建:
    不再走查 hunk_lines (避免额外行导致错位),
    直接从目标文件 change_pos 读取 context + 实际 - 行, 保留原始 + 行。
"""

import os
import re
import tempfile
import logging
import difflib
from collections import Counter
from typing import List, Optional, Tuple

from agents.dryrun_helpers import (
    clean_hunk_lines as _clean_hunk_lines,
    is_trivial_anchor as _is_trivial_anchor,
    split_hunk_segments as _split_hunk_segments,
    split_to_sub_hunks as _split_to_sub_hunks,
)
from core.models import PatchInfo, DryRunResult
from core.git_manager import GitRepoManager
from core.code_matcher import CodeMatcher, PatchContextExtractor
from core.search_report import HunkSearchReport, StrategyResult, DetailedSearchReport

logger = logging.getLogger(__name__)


class DryRunAgent:
    """补丁试应用Agent — 多级上下文自适应 + 路径映射 + 代码语义匹配"""

    def __init__(self, git_mgr: GitRepoManager, path_mapper=None,
                 ai_patch_generator=None, ai_config=None):
        self.git_mgr = git_mgr
        self.path_mapper = path_mapper
        self.code_matcher = CodeMatcher()
        self.ai_patch_generator = ai_patch_generator
        self.ai_config = ai_config

    # ─── 公开接口 ─────────────────────────────────────────────────

    def check(self, patch: PatchInfo, target_version: str) -> DryRunResult:
        return self._try_apply(patch, target_version, method="strict")

    def check_with_3way(self, patch: PatchInfo,
                        target_version: str) -> DryRunResult:
        result = self._try_apply(patch, target_version, method="strict")
        if result.applies_cleanly:
            return result
        r3 = self._try_apply(patch, target_version, method="3way")
        return r3 if r3.applies_cleanly else result

    def check_adaptive(self, patch: PatchInfo,
                       target_version: str) -> DryRunResult:
        base_result = self._prepare(patch, target_version)
        if base_result is not None:
            return base_result

        rp_path = self.git_mgr._get_repo_path(target_version)
        diff_text = self._extract_pure_diff(patch.diff_code)
        mapped_diff = self._rewrite_diff_paths(diff_text)

        _quick_levels = [
            ([], "strict"),
            (["--ignore-whitespace"], "ignore-ws"),
            (["-C1"], "context-C1"),
            (["-C1", "--ignore-whitespace"], "C1-ignore-ws"),
            (["--3way"], "3way"),
        ]
        apply_attempts = []
        first_err = None
        for opts, label in _quick_levels:
            r = self._apply_check(mapped_diff, rp_path, opts)
            failure_class = "" if r.applies_cleanly else self._classify_apply_failure(
                r.error_output, mapped_diff)
            detail = (r.error_output or "")[:180]
            if failure_class:
                detail = f"{failure_class}: {detail}"
            apply_attempts.append({
                "method": label,
                "success": "yes" if r.applies_cleanly else "no",
                "detail": detail,
                "failure_class": failure_class,
            })
            if first_err is None and not r.applies_cleanly:
                first_err = r
            if r.applies_cleanly:
                r.apply_method = label
                r.apply_attempts = apply_attempts
                r.stat_output = self._get_stat(
                    mapped_diff, target_version)
                if label != "strict":
                    r.error_output = f"(通过 {label} 成功适配)"
                logger.info("[DryRun] %s 成功: %s",
                            label, patch.commit_id[:12])
                self._ensure_adapted_patch(r, mapped_diff, rp_path)
                return r
        r0 = first_err or DryRunResult()
        r0.apply_attempts = apply_attempts

        # ── Direct-verify: 直接验证重建 — 完全绕过 git apply ───────
        # 在 Python 内存中定位+验证+修改+difflib 生成 diff,
        # 不依赖 git apply, 是最健壮的策略。
        direct_diff, verified = self._regenerate_verified(
            mapped_diff, rp_path)
        if verified and direct_diff:
            r5 = DryRunResult()
            r5.applies_cleanly = True
            r5.apply_method = "verified-direct"
            r5.adapted_patch = direct_diff
            r5.error_output = (
                "(直接验证成功: 变更点已在目标文件中精确定位"
                "并验证, 绕过 git apply)")
            r5.apply_attempts = apply_attempts + [{
                "method": "verified-direct",
                "success": "yes",
                "detail": "in-memory verified regeneration",
                "failure_class": "",
            }]
            r5.stat_output = self._get_stat(
                mapped_diff, target_version) or ""
            logger.info("[DryRun] 直接验证成功: %s",
                        patch.commit_id[:12])
            return r5

        # ── L3: 上下文重生成 + git apply ─────────────────────────
        adapted = self._regenerate_patch(mapped_diff, rp_path)
        if adapted:
            for l3_opts, l3_label in [
                    ([], "strict"),
                    (["--ignore-whitespace"], "ignore-ws"),
                    (["-C1"], "-C1"),
                    (["-C1", "--ignore-whitespace"], "C1-ign-ws"),
                    (["--3way"], "3way")]:
                r3 = self._apply_check(adapted, rp_path, l3_opts)
                if r3.applies_cleanly:
                    r3.apply_method = "regenerated"
                    r3.stat_output = self._get_stat(
                        adapted, target_version)
                    r3.adapted_patch = adapted
                    r3.error_output = (
                        f"(上下文重生成成功 [{l3_label}]: "
                        "context 已从目标文件更新)")
                    r3.apply_attempts = apply_attempts + [{
                        "method": f"regenerated/{l3_label}",
                        "success": "yes",
                        "detail": "context regenerated and checked",
                        "failure_class": "",
                    }]
                    logger.info("[DryRun] 上下文重生成成功 [%s]: %s",
                                l3_label, patch.commit_id[:12])
                    return r3

        # ── L3.5: 零上下文重建 — 消除 context 行匹配问题 ────────
        zero_ctx = self._regenerate_zero_context(mapped_diff, rp_path)
        if zero_ctx:
            for zc_opts, zc_label in [
                    (["--unidiff-zero"], "unidiff-zero"),
                    (["--unidiff-zero", "--ignore-whitespace"],
                     "unidiff-zero-ign-ws"),
                    (["--unidiff-zero", "-C1"], "unidiff-zero-C1")]:
                r35 = self._apply_check(zero_ctx, rp_path, zc_opts)
                if r35.applies_cleanly:
                    r35.apply_method = "regenerated"
                    r35.stat_output = self._get_stat(
                        zero_ctx, target_version)
                    r35.adapted_patch = zero_ctx
                    r35.error_output = (
                        f"(零上下文重建成功 [{zc_label}]: "
                        "context 已消除, 核心 +/- 不变)")
                    r35.apply_attempts = apply_attempts + [{
                        "method": f"regenerated-zero/{zc_label}",
                        "success": "yes",
                        "detail": "zero-context regenerated and checked",
                        "failure_class": "",
                    }]
                    logger.info("[DryRun] L3.5 零上下文成功 [%s]: %s",
                                zc_label, patch.commit_id[:12])
                    return r35

        # ── L4: 冲突分析适配 ─────────────────────────────────────
        r0.stat_output = self._get_stat(mapped_diff, target_version)
        analysis = self._analyze_conflicts(mapped_diff, rp_path)
        r0.conflict_hunks = analysis["hunks"]

        if analysis.get("search_reports"):
            r0.search_reports = analysis["search_reports"]

        if analysis.get("adapted_diff"):
            for l4_opts, l4_label in [
                    ([], "strict"),
                    (["--ignore-whitespace"], "ignore-ws"),
                    (["-C1"], "-C1"),
                    (["-C1", "--ignore-whitespace"], "C1-ign-ws"),
                    (["--3way"], "3way")]:
                r4 = self._apply_check(
                    analysis["adapted_diff"], rp_path, l4_opts)
                if r4.applies_cleanly:
                    r4.apply_method = "conflict-adapted"
                    r4.stat_output = self._get_stat(
                        analysis["adapted_diff"], target_version)
                    r4.adapted_patch = analysis["adapted_diff"]
                    r4.conflict_hunks = analysis["hunks"]
                    r4.search_reports = analysis.get(
                        "search_reports", [])
                    r4.error_output = (
                        f"(冲突适配成功 [{l4_label}]: "
                        "- 行替换为目标文件实际内容, "
                        "+ 行不变, 需人工审查)")
                    r4.apply_attempts = apply_attempts + [{
                        "method": f"conflict-adapted/{l4_label}",
                        "success": "yes",
                        "detail": "conflict-adapted patch checked",
                        "failure_class": "",
                    }]
                    logger.info("[DryRun] 冲突适配成功 [%s]: %s",
                                l4_label, patch.commit_id[:12])
                    return r4

        ai_result, ai_evidence = self._try_ai_patch_suggestion(
            mapped_diff, analysis, rp_path, target_version, apply_attempts)
        if ai_result is not None:
            return ai_result
        if ai_evidence:
            r0.ai_evidence = ai_evidence

        # ── 全部失败: 按优先级保留最佳可用补丁 ────────────────────
        # direct-verify > L3.5 零上下文 > L3 重建 > L4 适配 > 社区原始
        if direct_diff:
            r0.adapted_patch = direct_diff
            logger.info(
                "[DryRun] git apply 全失败, "
                "保留直接验证结果用于对比: %s",
                patch.commit_id[:12])
        elif zero_ctx:
            r0.adapted_patch = zero_ctx
            logger.info(
                "[DryRun] 保留 L3.5 零上下文结果: %s",
                patch.commit_id[:12])
        elif adapted:
            r0.adapted_patch = adapted
            logger.info(
                "[DryRun] 保留 L3 重建结果用于对比: %s",
                patch.commit_id[:12])
        elif analysis.get("adapted_diff"):
            r0.adapted_patch = analysis["adapted_diff"]
        else:
            r0.adapted_patch = mapped_diff
            logger.info(
                "[DryRun] L3-L5 均无产出, "
                "使用社区原始补丁作为 adapted_patch: %s",
                patch.commit_id[:12])

        logger.info("[DryRun] 所有策略均失败: %s (%d 文件, %d hunk)",
                    patch.commit_id[:12], len(r0.conflicting_files),
                    len(r0.conflict_hunks))
        return r0

    @staticmethod
    def _classify_apply_failure(error_output: str, diff_text: str = "") -> str:
        err = (error_output or "").lower()
        if not err:
            return "unknown_apply_failure"
        if (
            "no such file or directory" in err
            or "can't find file to patch" in err
            or "does not exist in index" in err
            or "outside repository" in err
        ):
            return "path_mismatch"
        if "patch is empty" in err or "reversed (or previously applied)" in err:
            return "already_applied_or_fixed"
        if "does not apply" in err or "patch failed" in err or "hunk #" in err:
            if re.search(r"^-", diff_text or "", re.MULTILINE) and (
                "does not match index" in err or "does not apply" in err
            ):
                return "delete_line_missing_or_context_drift"
            return "context_drift"
        if "conflict" in err or "with conflicts" in err:
            return "semantic_conflict_suspected"
        if "corrupt patch" in err or "unrecognized input" in err:
            return "patch_format_error"
        return "unknown_apply_failure"

    def _try_ai_patch_suggestion(self, mapped_diff: str, analysis: dict,
                                 repo_path: str, target_version: str,
                                 apply_attempts: List[dict]):
        if not bool(getattr(self.ai_config, "enable_conflict_patch_suggestion", False)):
            return None, {}
        if not self.ai_patch_generator:
            return None, {
                "enabled": True,
                "mode": getattr(self.ai_config, "mode", ""),
                "tasks": [{
                    "task": "ai_patch_suggestion",
                    "status": "disabled",
                    "summary": "AI patch generator 未配置",
                    "used_for_final_decision": False,
                }],
            }

        target = self._first_target_file_context(mapped_diff, repo_path)
        if not target:
            return None, {
                "enabled": True,
                "mode": getattr(self.ai_config, "mode", ""),
                "tasks": [{
                    "task": "ai_patch_suggestion",
                    "status": "no_target_context",
                    "summary": "无法读取目标文件上下文，跳过 AI patch suggestion",
                    "used_for_final_decision": False,
                }],
            }

        file_path, content = target
        report = self.ai_patch_generator.generate_patch_with_report(
            mapped_diff,
            content,
            analysis or {},
            file_path,
        )
        task = {
            "task": "ai_patch_suggestion",
            "status": report.get("status", "unknown"),
            "summary": report.get("summary", ""),
            "semantic_delta": report.get("semantic_delta", {}),
            "target_file": file_path,
            "conflict_context_pack": (analysis or {}).get("conflict_context_pack", [])[:6],
            "used_for_final_decision": False,
            "decision_guard": "AI 候选补丁必须通过 git apply --check；通过后仍按高风险候选处理",
        }
        llm_client = getattr(self.ai_patch_generator, "llm_client", None)
        ai_evidence = {
            "enabled": True,
            "mode": getattr(self.ai_config, "mode", ""),
            "provider": getattr(llm_client, "provider", "") if llm_client else "",
            "model": getattr(llm_client, "model", "") if llm_client else "",
            "tasks": [task],
            "summary": [task.get("summary", "")] if task.get("summary") else [],
        }
        patch_text = report.get("patch") or ""
        if not patch_text:
            return None, ai_evidence

        for opts, label in [
                ([], "strict"),
                (["--ignore-whitespace"], "ignore-ws"),
                (["-C1"], "context-C1")]:
            checked = self._apply_check(patch_text, repo_path, opts)
            if checked.applies_cleanly:
                checked.apply_method = "ai-generated"
                checked.adapted_patch = patch_text
                checked.conflict_hunks = analysis.get("hunks", []) if analysis else []
                checked.search_reports = analysis.get("search_reports", []) if analysis else []
                checked.stat_output = self._get_stat(patch_text, target_version)
                checked.error_output = (
                    f"(AI patch suggestion 通过 {label} apply check；"
                    "仅作为高风险候选，需人工审查)"
                )
                checked.apply_attempts = apply_attempts + [{
                    "method": f"ai-generated/{label}",
                    "success": "yes",
                    "detail": "AI patch suggestion passed git apply --check",
                }]
                task["status"] = "accepted_by_apply_check"
                task["apply_method"] = label
                task["used_for_final_decision"] = True
                task["summary"] = (
                    f"AI 候选补丁通过 {label} apply check；"
                    "仅代表可应用，仍需人工逐 hunk 审查")
                ai_evidence["summary"] = [task["summary"]]
                checked.ai_evidence = ai_evidence
                return checked, ai_evidence

        task["status"] = "rejected_by_apply_check"
        task["summary"] = "AI 生成了候选补丁，但未通过 git apply --check"
        ai_evidence["summary"] = [task["summary"]]
        return None, ai_evidence

    def _first_target_file_context(self, diff_text: str, repo_path: str):
        parsed = self._parse_hunks_for_regen(diff_text)
        if not parsed:
            return None
        limit = int(getattr(self.ai_config, "max_diff_chars", 12000) or 12000)
        for file_path, _header_lines, _hunks in parsed:
            resolved = self._resolve_file_path(file_path, repo_path)
            if not resolved:
                continue
            try:
                with open(resolved, "r", encoding="utf-8", errors="replace") as f:
                    return file_path, f.read(max(2000, min(limit, 20000)))
            except Exception:
                continue
        return None

    def _ensure_adapted_patch(self, result: DryRunResult,
                              diff_text: str, repo_path: str):
        """L0/L1/L2 成功后，仍生成 adapted_patch (行号对齐目标文件)。
        优先用直接验证, 其次 L3 重建, 最后回退社区原始补丁。"""
        try:
            direct, ok = self._regenerate_verified(
                diff_text, repo_path)
            if ok and direct:
                result.adapted_patch = direct
                return
        except Exception as e:
            logger.debug("[DryRun] _ensure direct-verify 异常: %s", e)
        try:
            adapted = self._regenerate_patch(diff_text, repo_path)
            if adapted:
                result.adapted_patch = adapted
                return
        except Exception as e:
            logger.debug("[DryRun] _ensure L3 异常: %s", e)
        result.adapted_patch = diff_text
        logger.info("[DryRun] L5/L3 重建未成功, "
                    "回退使用社区原始补丁作为 adapted_patch")

    # ─── 路径映射 ─────────────────────────────────────────────────

    def _rewrite_diff_paths(self, diff_text: str) -> str:
        if not self.path_mapper or not self.path_mapper.has_rules:
            return diff_text
        lines = diff_text.split("\n")
        result = []
        for line in lines:
            if line.startswith("diff --git"):
                for up, lo in self.path_mapper._rules:
                    line = line.replace(f"a/{up}", f"a/{lo}")
                    line = line.replace(f"b/{up}", f"b/{lo}")
                result.append(line)
            elif line.startswith("--- a/") or line.startswith("+++ b/"):
                prefix = line[:6]
                path = line[6:]
                for up, lo in self.path_mapper._rules:
                    if path.startswith(up):
                        path = lo + path[len(up):]
                        break
                result.append(prefix + path)
            else:
                result.append(line)
        return "\n".join(result)

    def _resolve_file_path(self, file_path: str,
                           repo_path: str) -> Optional[str]:
        target = os.path.join(repo_path, file_path)
        if os.path.isfile(target):
            return target
        if self.path_mapper:
            for variant in self.path_mapper.translate(file_path):
                if variant != file_path:
                    t = os.path.join(repo_path, variant)
                    if os.path.isfile(t):
                        return t
        return None

    # ─── Hunk 定位 (核心) ────────────────────────────────────────

    def _locate_hunk(self, hunk_lines: List[str],
                     file_lines: List[str],
                     hint_line: Optional[int],
                     func_name: Optional[str]
                     ) -> Tuple[Optional[int], int]:
        """
        定位 hunk 在目标文件中的变更点。
        返回 (change_pos, n_remove):
          - 有 - 行: change_pos = 第一个 removed 行的位置, n_remove = 删除行数
          - 纯添加:  change_pos = 插入点, n_remove = 0
        """
        ctx_before, removed, added, ctx_after = \
            _split_hunk_segments(hunk_lines)
        ctx_all = ctx_before + ctx_after

        if removed:
            return self._locate_removal_hunk(
                removed, ctx_before, ctx_after, file_lines,
                hint_line, func_name)

        return self._locate_addition_hunk(
            ctx_before, ctx_after, added, file_lines,
            hint_line, func_name)

    def _locate_removal_hunk(self, removed, ctx_before, ctx_after,
                             file_lines, hint_line, func_name):
        n = len(removed)
        ctx_all = ctx_before + ctx_after

        # A) 直接搜索 removed 行
        pos = self._locate_in_file(
            removed, ctx_all, file_lines, hint_line, func_name)
        if pos is not None:
            return pos, n

        # B) 用 before-context 最后一行做锚点, 候选位置验证 removed 行
        if ctx_before:
            adj = ((hint_line + len(ctx_before) - 1)
                   if hint_line else hint_line)
            candidates = self._find_anchor_line_candidates(
                ctx_before[-1], file_lines, adj,
                max_candidates=5)
            for anchor in candidates:
                pos = anchor + 1
                if pos + n <= len(file_lines):
                    actual = [l.strip() for l in
                              file_lines[pos:pos + n]]
                    expect = [l.strip() for l in removed]
                    if self._line_fuzzy_score(expect, actual) >= 0.50:
                        return pos, n
            if candidates:
                return candidates[0] + 1, n

        # C) 用 after-context 第一行做锚点, 候选位置验证 removed 行
        if ctx_after:
            adj = ((hint_line + len(ctx_before) + n)
                   if hint_line else hint_line)
            candidates = self._find_anchor_line_candidates(
                ctx_after[0], file_lines, adj,
                max_candidates=5)
            for anchor in candidates:
                pos = max(0, anchor - n)
                if pos + n <= len(file_lines):
                    actual = [l.strip() for l in
                              file_lines[pos:pos + n]]
                    expect = [l.strip() for l in removed]
                    if self._line_fuzzy_score(expect, actual) >= 0.50:
                        return pos, n
            if candidates:
                return max(0, candidates[0] - n), n

        # D) Level 8: 代码语义匹配 (context 被打断时的最后手段)
        if removed:
            pos = self.code_matcher.find_removed_lines(
                removed, file_lines, hint_line)
            if pos is not None:
                return pos, n

        # E) 单行最佳匹配: 选最具特征的 removed 行做全文搜索,
        #    用 ctx_before/ctx_after 交叉验证
        if removed:
            best_line = max(removed, key=lambda l: len(l.strip()))
            if len(best_line.strip()) >= 8:
                offset_in_rm = removed.index(best_line)
                candidates = self._find_anchor_line_candidates(
                    best_line, file_lines, hint_line,
                    window=600, max_candidates=8)
                for cand in candidates:
                    pos = cand - offset_in_rm
                    if pos < 0 or pos + n > len(file_lines):
                        continue
                    actual = [l.strip() for l in
                              file_lines[pos:pos + n]]
                    expect = [l.strip() for l in removed]
                    sim = self._line_fuzzy_score(expect, actual)
                    if sim >= 0.60:
                        return pos, n

        return None, n

    def _check_insertion_context(self, ctx_after: List[str],
                                file_lines: List[str],
                                insertion_pos: int) -> bool:
        """
        交叉验证：检查 insertion_pos 之后的文件行是否与 ctx_after 匹配。
        至少需要一行非空 ctx_after 匹配才通过。
        当 ctx_after 为空时默认通过。
        """
        if not ctx_after:
            return True
        checked, matched = 0, 0
        for i, line in enumerate(ctx_after[:4]):
            s = line.strip()
            if not s:
                continue
            checked += 1
            fi = insertion_pos + i
            if 0 <= fi < len(file_lines):
                if file_lines[fi].strip() == s:
                    matched += 1
                elif difflib.SequenceMatcher(
                    None, s, file_lines[fi].strip()
                ).ratio() >= 0.80:
                    matched += 0.5
        if checked == 0:
            return True
        return matched / checked >= 0.4

    def _locate_addition_hunk(self, ctx_before, ctx_after, added,
                              file_lines, hint_line, func_name):
        """
        纯添加 hunk: 找插入点。
        策略 A/B 向 ctx_before/ctx_after 深处搜索非 trivial 锚点，
        避免用 return 0; / } 等通用行做锚点导致定位到错误函数。
        每个策略找到候选后都会用 ctx_after 做交叉验证，
        防止同名行在文件中多次出现时选错位置。
        """
        # A) before-context: 从末尾向前迭代，跳过 trivial 行，
        #    每个非 trivial 锚点尝试所有候选位置
        if ctx_before:
            for back in range(len(ctx_before)):
                idx = len(ctx_before) - 1 - back
                if _is_trivial_anchor(ctx_before[idx]):
                    continue
                adj = ((hint_line + idx)
                       if hint_line else hint_line)
                candidates = self._find_anchor_line_candidates(
                    ctx_before[idx], file_lines, adj,
                    max_candidates=5)
                for anchor in candidates:
                    ins = anchor + 1 + back
                    if self._check_insertion_context(
                            ctx_after, file_lines, ins):
                        return ins, 0
                break

        # B) after-context: 从首行向后迭代，跳过 trivial 行，
        #    每个非 trivial 锚点尝试所有候选位置
        if ctx_after:
            for fwd in range(len(ctx_after)):
                if _is_trivial_anchor(ctx_after[fwd]):
                    continue
                adj = ((hint_line + len(ctx_before) + fwd)
                       if hint_line else hint_line)
                candidates = self._find_anchor_line_candidates(
                    ctx_after[fwd], file_lines, adj,
                    max_candidates=5)
                for anchor in candidates:
                    ins = anchor - fwd
                    if self._check_insertion_context(
                            ctx_after, file_lines, ins):
                        return ins, 0
                break

        # C) 整段 before-context 精确/模糊搜索 (利用 func_name 约束)
        if ctx_before and len(ctx_before) >= 2:
            pos = self._locate_in_file(
                ctx_before, ctx_after, file_lines, hint_line, func_name)
            if pos is not None:
                ins = pos + len(ctx_before)
                if self._check_insertion_context(
                        ctx_after, file_lines, ins):
                    return ins, 0

        # D) 整段 after-context 精确/模糊搜索 (利用 func_name 约束)
        if ctx_after and len(ctx_after) >= 2:
            adj = ((hint_line + len(ctx_before))
                   if hint_line else hint_line)
            pos = self._locate_in_file(
                ctx_after, ctx_before, file_lines, adj, func_name)
            if pos is not None:
                if self._check_insertion_context(
                        ctx_after, file_lines, pos):
                    return pos, 0

        # ── 交叉验证全部失败，使用宽松回退策略 ─────────────────
        # A-fallback) 锚点搜索不做交叉验证，但尝试所有候选位置中
        #   context 最佳的一个
        if ctx_before:
            for back in range(len(ctx_before)):
                idx = len(ctx_before) - 1 - back
                if _is_trivial_anchor(ctx_before[idx]):
                    continue
                adj = ((hint_line + idx)
                       if hint_line else hint_line)
                candidates = self._find_anchor_line_candidates(
                    ctx_before[idx], file_lines, adj,
                    max_candidates=5)
                if candidates:
                    return candidates[0] + 1 + back, 0
                break

        # E) 全 hunk 非 + 行投票
        non_plus = [
            l[1:] if (l.startswith("-") or l.startswith(" ")) else l
            for l in _clean_hunk_lines(ctx_before + ctx_after)
            if l.strip()
        ]
        if not non_plus:
            non_plus = [l for l in ctx_before + ctx_after if l.strip()]
        if non_plus and len(non_plus) >= 2:
            pos = self._find_by_line_voting(non_plus, file_lines)
            if pos is not None:
                return pos + len(ctx_before), 0

        # F) Level 8: 代码语义匹配 (context 被打断时的最后手段)
        if ctx_before:
            pos = self.code_matcher.find_insertion_point(
                ctx_before, ctx_after, file_lines, hint_line)
            if pos is not None:
                return pos, 0

        return None, 0

    def _find_anchor_line(self, line: str, file_lines: List[str],
                          hint_line: Optional[int],
                          window: int = 300) -> Optional[int]:
        """
        在 hint 附近精确或高阈值模糊查找单行。
        优先返回离 hint 最近的匹配（而非第一个匹配）。
        """
        candidates = self._find_anchor_line_candidates(
            line, file_lines, hint_line, window, max_candidates=1)
        return candidates[0] if candidates else None

    def _find_anchor_line_candidates(
            self, line: str, file_lines: List[str],
            hint_line: Optional[int],
            window: int = 300,
            max_candidates: int = 5) -> List[int]:
        """
        返回最多 max_candidates 个匹配位置，按距离 hint 排序。
        支持精确匹配和高阈值模糊匹配。
        """
        ns = line.strip()
        if not ns or len(ns) < 4:
            return []
        hs = [l.strip() for l in file_lines]

        if hint_line and hint_line > 0:
            center = hint_line - 1
            lo = max(0, center - window)
            hi = min(len(hs), center + window)
            if hi <= lo:
                lo, hi = 0, len(hs)
        else:
            lo, hi = 0, len(hs)
            center = len(hs) // 2

        exact = []
        for i in range(lo, hi):
            if hs[i] == ns:
                exact.append((abs(i - center), i))
        if exact:
            exact.sort()
            return [pos for _, pos in exact[:max_candidates]]

        fuzzy = []
        for i in range(lo, hi):
            r = difflib.SequenceMatcher(None, ns, hs[i]).ratio()
            if r >= 0.85:
                fuzzy.append((-r, abs(i - center), i))
        if fuzzy:
            fuzzy.sort()
            return [pos for _, _, pos in fuzzy[:max_candidates]]
        return []

    # ─── 序列定位算法 ────────────────────────────────────────────

    def _locate_in_file(self, expected: List[str],
                        context_lines: List[str],
                        file_lines: List[str],
                        hint_line: Optional[int] = None,
                        func_name: Optional[str] = None) -> Optional[int]:
        search_seq = expected if expected else context_lines
        if not search_seq:
            return None
        seq = [l for l in search_seq if not l.startswith("\\")]
        if not seq:
            return None

        pos = self._find_exact_sequence(seq, file_lines)
        if pos is not None:
            return pos

        pos = self._find_normalized_sequence(seq, file_lines)
        if pos is not None:
            return pos

        if func_name:
            pos = self._find_in_function(seq, file_lines, func_name)
            if pos is not None:
                return pos

        if hint_line is not None and hint_line > 0:
            pos = self._find_near_hint(seq, file_lines,
                                       hint_line, window=300)
            if pos is not None:
                return pos

        pos = self._find_fuzzy_sequence(seq, file_lines)
        if pos is not None:
            return pos

        if expected and context_lines:
            ctx = [l for l in context_lines if not l.startswith("\\")]
            if ctx:
                for m in (self._find_exact_sequence,
                          self._find_fuzzy_sequence):
                    pos = m(ctx, file_lines)
                    if pos is not None:
                        return pos

        # 逐行投票: 过滤空行
        vote_seq = [l for l in seq if l.strip()]
        if vote_seq and len(vote_seq) >= 2:
            pos = self._find_by_line_voting(vote_seq, file_lines)
            if pos is not None:
                return pos

        best = max((l for l in seq if l.strip()),
                   key=lambda l: len(l.strip()), default=None)
        if best and len(best.strip()) >= 8:
            return self._find_best_single_line(best, file_lines)

        return None

    # ─── 定位策略实现 ─────────────────────────────────────────────

    def _find_exact_sequence(self, needle: List[str],
                             haystack: List[str]) -> Optional[int]:
        if not needle:
            return None
        n = len(needle)
        ns = [l.strip() for l in needle]
        hs = [l.strip() for l in haystack]
        for i in range(len(hs) - n + 1):
            if hs[i:i + n] == ns:
                return i
        return None

    @staticmethod
    def _normalize_ws(s: str) -> str:
        return re.sub(r'\s+', ' ', s.strip())

    def _find_normalized_sequence(self, needle: List[str],
                                  haystack: List[str]) -> Optional[int]:
        """tab/多空格归一化后匹配，处理缩进风格差异"""
        if not needle:
            return None
        n = len(needle)
        ns = [self._normalize_ws(l) for l in needle]
        hs = [self._normalize_ws(l) for l in haystack]
        for i in range(len(hs) - n + 1):
            if hs[i:i + n] == ns:
                return i
        return None

    def _find_in_function(self, needle: List[str],
                          haystack: List[str],
                          func_name: str) -> Optional[int]:
        fn_tokens = func_name.strip().split("(")[0].strip().split()
        fn_key = fn_tokens[-1] if fn_tokens else ""
        if not fn_key or len(fn_key) < 2:
            return None

        func_start = None
        for i, line in enumerate(haystack):
            if fn_key in line and ("(" in line or "{" in line):
                func_start = i
                break
        if func_start is None:
            return None

        brace, found_open = 0, False
        func_end = min(len(haystack), func_start + 500)
        for i in range(func_start, func_end):
            brace += haystack[i].count("{") - haystack[i].count("}")
            if "{" in haystack[i]:
                found_open = True
            if found_open and brace <= 0:
                func_end = i + 1
                break

        scope = haystack[func_start:func_end]
        pos = self._find_exact_sequence(needle, scope)
        if pos is not None:
            return func_start + pos
        pos = self._find_normalized_sequence(needle, scope)
        if pos is not None:
            return func_start + pos
        pos = self._find_fuzzy_sequence(needle, scope)
        if pos is not None:
            return func_start + pos
        return None

    def _find_near_hint(self, needle: List[str],
                        haystack: List[str],
                        hint_line: int,
                        window: int = 300) -> Optional[int]:
        if not needle:
            return None
        n = len(needle)
        ns = [l.strip() for l in needle]
        hs = [l.strip() for l in haystack]

        lo = max(0, hint_line - 1 - window)
        hi = min(len(hs) - n + 1, hint_line - 1 + window)
        if lo >= hi:
            return None

        for i in range(lo, hi):
            if hs[i:i + n] == ns:
                return i

        ns_norm = [self._normalize_ws(l) for l in needle]
        hs_norm = [self._normalize_ws(l) for l in haystack]
        for i in range(lo, min(len(hs_norm) - n + 1, hi)):
            if hs_norm[i:i + n] == ns_norm:
                return i

        threshold = 0.45 if n <= 3 else 0.50
        best_pos, best_score = None, 0.0
        for i in range(lo, hi):
            s = self._line_fuzzy_score(ns, hs[i:i + n])
            if s > best_score and s >= threshold:
                best_score = s
                best_pos = i
        return best_pos

    def _find_fuzzy_sequence(self, needle: List[str],
                             haystack: List[str]) -> Optional[int]:
        if not needle:
            return None
        n = len(needle)
        if n > len(haystack):
            return None
        ns = [l.strip() for l in needle]
        hs = [l.strip() for l in haystack]
        threshold = 0.45 if n <= 3 else 0.50

        best_pos, best_score = None, 0.0
        for i in range(len(hs) - n + 1):
            s = self._line_fuzzy_score(ns, hs[i:i + n])
            if s > best_score and s >= threshold:
                best_score = s
                best_pos = i
        return best_pos

    def _find_by_line_voting(self, needle: List[str],
                             haystack: List[str]) -> Optional[int]:
        """
        每行独立估算序列起始位置 estimate = file_pos - needle_idx, 取众数。
        """
        if not needle or len(needle) < 2:
            return None
        hs = [l.strip() for l in haystack]
        estimates = []

        for idx, nl in enumerate(needle):
            ns = nl.strip()
            if len(ns) < 5:
                continue
            found = False
            for i, h in enumerate(hs):
                if ns == h:
                    estimates.append(i - idx)
                    found = True
                    break
            if not found:
                best_i, best_r = None, 0.0
                for i, h in enumerate(hs):
                    r = difflib.SequenceMatcher(None, ns, h).ratio()
                    if r > best_r and r >= 0.70:
                        best_r = r
                        best_i = i
                if best_i is not None:
                    estimates.append(best_i - idx)

        if len(estimates) < max(1, len(needle) * 0.3):
            return None

        vote = Counter(estimates)
        best_est, best_cnt = vote.most_common(1)[0]
        if best_cnt < max(1, len(estimates) * 0.3):
            grouped = {}
            for e in estimates:
                bucket = round(e / 2) * 2
                grouped[bucket] = grouped.get(bucket, 0) + 1
            best_est = max(grouped, key=grouped.get)

        return max(0, best_est)

    @staticmethod
    def _line_fuzzy_score(a_lines: List[str],
                          b_lines: List[str]) -> float:
        if not a_lines or len(a_lines) != len(b_lines):
            return 0.0
        total_w, total_s = 0.0, 0.0
        for a, b in zip(a_lines, b_lines):
            w = max(1.0, len(a) / 10.0)
            s = 1.0 if a == b else difflib.SequenceMatcher(
                None, a, b).ratio()
            total_w += w
            total_s += w * s
        return total_s / total_w if total_w > 0 else 0.0

    def _find_best_single_line(self, needle: str,
                               haystack: List[str]) -> Optional[int]:
        ns = needle.strip()
        if not ns or len(ns) < 4:
            return None
        best_pos, best_r = None, 0.0
        for i, line in enumerate(haystack):
            r = difflib.SequenceMatcher(
                None, ns, line.strip()).ratio()
            if r > best_r and r >= 0.60:
                best_r = r
                best_pos = i
        return best_pos

    @staticmethod
    def _compare_lines(expected, actual, pos):
        if not expected:
            return 0.0, []
        sim = difflib.SequenceMatcher(
            None, [l.strip() for l in expected],
            [l.strip() for l in actual]).ratio()
        changed = []
        for i, (e, a) in enumerate(zip(expected, actual)):
            if e.strip() != a.strip():
                changed.append({
                    "line": pos + i + 1,
                    "expected": e.strip(),
                    "actual": a.strip(),
                })
        return sim, changed

    @staticmethod
    def _parse_hunk_line_hint(hunk_header: str) -> Optional[int]:
        m = re.match(r"@@\s+-(\d+)", hunk_header)
        return int(m.group(1)) if m else None

    @staticmethod
    def _extract_func_from_hunk(hunk_header: str) -> Optional[str]:
        m = re.match(r"@@[^@]+@@\s*(.+)", hunk_header)
        if m:
            name = m.group(1).strip()
            if name and len(name) > 2:
                return name
        return None

    # ─── 符号映射与缩进适配 ──────────────────────────────────────

    @staticmethod
    def _extract_symbol_mapping(expected_lines: List[str],
                                actual_lines: List[str]) -> dict:
        """
        逐 token 对比 expected（社区补丁 - 行）与 actual（目标文件实际行），
        提取一致的标识符重命名映射。
        仅当映射完全一致（同一旧 token 始终映射到同一新 token）时返回。
        """
        mapping = {}
        for exp, act in zip(expected_lines, actual_lines):
            exp_tokens = re.findall(r'[A-Za-z_]\w{2,}', exp.strip())
            act_tokens = re.findall(r'[A-Za-z_]\w{2,}', act.strip())
            if len(exp_tokens) != len(act_tokens):
                continue
            for et, at in zip(exp_tokens, act_tokens):
                if et == at:
                    continue
                if et in mapping:
                    if mapping[et] != at:
                        return {}
                else:
                    mapping[et] = at
        return mapping

    @staticmethod
    def _apply_symbol_mapping(lines: List[str],
                              mapping: dict) -> List[str]:
        if not mapping:
            return lines
        result = []
        for line in lines:
            for old, new in sorted(mapping.items(),
                                   key=lambda x: -len(x[0])):
                line = re.sub(r'\b' + re.escape(old) + r'\b', new, line)
            result.append(line)
        return result

    @staticmethod
    def _adapt_indentation(added_lines: List[str],
                           expected_removed: List[str],
                           actual_removed: List[str]) -> List[str]:
        """
        将 + 行的缩进风格从社区补丁适配到目标文件:
        检测 expected removed 与 actual removed 之间的缩进映射（如 space→tab），
        对 added lines 应用相同的转换。
        """
        if (not added_lines or not expected_removed
                or not actual_removed):
            return added_lines

        space_to_tab = False
        tab_to_space = False
        tab_width = 8

        for exp, act in zip(expected_removed, actual_removed):
            ews = exp[:len(exp) - len(exp.lstrip())]
            aws = act[:len(act) - len(act.lstrip())]
            if not ews and not aws:
                continue
            if '\t' not in ews and '\t' in aws:
                space_to_tab = True
                nsp = len(ews)
                ntab = aws.count('\t')
                if ntab > 0 and nsp > 0:
                    tab_width = max(1, round(nsp / ntab))
            elif '\t' in ews and '\t' not in aws:
                tab_to_space = True
                ntab = ews.count('\t')
                nsp = len(aws)
                if ntab > 0 and nsp > 0:
                    tab_width = max(1, round(nsp / ntab))

        if not space_to_tab and not tab_to_space:
            return added_lines

        result = []
        for line in added_lines:
            ws_end = len(line) - len(line.lstrip())
            ws = line[:ws_end]
            body = line[ws_end:]
            if space_to_tab and '\t' not in ws and ' ' in ws:
                n = len(ws)
                ws = '\t' * (n // tab_width) + ' ' * (n % tab_width)
            elif tab_to_space and '\t' in ws:
                ws = ws.replace('\t', ' ' * tab_width)
            result.append(ws + body)
        return result

    # ─── 直接验证重建 (L5) ─ 完全绕过 git apply ──────────────────

    def _regenerate_verified(self, diff_text: str,
                             repo_path: str
                             ) -> Tuple[Optional[str], bool]:
        """
        L5: 直接验证补丁重建 — 完全绕过 git apply。
        对每个文件：读取目标文件 → 定位 hunk → 验证匹配 → 内存中修改
        → difflib.unified_diff 生成 diff。
        返回 (adapted_diff_text, verified: bool)。
        """
        if not diff_text:
            return None, False
        parsed = self._parse_hunks_for_regen(diff_text)
        if not parsed:
            return None, False

        all_diff_parts = []
        total_hunks = 0
        verified_hunks = 0
        diag = []

        for file_path, header_lines, hunks in parsed:
            resolved = self._resolve_file_path(file_path, repo_path)
            if resolved is None:
                logger.info("[L5] 文件不存在: %s (repo=%s)",
                            file_path, repo_path)
                diag.append(f"  {file_path}: 文件不存在")
                for _, hl in hunks:
                    total_hunks += 1
                continue

            try:
                with open(resolved, "r", encoding="utf-8",
                          errors="replace") as f:
                    target_lines = [l.rstrip("\n")
                                    for l in f.readlines()]
            except Exception as e:
                logger.info("[L5] 读取失败 %s: %s", resolved, e)
                diag.append(f"  {file_path}: 读取失败 {e}")
                for _, hl in hunks:
                    total_hunks += 1
                continue

            logger.debug("[L5] 文件已加载: %s (%d行)", file_path,
                         len(target_lines))
            changes = []
            file_offset = 0

            for orig_header, orig_lines in hunks:
                sub_hunks = _split_to_sub_hunks(
                    orig_header, orig_lines)

                for hh, hl in sub_hunks:
                    total_hunks += 1
                    hint = self._parse_hunk_line_hint(hh)
                    fn = self._extract_func_from_hunk(hh)
                    adj = (hint + file_offset) if hint else hint

                    pos, n_rm = self._locate_hunk(
                        hl, target_lines, adj, fn)

                    if pos is not None and hint:
                        ctx_len = len(
                            _split_hunk_segments(hl)[0])
                        file_offset = (
                            (pos - ctx_len) - (hint - 1))

                    if pos is None:
                        segs = _split_hunk_segments(hl)
                        snippet = (segs[1] or segs[2] or ["?"])
                        logger.info(
                            "[L5] 定位失败: %s hint=%s "
                            "first_line='%s'",
                            file_path, hint,
                            snippet[0][:70].strip())
                        diag.append(
                            f"  {file_path}:L{hint or '?'} "
                            f"定位失败 '{snippet[0][:50].strip()}'")
                        continue

                    _, exp_rm, added, _ = \
                        _split_hunk_segments(hl)
                    actual_rm = target_lines[pos:pos + n_rm]

                    if n_rm > 0:
                        expect_s = [l.strip() for l in exp_rm]
                        actual_s = [l.strip() for l in actual_rm]
                        sim = self._line_fuzzy_score(
                            expect_s, actual_s)
                        if sim < 0.30:
                            logger.info(
                                "[L5] 验证不通过 sim=%.2f: "
                                "%s pos=%d",
                                sim, file_path, pos + 1)
                            diag.append(
                                f"  {file_path}:L{pos+1} "
                                f"sim={sim:.2f} 不通过")
                            continue

                    sym_map = self._extract_symbol_mapping(
                        exp_rm, actual_rm)
                    if sym_map:
                        added = self._apply_symbol_mapping(
                            added, sym_map)
                        logger.debug("[L5] 符号映射: %s",
                                     sym_map)
                    added = self._adapt_indentation(
                        added, exp_rm, actual_rm)

                    verified_hunks += 1
                    changes.append((pos, n_rm, added))
                    logger.debug(
                        "[L5] hunk 定位成功: %s pos=%d "
                        "rm=%d add=%d",
                        file_path, pos + 1, n_rm, len(added))

            if not changes:
                continue

            modified = list(target_lines)
            for pos, n_rm, added in sorted(
                    changes, key=lambda x: -x[0]):
                modified[pos:pos + n_rm] = added

            orig_nl = [l + "\n" for l in target_lines]
            mod_nl = [l + "\n" for l in modified]
            diff_lines = list(difflib.unified_diff(
                orig_nl, mod_nl,
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
            ))

            if diff_lines:
                all_diff_parts.append(
                    f"diff --git a/{file_path} b/{file_path}")
                all_diff_parts.extend(
                    line.rstrip("\n") for line in diff_lines)

        logger.info("[L5] 直接验证: %d/%d hunk 成功",
                    verified_hunks, total_hunks)
        if diag:
            for d in diag[:10]:
                logger.info("[L5-DIAG] %s", d)

        if verified_hunks == 0:
            return None, False
        return "\n".join(all_diff_parts) + "\n", True

    # ─── 上下文重生成 (L3) ────────────────────────────────────────

    def _regenerate_patch(self, diff_text: str,
                          repo_path: str) -> Optional[str]:
        if not diff_text:
            return None
        parsed = self._parse_hunks_for_regen(diff_text)
        if not parsed:
            logger.debug("[L3] _parse_hunks_for_regen 返回空")
            return None

        new_parts = []
        total_hunks = 0
        adapted_hunks = 0
        failed_detail = []

        for file_path, header_lines, hunks in parsed:
            resolved = self._resolve_file_path(file_path, repo_path)
            if resolved is None:
                logger.debug("[L3] 文件路径无法解析: %s", file_path)
                new_parts.append("\n".join(header_lines))
                for hh, hl in hunks:
                    total_hunks += 1
                    new_parts.append(hh)
                    new_parts.append("\n".join(hl))
                    failed_detail.append(
                        f"{file_path}:{hh[:40]}... (文件不存在)")
                continue

            try:
                with open(resolved, "r", encoding="utf-8",
                          errors="replace") as f:
                    target_lines = [l.rstrip("\n") for l in f.readlines()]
            except Exception as e:
                logger.debug("[L3] 读取文件失败 %s: %s", resolved, e)
                new_parts.append("\n".join(header_lines))
                for hh, hl in hunks:
                    total_hunks += 1
                    new_parts.append(hh)
                    new_parts.append("\n".join(hl))
                    failed_detail.append(
                        f"{file_path}:{hh[:40]}... (读取失败)")
                continue

            new_parts.append("\n".join(header_lines))
            file_offset = 0
            cum_delta = 0

            for orig_header, orig_lines in hunks:
                sub_hunks = _split_to_sub_hunks(orig_header, orig_lines)

                for hunk_header, hunk_lines in sub_hunks:
                    total_hunks += 1
                    hint_line = self._parse_hunk_line_hint(hunk_header)
                    func_name = self._extract_func_from_hunk(hunk_header)
                    adj_hint = ((hint_line + file_offset) if hint_line
                                else hint_line)

                    change_pos, n_remove = self._locate_hunk(
                        hunk_lines, target_lines, adj_hint, func_name)

                    if change_pos is not None and hint_line:
                        ctx_before_len = len(
                            _split_hunk_segments(hunk_lines)[0])
                        expected_start = hint_line - 1
                        actual_start = change_pos - ctx_before_len
                        file_offset = actual_start - expected_start

                    if change_pos is None:
                        segs = _split_hunk_segments(hunk_lines)
                        snippet = (segs[1] or segs[2] or ["?"])
                        failed_detail.append(
                            f"{file_path}:L{hint_line or '?'} "
                            f"{snippet[0][:50].strip()}")
                        if file_offset != 0 and hint_line:
                            adj_hdr = self._adjust_hunk_header(
                                hunk_header, file_offset)
                            new_parts.append(adj_hdr)
                        else:
                            new_parts.append(hunk_header)
                        new_parts.append("\n".join(hunk_lines))
                        continue

                    _, expected_rm, added_lines, _ = \
                        _split_hunk_segments(hunk_lines)
                    adapted_hunks += 1

                    actual_rm = target_lines[
                        change_pos:change_pos + n_remove]

                    sym_map = self._extract_symbol_mapping(
                        expected_rm, actual_rm)
                    if sym_map:
                        added_lines = self._apply_symbol_mapping(
                            added_lines, sym_map)
                        logger.debug("[L3] 符号映射: %s", sym_map)

                    added_lines = self._adapt_indentation(
                        added_lines, expected_rm, actual_rm)

                    ctx_n = 3
                    start = max(0, change_pos - ctx_n)
                    rebuilt = []
                    for i in range(start, change_pos):
                        rebuilt.append(" " + target_lines[i])
                    for i in range(change_pos,
                                   min(len(target_lines),
                                       change_pos + n_remove)):
                        rebuilt.append("-" + target_lines[i])
                    for a in added_lines:
                        rebuilt.append("+" + a)
                    end = min(len(target_lines),
                              change_pos + n_remove + ctx_n)
                    for i in range(change_pos + n_remove, end):
                        rebuilt.append(" " + target_lines[i])

                    oc = sum(1 for l in rebuilt
                             if l.startswith(" ") or l.startswith("-"))
                    nc = sum(1 for l in rebuilt
                             if l.startswith(" ") or l.startswith("+"))
                    new_start = start + 1 + cum_delta
                    new_parts.append(
                        f"@@ -{start + 1},{oc} +{new_start},{nc} @@")
                    new_parts.append("\n".join(rebuilt))
                    cum_delta += (len(added_lines) - n_remove)

        logger.info("[L3] 重建结果: %d/%d hunk 已适配", adapted_hunks,
                    total_hunks)
        if failed_detail:
            for d in failed_detail[:5]:
                logger.debug("[L3] 定位失败: %s", d)

        if adapted_hunks == 0:
            return None
        return self._strip_index_lines("\n".join(new_parts) + "\n")

    # ─── 零上下文重建 (L3.5) ─────────────────────────────────────

    def _regenerate_zero_context(self, diff_text: str,
                                 repo_path: str) -> Optional[str]:
        """
        零上下文补丁重建：完全不使用 context 行，仅保留 +/- 行。
        配合 --unidiff-zero 使用，彻底消除 context 行不匹配问题。
        适用于社区补丁与目标文件上下文差异较大但核心改动一致的场景。
        """
        if not diff_text:
            return None
        parsed = self._parse_hunks_for_regen(diff_text)
        if not parsed:
            return None

        new_parts = []
        total_hunks = 0
        adapted_hunks = 0

        for file_path, header_lines, hunks in parsed:
            resolved = self._resolve_file_path(file_path, repo_path)
            if resolved is None:
                continue
            try:
                with open(resolved, "r", encoding="utf-8",
                          errors="replace") as f:
                    target_lines = [l.rstrip("\n")
                                    for l in f.readlines()]
            except Exception:
                continue

            file_hunk_parts = []
            file_offset = 0
            cum_delta = 0

            for orig_header, orig_lines in hunks:
                sub_hunks = _split_to_sub_hunks(
                    orig_header, orig_lines)
                for hh, hl in sub_hunks:
                    total_hunks += 1
                    hint = self._parse_hunk_line_hint(hh)
                    fn = self._extract_func_from_hunk(hh)
                    adj = ((hint + file_offset) if hint
                           else hint)

                    pos, n_rm = self._locate_hunk(
                        hl, target_lines, adj, fn)

                    if pos is not None and hint:
                        ctx_len = len(
                            _split_hunk_segments(hl)[0])
                        file_offset = (
                            (pos - ctx_len) - (hint - 1))

                    if pos is None:
                        continue

                    _, exp_rm, added, _ = _split_hunk_segments(
                        hl)
                    actual_rm = target_lines[
                        pos:pos + n_rm]
                    sym_map = self._extract_symbol_mapping(
                        exp_rm, actual_rm)
                    if sym_map:
                        added = self._apply_symbol_mapping(
                            added, sym_map)
                    added = self._adapt_indentation(
                        added, exp_rm, actual_rm)

                    adapted_hunks += 1

                    rebuilt = []
                    for i in range(
                            pos,
                            min(len(target_lines), pos + n_rm)):
                        rebuilt.append("-" + target_lines[i])
                    for a in added:
                        rebuilt.append("+" + a)

                    old_start = pos + 1
                    new_start = pos + 1 + cum_delta
                    old_count = n_rm
                    new_count = len(added)
                    cum_delta += (new_count - old_count)

                    file_hunk_parts.append(
                        f"@@ -{old_start},{old_count}"
                        f" +{new_start},{new_count} @@")
                    file_hunk_parts.append(
                        "\n".join(rebuilt))

            if file_hunk_parts:
                clean_headers = [
                    h for h in header_lines
                    if not h.startswith("index ")]
                new_parts.append("\n".join(clean_headers))
                new_parts.extend(file_hunk_parts)

        logger.info("[L3.5] 零上下文重建: %d/%d hunk",
                    adapted_hunks, total_hunks)
        if adapted_hunks == 0:
            return None
        return "\n".join(new_parts) + "\n"

    @staticmethod
    def _adjust_hunk_header(header: str, offset: int) -> str:
        m = re.match(
            r'@@\s+-(\d+)(,\d+)?\s+\+(\d+)(,\d+)?\s*@@(.*)',
            header)
        if not m:
            return header
        old_s = int(m.group(1)) + offset
        new_s = int(m.group(3)) + offset
        oc = m.group(2) or ""
        nc = m.group(4) or ""
        fn = m.group(5) or ""
        return f"@@ -{max(1,old_s)}{oc} +{max(1,new_s)}{nc} @@{fn}"

    @staticmethod
    def _strip_index_lines(diff_text: str) -> str:
        """去除 index 行中的 blob hash，避免引用不存在的对象"""
        lines = diff_text.split("\n")
        result = []
        for line in lines:
            if line.startswith("index "):
                m = re.match(r'index\s+\S+\s+(\d+)', line)
                if m:
                    result.append(f"index 0000000..0000000 {m.group(1)}")
                    continue
            result.append(line)
        return "\n".join(result)

    # ─── 冲突分析 (L4) ───────────────────────────────────────────

    # ─── 冲突分析与搜索报告 ────────────────────────────────────────

    def _locate_hunk_with_report(self, hunk_lines: List[str],
                                  file_lines: List[str],
                                  hint_line: Optional[int],
                                  func_name: Optional[str],
                                  hunk_header: str,
                                  file_path: str) -> Tuple[Optional[int], int, HunkSearchReport]:
        """
        定位 hunk 并收集详细搜索过程报告
        返回 (change_pos, n_remove, report)
        """
        ctx_before, removed, added, ctx_after = _split_hunk_segments(hunk_lines)
        
        report = HunkSearchReport(
            hunk_index=0,  # 由调用者设置
            file_path=file_path,
            hunk_header=hunk_header,
            removed_lines=removed,
            added_lines=added,
            before_context=ctx_before,
            after_context=ctx_after,
        )
        
        # 记录 mainline context
        report.mainline_context = ctx_before + ctx_after
        
        # 尝试定位
        change_pos, n_remove = self._locate_hunk(
            hunk_lines, file_lines, hint_line, func_name)
        
        if change_pos is not None:
            # 获取目标文件的实际 context
            snippet_start = max(0, change_pos - len(ctx_before))
            snippet_end = min(len(file_lines), change_pos + n_remove + len(ctx_after))
            report.target_context = file_lines[snippet_start:snippet_end]
            
            # 计算 context 匹配率
            if report.mainline_context and report.target_context:
                matches = sum(1 for m, t in zip(report.mainline_context, report.target_context)
                            if m.strip() == t.strip())
                report.context_match_rate = matches / max(len(report.mainline_context), 
                                                         len(report.target_context))
            
            report.final_position = change_pos
            report.final_confidence = 0.95  # 成功定位
        
        return change_pos, n_remove, report

    def _analyze_conflicts(self, diff_text: str, repo_path: str) -> dict:
        parsed = self._parse_hunks_for_regen(diff_text)
        if not parsed:
            return {"hunks": [], "adapted_diff": None, "search_reports": []}

        hunk_analyses = []
        adapted_parts = []
        any_l3 = False
        conflict_context_pack = []

        for file_path, header_lines, hunks in parsed:
            resolved = self._resolve_file_path(file_path, repo_path)
            if resolved is None:
                for _hh, _hl in hunks:
                    hunk_analyses.append({
                        "file": file_path, "severity": "L3",
                        "reason": f"文件不存在: {file_path}",
                        "expected": [], "actual": [], "added": [],
                    })
                any_l3 = True
                adapted_parts.append("\n".join(header_lines))
                for hh, hl in hunks:
                    adapted_parts.append(hh)
                    adapted_parts.append("\n".join(hl))
                continue

            try:
                with open(resolved, "r", encoding="utf-8",
                          errors="replace") as f:
                    file_lines = [l.rstrip("\n") for l in f.readlines()]
            except Exception:
                any_l3 = True
                adapted_parts.append("\n".join(header_lines))
                for hh, hl in hunks:
                    adapted_parts.append(hh)
                    adapted_parts.append("\n".join(hl))
                continue

            adapted_parts.append("\n".join(header_lines))
            file_offset = 0

            for orig_header, orig_lines in hunks:
                sub_hunks = _split_to_sub_hunks(orig_header, orig_lines)

                for hunk_header, hunk_lines in sub_hunks:
                    ctx_before, expected, added, ctx_after = \
                        _split_hunk_segments(hunk_lines)

                    hint_line = self._parse_hunk_line_hint(hunk_header)
                    func_name = self._extract_func_from_hunk(hunk_header)
                    adj_hint = ((hint_line + file_offset) if hint_line
                                else hint_line)

                    change_pos, n_remove = self._locate_hunk(
                        hunk_lines, file_lines, adj_hint, func_name)

                    if change_pos is not None and hint_line:
                        expected_start = hint_line - 1
                        actual_start = change_pos - len(ctx_before)
                        file_offset = actual_start - expected_start

                    if change_pos is None:
                        hint_idx = max((hint_line or 1) - 1, 0)
                        pack_lo = max(0, hint_idx - 6)
                        pack_hi = min(len(file_lines), hint_idx + 6)
                        context_pack = {
                            "file": file_path,
                            "hunk_header": hunk_header,
                            "location": hint_line or 0,
                            "target_context_start": pack_lo + 1,
                            "target_context": file_lines[pack_lo:pack_hi],
                            "patch_expected": expected[:10],
                            "patch_added": added[:10],
                            "reason": "无法定位，按 hunk 行号提示截取目标上下文",
                        }
                        conflict_context_pack.append(context_pack)
                        hunk_analyses.append({
                            "file": file_path, "severity": "L3",
                            "reason": "无法在目标文件中定位对应代码区域",
                            "expected": expected[:8], "actual": [],
                            "added": added[:8], "hint_line": hint_line,
                            "patch_ctx_before": ctx_before[:5],
                            "patch_ctx_after": ctx_after[:5],
                            "conflict_context_pack": context_pack,
                        })
                        any_l3 = True
                        adapted_parts.append(hunk_header)
                        adapted_parts.append("\n".join(hunk_lines))
                        continue

                    actual = file_lines[change_pos:change_pos + n_remove]
                    if n_remove > 0:
                        sim, changed = self._compare_lines(
                            expected, actual, change_pos)
                    else:
                        sim, changed = 1.0, []

                    if n_remove == 0:
                        sev, reason = "L1", "纯添加 hunk — 已定位插入点"
                    elif sim >= 0.85:
                        sev, reason = "L1", "轻微差异 — 可自动适配"
                    elif sim >= 0.50:
                        sev, reason = "L2", "中度差异 — 需人工审查"
                    else:
                        sev, reason = "L3", "重大差异 — 需人工手动合入"

                    snippet_lo = max(0, change_pos - 3)
                    snippet_hi = min(len(file_lines),
                                     change_pos + n_remove + 3)
                    pack_lo = max(0, change_pos - 8)
                    pack_hi = min(len(file_lines), change_pos + max(n_remove, 1) + 8)
                    context_pack = {
                        "file": file_path,
                        "hunk_header": hunk_header,
                        "location": change_pos + 1,
                        "target_context_start": pack_lo + 1,
                        "target_context": file_lines[pack_lo:pack_hi],
                        "target_actual_removed_region": actual[:12],
                        "patch_expected": expected[:12],
                        "patch_added": added[:12],
                        "similarity": round(sim, 3),
                        "severity": sev,
                        "reason": reason,
                    }
                    if sev in ("L2", "L3"):
                        conflict_context_pack.append(context_pack)
                    hunk_analyses.append({
                        "file": file_path, "severity": sev,
                        "similarity": round(sim, 3), "reason": reason,
                        "expected": expected[:10], "actual": actual[:10],
                        "added": added[:10],
                        "changed_lines": changed[:6],
                        "location": change_pos + 1,
                        "patch_ctx_before": ctx_before[:5],
                        "patch_ctx_after": ctx_after[:5],
                        "target_snippet":
                            file_lines[snippet_lo:snippet_hi][:12],
                        "conflict_context_pack": context_pack if sev in ("L2", "L3") else {},
                    })

                    if sev != "L3":
                        sym_map = self._extract_symbol_mapping(
                            expected, actual)
                        adapted_added = added
                        if sym_map:
                            adapted_added = self._apply_symbol_mapping(
                                added, sym_map)
                        adapted_added = self._adapt_indentation(
                            adapted_added, expected, actual)

                        ctx_n = 3
                        start = max(0, change_pos - ctx_n)
                        rebuilt = []
                        for i in range(start, change_pos):
                            rebuilt.append(" " + file_lines[i])
                        for i in range(change_pos,
                                       min(len(file_lines),
                                           change_pos + n_remove)):
                            rebuilt.append("-" + file_lines[i])
                        for a in adapted_added:
                            rebuilt.append("+" + a)
                        end = min(len(file_lines),
                                  change_pos + n_remove + ctx_n)
                        for i in range(change_pos + n_remove, end):
                            rebuilt.append(" " + file_lines[i])
                        oc = sum(1 for l in rebuilt if
                                 l.startswith(" ") or l.startswith("-"))
                        nc = sum(1 for l in rebuilt if
                                 l.startswith(" ") or l.startswith("+"))
                        adapted_parts.append(
                            f"@@ -{start+1},{oc} +{start+1},{nc} @@")
                        adapted_parts.append("\n".join(rebuilt))
                    else:
                        any_l3 = True
                        adapted_parts.append(hunk_header)
                        adapted_parts.append("\n".join(hunk_lines))

        adapted_diff = None
        if hunk_analyses and not all(
                h["severity"] == "L3" for h in hunk_analyses):
            adapted_diff = "\n".join(adapted_parts) + "\n"

        return {
            "hunks": hunk_analyses,
            "adapted_diff": adapted_diff,
            "conflict_context_pack": conflict_context_pack[:10],
            "search_reports": []  # 暂时为空，后续可扩展
        }

    # ─── 内部方法 ─────────────────────────────────────────────────

    def _prepare(self, patch, target_version):
        result = DryRunResult()
        if not patch.diff_code:
            result.error_output = "补丁无diff内容"
            return result
        rp = self.git_mgr._get_repo_path(target_version)
        if not rp or not os.path.exists(rp):
            result.error_output = f"仓库路径不可用: {target_version}"
            return result
        if not self._extract_pure_diff(patch.diff_code):
            result.error_output = "无法提取有效的diff内容"
            return result
        return None

    def _try_apply(self, patch, target_version, method="strict"):
        result = DryRunResult()
        if not patch.diff_code:
            result.error_output = "补丁无diff内容"
            return result
        rp = self.git_mgr._get_repo_path(target_version)
        if not rp or not os.path.exists(rp):
            result.error_output = f"仓库路径不可用: {target_version}"
            return result
        diff_text = self._extract_pure_diff(patch.diff_code)
        if not diff_text:
            result.error_output = "无法提取有效的diff内容"
            return result
        mapped = self._rewrite_diff_paths(diff_text)
        extra = {"3way": ["--3way"], "context-C1": ["-C1"]}.get(method, [])
        r = self._apply_check(mapped, rp, extra)
        r.stat_output = self._get_stat(mapped, target_version)
        if r.applies_cleanly:
            r.apply_method = method
        return r

    def _apply_check(self, diff_text, repo_path, extra_args):
        import subprocess
        result = DryRunResult()
        patch_file = self._write_temp_patch(diff_text)
        try:
            cmd = ["git", "apply", "--check"] + extra_args + [patch_file]
            proc = subprocess.run(
                cmd, cwd=repo_path, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=60)
            if proc.returncode == 0:
                result.applies_cleanly = True
            else:
                result.error_output = proc.stderr.strip()
                result.conflicting_files = self._parse_conflicts(proc.stderr)
        except Exception as e:
            result.error_output = str(e)
        finally:
            try:
                os.unlink(patch_file)
            except OSError:
                pass
        return result

    def _get_stat(self, diff_text, target_version):
        patch_file = self._write_temp_patch(diff_text)
        try:
            out = self.git_mgr.run_git(
                ["git", "apply", "--stat", patch_file],
                target_version, timeout=30)
            return out.strip() if out else ""
        finally:
            try:
                os.unlink(patch_file)
            except OSError:
                pass

    def _parse_hunks_for_regen(self, diff_text: str):
        """hunk 内容捕获必须在 ---/+++ 判断之前"""
        results = []
        current_file = None
        header_lines = []
        hunks = []
        current_hunk_header = None
        current_hunk_lines = []

        for line in diff_text.split("\n"):
            if line.startswith("diff --git"):
                if current_file is not None:
                    if current_hunk_header:
                        hunks.append((current_hunk_header,
                                      current_hunk_lines))
                    results.append((current_file, header_lines, hunks))
                m = re.search(r" b/(.*)", line)
                current_file = m.group(1) if m else None
                header_lines = [line]
                hunks = []
                current_hunk_header = None
                current_hunk_lines = []
            elif line.startswith("@@"):
                if current_hunk_header:
                    hunks.append((current_hunk_header, current_hunk_lines))
                current_hunk_header = line
                current_hunk_lines = []
            elif current_hunk_header is not None:
                current_hunk_lines.append(line)
            elif line.startswith("---") or line.startswith("+++"):
                header_lines.append(line)
            elif current_file is not None:
                header_lines.append(line)

        if current_file is not None:
            if current_hunk_header:
                hunks.append((current_hunk_header, current_hunk_lines))
            results.append((current_file, header_lines, hunks))

        return results if results else None

    @staticmethod
    def _extract_pure_diff(text):
        lines = text.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("diff --git"):
                return "\n".join(lines[i:])
        return None

    @staticmethod
    def _write_temp_patch(diff_text):
        fd, path = tempfile.mkstemp(suffix=".patch", prefix="dryrun_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(diff_text)
        return path

    @staticmethod
    def _parse_conflicts(stderr):
        files = set()
        for line in stderr.split("\n"):
            m = re.search(r"error:\s+patch failed:\s+(\S+?):\d+", line)
            if m:
                files.add(m.group(1))
                continue
            m = re.search(r"error:\s+(\S+?):\s+does not exist", line)
            if m:
                files.add(m.group(1))
                continue
            m = re.search(r"error:\s+(\S+?):\s+No such file", line)
            if m:
                files.add(m.group(1))
        return sorted(files)
