"""
Dry-Run Agent — 多级补丁试应用 + 逐 hunk 冲突分析

多级策略:
  Level 0 - strict:           git apply --check
  Level 1 - context-C1:       git apply --check -C1
  Level 2 - 3way:             git apply --check --3way
  Level 3 - regenerated:      从目标文件重建 context (核心 +/- 不变)
  Level 4 - conflict-adapted: 用目标文件实际行替换 - 行, 保留 + 行

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

from core.models import PatchInfo, DryRunResult
from core.git_manager import GitRepoManager
from core.code_matcher import CodeMatcher, PatchContextExtractor
from core.search_report import HunkSearchReport, StrategyResult, DetailedSearchReport

logger = logging.getLogger(__name__)

_NOISE_PREFIXES = ("\\",)


def _clean_hunk_lines(lines: List[str]) -> List[str]:
    return [l for l in lines
            if not any(l.startswith(p) for p in _NOISE_PREFIXES)]


_TRIVIAL_ANCHORS = frozenset({
    "return 0;", "return ret;", "return;", "return -1;",
    "return err;", "return rc;", "return result;",
    "return NULL;", "return false;", "return true;",
    "return -EINVAL;", "return -ENOMEM;", "return -EIO;",
    "break;", "continue;", "default:",
    "{", "}", "} else {", "else {",
    "out:", "err:", "error:", "unlock:", "fail:",
})


def _is_trivial_anchor(line: str) -> bool:
    s = line.strip()
    if not s or len(s) < 4:
        return True
    if s in _TRIVIAL_ANCHORS:
        return True
    if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
        return True
    return False


def _split_hunk_segments(hunk_lines: List[str]):
    """
    拆分 hunk → (ctx_before, removed, added, ctx_after)
    ctx_before: 第一个变更行之前的 context
    ctx_after:  最后一个变更行之后的 context
    """
    clean = _clean_hunk_lines(hunk_lines)
    ctx_before, removed, added, ctx_after = [], [], [], []
    first_change, last_change = len(clean), -1

    for i, l in enumerate(clean):
        if l.startswith("-") or l.startswith("+"):
            first_change = min(first_change, i)
            last_change = max(last_change, i)

    for i, l in enumerate(clean):
        if l.startswith("-"):
            removed.append(l[1:])
        elif l.startswith("+"):
            added.append(l[1:])
        else:
            line = l[1:] if l.startswith(" ") else l
            if i < first_change:
                ctx_before.append(line)
            elif i > last_change:
                ctx_after.append(line)

    return ctx_before, removed, added, ctx_after


def _parse_hunk_regions(hunk_lines: List[str]):
    """
    将 hunk 解析为有序的区域列表，正确保留多变更区域之间的 context。
    返回: [{"type": "context", "lines": [...]},
           {"type": "change",  "removed": [...], "added": [...]},
           ...]
    """
    clean = _clean_hunk_lines(hunk_lines)
    regions = []
    current_ctx = []
    current_removed = []
    current_added = []
    in_change = False

    for line in clean:
        if line.startswith("-"):
            if not in_change and current_ctx:
                regions.append({"type": "context", "lines": current_ctx})
                current_ctx = []
            in_change = True
            current_removed.append(line[1:])
        elif line.startswith("+"):
            if not in_change and current_ctx:
                regions.append({"type": "context", "lines": current_ctx})
                current_ctx = []
            in_change = True
            current_added.append(line[1:])
        else:
            text = line[1:] if line.startswith(" ") else line
            if in_change:
                regions.append({
                    "type": "change",
                    "removed": current_removed,
                    "added": current_added,
                })
                current_removed = []
                current_added = []
                in_change = False
            current_ctx.append(text)

    if in_change:
        regions.append({
            "type": "change",
            "removed": current_removed,
            "added": current_added,
        })
    elif current_ctx:
        regions.append({"type": "context", "lines": current_ctx})

    return regions


def _split_to_sub_hunks(hunk_header: str, hunk_lines: List[str]):
    """
    将包含多个变更区域的 hunk 拆分为独立的 sub-hunk。
    每个 sub-hunk 只有一个连续的变更区域和各自的 context。
    单区域 hunk 原样返回。
    """
    regions = _parse_hunk_regions(hunk_lines)
    change_indices = [i for i, r in enumerate(regions)
                      if r["type"] == "change"]

    if len(change_indices) <= 1:
        return [(hunk_header, hunk_lines)]

    sub_hunks = []
    for ci in change_indices:
        change = regions[ci]

        ctx_before = []
        if ci > 0 and regions[ci - 1]["type"] == "context":
            ctx_before = regions[ci - 1]["lines"][-3:]

        ctx_after = []
        if ci + 1 < len(regions) and regions[ci + 1]["type"] == "context":
            ctx_after = regions[ci + 1]["lines"][:3]

        sub_lines = []
        for l in ctx_before:
            sub_lines.append(" " + l)
        for l in change["removed"]:
            sub_lines.append("-" + l)
        for l in change["added"]:
            sub_lines.append("+" + l)
        for l in ctx_after:
            sub_lines.append(" " + l)

        sub_hunks.append((hunk_header, sub_lines))

    return sub_hunks


class DryRunAgent:
    """补丁试应用Agent — 多级上下文自适应 + 路径映射 + 代码语义匹配"""

    def __init__(self, git_mgr: GitRepoManager, path_mapper=None):
        self.git_mgr = git_mgr
        self.path_mapper = path_mapper
        self.code_matcher = CodeMatcher()

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

        r0 = self._apply_check(mapped_diff, rp_path, [])
        if r0.applies_cleanly:
            r0.apply_method = "strict"
            r0.stat_output = self._get_stat(mapped_diff, target_version)
            logger.info("[DryRun] strict 成功: %s", patch.commit_id[:12])
            self._ensure_adapted_patch(r0, mapped_diff, rp_path)
            return r0

        r1 = self._apply_check(mapped_diff, rp_path, ["-C1"])
        if r1.applies_cleanly:
            r1.apply_method = "context-C1"
            r1.stat_output = self._get_stat(mapped_diff, target_version)
            r1.error_output = (
                f"(严格模式失败, -C1 成功: {len(r0.conflicting_files)} 个文件"
                " context 偏移)")
            logger.info("[DryRun] -C1 成功: %s", patch.commit_id[:12])
            self._ensure_adapted_patch(r1, mapped_diff, rp_path)
            return r1

        r2 = self._apply_check(mapped_diff, rp_path, ["--3way"])
        if r2.applies_cleanly:
            r2.apply_method = "3way"
            r2.stat_output = self._get_stat(mapped_diff, target_version)
            r2.error_output = "(3-way merge成功)"
            logger.info("[DryRun] 3-way merge成功: %s", patch.commit_id[:12])
            self._ensure_adapted_patch(r2, mapped_diff, rp_path)
            return r2

        adapted = self._regenerate_patch(mapped_diff, rp_path)
        if adapted:
            r3 = self._apply_check(adapted, rp_path, [])
            if r3.applies_cleanly:
                r3.apply_method = "regenerated"
                r3.stat_output = self._get_stat(adapted, target_version)
                r3.adapted_patch = adapted
                r3.error_output = (
                    "(上下文重生成成功: context 已从目标文件更新)")
                logger.info("[DryRun] 上下文重生成成功: %s",
                            patch.commit_id[:12])
                return r3

        r0.stat_output = self._get_stat(mapped_diff, target_version)
        analysis = self._analyze_conflicts(mapped_diff, rp_path)
        r0.conflict_hunks = analysis["hunks"]

        if analysis.get("search_reports"):
            r0.search_reports = analysis["search_reports"]

        if analysis.get("adapted_diff"):
            r4 = self._apply_check(analysis["adapted_diff"], rp_path, [])
            if r4.applies_cleanly:
                r4.apply_method = "conflict-adapted"
                r4.stat_output = self._get_stat(
                    analysis["adapted_diff"], target_version)
                r4.adapted_patch = analysis["adapted_diff"]
                r4.conflict_hunks = analysis["hunks"]
                r4.search_reports = analysis.get("search_reports", [])
                r4.error_output = (
                    "(冲突适配成功: - 行替换为目标文件实际内容, "
                    "+ 行不变, 需人工审查)")
                logger.info("[DryRun] 冲突适配成功: %s",
                            patch.commit_id[:12])
                return r4

        # 全部失败时，按优先级保留最佳可用补丁用于 validate 对比:
        # L3 重建 > L4 冲突适配 > 社区原始补丁 (兜底)
        if adapted:
            r0.adapted_patch = adapted
            logger.info(
                "[DryRun] 所有策略均失败, 保留 L3 重建结果用于对比: %s",
                patch.commit_id[:12])
        elif analysis.get("adapted_diff"):
            r0.adapted_patch = analysis["adapted_diff"]
        else:
            r0.adapted_patch = mapped_diff
            logger.info(
                "[DryRun] L3/L4 均无产出, 使用社区原始补丁作为 adapted_patch: %s",
                patch.commit_id[:12])

        logger.info("[DryRun] 所有策略均失败: %s (%d 文件, %d hunk)",
                    patch.commit_id[:12], len(r0.conflicting_files),
                    len(r0.conflict_hunks))
        return r0

    def _ensure_adapted_patch(self, result: DryRunResult,
                              diff_text: str, repo_path: str):
        """L0/L1/L2 成功后，仍执行 L3 重建以生成 adapted_patch。
        adapted_patch 的行号对齐目标文件，可用于 validate 的补丁本质比较。
        若 L3 重建失败，回退使用社区原始补丁（已确认可 apply）。"""
        try:
            adapted = self._regenerate_patch(diff_text, repo_path)
            if adapted:
                result.adapted_patch = adapted
                return
        except Exception as e:
            logger.debug("[DryRun] _ensure_adapted_patch L3 重建异常: %s", e)
        result.adapted_patch = diff_text
        logger.info("[DryRun] L3 重建未成功, 回退使用社区原始补丁作为 adapted_patch")

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

        # B) 用 before-context 最后一行做锚点
        if ctx_before:
            adj = ((hint_line + len(ctx_before) - 1)
                   if hint_line else hint_line)
            anchor = self._find_anchor_line(
                ctx_before[-1], file_lines, adj)
            if anchor is not None:
                return anchor + 1, n

        # C) 用 after-context 第一行做锚点
        if ctx_after:
            adj = ((hint_line + len(ctx_before) + n)
                   if hint_line else hint_line)
            anchor = self._find_anchor_line(
                ctx_after[0], file_lines, adj)
            if anchor is not None:
                return max(0, anchor - n), n

        # D) Level 8: 代码语义匹配 (context 被打断时的最后手段)
        if removed:
            pos = self.code_matcher.find_removed_lines(
                removed, file_lines, hint_line)
            if pos is not None:
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
        # A) before-context: 从末尾向前迭代，跳过 trivial 行
        if ctx_before:
            for back in range(len(ctx_before)):
                idx = len(ctx_before) - 1 - back
                if _is_trivial_anchor(ctx_before[idx]):
                    continue
                adj = ((hint_line + idx)
                       if hint_line else hint_line)
                anchor = self._find_anchor_line(
                    ctx_before[idx], file_lines, adj)
                if anchor is not None:
                    ins = anchor + 1 + back
                    if self._check_insertion_context(
                            ctx_after, file_lines, ins):
                        return ins, 0
                break

        # B) after-context: 从首行向后迭代，跳过 trivial 行
        if ctx_after:
            for fwd in range(len(ctx_after)):
                if _is_trivial_anchor(ctx_after[fwd]):
                    continue
                adj = ((hint_line + len(ctx_before) + fwd)
                       if hint_line else hint_line)
                anchor = self._find_anchor_line(
                    ctx_after[fwd], file_lines, adj)
                if anchor is not None:
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
        # A-fallback) 锚点搜索不做交叉验证（覆盖面更广）
        if ctx_before:
            for back in range(len(ctx_before)):
                idx = len(ctx_before) - 1 - back
                if _is_trivial_anchor(ctx_before[idx]):
                    continue
                adj = ((hint_line + idx)
                       if hint_line else hint_line)
                anchor = self._find_anchor_line(
                    ctx_before[idx], file_lines, adj)
                if anchor is not None:
                    return anchor + 1 + back, 0
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
        ns = line.strip()
        if not ns or len(ns) < 4:
            return None
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

        best, best_dist = None, float("inf")
        for i in range(lo, hi):
            if hs[i] == ns:
                dist = abs(i - center)
                if dist < best_dist:
                    best_dist = dist
                    best = i
        if best is not None:
            return best

        best_pos, best_r, best_fdist = None, 0.0, float("inf")
        for i in range(lo, hi):
            r = difflib.SequenceMatcher(None, ns, hs[i]).ratio()
            if r >= 0.85:
                dist = abs(i - center)
                if r > best_r or (r == best_r and dist < best_fdist):
                    best_r = r
                    best_pos = i
                    best_fdist = dist
        return best_pos

    # ─── 序列定位算法 ────────────────────────────────────────────

    def _locate_in_file(self, expected: List[str],
                        context_lines: List[str],
                        file_lines: List[str],
                        hint_line: Optional[int] = None,
                        func_name: Optional[str] = None) -> Optional[int]:
        search_seq = expected if expected else context_lines
        if not search_seq:
            return None
        # 保留空行, 仅去噪声行
        seq = [l for l in search_seq if not l.startswith("\\")]
        if not seq:
            return None

        pos = self._find_exact_sequence(seq, file_lines)
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

    # ─── 上下文重生成 (L3) ────────────────────────────────────────

    def _regenerate_patch(self, diff_text: str,
                          repo_path: str) -> Optional[str]:
        parsed = self._parse_hunks_for_regen(diff_text)
        if not parsed:
            return None

        new_parts = []
        any_adapted = False

        for file_path, header_lines, hunks in parsed:
            resolved = self._resolve_file_path(file_path, repo_path)
            if resolved is None:
                new_parts.append("\n".join(header_lines))
                for hh, hl in hunks:
                    new_parts.append(hh)
                    new_parts.append("\n".join(hl))
                continue

            try:
                with open(resolved, "r", encoding="utf-8",
                          errors="replace") as f:
                    target_lines = [l.rstrip("\n") for l in f.readlines()]
            except Exception:
                new_parts.append("\n".join(header_lines))
                for hh, hl in hunks:
                    new_parts.append(hh)
                    new_parts.append("\n".join(hl))
                continue

            new_parts.append("\n".join(header_lines))
            file_offset = 0

            for orig_header, orig_lines in hunks:
                sub_hunks = _split_to_sub_hunks(orig_header, orig_lines)

                for hunk_header, hunk_lines in sub_hunks:
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
                        new_parts.append(hunk_header)
                        new_parts.append("\n".join(hunk_lines))
                        continue

                    _, _, added_lines, _ = _split_hunk_segments(
                        hunk_lines)
                    any_adapted = True

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
                    new_parts.append(
                        f"@@ -{start + 1},{oc} +{start + 1},{nc} @@")
                    new_parts.append("\n".join(rebuilt))

        if not any_adapted:
            return None
        return "\n".join(new_parts) + "\n"

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
                        hunk_analyses.append({
                            "file": file_path, "severity": "L3",
                            "reason": "无法在目标文件中定位对应代码区域",
                            "expected": expected[:8], "actual": [],
                            "added": added[:8], "hint_line": hint_line,
                            "patch_ctx_before": ctx_before[:5],
                            "patch_ctx_after": ctx_after[:5],
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
                    })

                    if sev != "L3":
                        ctx_n = 3
                        start = max(0, change_pos - ctx_n)
                        rebuilt = []
                        for i in range(start, change_pos):
                            rebuilt.append(" " + file_lines[i])
                        for i in range(change_pos,
                                       min(len(file_lines),
                                           change_pos + n_remove)):
                            rebuilt.append("-" + file_lines[i])
                        for a in added:
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
