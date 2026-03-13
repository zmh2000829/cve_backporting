"""
Dry-Run Agent — 多级补丁试应用 + 逐 hunk 冲突分析

多级策略:
  Level 0 - strict:           git apply --check
  Level 1 - context-C1:       git apply --check -C1
  Level 2 - 3way:             git apply --check --3way
  Level 3 - regenerated:      从目标文件重建 context (核心 +/- 不变)
  Level 4 - conflict-adapted: 用目标文件实际行替换 - 行, 保留 + 行

核心定位算法 (_locate_in_file) — 七策略渐进式:
  1. 精确序列匹配 (strip 后)
  2. 函数名锚点搜索 (@@ 行提取函数名, 限定函数作用域)
  3. 行号提示 ± 窗口搜索 (hunk header @@ -X,Y @@, ±200 行)
  4. 全局逐行模糊匹配 (SequenceMatcher 加权评分)
  5. Context 行重试
  6. 逐行独立投票 (每行独立匹配, 取位置聚簇中位数)
  7. 最长行最佳匹配
"""

import os
import re
import tempfile
import logging
import difflib
from typing import List, Optional

from core.models import PatchInfo, DryRunResult
from core.git_manager import GitRepoManager

logger = logging.getLogger(__name__)

_NOISE_PREFIXES = ("\\",)


def _clean_hunk_lines(lines: List[str]) -> List[str]:
    """过滤 hunk 中的非代码行 (如 '\\ No newline at end of file')"""
    return [l for l in lines
            if not any(l.startswith(p) for p in _NOISE_PREFIXES)]


class DryRunAgent:
    """补丁试应用Agent — 多级上下文自适应 + 路径映射"""

    def __init__(self, git_mgr: GitRepoManager, path_mapper=None):
        self.git_mgr = git_mgr
        self.path_mapper = path_mapper

    # ─── 公开接口 ─────────────────────────────────────────────────

    def check(self, patch: PatchInfo, target_version: str) -> DryRunResult:
        return self._try_apply(patch, target_version, method="strict")

    def check_with_3way(self, patch: PatchInfo, target_version: str) -> DryRunResult:
        result = self._try_apply(patch, target_version, method="strict")
        if result.applies_cleanly:
            return result
        r3 = self._try_apply(patch, target_version, method="3way")
        return r3 if r3.applies_cleanly else result

    def check_adaptive(self, patch: PatchInfo,
                       target_version: str) -> DryRunResult:
        """
        多级自适应试应用:
          strict → -C1 → --3way → 上下文重生成 → 冲突适配
        """
        base_result = self._prepare(patch, target_version)
        if base_result is not None:
            return base_result

        rp_path = self.git_mgr._get_repo_path(target_version)
        diff_text = self._extract_pure_diff(patch.diff_code)
        mapped_diff = self._rewrite_diff_paths(diff_text)

        # Level 0: strict
        r0 = self._apply_check(mapped_diff, rp_path, [])
        if r0.applies_cleanly:
            r0.apply_method = "strict"
            r0.stat_output = self._get_stat(mapped_diff, target_version)
            logger.info("[DryRun] strict 成功: %s", patch.commit_id[:12])
            return r0

        # Level 1: -C1
        r1 = self._apply_check(mapped_diff, rp_path, ["-C1"])
        if r1.applies_cleanly:
            r1.apply_method = "context-C1"
            r1.stat_output = self._get_stat(mapped_diff, target_version)
            r1.error_output = (
                f"(严格模式失败, -C1 成功: {len(r0.conflicting_files)} 个文件"
                " context 偏移)")
            logger.info("[DryRun] -C1 成功: %s", patch.commit_id[:12])
            return r1

        # Level 2: --3way
        r2 = self._apply_check(mapped_diff, rp_path, ["--3way"])
        if r2.applies_cleanly:
            r2.apply_method = "3way"
            r2.stat_output = self._get_stat(mapped_diff, target_version)
            r2.error_output = "(3-way merge成功)"
            logger.info("[DryRun] 3-way merge成功: %s", patch.commit_id[:12])
            return r2

        # Level 3: 上下文重生成
        adapted = self._regenerate_patch(mapped_diff, rp_path)
        if adapted:
            r3 = self._apply_check(adapted, rp_path, [])
            if r3.applies_cleanly:
                r3.apply_method = "regenerated"
                r3.stat_output = self._get_stat(adapted, target_version)
                r3.adapted_patch = adapted
                r3.error_output = "(上下文重生成成功: context 已从目标文件更新)"
                logger.info("[DryRun] 上下文重生成成功: %s",
                            patch.commit_id[:12])
                return r3

        # Level 4: 逐 hunk 冲突分析 + 冲突适配
        r0.stat_output = self._get_stat(mapped_diff, target_version)
        analysis = self._analyze_conflicts(mapped_diff, rp_path)
        r0.conflict_hunks = analysis["hunks"]

        if analysis.get("adapted_diff"):
            r4 = self._apply_check(analysis["adapted_diff"], rp_path, [])
            if r4.applies_cleanly:
                r4.apply_method = "conflict-adapted"
                r4.stat_output = self._get_stat(
                    analysis["adapted_diff"], target_version)
                r4.adapted_patch = analysis["adapted_diff"]
                r4.conflict_hunks = analysis["hunks"]
                r4.error_output = (
                    "(冲突适配成功: - 行替换为目标文件实际内容, "
                    "+ 行不变, 需人工审查)")
                logger.info("[DryRun] 冲突适配成功: %s",
                            patch.commit_id[:12])
                return r4

        logger.info("[DryRun] 所有策略均失败: %s (%d 文件, %d hunk)",
                    patch.commit_id[:12], len(r0.conflicting_files),
                    len(r0.conflict_hunks))
        return r0

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

    # ─── 冲突分析 ─────────────────────────────────────────────────

    def _analyze_conflicts(self, diff_text: str, repo_path: str) -> dict:
        parsed = self._parse_hunks_for_regen(diff_text)
        if not parsed:
            return {"hunks": [], "adapted_diff": None}

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

            for hunk_header, hunk_lines in hunks:
                clean = _clean_hunk_lines(hunk_lines)
                expected = [l[1:] for l in clean if l.startswith("-")]
                added = [l[1:] for l in clean if l.startswith("+")]
                ctx = [l[1:] if l.startswith(" ") else l
                       for l in clean
                       if not l.startswith("+") and not l.startswith("-")]

                hint_line = self._parse_hunk_line_hint(hunk_header)
                func_name = self._extract_func_from_hunk(hunk_header)

                pos = self._locate_in_file(
                    expected, ctx, file_lines, hint_line, func_name)

                if pos is None:
                    hunk_analyses.append({
                        "file": file_path, "severity": "L3",
                        "reason": "无法在目标文件中定位对应代码区域",
                        "expected": expected[:8], "actual": [],
                        "added": added[:8], "hint_line": hint_line,
                    })
                    any_l3 = True
                    adapted_parts.append(hunk_header)
                    adapted_parts.append("\n".join(hunk_lines))
                    continue

                n_exp = len(expected) if expected else len(ctx)
                actual = file_lines[pos:pos + n_exp]
                sim, changed = self._compare_lines(expected, actual, pos)

                if sim >= 0.85:
                    sev, reason = "L1", "轻微差异 — 可自动适配"
                elif sim >= 0.50:
                    sev, reason = "L2", "中度差异 — 需人工审查适配结果"
                else:
                    sev, reason = "L3", "重大差异 — 需人工手动合入"

                hunk_analyses.append({
                    "file": file_path, "severity": sev,
                    "similarity": round(sim, 3), "reason": reason,
                    "expected": expected[:10], "actual": actual[:10],
                    "added": added[:10], "changed_lines": changed[:6],
                    "location": pos + 1,
                })

                if sev != "L3":
                    start = max(0, pos - 3)
                    rebuilt = []
                    for i in range(start, pos):
                        rebuilt.append(" " + file_lines[i])
                    for a in actual:
                        rebuilt.append("-" + a)
                    for a in added:
                        rebuilt.append("+" + a)
                    end = min(len(file_lines), pos + n_exp + 3)
                    for i in range(pos + n_exp, end):
                        rebuilt.append(" " + file_lines[i])
                    oc = sum(1 for l in rebuilt
                             if l.startswith(" ") or l.startswith("-"))
                    nc = sum(1 for l in rebuilt
                             if l.startswith(" ") or l.startswith("+"))
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

        return {"hunks": hunk_analyses, "adapted_diff": adapted_diff}

    # ─── 核心定位算法 (七策略) ────────────────────────────────────

    def _locate_in_file(self, expected: List[str],
                        context_lines: List[str],
                        file_lines: List[str],
                        hint_line: Optional[int] = None,
                        func_name: Optional[str] = None) -> Optional[int]:
        """
        七策略渐进式在目标文件中定位 hunk 对应位置:
        1. 精确序列匹配
        2. 函数名锚点 + 函数作用域内搜索
        3. 行号提示 ± 窗口
        4. 全局逐行模糊匹配
        5. Context 行重试
        6. 逐行独立投票
        7. 最长行最佳匹配
        """
        search_seq = expected if expected else context_lines
        if not search_seq:
            return None
        # 过滤空行和噪声
        clean_seq = [l for l in search_seq
                     if l.strip() and not l.startswith("\\")]
        if not clean_seq:
            clean_seq = search_seq

        # 策略1: 精确序列匹配
        pos = self._find_exact_sequence(clean_seq, file_lines)
        if pos is not None:
            return pos

        # 策略2: 函数名锚点搜索
        if func_name:
            pos = self._find_in_function(clean_seq, file_lines, func_name)
            if pos is not None:
                return pos

        # 策略3: 行号提示 ± 窗口 (±200 行)
        if hint_line is not None and hint_line > 0:
            pos = self._find_near_hint(clean_seq, file_lines,
                                       hint_line, window=200)
            if pos is not None:
                return pos

        # 策略4: 全局逐行模糊匹配
        pos = self._find_fuzzy_sequence(clean_seq, file_lines)
        if pos is not None:
            return pos

        # 策略5: Context 行重试
        if expected and context_lines:
            clean_ctx = [l for l in context_lines
                         if l.strip() and not l.startswith("\\")]
            if clean_ctx:
                for m in (self._find_exact_sequence,
                          self._find_fuzzy_sequence):
                    pos = m(clean_ctx, file_lines)
                    if pos is not None:
                        return pos

        # 策略6: 逐行独立投票
        pos = self._find_by_line_voting(clean_seq, file_lines)
        if pos is not None:
            return pos

        # 策略7: 最长行最佳匹配
        best = max(clean_seq, key=lambda l: len(l.strip()), default=None)
        if best and len(best.strip()) >= 6:
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
        """
        在目标文件中查找函数的起止范围，在该范围内搜索。
        函数边界: 找到函数签名行, 向下追踪大括号平衡。
        """
        func_start, func_end = None, None
        fn = func_name.strip().split("(")[0].strip()
        if not fn or len(fn) < 2:
            return None

        for i, line in enumerate(haystack):
            if fn in line and ("(" in line or "{" in line):
                func_start = i
                break
        if func_start is None:
            return None

        # 从函数起始找到函数结束 (大括号平衡)
        brace = 0
        found_open = False
        for i in range(func_start, min(len(haystack), func_start + 500)):
            brace += haystack[i].count("{") - haystack[i].count("}")
            if "{" in haystack[i]:
                found_open = True
            if found_open and brace <= 0:
                func_end = i + 1
                break
        if func_end is None:
            func_end = min(len(haystack), func_start + 300)

        scope = haystack[func_start:func_end]
        # 在函数作用域内精确搜索
        pos = self._find_exact_sequence(needle, scope)
        if pos is not None:
            return func_start + pos
        # 函数作用域内模糊搜索
        pos = self._find_fuzzy_sequence(needle, scope)
        if pos is not None:
            return func_start + pos
        return None

    def _find_near_hint(self, needle: List[str],
                        haystack: List[str],
                        hint_line: int,
                        window: int = 200) -> Optional[int]:
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

        best_pos, best_score = None, 0.0
        for i in range(lo, hi):
            s = self._line_fuzzy_score(ns, hs[i:i + n])
            if s > best_score and s >= 0.50:
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
        # 短序列降低阈值
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
        逐行独立匹配, 收集每行在文件中的位置, 取聚簇中位数。
        解决"序列整体不匹配但大部分行可独立找到"的场景。
        """
        if not needle or len(needle) < 2:
            return None
        hs = [l.strip() for l in haystack]
        positions = []

        for idx, nl in enumerate(needle):
            ns = nl.strip()
            if len(ns) < 6:
                continue
            found = False
            for i, h in enumerate(hs):
                if ns == h:
                    positions.append((i, idx))
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
                    positions.append((best_i, idx))

        if len(positions) < max(1, len(needle) * 0.3):
            return None

        # 找最大聚簇: 按文件行号排序, 找连续递增的最长子序列
        positions.sort()
        file_positions = [p[0] for p in positions]

        if len(file_positions) == 1:
            return max(0, file_positions[0] - positions[0][1])

        # 用中位数估算起始位置
        median = file_positions[len(file_positions) // 2]
        first_needle_idx = positions[len(positions) // 2][1]
        return max(0, median - first_needle_idx)

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
    def _compare_lines(expected: List[str], actual: List[str],
                       pos: int) -> tuple:
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
        """从 @@ ... @@ function_name 提取函数名"""
        m = re.match(r"@@[^@]+@@\s*(.+)", hunk_header)
        if m:
            name = m.group(1).strip()
            if name and len(name) > 2:
                return name
        return None

    # ─── 上下文重生成 ─────────────────────────────────────────────

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

            for hunk_header, hunk_lines in hunks:
                clean = _clean_hunk_lines(hunk_lines)
                removed = [l[1:] for l in clean if l.startswith("-")]
                ctx = [l[1:] if l.startswith(" ") else l
                       for l in clean
                       if not l.startswith("+") and not l.startswith("-")]

                hint_line = self._parse_hunk_line_hint(hunk_header)
                func_name = self._extract_func_from_hunk(hunk_header)
                search_seq = removed if removed else ctx
                pos = self._locate_in_file(
                    search_seq, ctx, target_lines, hint_line, func_name)

                if pos is None:
                    new_parts.append(hunk_header)
                    new_parts.append("\n".join(hunk_lines))
                    continue

                any_adapted = True
                start = max(0, pos - 3)
                rebuilt = []
                for i in range(start, pos):
                    rebuilt.append(" " + target_lines[i])

                idx = pos
                for hl in hunk_lines:
                    if hl.startswith("\\"):
                        continue
                    if hl.startswith("-"):
                        rebuilt.append(hl)
                        idx += 1
                    elif hl.startswith("+"):
                        rebuilt.append(hl)
                    else:
                        if idx < len(target_lines):
                            rebuilt.append(" " + target_lines[idx])
                            idx += 1
                        else:
                            rebuilt.append(hl)

                end_ctx = min(len(target_lines), idx + 3)
                for i in range(idx, end_ctx):
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
        """
        解析 unified diff → [(file_path, header_lines, [(hunk_header, hunk_lines)])]

        关键: hunk 内容捕获必须在 ---/+++ 判断之前，
        否则 hunk 中以 ---/+++ 开头的代码行会被错误吞入 header。
        """
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
                m = re.search(r"b/(.*)", line)
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
                # ★ 必须在 ---/+++ 判断之前! 否则 hunk 中的
                # `---xxx` (删除 `--xxx`) 会被错误解析为文件 header
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

    # ─── 工具方法 ─────────────────────────────────────────────────

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
