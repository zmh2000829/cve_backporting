"""
Dry-Run Agent — 多级补丁试应用 + 逐 hunk 冲突分析

多级策略:
  Level 0 - strict:           git apply --check (完整 context 匹配)
  Level 1 - context-C1:       git apply --check -C1 (仅需 1 行 context)
  Level 2 - 3way:             git apply --check --3way (三方合并)
  Level 3 - regenerated:      从目标文件重建 context (核心 +/- 不变)
  Level 4 - conflict-adapted: 用目标文件实际行替换 - 行, 保留 + 行 (需人工审查)

核心算法改进:
  - 路径映射感知: 社区补丁路径 (upstream) 自动映射到本地路径 (local)
  - 行号提示搜索: 利用 hunk header @@ -X,Y @@ 缩小搜索窗口
  - 三级序列定位: 精确匹配 → 逐行模糊匹配 → 单行最佳匹配
  - 冲突分级: L1 轻微 / L2 中度 / L3 重大
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


class DryRunAgent:
    """补丁试应用Agent — 多级上下文自适应 + 路径映射"""

    def __init__(self, git_mgr: GitRepoManager, path_mapper=None):
        self.git_mgr = git_mgr
        self.path_mapper = path_mapper

    # ─── 公开接口 ─────────────────────────────────────────────────

    def check(self, patch: PatchInfo, target_version: str) -> DryRunResult:
        """严格模式试应用 (向后兼容)"""
        return self._try_apply(patch, target_version, method="strict")

    def check_with_3way(self, patch: PatchInfo, target_version: str) -> DryRunResult:
        """先 strict，失败则 3-way (向后兼容)"""
        result = self._try_apply(patch, target_version, method="strict")
        if result.applies_cleanly:
            return result
        r3 = self._try_apply(patch, target_version, method="3way")
        return r3 if r3.applies_cleanly else result

    def check_adaptive(self, patch: PatchInfo,
                       target_version: str) -> DryRunResult:
        """
        多级自适应试应用。按顺序尝试:
          strict → -C1 → --3way → 上下文重生成 → 冲突适配
        返回第一个成功的结果, 或最后一个失败结果(附带冲突分析)。
        """
        base_result = self._prepare(patch, target_version)
        if base_result is not None:
            return base_result

        rp_path = self.git_mgr._get_repo_path(target_version)
        diff_text = self._extract_pure_diff(patch.diff_code)

        # 路径映射: 将社区补丁路径映射到本地路径
        mapped_diff = self._rewrite_diff_paths(diff_text)

        # Level 0: strict
        r0 = self._apply_check(mapped_diff, rp_path, [])
        if r0.applies_cleanly:
            r0.apply_method = "strict"
            r0.stat_output = self._get_stat(mapped_diff, target_version)
            logger.info("[DryRun] 补丁 %s 可以干净应用 (strict)",
                        patch.commit_id[:12])
            return r0

        # Level 1: -C1
        r1 = self._apply_check(mapped_diff, rp_path, ["-C1"])
        if r1.applies_cleanly:
            r1.apply_method = "context-C1"
            r1.stat_output = self._get_stat(mapped_diff, target_version)
            r1.error_output = (
                f"(严格模式失败, -C1 成功: {len(r0.conflicting_files)} 个文件的 "
                "context lines 有偏移但核心改动位置正确)")
            logger.info("[DryRun] 补丁 %s -C1 成功", patch.commit_id[:12])
            return r1

        # Level 2: --3way
        r2 = self._apply_check(mapped_diff, rp_path, ["--3way"])
        if r2.applies_cleanly:
            r2.apply_method = "3way"
            r2.stat_output = self._get_stat(mapped_diff, target_version)
            r2.error_output = "(3-way merge成功)"
            logger.info("[DryRun] 3-way merge成功: %s", patch.commit_id[:12])
            return r2

        # Level 3: 上下文重生成 (核心 +/- 不变, 仅替换 context lines)
        adapted = self._regenerate_patch(mapped_diff, rp_path)
        if adapted:
            r3 = self._apply_check(adapted, rp_path, [])
            if r3.applies_cleanly:
                r3.apply_method = "regenerated"
                r3.stat_output = self._get_stat(adapted, target_version)
                r3.adapted_patch = adapted
                r3.error_output = (
                    "(上下文重生成成功: 从目标文件提取正确 context, "
                    "核心 +/- 改动行不变)")
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
                    "(冲突适配成功: - 行已替换为目标文件实际内容, "
                    "+ 行不变, 需人工审查语义)")
                logger.info("[DryRun] 冲突适配成功: %s",
                            patch.commit_id[:12])
                return r4

        logger.info("[DryRun] 补丁 %s 所有策略均失败: %d 文件冲突, "
                    "%d hunk 已分析",
                    patch.commit_id[:12], len(r0.conflicting_files),
                    len(r0.conflict_hunks))
        return r0

    # ─── 路径映射 ─────────────────────────────────────────────────

    def _rewrite_diff_paths(self, diff_text: str) -> str:
        """将 diff 中的 upstream 路径映射为 local 路径"""
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
        """
        在目标仓库中查找文件的实际路径。
        先尝试原始路径, 再尝试 path_mapper 映射的所有变体。
        """
        target = os.path.join(repo_path, file_path)
        if os.path.isfile(target):
            return target

        if self.path_mapper:
            for variant in self.path_mapper.translate(file_path):
                if variant != file_path:
                    t = os.path.join(repo_path, variant)
                    if os.path.isfile(t):
                        logger.debug("[DryRun] 路径映射: %s → %s",
                                     file_path, variant)
                        return t
        return None

    # ─── 冲突分析 (核心) ────────────────────────────────────────────

    def _analyze_conflicts(self, diff_text: str, repo_path: str) -> dict:
        """
        逐 hunk 分析冲突原因。
        1. 提取 patch 期望的 - 行
        2. 利用 hunk header 行号提示 + 多级搜索定位
        3. 比较 expected vs actual, 分级
        4. 尝试生成冲突适配 patch
        """
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
                expected = [l[1:] for l in hunk_lines if l.startswith("-")]
                added = [l[1:] for l in hunk_lines if l.startswith("+")]
                context_lines = [
                    l[1:] if l.startswith(" ") else l
                    for l in hunk_lines
                    if not l.startswith("+") and not l.startswith("-")
                ]

                # 从 hunk header 提取行号提示
                hint_line = self._parse_hunk_line_hint(hunk_header)

                # 多策略定位
                pos = self._locate_in_file(
                    expected, context_lines, file_lines, hint_line)

                if pos is None:
                    hunk_analyses.append({
                        "file": file_path, "severity": "L3",
                        "reason": "无法在目标文件中定位对应代码区域"
                                  " (所有搜索策略均未命中)",
                        "expected": expected[:8], "actual": [],
                        "added": added[:8],
                        "hint_line": hint_line,
                    })
                    any_l3 = True
                    adapted_parts.append(hunk_header)
                    adapted_parts.append("\n".join(hunk_lines))
                    continue

                n_expected = len(expected) if expected else len(context_lines)
                actual = file_lines[pos:pos + n_expected]

                sim, changed_lines = self._compare_lines(
                    expected, actual, pos)

                if sim >= 0.85:
                    severity, reason = "L1", (
                        "轻微差异 — 仅部分行有细微变动, 可自动适配")
                elif sim >= 0.50:
                    severity, reason = "L2", (
                        "中度差异 — 部分代码被中间 commit 修改, "
                        "需人工审查适配结果")
                else:
                    severity, reason = "L3", (
                        "重大差异 — 代码被大幅改写, 需人工手动合入")

                hunk_analyses.append({
                    "file": file_path,
                    "severity": severity,
                    "similarity": round(sim, 3),
                    "reason": reason,
                    "expected": expected[:10],
                    "actual": actual[:10],
                    "added": added[:10],
                    "changed_lines": changed_lines[:6],
                    "location": pos + 1,
                })

                if severity != "L3":
                    ctx_before = 3
                    start = max(0, pos - ctx_before)
                    rebuilt = []
                    for i in range(start, pos):
                        rebuilt.append(" " + file_lines[i])
                    for a_line in actual:
                        rebuilt.append("-" + a_line)
                    for a_line in added:
                        rebuilt.append("+" + a_line)
                    end_ctx = min(len(file_lines), pos + n_expected + 3)
                    for i in range(pos + n_expected, end_ctx):
                        rebuilt.append(" " + file_lines[i])

                    old_c = sum(1 for l in rebuilt
                                if l.startswith(" ") or l.startswith("-"))
                    new_c = sum(1 for l in rebuilt
                                if l.startswith(" ") or l.startswith("+"))
                    new_hh = f"@@ -{start+1},{old_c} +{start+1},{new_c} @@"
                    adapted_parts.append(new_hh)
                    adapted_parts.append("\n".join(rebuilt))
                else:
                    any_l3 = True
                    adapted_parts.append(hunk_header)
                    adapted_parts.append("\n".join(hunk_lines))

        adapted_diff = None
        if hunk_analyses and not all(h["severity"] == "L3"
                                     for h in hunk_analyses):
            adapted_diff = "\n".join(adapted_parts) + "\n"

        return {"hunks": hunk_analyses, "adapted_diff": adapted_diff}

    # ─── 核心定位算法 ─────────────────────────────────────────────

    def _locate_in_file(self, expected: List[str],
                        context_lines: List[str],
                        file_lines: List[str],
                        hint_line: Optional[int] = None) -> Optional[int]:
        """
        多策略在文件中定位 hunk 对应位置:
        1. 精确序列匹配 (strip 后完全一致)
        2. 行号提示 + 局部窗口搜索 (利用 hunk header)
        3. 逐行模糊匹配 (SequenceMatcher)
        4. Context 行定位
        5. 首行最佳匹配
        """
        # 合并搜索序列: expected 优先, 否则用 context
        search_seq = expected if expected else context_lines
        if not search_seq:
            return None

        # 策略1: 精确序列匹配
        pos = self._find_exact_sequence(search_seq, file_lines)
        if pos is not None:
            return pos

        # 策略2: 行号提示 + 窗口内模糊搜索
        if hint_line is not None and hint_line > 0:
            pos = self._find_near_hint(search_seq, file_lines, hint_line)
            if pos is not None:
                return pos

        # 策略3: 全局逐行模糊匹配
        pos = self._find_fuzzy_sequence(search_seq, file_lines)
        if pos is not None:
            return pos

        # 策略4: 用 context 行重新尝试 (如果 expected 失败)
        if expected and context_lines:
            for method in [self._find_exact_sequence,
                           self._find_fuzzy_sequence]:
                pos = method(context_lines, file_lines)
                if pos is not None:
                    return pos

        # 策略5: 首行最佳匹配
        if search_seq:
            return self._find_best_single_line(search_seq[0], file_lines)

        return None

    def _find_exact_sequence(self, needle: List[str],
                             haystack: List[str]) -> Optional[int]:
        """精确匹配 (strip 后)"""
        if not needle:
            return None
        n = len(needle)
        ns = [l.strip() for l in needle]
        hs = [l.strip() for l in haystack]
        for i in range(len(hs) - n + 1):
            if hs[i:i + n] == ns:
                return i
        return None

    def _find_near_hint(self, needle: List[str],
                        haystack: List[str],
                        hint_line: int,
                        window: int = 100) -> Optional[int]:
        """
        在 hunk header 指示的行号附近搜索。
        先精确, 再逐行模糊。窗口默认 ±100 行。
        """
        if not needle:
            return None
        n = len(needle)
        ns = [l.strip() for l in needle]
        hs = [l.strip() for l in haystack]

        start = max(0, hint_line - 1 - window)
        end = min(len(hs) - n + 1, hint_line - 1 + window)

        # 精确
        for i in range(start, end):
            if hs[i:i + n] == ns:
                return i

        # 逐行模糊
        best_pos, best_score = None, 0
        for i in range(start, end):
            score = self._line_fuzzy_score(ns, hs[i:i + n])
            if score > best_score and score >= 0.55:
                best_score = score
                best_pos = i
        return best_pos

    def _find_fuzzy_sequence(self, needle: List[str],
                             haystack: List[str]) -> Optional[int]:
        """
        逐行模糊匹配: 对每对 (needle_line, haystack_line) 计算
        SequenceMatcher.ratio(), 求加权平均。阈值 0.55。
        """
        if not needle:
            return None
        n = len(needle)
        if n > len(haystack):
            return None
        ns = [l.strip() for l in needle]
        hs = [l.strip() for l in haystack]

        best_pos, best_score = None, 0
        for i in range(len(hs) - n + 1):
            score = self._line_fuzzy_score(ns, hs[i:i + n])
            if score > best_score and score >= 0.55:
                best_score = score
                best_pos = i
        return best_pos

    @staticmethod
    def _line_fuzzy_score(a_lines: List[str],
                          b_lines: List[str]) -> float:
        """
        逐行计算 SequenceMatcher 相似度, 返回加权平均。
        空行/短行权重降低, 避免被 '{' '}' 等干扰。
        """
        if not a_lines or len(a_lines) != len(b_lines):
            return 0.0
        total_w, total_s = 0.0, 0.0
        for a, b in zip(a_lines, b_lines):
            w = max(1.0, len(a) / 10.0)
            if a == b:
                s = 1.0
            else:
                s = difflib.SequenceMatcher(None, a, b).ratio()
            total_w += w
            total_s += w * s
        return total_s / total_w if total_w > 0 else 0.0

    def _find_best_single_line(self, needle: str,
                               haystack: List[str]) -> Optional[int]:
        """用单行模糊匹配找最佳位置"""
        needle_s = needle.strip()
        if not needle_s or len(needle_s) < 4:
            return None
        best_pos, best_ratio = None, 0.0
        for i, line in enumerate(haystack):
            r = difflib.SequenceMatcher(
                None, needle_s, line.strip()).ratio()
            if r > best_ratio and r >= 0.6:
                best_ratio = r
                best_pos = i
        return best_pos

    @staticmethod
    def _compare_lines(expected: List[str], actual: List[str],
                       pos: int) -> tuple:
        """逐行比较, 返回 (similarity, changed_lines)"""
        if not expected:
            return 0.0, []
        sim = difflib.SequenceMatcher(
            None,
            [l.strip() for l in expected],
            [l.strip() for l in actual],
        ).ratio()
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
        """从 @@ -X,Y +Z,W @@ 提取旧文件起始行号"""
        m = re.match(r"@@\s+-(\d+)", hunk_header)
        return int(m.group(1)) if m else None

    # ─── 上下文重生成 ─────────────────────────────────────────────

    def _regenerate_patch(self, diff_text: str,
                          repo_path: str) -> Optional[str]:
        """
        从目标文件重新生成 context lines。核心 +/- 不变。

        算法:
        1. 解析 diff 为 per-file hunks
        2. 提取每个 hunk 的 removed(-) 行
        3. 用多策略定位在目标文件中的位置
        4. 从目标文件提取正确 context, 重建 hunk
        """
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
                # 正确提取 removed 和 context 行 (不使用 zip, 避免对齐问题)
                removed = [l[1:] for l in hunk_lines if l.startswith("-")]
                context = [
                    l[1:] if l.startswith(" ") else l
                    for l in hunk_lines
                    if not l.startswith("+") and not l.startswith("-")
                ]

                hint_line = self._parse_hunk_line_hint(hunk_header)
                search_seq = removed if removed else context
                pos = self._locate_in_file(
                    search_seq, context, target_lines, hint_line)

                if pos is None:
                    new_parts.append(hunk_header)
                    new_parts.append("\n".join(hunk_lines))
                    continue

                any_adapted = True
                ctx_before, ctx_after = 3, 3
                start = max(0, pos - ctx_before)

                rebuilt = []
                for i in range(start, pos):
                    rebuilt.append(" " + target_lines[i])

                idx = pos
                for hl in hunk_lines:
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

                end_ctx = min(len(target_lines), idx + ctx_after)
                for i in range(idx, end_ctx):
                    rebuilt.append(" " + target_lines[i])

                old_count = sum(1 for l in rebuilt
                                if l.startswith(" ") or l.startswith("-"))
                new_count = sum(1 for l in rebuilt
                                if l.startswith(" ") or l.startswith("+"))
                new_hdr = (f"@@ -{start + 1},{old_count} "
                           f"+{start + 1},{new_count} @@")
                new_parts.append(new_hdr)
                new_parts.append("\n".join(rebuilt))

        if not any_adapted:
            return None

        return "\n".join(new_parts) + "\n"

    # ─── 内部方法 ─────────────────────────────────────────────────

    def _prepare(self, patch: PatchInfo,
                 target_version: str) -> Optional[DryRunResult]:
        """校验输入, 返回 None 表示可以继续"""
        result = DryRunResult()
        if not patch.diff_code:
            result.error_output = "补丁无diff内容"
            logger.warning("[DryRun] 补丁 %s 无diff内容", patch.commit_id[:12])
            return result
        rp = self.git_mgr._get_repo_path(target_version)
        if not rp or not os.path.exists(rp):
            result.error_output = f"仓库路径不可用: {target_version}"
            return result
        diff_text = self._extract_pure_diff(patch.diff_code)
        if not diff_text:
            result.error_output = "无法提取有效的diff内容"
            return result
        return None

    def _try_apply(self, patch: PatchInfo, target_version: str,
                   method: str = "strict") -> DryRunResult:
        """单策略试应用"""
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

    def _apply_check(self, diff_text: str, repo_path: str,
                     extra_args: list) -> DryRunResult:
        """调用 git apply --check"""
        import subprocess
        result = DryRunResult()
        patch_file = self._write_temp_patch(diff_text)
        try:
            cmd = ["git", "apply", "--check"] + extra_args + [patch_file]
            proc = subprocess.run(
                cmd, cwd=repo_path, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=60,
            )
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

    def _get_stat(self, diff_text: str, target_version: str) -> str:
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
        """解析 unified diff → [(file_path, header_lines, [(hunk_header, hunk_lines)])]"""
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
                        hunks.append((current_hunk_header, current_hunk_lines))
                    results.append((current_file, header_lines, hunks))

                m = re.search(r"b/(.*)", line)
                current_file = m.group(1) if m else None
                header_lines = [line]
                hunks = []
                current_hunk_header = None
                current_hunk_lines = []
            elif line.startswith("---") or line.startswith("+++"):
                header_lines.append(line)
            elif line.startswith("@@"):
                if current_hunk_header:
                    hunks.append((current_hunk_header, current_hunk_lines))
                current_hunk_header = line
                current_hunk_lines = []
            elif current_hunk_header is not None:
                current_hunk_lines.append(line)
            elif current_file is not None:
                header_lines.append(line)

        if current_file is not None:
            if current_hunk_header:
                hunks.append((current_hunk_header, current_hunk_lines))
            results.append((current_file, header_lines, hunks))

        return results if results else None

    # ─── 工具方法 ─────────────────────────────────────────────────

    @staticmethod
    def _extract_pure_diff(text: str) -> Optional[str]:
        """从完整 commit 输出中提取纯 diff"""
        lines = text.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("diff --git"):
                return "\n".join(lines[i:])
        return None

    @staticmethod
    def _write_temp_patch(diff_text: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".patch", prefix="dryrun_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(diff_text)
        return path

    @staticmethod
    def _parse_conflicts(stderr: str) -> List[str]:
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
