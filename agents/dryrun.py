"""
Dry-Run Agent
多级补丁试应用策略:
  Level 0 - strict:     git apply --check (完整 context 匹配)
  Level 1 - context-C1: git apply --check -C1 (仅需 1 行 context 匹配)
  Level 2 - 3way:       git apply --check --3way (三方合并)
  Level 3 - regenerated: 从目标文件重新生成带正确 context 的补丁

当社区补丁与本地修复代码 100% 一致但因中间 commit 导致 context 偏移时,
Level 1/2/3 可自动适配。
"""

import os
import re
import tempfile
import logging
import difflib
from typing import List, Optional, Tuple

from core.models import PatchInfo, DryRunResult
from core.git_manager import GitRepoManager

logger = logging.getLogger(__name__)


class DryRunAgent:
    """补丁试应用Agent — 多级上下文自适应"""

    def __init__(self, git_mgr: GitRepoManager):
        self.git_mgr = git_mgr

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
          strict → -C1 → --3way → 上下文重生成
        返回第一个成功的结果, 或最后一个失败结果(附带所有尝试记录)。
        """
        base_result = self._prepare(patch, target_version)
        if base_result is not None:
            return base_result

        rp_path = self.git_mgr._get_repo_path(target_version)
        diff_text = self._extract_pure_diff(patch.diff_code)

        # Level 0: strict
        r0 = self._apply_check(diff_text, rp_path, [])
        if r0.applies_cleanly:
            r0.apply_method = "strict"
            r0.stat_output = self._get_stat(diff_text, target_version)
            logger.info("[DryRun] 补丁 %s 可以干净应用 (strict)",
                        patch.commit_id[:12])
            return r0

        # Level 1: -C1 (仅需 1 行 context)
        r1 = self._apply_check(diff_text, rp_path, ["-C1"])
        if r1.applies_cleanly:
            r1.apply_method = "context-C1"
            r1.stat_output = self._get_stat(diff_text, target_version)
            r1.error_output = (
                f"(严格模式失败, -C1 成功: {len(r0.conflicting_files)} 个文件的 "
                "context lines 有偏移但核心改动位置正确)")
            logger.info("[DryRun] 补丁 %s -C1 成功 (context偏移已适配)",
                        patch.commit_id[:12])
            return r1

        # Level 2: --3way
        r2 = self._apply_check(diff_text, rp_path, ["--3way"])
        if r2.applies_cleanly:
            r2.apply_method = "3way"
            r2.stat_output = self._get_stat(diff_text, target_version)
            r2.error_output = "(3-way merge成功)"
            logger.info("[DryRun] 3-way merge成功: %s", patch.commit_id[:12])
            return r2

        # Level 3: 上下文重生成
        adapted = self._regenerate_patch(diff_text, rp_path)
        if adapted:
            r3 = self._apply_check(adapted, rp_path, [])
            if r3.applies_cleanly:
                r3.apply_method = "regenerated"
                r3.stat_output = self._get_stat(adapted, target_version)
                r3.adapted_patch = adapted
                r3.error_output = (
                    "(上下文重生成成功: 从目标仓库文件提取正确的 context lines, "
                    "核心 +/- 改动行不变)")
                logger.info("[DryRun] 上下文重生成成功: %s",
                            patch.commit_id[:12])
                return r3

        # 全部失败 → 逐 hunk 冲突分析
        r0.stat_output = self._get_stat(diff_text, target_version)
        analysis = self._analyze_conflicts(diff_text, rp_path)
        r0.conflict_hunks = analysis["hunks"]

        # 尝试冲突适配: 用目标文件实际行替换 patch 的 - 行, 保留 + 行
        if analysis.get("adapted_diff"):
            r4 = self._apply_check(analysis["adapted_diff"], rp_path, [])
            if r4.applies_cleanly:
                r4.apply_method = "conflict-adapted"
                r4.stat_output = self._get_stat(
                    analysis["adapted_diff"], target_version)
                r4.adapted_patch = analysis["adapted_diff"]
                r4.conflict_hunks = analysis["hunks"]
                r4.error_output = (
                    "(冲突适配成功: 补丁的 - 行已替换为目标文件实际内容, "
                    "+ 行保持不变, 需人工确认语义正确性)")
                logger.info("[DryRun] 冲突适配成功: %s",
                            patch.commit_id[:12])
                return r4

        logger.info("[DryRun] 补丁 %s 所有策略均失败: %d 个文件冲突, "
                    "%d 个 hunk 已分析",
                    patch.commit_id[:12], len(r0.conflicting_files),
                    len(r0.conflict_hunks))
        return r0

    # ─── 冲突分析 (核心) ────────────────────────────────────────────

    def _analyze_conflicts(self, diff_text: str, repo_path: str) -> dict:
        """
        逐 hunk 分析冲突原因。对每个 hunk:
        1. 提取 patch 期望的 - 行 (expected)
        2. 在目标文件中找到最近匹配位置
        3. 比较 expected vs actual, 计算相似度
        4. 分类冲突等级: L1 trivial / L2 minor / L3 significant
        5. 尝试生成适配 patch: 用 actual 替换 expected, 保留 + 行
        """
        parsed = self._parse_hunks_for_regen(diff_text)
        if not parsed:
            return {"hunks": [], "adapted_diff": None}

        hunk_analyses = []
        adapted_parts = []
        all_adaptable = True

        for file_path, header_lines, hunks in parsed:
            target_file = os.path.join(repo_path, file_path)

            if not os.path.isfile(target_file):
                for hh, hl in hunks:
                    hunk_analyses.append({
                        "file": file_path, "severity": "L3",
                        "reason": "文件不存在",
                        "expected": [], "actual": [], "added": [],
                    })
                all_adaptable = False
                adapted_parts.append("\n".join(header_lines))
                for hh, hl in hunks:
                    adapted_parts.append(hh)
                    adapted_parts.append("\n".join(hl))
                continue

            try:
                with open(target_file, "r", encoding="utf-8",
                          errors="replace") as f:
                    file_lines = [l.rstrip("\n") for l in f.readlines()]
            except Exception:
                all_adaptable = False
                adapted_parts.append("\n".join(header_lines))
                for hh, hl in hunks:
                    adapted_parts.append(hh)
                    adapted_parts.append("\n".join(hl))
                continue

            adapted_parts.append("\n".join(header_lines))

            for hunk_header, hunk_lines in hunks:
                expected = [l[1:] for l in hunk_lines if l.startswith("-")]
                added = [l[1:] for l in hunk_lines if l.startswith("+")]
                context = [l[1:] if l.startswith(" ") else l
                           for l in hunk_lines
                           if not l.startswith("+") and not l.startswith("-")]

                # 定位: 先用 expected 行, 再用 context 行
                pos = None
                if expected:
                    pos = self._find_sequence_in_file(expected, file_lines)
                if pos is None and context:
                    pos = self._find_sequence_in_file(context, file_lines)
                if pos is None and expected:
                    # 最后尝试用首行 fuzzy 定位
                    pos = self._find_best_single_line(
                        expected[0], file_lines)

                if pos is None:
                    hunk_analyses.append({
                        "file": file_path, "severity": "L3",
                        "reason": "无法在目标文件中定位对应代码区域",
                        "expected": expected[:8], "actual": [],
                        "added": added[:8],
                    })
                    all_adaptable = False
                    adapted_parts.append(hunk_header)
                    adapted_parts.append("\n".join(hunk_lines))
                    continue

                # 提取目标文件中实际行
                n_expected = len(expected) if expected else len(context)
                actual = file_lines[pos:pos + n_expected]

                # 逐行比较
                sim = difflib.SequenceMatcher(
                    None,
                    [l.strip() for l in expected],
                    [l.strip() for l in actual],
                ).ratio() if expected else 0.0

                changed_lines = []
                for i, (e, a) in enumerate(
                        zip(expected, actual)):
                    if e.strip() != a.strip():
                        changed_lines.append({
                            "line": pos + i + 1,
                            "expected": e.strip(),
                            "actual": a.strip(),
                        })

                if sim >= 0.85:
                    severity = "L1"
                    reason = "轻微差异 — 仅部分行有细微变动, 可自动适配"
                elif sim >= 0.50:
                    severity = "L2"
                    reason = "中度差异 — 部分代码被中间 commit 重构, 需人工审查适配结果"
                else:
                    severity = "L3"
                    reason = "重大差异 — 代码被大幅改写, 需人工手动合入"

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

                # 生成适配 hunk: 用 actual 替换 expected
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
                    all_adaptable = False
                    adapted_parts.append(hunk_header)
                    adapted_parts.append("\n".join(hunk_lines))

        adapted_diff = None
        if hunk_analyses and not all(h["severity"] == "L3"
                                     for h in hunk_analyses):
            adapted_diff = "\n".join(adapted_parts) + "\n"

        return {"hunks": hunk_analyses, "adapted_diff": adapted_diff}

    def _find_best_single_line(self, needle: str,
                               haystack: List[str]) -> Optional[int]:
        """用单行模糊匹配找最佳位置"""
        needle_s = needle.strip()
        if not needle_s:
            return None
        best_pos, best_ratio = None, 0.0
        for i, line in enumerate(haystack):
            r = difflib.SequenceMatcher(
                None, needle_s, line.strip()).ratio()
            if r > best_ratio and r >= 0.6:
                best_ratio = r
                best_pos = i
        return best_pos

    # ─── 内部方法 ─────────────────────────────────────────────────

    def _prepare(self, patch: PatchInfo,
                 target_version: str) -> Optional[DryRunResult]:
        """校验输入, 返回 None 表示可以继续, 否则返回错误结果"""
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

        extra = {"3way": ["--3way"], "context-C1": ["-C1"]}.get(method, [])
        r = self._apply_check(diff_text, rp, extra)
        r.stat_output = self._get_stat(diff_text, target_version)
        if r.applies_cleanly:
            r.apply_method = method
            logger.info("[DryRun] 补丁 %s 可以干净应用 (%s)",
                        patch.commit_id[:12], method)
        else:
            logger.info("[DryRun] 补丁 %s 应用失败 (%s): %d 个文件冲突",
                        patch.commit_id[:12], method, len(r.conflicting_files))
        return r

    def _apply_check(self, diff_text: str, repo_path: str,
                     extra_args: list) -> DryRunResult:
        """调用 git apply --check, 返回结果"""
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
        """获取 git apply --stat 输出"""
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

    # ─── 上下文重生成 (核心算法) ──────────────────────────────────

    def _regenerate_patch(self, diff_text: str,
                          repo_path: str) -> Optional[str]:
        """
        从目标仓库的实际文件中重新生成补丁的 context lines。
        保持 +/- 变更行不变, 仅替换 context 行和行号。

        算法:
        1. 解析原始 diff 为 per-file hunks
        2. 对每个 hunk, 提取 removed(-) 行序列
        3. 在目标文件中用 difflib 定位这些行的实际位置
        4. 从目标文件中提取正确的 context, 重新组装 hunk header
        """
        parsed = self._parse_hunks_for_regen(diff_text)
        if not parsed:
            return None

        new_parts = []
        any_adapted = False

        for file_path, header_lines, hunks in parsed:
            target_file = os.path.join(repo_path, file_path)
            if not os.path.isfile(target_file):
                new_parts.append("\n".join(header_lines))
                for hunk_header, hunk_lines in hunks:
                    new_parts.append(hunk_header)
                    new_parts.append("\n".join(hunk_lines))
                continue

            try:
                with open(target_file, "r", encoding="utf-8",
                          errors="replace") as f:
                    target_lines = f.readlines()
            except Exception:
                new_parts.append("\n".join(header_lines))
                for hh, hl in hunks:
                    new_parts.append(hh)
                    new_parts.append("\n".join(hl))
                continue

            target_stripped = [l.rstrip("\n") for l in target_lines]
            new_parts.append("\n".join(header_lines))

            for _hunk_header, hunk_lines in hunks:
                old_lines = []    # 原始文件中应有的行 (context + removed)
                new_lines = []    # 新文件中应有的行 (context + added)
                for hl in hunk_lines:
                    if hl.startswith("-"):
                        old_lines.append(hl[1:])
                    elif hl.startswith("+"):
                        new_lines.append(hl[1:])
                    else:
                        # context 行 (空格开头或空行)
                        content = hl[1:] if hl.startswith(" ") else hl
                        old_lines.append(content)
                        new_lines.append(content)

                removed = [l for hl, l in zip(hunk_lines, old_lines)
                           if hl.startswith("-")]
                if not removed:
                    # 纯新增 hunk, 用 context 行定位
                    ctx = [l for hl, l in zip(hunk_lines, old_lines)
                           if not hl.startswith("-") and not hl.startswith("+")]
                    pos = self._find_sequence_in_file(ctx, target_stripped)
                else:
                    pos = self._find_sequence_in_file(removed, target_stripped)

                if pos is None:
                    new_parts.append(_hunk_header)
                    new_parts.append("\n".join(hunk_lines))
                    continue

                any_adapted = True
                ctx_before = 3
                ctx_after = 3
                start = max(0, pos - ctx_before)

                rebuilt = []
                for i in range(start, pos):
                    rebuilt.append(" " + target_stripped[i])

                idx = pos
                for hl in hunk_lines:
                    if hl.startswith("-"):
                        rebuilt.append(hl)
                        idx += 1
                    elif hl.startswith("+"):
                        rebuilt.append(hl)
                    else:
                        if idx < len(target_stripped):
                            rebuilt.append(" " + target_stripped[idx])
                            idx += 1
                        else:
                            rebuilt.append(hl)

                end_ctx = min(len(target_stripped), idx + ctx_after)
                for i in range(idx, end_ctx):
                    rebuilt.append(" " + target_stripped[i])

                old_count = sum(1 for l in rebuilt
                                if l.startswith(" ") or l.startswith("-"))
                new_count = sum(1 for l in rebuilt
                                if l.startswith(" ") or l.startswith("+"))
                new_header = (f"@@ -{start + 1},{old_count} "
                              f"+{start + 1},{new_count} @@")
                new_parts.append(new_header)
                new_parts.append("\n".join(rebuilt))

        if not any_adapted:
            return None

        return "\n".join(new_parts) + "\n"

    def _find_sequence_in_file(self, needle: List[str],
                               haystack: List[str]) -> Optional[int]:
        """
        在文件行列表中查找 needle 序列的起始位置。
        先尝试精确匹配, 再尝试 strip 后模糊匹配。
        """
        if not needle:
            return None
        needle_stripped = [l.strip() for l in needle]
        haystack_stripped = [l.strip() for l in haystack]
        n = len(needle_stripped)

        # 精确匹配 (strip 后)
        for i in range(len(haystack_stripped) - n + 1):
            if haystack_stripped[i:i + n] == needle_stripped:
                return i

        # 模糊匹配: 找最长连续子序列
        best_pos, best_score = None, 0
        for i in range(len(haystack_stripped) - n + 1):
            matches = sum(1 for a, b in
                          zip(needle_stripped, haystack_stripped[i:i + n])
                          if a == b)
            if matches > best_score and matches >= max(1, n * 0.7):
                best_score = matches
                best_pos = i

        return best_pos

    def _parse_hunks_for_regen(self, diff_text: str):
        """
        解析 unified diff 为结构化数据: [(file_path, header_lines, [(hunk_header, hunk_lines)])]
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
        """从完整commit输出中提取纯diff部分"""
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
        """从git apply --check的stderr中提取冲突文件"""
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
