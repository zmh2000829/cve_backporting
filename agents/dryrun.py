"""
Dry-Run Agent
在不实际修改代码的前提下，试应用补丁到目标仓库：
  - git apply --check 检测是否能干净应用
  - git apply --stat 显示修改统计
  - 解析冲突信息，定位具体失败的文件和hunk
"""

import os
import re
import tempfile
import logging
from typing import List, Optional

from core.models import PatchInfo, DryRunResult
from core.git_manager import GitRepoManager

logger = logging.getLogger(__name__)


class DryRunAgent:
    """补丁试应用Agent"""

    def __init__(self, git_mgr: GitRepoManager):
        self.git_mgr = git_mgr

    def check(self, patch: PatchInfo, target_version: str) -> DryRunResult:
        """
        试应用补丁（不修改工作树）

        流程:
        1. 将diff写入临时文件
        2. git apply --check 检测能否应用
        3. git apply --stat 统计修改
        4. 若失败，解析错误输出定位冲突
        """
        result = DryRunResult()

        if not patch.diff_code:
            result.error_output = "补丁无diff内容"
            logger.warning("[DryRun] 补丁 %s 无diff内容", patch.commit_id[:12])
            return result

        rp = self.git_mgr._get_repo_path(target_version)
        if not rp or not os.path.exists(rp):
            result.error_output = f"仓库路径不可用: {target_version}"
            return result

        # 提取纯diff部分（跳过commit header）
        diff_text = self._extract_pure_diff(patch.diff_code)
        if not diff_text:
            result.error_output = "无法提取有效的diff内容"
            return result

        patch_file = self._write_temp_patch(diff_text)
        result.patch_file = patch_file

        try:
            # stat
            stat_out = self.git_mgr.run_git(
                ["git", "apply", "--stat", patch_file], target_version, timeout=30)
            result.stat_output = stat_out.strip() if stat_out else ""

            # check
            rp_path = self.git_mgr._get_repo_path(target_version)
            import subprocess
            proc = subprocess.run(
                ["git", "apply", "--check", patch_file],
                cwd=rp_path, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
            )

            if proc.returncode == 0:
                result.applies_cleanly = True
                logger.info("[DryRun] 补丁 %s 可以干净应用", patch.commit_id[:12])
            else:
                result.applies_cleanly = False
                result.error_output = proc.stderr.strip()
                result.conflicting_files = self._parse_conflicts(proc.stderr)
                logger.info("[DryRun] 补丁 %s 应用失败: %d 个文件冲突",
                            patch.commit_id[:12], len(result.conflicting_files))

        except Exception as e:
            result.error_output = str(e)
            logger.error("[DryRun] 异常: %s", e)
        finally:
            try:
                os.unlink(patch_file)
            except OSError:
                pass

        return result

    def check_with_3way(self, patch: PatchInfo, target_version: str) -> DryRunResult:
        """使用3-way merge尝试应用（更宽松，能处理部分上下文偏移）"""
        result = self.check(patch, target_version)
        if result.applies_cleanly:
            return result

        # 3-way merge fallback
        if not patch.diff_code:
            return result

        diff_text = self._extract_pure_diff(patch.diff_code)
        if not diff_text:
            return result

        patch_file = self._write_temp_patch(diff_text)
        try:
            rp_path = self.git_mgr._get_repo_path(target_version)
            import subprocess
            proc = subprocess.run(
                ["git", "apply", "--check", "--3way", patch_file],
                cwd=rp_path, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=60,
            )
            if proc.returncode == 0:
                result.applies_cleanly = True
                result.error_output = "(3-way merge成功)"
                result.conflicting_files = []
                logger.info("[DryRun] 3-way merge成功: %s", patch.commit_id[:12])
        except Exception:
            pass
        finally:
            try:
                os.unlink(patch_file)
            except OSError:
                pass

        return result

    # ─── internals ───────────────────────────────────────────────────

    @staticmethod
    def _extract_pure_diff(text: str) -> Optional[str]:
        """从完整commit输出中提取纯diff部分"""
        lines = text.split("\n")
        start = -1
        for i, line in enumerate(lines):
            if line.startswith("diff --git"):
                start = i
                break
        if start < 0:
            return None
        return "\n".join(lines[start:])

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
            # "error: patch failed: drivers/net/foo.c:123"
            m = re.search(r"error:\s+patch failed:\s+(\S+?):\d+", line)
            if m:
                files.add(m.group(1))
                continue
            # "error: drivers/net/foo.c: does not exist in index"
            m = re.search(r"error:\s+(\S+?):\s+does not exist", line)
            if m:
                files.add(m.group(1))
                continue
            # "error: while searching for: ..."
            m = re.search(r"error:\s+(\S+?):\s+No such file", line)
            if m:
                files.add(m.group(1))
        return sorted(files)
