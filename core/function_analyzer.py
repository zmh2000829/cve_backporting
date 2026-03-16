"""
函数分析 — 提取函数定义、调用关系和修改影响

用于分析补丁修改的函数及其调用链，帮助理解修改的影响范围。
"""

import re
import logging
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FunctionInfo:
    """函数信息"""
    name: str
    file_path: str
    line_number: int
    signature: str = ""
    return_type: str = ""
    parameters: List[str] = field(default_factory=list)
    callers: List[str] = field(default_factory=list)  # 调用者函数名
    callees: List[str] = field(default_factory=list)  # 被调用者函数名
    modified_lines: List[int] = field(default_factory=list)  # 被修改的行号


class FunctionAnalyzer:
    """C 代码函数分析"""

    def __init__(self):
        # C 关键字
        self.c_keywords = {
            'void', 'int', 'char', 'float', 'double', 'long', 'short',
            'unsigned', 'signed', 'struct', 'union', 'enum', 'static',
            'extern', 'const', 'volatile', 'inline', 'restrict',
            'return', 'if', 'else', 'for', 'while', 'do', 'switch',
            'case', 'break', 'continue', 'goto', 'typedef'
        }

    def extract_functions(self, file_content: str,
                         file_path: str) -> List[FunctionInfo]:
        """
        从文件内容中提取所有函数定义。

        Returns:
            函数信息列表
        """
        functions = []
        lines = file_content.split("\n")

        i = 0
        while i < len(lines):
            line = lines[i]

            # 简单的函数定义检测：行末有 { 或下一行有 {
            if self._is_function_definition(line, lines, i):
                func_info = self._parse_function_definition(
                    line, lines, i, file_path
                )
                if func_info:
                    functions.append(func_info)

            i += 1

        return functions

    def analyze_patch_impact(self, patch_diff: str,
                            file_content: str,
                            file_path: str) -> Dict:
        """
        分析补丁对函数的影响。

        Returns:
            {
                "modified_functions": [FunctionInfo, ...],
                "affected_functions": [FunctionInfo, ...],  # 调用被修改函数的函数
                "impact_summary": str
            }
        """
        # 提取补丁修改的行号
        modified_lines = self._extract_modified_lines(patch_diff)
        if not modified_lines:
            return {
                "modified_functions": [],
                "affected_functions": [],
                "impact_summary": "无法提取修改行号"
            }

        # 提取所有函数
        all_functions = self.extract_functions(file_content, file_path)

        # 找出被修改的函数
        modified_funcs = []
        for func in all_functions:
            if any(line in modified_lines for line in range(
                    func.line_number,
                    func.line_number + 100)):  # 简化：假设函数不超过 100 行
                func.modified_lines = [
                    l for l in modified_lines
                    if func.line_number <= l < func.line_number + 100
                ]
                modified_funcs.append(func)

        # 找出调用被修改函数的函数
        affected_funcs = []
        for func in all_functions:
            if any(mf.name in func.callees for mf in modified_funcs):
                affected_funcs.append(func)

        # 生成影响摘要
        impact_summary = self._generate_impact_summary(
            modified_funcs, affected_funcs
        )

        return {
            "modified_functions": modified_funcs,
            "affected_functions": affected_funcs,
            "impact_summary": impact_summary
        }

    def _is_function_definition(self, line: str,
                                lines: List[str],
                                line_idx: int) -> bool:
        """检测是否是函数定义行"""
        line = line.strip()

        # 跳过注释、空行、预处理指令
        if not line or line.startswith("//") or line.startswith("/*") or line.startswith("#"):
            return False

        # 检查是否包含 ( 和 )
        if "(" not in line or ")" not in line:
            return False

        # 检查是否是函数指针或宏
        if "*" in line.split("(")[0]:
            return False

        # 检查是否有 { 或下一行有 {
        has_brace = "{" in line
        if not has_brace and line_idx + 1 < len(lines):
            next_line = lines[line_idx + 1].strip()
            has_brace = next_line == "{"

        return has_brace

    def _parse_function_definition(self, line: str,
                                   lines: List[str],
                                   line_idx: int,
                                   file_path: str) -> Optional[FunctionInfo]:
        """解析函数定义"""
        try:
            # 提取函数名
            match = re.search(r'(\w+)\s*\(', line)
            if not match:
                return None

            func_name = match.group(1)

            # 跳过 C 关键字
            if func_name in self.c_keywords:
                return None

            # 提取参数
            paren_start = line.find("(")
            paren_end = line.find(")")
            if paren_start == -1 or paren_end == -1:
                return None

            params_str = line[paren_start + 1:paren_end]
            parameters = [p.strip() for p in params_str.split(",") if p.strip()]

            # 提取返回类型
            before_func = line[:paren_start]
            tokens = before_func.split()
            return_type = tokens[-2] if len(tokens) >= 2 else ""

            return FunctionInfo(
                name=func_name,
                file_path=file_path,
                line_number=line_idx + 1,
                signature=line.strip(),
                return_type=return_type,
                parameters=parameters,
            )

        except Exception as e:
            logger.debug(f"解析函数定义失败: {e}")
            return None

    def _extract_modified_lines(self, patch_diff: str) -> Set[int]:
        """从 patch 中提取修改的行号"""
        modified_lines = set()
        lines = patch_diff.split("\n")

        current_line_num = 0
        for line in lines:
            # 检查 hunk 头
            match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', line)
            if match:
                current_line_num = int(match.group(1))
                continue

            # 跳过 diff 头
            if line.startswith("diff --git") or line.startswith("---") or line.startswith("+++"):
                continue

            # 记录修改的行
            if line.startswith("+") or line.startswith("-"):
                if not line.startswith("+++") and not line.startswith("---"):
                    modified_lines.add(current_line_num)
                    if line.startswith("+"):
                        current_line_num += 1
            elif line.startswith(" "):
                current_line_num += 1

        return modified_lines

    def _generate_impact_summary(self, modified_funcs: List[FunctionInfo],
                                 affected_funcs: List[FunctionInfo]) -> str:
        """生成影响摘要"""
        if not modified_funcs:
            return "无修改的函数"

        summary = f"修改了 {len(modified_funcs)} 个函数:\n"
        for func in modified_funcs[:5]:
            summary += f"  - {func.name} (line {func.line_number})\n"

        if affected_funcs:
            summary += f"\n影响了 {len(affected_funcs)} 个调用者:\n"
            for func in affected_funcs[:5]:
                summary += f"  - {func.name} (line {func.line_number})\n"

        return summary
