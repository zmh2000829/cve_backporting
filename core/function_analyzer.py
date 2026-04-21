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
    end_line: int = 0
    signature: str = ""
    return_type: str = ""
    parameters: List[str] = field(default_factory=list)
    callers: List[str] = field(default_factory=list)  # 调用者函数名
    callees: List[str] = field(default_factory=list)  # 被调用者函数名
    indirect_calls: List[str] = field(default_factory=list)  # 函数指针/间接调用
    modified_lines: List[int] = field(default_factory=list)  # 被修改的行号
    parse_uncertain: bool = False
    parse_warnings: List[str] = field(default_factory=list)


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
        self.c_pseudo_calls = {
            "sizeof", "typeof", "__typeof__", "__builtin_types_compatible_p",
            "__builtin_expect", "__builtin_choose_expr", "__builtin_offsetof",
            "likely", "unlikely", "min", "max", "clamp", "roundup",
            "rounddown", "ARRAY_SIZE", "BUILD_BUG_ON", "IS_ENABLED",
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
            collected = self._collect_function_signature(lines, i)
            if not collected:
                i += 1
                continue

            signature, brace_idx = collected
            func_info = self._parse_function_definition(
                signature, lines, i, file_path
            )
            if not func_info:
                i += 1
                continue

            _, end_idx = self.extract_function_body(lines, i)
            func_info.end_line = end_idx + 1
            if end_idx >= min(i + 500, len(lines)) - 1:
                func_info.parse_uncertain = True
                func_info.parse_warnings.append("function_body_scan_limit")
            if brace_idx != i and "{" not in lines[i]:
                func_info.parse_warnings.append("multi_line_signature")
            functions.append(func_info)
            i = max(i + 1, end_idx + 1)

        return functions

    def _collect_function_signature(self, lines: List[str],
                                    line_idx: int) -> Optional[Tuple[str, int]]:
        """收集可能跨多行的 C 函数签名，返回 (signature, brace_line_idx)。"""
        first = lines[line_idx].strip()
        if self._skip_signature_start(first):
            return None

        parts: List[str] = []
        paren_depth = 0
        saw_paren = False
        max_signature_lines = 12

        for j in range(line_idx, min(line_idx + max_signature_lines, len(lines))):
            raw = lines[j].strip()
            if not raw:
                if parts:
                    return None
                continue
            if raw.startswith("#") or raw.startswith("//") or raw.startswith("/*") or raw.startswith("*"):
                return None

            parts.append(raw)
            paren_depth += raw.count("(") - raw.count(")")
            saw_paren = saw_paren or "(" in raw
            signature = " ".join(parts)

            if saw_paren and paren_depth <= 0:
                if self._looks_like_declaration_or_macro(signature):
                    return None
                if "{" in raw:
                    return signature, j
                if j + 1 < len(lines) and lines[j + 1].strip() == "{":
                    return signature + " {", j + 1
                if raw.endswith(";"):
                    return None

            if not saw_paren and raw.endswith(";"):
                return None

        return None

    def _skip_signature_start(self, line: str) -> bool:
        if not line:
            return True
        if line.startswith(("//", "/*", "*", "#")):
            return True
        if re.match(r"^(if|for|while|switch|return|else|do|case)\b", line):
            return True
        return False

    def _looks_like_declaration_or_macro(self, signature: str) -> bool:
        sig = re.sub(r"\s+", " ", signature or "").strip()
        if not sig or sig.endswith(";"):
            return True
        if re.search(r"\(\s*\*\s*[A-Za-z_]\w*\s*\)", sig):
            return True
        if re.match(r"^[A-Z_][A-Z0-9_]*\s*\(", sig):
            return True
        if "=" in sig and "{" not in sig:
            return True
        return False

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
        source_lines = file_content.split("\n")
        for func in all_functions:
            body, _ = self.extract_function_body(source_lines, func.line_number - 1)
            func.callees = self.extract_callees(body)
            func.indirect_calls = self.extract_indirect_calls(body)
            if func.indirect_calls:
                func.parse_uncertain = True
                func.parse_warnings.append("indirect_function_pointer_call")

        # 找出被修改的函数
        modified_funcs = []
        for func in all_functions:
            end_line = func.end_line or func.line_number
            if any(func.line_number <= line <= end_line for line in modified_lines):
                func.modified_lines = [
                    l for l in modified_lines
                    if func.line_number <= l <= end_line
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
        return self._collect_function_signature(lines, line_idx) is not None

    def _parse_function_definition(self, line: str,
                                   lines: List[str],
                                   line_idx: int,
                                   file_path: str) -> Optional[FunctionInfo]:
        """解析函数定义"""
        try:
            line = re.sub(r"\s+", " ", line.replace("{", " { ")).strip()
            # 提取函数名
            paren_start = line.find("(")
            if paren_start == -1:
                return None
            before_func = line[:paren_start]
            name_tokens = re.findall(r"[A-Za-z_]\w*", before_func)
            if not name_tokens:
                return None
            func_name = name_tokens[-1]

            # 跳过 C 关键字
            if func_name in self.c_keywords:
                return None

            # 提取参数
            paren_end = self._find_matching_paren(line, paren_start)
            if paren_start == -1 or paren_end == -1:
                return None

            params_str = line[paren_start + 1:paren_end]
            parameters = [p.strip() for p in params_str.split(",") if p.strip()]

            # 提取返回类型
            return_type = before_func[:before_func.rfind(func_name)].strip()
            return_type = re.sub(r"\s+", " ", return_type).strip()

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

    @staticmethod
    def _find_matching_paren(text: str, start: int) -> int:
        depth = 0
        for idx in range(start, len(text)):
            ch = text[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return idx
        return -1

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

    def extract_callees(self, func_body: str) -> List[str]:
        """从函数体中提取被调用的函数名"""
        brace = (func_body or "").find("{")
        if brace >= 0:
            func_body = func_body[brace + 1:]
        callees = set()
        for m in re.finditer(r'\b([a-zA-Z_]\w*)\s*\(', func_body):
            name = m.group(1)
            if name in self.c_keywords or name in self.c_pseudo_calls or name.isupper():
                continue

            # 跳过成员访问/函数指针字段等“看起来像调用、实际上不是符号调用”的场景。
            prefix = func_body[max(0, m.start() - 8):m.start()].rstrip()
            if prefix.endswith(("->", ".")):
                continue
            if re.search(r"\(\s*\*\s*$", prefix):
                continue

            # 跳过 GCC/Clang builtin 与 __ 开头的伪调用。
            if name.startswith("__builtin_"):
                continue

            if name not in self.c_keywords and not name.isupper():
                callees.add(name)
        return sorted(callees)

    def extract_indirect_calls(self, func_body: str) -> List[str]:
        """提取 `(*fn)(...)` 形式的函数指针调用，用于标记不确定调用边。"""
        brace = (func_body or "").find("{")
        if brace >= 0:
            func_body = func_body[brace + 1:]
        calls = set()
        for m in re.finditer(
            r"\(\s*\*\s*([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*\)\s*\(",
            func_body or "",
        ):
            calls.add(re.split(r"->|\.", m.group(1))[-1])
        return sorted(calls)

    def extract_function_body(self, lines: List[str],
                              start_idx: int) -> Tuple[str, int]:
        """
        从函数定义行开始，提取完整函数体（通过大括号配对）。
        返回 (body_text, end_idx)。
        """
        depth = 0
        body_lines: List[str] = []
        started = False

        for i in range(start_idx, min(start_idx + 500, len(lines))):
            line = lines[i]
            body_lines.append(line)
            for ch in line:
                if ch == '{':
                    depth += 1
                    started = True
                elif ch == '}':
                    depth -= 1
            if started and depth <= 0:
                return "\n".join(body_lines), i
        return "\n".join(body_lines), min(start_idx + 500, len(lines) - 1)

    def detect_data_structures(self, code: str) -> List[Dict]:
        """
        检测代码中涉及的关键数据结构和同步原语。
        返回列表: [{"type": "lock/refcount/rcu/...", "name": str, "usage": str}]
        """
        results: List[Dict] = []
        patterns = [
            (r'\b(spin_lock|spin_unlock|spin_lock_irq(?:save)?|spin_unlock_irq(?:restore)?)\s*\(\s*&?(\w+)',
             "spinlock"),
            (r'\b(mutex_lock|mutex_unlock|mutex_lock_interruptible)\s*\(\s*&?(\w+)',
             "mutex"),
            (r'\b(rcu_read_lock|rcu_read_unlock|rcu_dereference|rcu_assign_pointer)\b',
             "rcu"),
            (r'\b(kref_get|kref_put|refcount_inc|refcount_dec|refcount_set|atomic_inc|atomic_dec)\s*\(\s*&?(\w+)',
             "refcount"),
            (r'\b(kfree|kzalloc|kmalloc|kvmalloc|vmalloc|vfree|kvfree)\s*\(',
             "memory"),
            (r'\b(get_user|put_user|copy_from_user|copy_to_user)\s*\(',
             "user_access"),
        ]
        seen = set()
        for pat, dtype in patterns:
            for m in re.finditer(pat, code):
                key = (dtype, m.group(0)[:60])
                if key not in seen:
                    seen.add(key)
                    name = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                    results.append({
                        "type": dtype,
                        "name": name,
                        "usage": m.group(0).strip()[:80],
                    })
        return results

    def detect_security_patterns(self, code: str) -> List[Dict]:
        """
        检测常见的安全/漏洞模式。
        返回 [{"pattern": str, "description": str, "match": str}]
        """
        results: List[Dict] = []
        checks = [
            (r'\bkfree\s*\([^)]+\)(?:(?!\s*=\s*NULL).)*$',
             "use_after_free_risk",
             "kfree 后未置 NULL，可能存在 UAF 风险"),
            (r'if\s*\(\s*!\s*(\w+)\s*\)(?:(?!return|goto).)*$',
             "missing_null_check_action",
             "NULL 检查后可能缺少 return/goto"),
            (r'(memcpy|memmove|strncpy)\s*\([^,]+,[^,]+,\s*(\w+)\s*\)',
             "bounded_copy",
             "有界内存拷贝，需确认长度参数来源"),
            (r'(copy_from_user|get_user)\s*\(',
             "user_input",
             "用户空间输入，需检查边界验证"),
            (r'(\w+)\s*=\s*(kzalloc|kmalloc|kstrdup)\s*\([^)]*\);\s*\n(?:(?!if\s*\(\s*!\s*\1).)*$',
             "missing_alloc_check",
             "内存分配后可能缺少 NULL 检查"),
        ]
        for pat, name, desc in checks:
            for m in re.finditer(pat, code, re.MULTILINE):
                results.append({
                    "pattern": name,
                    "description": desc,
                    "match": m.group(0).strip()[:100],
                })
        return results

    def build_call_topology(self, file_content: str,
                            file_path: str) -> Dict:
        """
        构建文件内的函数调用拓扑。
        返回: {func_name: {"callers": [...], "callees": [...], "line": int}}
        """
        functions = self.extract_functions(file_content, file_path)
        lines = file_content.split("\n")
        topo: Dict[str, Dict] = {}

        for func in functions:
            body, _ = self.extract_function_body(lines, func.line_number - 1)
            callees = self.extract_callees(body)
            indirect_calls = self.extract_indirect_calls(body)
            func.callees = callees
            func.indirect_calls = indirect_calls
            if indirect_calls:
                func.parse_uncertain = True
                func.parse_warnings.append("indirect_function_pointer_call")
            topo[func.name] = {
                "callees": callees,
                "callers": [],
                "line": func.line_number,
                "end_line": func.end_line,
                "signature": func.signature,
                "indirect_calls": indirect_calls,
                "parse_uncertain": func.parse_uncertain,
            }

        all_names = set(topo.keys())
        for fname, info in topo.items():
            for callee in info["callees"]:
                if callee in all_names and callee != fname:
                    topo[callee]["callers"].append(fname)

        return topo

    def build_cross_file_call_graph(
        self,
        file_contents: List[Tuple[str, str]],
        global_func_names: Optional[Set[str]] = None,
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """
        在多个已修改文件之间合并调用关系：若 A.c 调用 B.c 中定义的符号且二者均在
        global_func_names 中，则建立跨文件边。用于策略引擎的扇出/牵连告警。

        Returns:
            (callees_of, callers_of) 均为 函数名 -> 去重后的相对方函数名列表
        """
        if not file_contents:
            return {}, {}

        definition_counts: Dict[str, int] = {}
        local_names_by_file: Dict[str, Set[str]] = {}
        if global_func_names is None:
            global_func_names = set()
            for file_path, content in file_contents:
                local_names = set()
                for fn in self.extract_functions(content, file_path):
                    global_func_names.add(fn.name)
                    local_names.add(fn.name)
                    definition_counts[fn.name] = definition_counts.get(fn.name, 0) + 1
                local_names_by_file[file_path] = local_names
        else:
            for file_path, content in file_contents:
                local_names = set()
                for fn in self.extract_functions(content, file_path):
                    local_names.add(fn.name)
                    definition_counts[fn.name] = definition_counts.get(fn.name, 0) + 1
                local_names_by_file[file_path] = local_names

        unique_global_names = {name for name, count in definition_counts.items() if count == 1}

        callees_of: Dict[str, Set[str]] = {}
        callers_of: Dict[str, Set[str]] = {}

        for fpath, content in file_contents:
            topo = self.build_call_topology_extended(
                content,
                fpath,
                local_func_names=local_names_by_file.get(fpath, set()),
                external_func_names=unique_global_names,
            )
            for fname, info in topo.items():
                callees_of.setdefault(fname, set()).update(info.get("callees") or [])
                for c in info.get("callees") or []:
                    callers_of.setdefault(c, set()).add(fname)

        return (
            {k: sorted(v) for k, v in callees_of.items()},
            {k: sorted(v) for k, v in callers_of.items()},
        )

    def build_call_topology_extended(
        self,
        file_content: str,
        file_path: str,
        local_func_names: Set[str],
        external_func_names: Set[str],
    ) -> Dict:
        """
        同 build_call_topology，但 callees 可指向其它文件中的符号（只要在 global_func_names 内）。
        """
        functions = self.extract_functions(file_content, file_path)
        lines = file_content.split("\n")
        topo: Dict[str, Dict] = {}

        for func in functions:
            body, _ = self.extract_function_body(lines, func.line_number - 1)
            raw_callees = self.extract_callees(body)
            indirect_calls = self.extract_indirect_calls(body)
            linked = sorted(
                {
                    c
                    for c in raw_callees
                    if c != func.name and (c in local_func_names or c in external_func_names)
                }
            )
            func.callees = linked
            func.indirect_calls = indirect_calls
            if indirect_calls:
                func.parse_uncertain = True
                func.parse_warnings.append("indirect_function_pointer_call")
            topo[func.name] = {
                "callees": linked,
                "callers": [],
                "line": func.line_number,
                "end_line": func.end_line,
                "signature": func.signature,
                "file": file_path,
                "indirect_calls": indirect_calls,
                "parse_uncertain": func.parse_uncertain,
            }

        for fname, info in topo.items():
            for callee in info["callees"]:
                if callee in topo and callee != fname:
                    topo[callee]["callers"].append(fname)

        return topo

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
