"""
PatchReview Agent — 修复补丁逻辑分析

确定性层:
  - 函数修改映射 (修改了哪些函数、怎么改的)
  - 调用拓扑 (modified → callers/callees)
  - 数据结构检测 (锁/引用计数/RCU/内存分配)
  - 安全模式检测 (UAF 风险/NULL 检查缺失/有界拷贝)

LLM 增强层:
  - 补丁代码走读
  - 触发方式分析 (原始漏洞怎么触发，修复方案怎么预防)
  - 安全性综合分析
"""

import logging
import re
from typing import Dict, List, Optional

from core.models import PatchInfo, PatchReview, CodeReviewItem
from core.function_analyzer import FunctionAnalyzer
from core.git_manager import GitRepoManager
from core.llm_client import LLMClient

logger = logging.getLogger(__name__)


class PatchReviewAgent:
    """修复补丁逻辑分析"""

    def __init__(self, git_mgr: GitRepoManager,
                 llm: Optional[LLMClient] = None):
        self.git_mgr = git_mgr
        self.fa = FunctionAnalyzer()
        self.llm = llm

    def analyze(self, fix_patch: PatchInfo,
                target_version: str) -> PatchReview:
        """
        分析修复补丁的逻辑，返回 PatchReview。
        确定性层始终执行，LLM 层按需增强。
        """
        result = PatchReview()

        result.modified_functions = self._extract_modified_funcs(fix_patch)

        result.call_topology = self._build_topology(
            fix_patch, target_version
        )
        result.data_structures = self._detect_data_structures(fix_patch)
        result.code_review_items = self._run_security_checks(
            fix_patch, target_version
        )
        result.security_patterns = [
            item.category for item in result.code_review_items
            if item.severity in ("critical", "warning")
        ]

        result.fix_summary = self._deterministic_summary(fix_patch, result)
        result.trigger_analysis = self._deterministic_trigger(fix_patch)
        result.prevention_mechanism = self._deterministic_prevention(
            fix_patch
        )

        if self.llm and self.llm.enabled:
            self._enhance_with_llm(fix_patch, result)
            result.llm_enhanced = True

        logger.info("[PatchReview] %s: %d modified funcs, %d data structs, "
                    "%d review items",
                    fix_patch.commit_id[:12],
                    len(result.modified_functions),
                    len(result.data_structures),
                    len(result.code_review_items))
        return result

    # ── 确定性分析 ────────────────────────────────────────────────────

    def _extract_modified_funcs(self, patch: PatchInfo) -> List[str]:
        if not patch.diff_code:
            return []
        funcs = set()
        for m in re.finditer(r'^@@.*@@\s+(\w+)', patch.diff_code,
                             re.MULTILINE):
            name = m.group(1)
            if name and len(name) > 2:
                funcs.add(name)
        return sorted(funcs)

    def _build_topology(self, patch: PatchInfo,
                        target_version: str) -> Dict:
        """为补丁涉及的文件构建调用拓扑"""
        topology: Dict = {}
        if not patch.modified_files:
            return topology

        for fpath in patch.modified_files[:5]:
            content = self._get_file_content(fpath, target_version)
            if not content:
                continue
            file_topo = self.fa.build_call_topology(content, fpath)
            if file_topo:
                topology[fpath] = file_topo
        return topology

    def _detect_data_structures(self, patch: PatchInfo) -> List[Dict]:
        if not patch.diff_code:
            return []
        return self.fa.detect_data_structures(patch.diff_code)

    def _run_security_checks(self, patch: PatchInfo,
                             target_version: str) -> List[CodeReviewItem]:
        """运行安全检查"""
        items: List[CodeReviewItem] = []

        if patch.diff_code:
            items.extend(self._check_diff_patterns(patch))

        for fpath in (patch.modified_files or [])[:3]:
            content = self._get_file_content(fpath, target_version)
            if not content:
                continue
            items.extend(self._check_file_patterns(content, fpath))

        return items

    def _check_diff_patterns(self, patch: PatchInfo) -> List[CodeReviewItem]:
        """检查 diff 中的安全模式"""
        items: List[CodeReviewItem] = []
        diff = patch.diff_code or ""

        added_lines = [l[1:] for l in diff.split("\n") if l.startswith("+")
                       and not l.startswith("+++")]
        removed_lines = [l[1:] for l in diff.split("\n") if l.startswith("-")
                         and not l.startswith("---")]
        added_text = "\n".join(added_lines)
        removed_text = "\n".join(removed_lines)

        if re.search(r'\bkfree\b', removed_text) and not re.search(
                r'\bkfree\b', added_text):
            items.append(CodeReviewItem(
                category="memory",
                description="补丁移除了 kfree 调用，需确认是否移至其他路径",
                severity="warning",
            ))

        lock_added = re.findall(
            r'(spin_lock|mutex_lock|rcu_read_lock)\w*', added_text
        )
        lock_removed = re.findall(
            r'(spin_unlock|mutex_unlock|rcu_read_unlock)\w*', added_text
        )
        if lock_added and not lock_removed:
            items.append(CodeReviewItem(
                category="lock",
                description=f"补丁新增了锁操作 ({', '.join(sorted(set(lock_added))[:3])})，"
                           f"需确认解锁路径完整",
                severity="warning",
            ))

        null_checks_added = re.findall(r'if\s*\(\s*!?\s*\w+\s*\)', added_text)
        if null_checks_added:
            items.append(CodeReviewItem(
                category="null_check",
                description=f"补丁新增了 {len(null_checks_added)} 处条件检查",
                severity="info",
            ))

        refcount_ops = re.findall(
            r'(kref_get|kref_put|refcount_inc|refcount_dec)\b', added_text
        )
        if refcount_ops:
            items.append(CodeReviewItem(
                category="refcount",
                description=f"补丁涉及引用计数操作: {', '.join(set(refcount_ops))}",
                severity="warning",
            ))

        return items

    def _check_file_patterns(self, content: str,
                             fpath: str) -> List[CodeReviewItem]:
        """检查文件中的安全模式"""
        items: List[CodeReviewItem] = []

        patterns = self.fa.detect_security_patterns(content)
        for pat in patterns[:5]:
            items.append(CodeReviewItem(
                category=pat["pattern"],
                location=fpath,
                description=pat["description"],
                severity="info",
            ))

        return items

    def _deterministic_summary(self, patch: PatchInfo,
                               review: PatchReview) -> str:
        parts: List[str] = []

        files_str = "、".join(patch.modified_files[:3]) if patch.modified_files else "未知文件"
        n_func = len(review.modified_functions)
        if n_func:
            func_str = "、".join(review.modified_functions[:5])
            parts.append(
                f"该补丁修改了 {files_str} 中的 {n_func} 个函数 "
                f"({func_str})")
        else:
            parts.append(f"该补丁修改了 {files_str}")

        if patch.subject:
            parts.append(f"补丁标题: {patch.subject}")

        if review.data_structures:
            ds_groups: Dict[str, List[str]] = {}
            for d in review.data_structures:
                t = d["type"]
                name = d.get("name", "")
                ds_groups.setdefault(t, [])
                if name and name not in ds_groups[t]:
                    ds_groups[t].append(name)
            ds_parts = []
            type_cn = {"spinlock": "自旋锁", "mutex": "互斥锁",
                       "rcu": "RCU 读写保护", "refcount": "引用计数",
                       "memory": "内存分配/释放", "user_access": "用户空间访问"}
            for t, names in ds_groups.items():
                cn = type_cn.get(t, t)
                if names:
                    ds_parts.append(f"{cn} ({', '.join(names[:2])})")
                else:
                    ds_parts.append(cn)
            parts.append(
                f"补丁涉及以下关键数据结构/同步原语: {', '.join(ds_parts)}")

        n_crit = sum(1 for i in review.code_review_items
                     if i.severity == "critical")
        n_warn = sum(1 for i in review.code_review_items
                     if i.severity == "warning")
        n_info = sum(1 for i in review.code_review_items
                     if i.severity == "info")
        if n_crit or n_warn:
            crit_items = [i.description for i in review.code_review_items
                          if i.severity in ("critical", "warning")]
            parts.append(
                f"安全检视发现 {n_crit} 项 critical、{n_warn} 项 warning"
                f"（共 {n_crit+n_warn+n_info} 项）需重点关注: "
                + "；".join(crit_items[:3]))
        elif n_info:
            parts.append(f"安全检视发现 {n_info} 项信息级条目，无高风险项")
        else:
            parts.append("安全检视未发现需关注的条目")

        return "。".join(parts) + "。"

    def _deterministic_trigger(self, patch: PatchInfo) -> str:
        diff = patch.diff_code or ""
        removed = [l[1:].strip() for l in diff.split("\n")
                   if l.startswith("-") and not l.startswith("---")]
        added = [l[1:].strip() for l in diff.split("\n")
                 if l.startswith("+") and not l.startswith("+++")]

        patterns = {
            "内存释放操作": (r'\bkfree\b', "补丁修改了 kfree 相关调用，说明原始漏洞可能通过触发对象释放后的悬挂引用来利用"),
            "指针解引用": (r'->', "补丁涉及指针解引用操作，可能存在 NULL 指针或悬挂指针解引用风险"),
            "边界检查": (r'\blen\b.*[<>]|size.*[<>]|count.*[<>]', "补丁涉及长度/大小比较，说明原始漏洞可能通过超出边界的参数值触发"),
            "同步原语": (r'spin_lock|mutex_lock|rcu_read_lock', "补丁涉及锁操作，说明原始漏洞可能通过并发竞争触发"),
            "引用计数": (r'kref_get|kref_put|refcount_inc|refcount_dec', "补丁涉及引用计数操作，说明原始漏洞可能因引用计数管理不当触发"),
        }

        findings: List[str] = []
        removed_text = "\n".join(removed)
        added_text = "\n".join(added)
        combined = removed_text + "\n" + added_text

        for desc, (pat, explanation) in patterns.items():
            if re.search(pat, combined):
                findings.append(explanation)

        if findings:
            parts = ["根据补丁 diff 代码分析，原始漏洞的触发方式如下"]
            parts.extend(findings)
            return "。".join(parts) + "。"
        return "补丁 diff 中未检测到明显的漏洞触发模式特征，需结合代码上下文人工分析触发路径。"

    def _deterministic_prevention(self, patch: PatchInfo) -> str:
        diff = patch.diff_code or ""
        added = [l[1:].strip() for l in diff.split("\n")
                 if l.startswith("+") and not l.startswith("+++")]
        text = "\n".join(added)

        mechanisms: List[str] = []

        if re.search(r'if\s*\(\s*!\s*\w+\s*\)', text):
            mechanisms.append(
                "新增 NULL/错误返回值检查，在指针无效时提前返回，"
                "防止后续对无效指针的解引用")
        if re.search(r'(spin_lock|mutex_lock|rcu_read_lock)', text):
            locks_found = re.findall(
                r'(spin_lock\w*|mutex_lock\w*|rcu_read_lock)', text)
            mechanisms.append(
                f"新增同步保护 ({', '.join(sorted(set(locks_found))[:3])})，"
                f"通过加锁保证临界区的原子性，防止并发竞争")
        if re.search(r'(kref_get|kref_put|refcount_inc)', text):
            mechanisms.append(
                "修复引用计数管理，确保对象在所有引用释放前不会被销毁")
        if re.search(r'= NULL', text):
            mechanisms.append(
                "在释放对象后将指针置为 NULL，防止释放后使用 (UAF)")
        if re.search(r'\bkfree\b', text):
            mechanisms.append(
                "调整内存释放位置或添加释放操作，确保资源在正确的时机被回收")
        if re.search(r'(bounds|clamp|min|max)\s*\(', text):
            mechanisms.append(
                "添加边界限制函数 (clamp/min/max)，将参数值约束在安全范围内")

        if mechanisms:
            return (
                "修复补丁通过以下机制预防漏洞: "
                + "；".join(mechanisms) + "。"
            )
        return (
            "补丁的修复机制未被自动识别，建议人工审查 diff 中新增代码的安全语义。"
        )

    # ── LLM 增强 ─────────────────────────────────────────────────────

    def _enhance_with_llm(self, patch: PatchInfo, result: PatchReview):
        diff_snippet = (patch.diff_code or "")[:3000]
        prompt = (
            f"## 补丁: {patch.subject}\n"
            f"## Commit: {patch.commit_id[:12]}\n"
            f"## 修改函数: {', '.join(result.modified_functions[:10])}\n\n"
            f"```diff\n{diff_snippet}\n```\n\n"
            "请用 JSON 格式分析:\n"
            '{\n'
            '  "fix_summary": "补丁做了什么 (2-3 句话)",\n'
            '  "trigger_analysis": "原始漏洞如何触发",\n'
            '  "prevention_mechanism": "修复方案如何预防"\n'
            '}\n'
            "请用中文回答。"
        )
        resp = self.llm.chat_json(
            prompt,
            system="你是 Linux 内核补丁审查专家。",
            max_tokens=1200,
        )
        if resp:
            result.fix_summary = resp.get(
                "fix_summary", result.fix_summary
            )
            result.trigger_analysis = resp.get(
                "trigger_analysis", result.trigger_analysis
            )
            result.prevention_mechanism = resp.get(
                "prevention_mechanism", result.prevention_mechanism
            )

    # ── 工具 ─────────────────────────────────────────────────────────

    def _get_file_content(self, fpath: str,
                          target_version: str) -> Optional[str]:
        try:
            branch = None
            cfg = self.git_mgr.repo_configs.get(target_version)
            if isinstance(cfg, dict):
                branch = cfg.get("branch")
            ref = branch or "HEAD"
            return self.git_mgr.run_git(
                ["git", "show", f"{ref}:{fpath}"], target_version
            )
        except Exception:
            return None
