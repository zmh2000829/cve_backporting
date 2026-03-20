"""
VulnAnalysis Agent — 漏洞深度分析

确定性层:
  - 关键词规则分类漏洞类型 (UAF/OOB/race/NULL_deref/...)
  - 从 CVE 描述和补丁 diff 中提取受影响子系统/函数
  - CVSS 评分提取

LLM 增强层:
  - 技术根因分析
  - 触发路径推演
  - 利用条件评估
  - 漏洞判断方法
"""

import logging
import re
from typing import Dict, List, Optional

from core.models import CveInfo, PatchInfo, VulnAnalysis
from core.llm_client import LLMClient

logger = logging.getLogger(__name__)

_C_NOISE = {
    "static", "inline", "void", "int", "long", "unsigned", "signed",
    "char", "short", "bool", "const", "struct", "enum", "union",
    "extern", "register", "volatile", "restrict", "__init", "__exit",
    "__always_inline", "noinline", "asmlinkage", "notrace",
    "ssize_t", "size_t", "u8", "u16", "u32", "u64", "s8", "s16",
    "s32", "s64", "__u8", "__u16", "__u32", "__u64", "loff_t",
    "noinline_for_stack", "syscall_define", "__net_init", "__net_exit",
    "define_mutex", "define_spinlock", "define_rwlock", "define_semaphore",
    "define_per_cpu", "define_ida", "define_idr", "list_head",
    "declare_wait_queue_head", "export_symbol", "export_symbol_gpl",
    "module_license", "module_author", "module_description",
}


def _extract_c_func_names(diff: str) -> list:
    """从 diff hunk header 中提取真正的 C 函数名/标识符"""
    funcs = set()
    for m in re.finditer(
            r'@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@\s*(.+)', diff):
        sig = m.group(1).strip()
        if not sig:
            continue
        fm = re.search(r'\b([a-zA-Z_]\w{2,})\s*\(', sig)
        if fm and fm.group(1).lower() not in _C_NOISE:
            funcs.add(fm.group(1))
            continue
        vm = re.search(r'\b([a-zA-Z_]\w{2,})\s*[=\[]', sig)
        if vm and vm.group(1).lower() not in _C_NOISE:
            funcs.add(vm.group(1))
            continue
        tokens = re.findall(r'\b([a-zA-Z_]\w+)\b', sig)
        for tok in reversed(tokens):
            if tok.lower() not in _C_NOISE and len(tok) > 2:
                funcs.add(tok)
                break
    return sorted(funcs)

# 漏洞类型关键词 → 类型映射
_VULN_PATTERNS: List[Dict] = [
    {"keywords": ["use-after-free", "use after free", "UAF", "freed memory",
                  "dangling pointer"],
     "type": "UAF", "severity_hint": "high"},
    {"keywords": ["out-of-bounds", "out of bounds", "OOB", "buffer overflow",
                  "heap overflow", "stack overflow", "overread"],
     "type": "OOB", "severity_hint": "high"},
    {"keywords": ["null pointer", "NULL dereference", "null deref",
                  "null-ptr-deref", "NPD"],
     "type": "NULL_deref", "severity_hint": "medium"},
    {"keywords": ["race condition", "data race", "TOCTOU", "double free",
                  "concurrent access"],
     "type": "race_condition", "severity_hint": "high"},
    {"keywords": ["integer overflow", "integer underflow", "sign extension",
                  "truncation"],
     "type": "integer_overflow", "severity_hint": "medium"},
    {"keywords": ["information leak", "info leak", "uninitialized",
                  "disclosure", "infoleak"],
     "type": "info_leak", "severity_hint": "medium"},
    {"keywords": ["deadlock", "hang", "soft lockup"],
     "type": "deadlock", "severity_hint": "medium"},
    {"keywords": ["privilege escalation", "privilege", "root",
                  "permission bypass"],
     "type": "privilege_escalation", "severity_hint": "critical"},
    {"keywords": ["denial of service", "DoS", "crash", "panic",
                  "BUG_ON", "kernel oops"],
     "type": "DoS", "severity_hint": "medium"},
    {"keywords": ["type confusion"],
     "type": "type_confusion", "severity_hint": "high"},
    {"keywords": ["memory leak", "memleak", "kmalloc.*without.*free"],
     "type": "memory_leak", "severity_hint": "low"},
]

# 子系统识别正则
_SUBSYSTEM_PATTERNS = [
    (r'(?:drivers/net|net/)', "networking"),
    (r'fs/', "filesystem"),
    (r'drivers/gpu', "gpu/drm"),
    (r'sound/', "audio/ALSA"),
    (r'drivers/usb', "USB"),
    (r'drivers/scsi|block/', "storage"),
    (r'mm/', "memory management"),
    (r'kernel/sched', "scheduler"),
    (r'security/', "security/LSM"),
    (r'crypto/', "crypto"),
    (r'arch/', "architecture"),
    (r'drivers/bluetooth|net/bluetooth', "bluetooth"),
    (r'net/wireless|drivers/net/wireless', "wireless"),
    (r'drivers/infiniband|net/rds', "RDMA/InfiniBand"),
]


_VULN_TYPE_CN = {
    "UAF": "Use-After-Free (释放后使用)",
    "OOB": "Out-of-Bounds (越界读写)",
    "NULL_deref": "NULL 指针解引用",
    "race_condition": "竞态条件",
    "integer_overflow": "整数溢出",
    "info_leak": "信息泄露",
    "deadlock": "死锁",
    "privilege_escalation": "权限提升",
    "DoS": "拒绝服务",
    "type_confusion": "类型混淆",
    "memory_leak": "内存泄漏",
}


class VulnAnalysisAgent:
    """漏洞深度分析"""

    def __init__(self, llm: Optional[LLMClient] = None):
        self.llm = llm

    def analyze(self, cve_info: CveInfo,
                fix_patch: Optional[PatchInfo] = None) -> VulnAnalysis:
        """
        执行漏洞分析，返回 VulnAnalysis。
        确定性层始终执行，LLM 层按需增强。
        """
        result = VulnAnalysis()

        text_corpus = self._build_corpus(cve_info, fix_patch)

        result.vuln_type = self._classify_vuln_type(text_corpus)
        result.severity = self._determine_severity(
            cve_info, result.vuln_type
        )
        result.cvss_score = self._extract_cvss(cve_info)
        result.affected_subsystem = self._detect_subsystem(
            fix_patch.modified_files if fix_patch else []
        )
        result.affected_functions = self._extract_affected_functions(
            fix_patch
        )

        result.root_cause = self._deterministic_root_cause(
            cve_info, fix_patch, result
        )
        result.trigger_path = self._deterministic_trigger_path(
            cve_info, fix_patch, result
        )
        result.exploit_conditions = self._deterministic_exploit_conditions(
            result
        )
        result.impact_description = self._deterministic_impact(
            cve_info, result
        )
        result.detection_method = self._deterministic_detection(
            result
        )

        if self.llm and self.llm.enabled:
            self._enhance_with_llm(cve_info, fix_patch, result)
            result.llm_enhanced = True

        logger.info("[VulnAnalysis] %s: type=%s, severity=%s, subsystem=%s",
                    cve_info.cve_id, result.vuln_type, result.severity,
                    result.affected_subsystem)
        return result

    # ── 确定性分类 ────────────────────────────────────────────────────

    def _classify_vuln_type(self, text: str) -> str:
        text_lower = text.lower()
        best_type = "unknown"
        best_count = 0

        for pat in _VULN_PATTERNS:
            count = sum(1 for kw in pat["keywords"]
                        if kw.lower() in text_lower)
            if count > best_count:
                best_count = count
                best_type = pat["type"]
        return best_type

    def _determine_severity(self, cve_info: CveInfo,
                            vuln_type: str) -> str:
        if cve_info.severity and cve_info.severity != "unknown":
            return cve_info.severity.lower()

        for pat in _VULN_PATTERNS:
            if pat["type"] == vuln_type:
                return pat.get("severity_hint", "medium")
        return "medium"

    def _extract_cvss(self, cve_info: CveInfo) -> float:
        sev_map = {"critical": 9.0, "high": 7.5,
                   "medium": 5.0, "low": 2.5}
        return sev_map.get(cve_info.severity.lower(), 0.0)

    def _detect_subsystem(self, files: List[str]) -> str:
        for f in files:
            for pat, name in _SUBSYSTEM_PATTERNS:
                if re.search(pat, f):
                    return name
        return "unknown"

    def _extract_affected_functions(self,
                                    patch: Optional[PatchInfo]) -> List[str]:
        if not patch or not patch.diff_code:
            return []
        return _extract_c_func_names(patch.diff_code)

    def _deterministic_root_cause(self, cve_info: CveInfo,
                                  patch: Optional[PatchInfo],
                                  result: VulnAnalysis) -> str:
        _mechanism = {
            "UAF": "对象被释放后仍被引用，可能由于引用计数管理错误或异步释放路径中释放时序与使用时序存在竞争",
            "OOB": "数组或缓冲区访问超出分配边界，可能由于长度校验不足或整数运算导致的错误偏移",
            "NULL_deref": "在未检查返回值为 NULL 的情况下解引用指针，通常发生在错误处理路径或资源分配失败后",
            "race_condition": "并发访问共享资源时缺少适当的同步保护（如自旋锁或互斥锁），导致数据不一致",
            "integer_overflow": "整数运算溢出导致后续缓冲区操作使用错误的长度或偏移量",
            "info_leak": "未初始化的内核栈或堆内存被拷贝到用户空间，泄露内核地址或敏感数据",
            "deadlock": "锁的获取顺序不一致或递归持锁，导致两个或多个执行路径互相等待",
            "privilege_escalation": "权限检查被绕过或存在可利用的权限提升路径",
            "DoS": "特定输入或操作序列触发内核 panic/oops 或资源耗尽，导致系统不可用",
            "type_confusion": "类型转换错误导致以错误类型访问对象，破坏内存布局",
            "memory_leak": "分配的内存在错误路径或正常路径中未被正确释放，导致内核内存持续增长",
        }

        parts: List[str] = []
        vt = result.vuln_type
        type_cn = _VULN_TYPE_CN.get(vt, vt)
        parts.append(f"该漏洞属于 {type_cn} 类型")

        desc = (cve_info.description or "").strip()
        if desc:
            snippet = desc[:200]
            if len(desc) > 200:
                snippet += "..."
            parts.append(f"根据 CVE 描述: \"{snippet}\"")

        if patch and patch.modified_files:
            files_str = "、".join(patch.modified_files[:3])
            n_func = len(result.affected_functions)
            func_str = "、".join(result.affected_functions[:4])
            subsys = result.affected_subsystem
            location = f"补丁修改了 {files_str}"
            if n_func:
                location += f" 中的 {func_str} 等 {n_func} 个函数"
            if subsys and subsys != "unknown":
                location += f"，说明漏洞根因位于 {subsys} 子系统"
            parts.append(location)

        mechanism = _mechanism.get(vt, "具体机制待进一步分析")
        parts.append(f"技术机制: {mechanism}")

        return "。".join(parts) + "。"

    def _deterministic_trigger_path(self, cve_info: CveInfo,
                                    patch: Optional[PatchInfo],
                                    result: VulnAnalysis) -> str:
        parts: List[str] = []
        vt = result.vuln_type
        _trigger_template = {
            "UAF": "攻击者需触发对象的释放操作，然后在释放后的窗口内再次访问该对象。通常通过精心安排系统调用序列或利用异步回调来制造时间窗口",
            "OOB": "攻击者通过构造超出预期范围的输入参数（如过大的长度值或负数索引），使内核在处理时越界访问内存",
            "NULL_deref": "攻击者通过特定操作路径使资源分配/查找返回 NULL，而后续代码未检查该返回值便直接解引用",
            "race_condition": "攻击者利用多线程或多进程并发执行特定系统调用，在缺少锁保护的临界区窗口内触发数据竞争",
            "integer_overflow": "攻击者通过传入接近整数极限的参数值，使内核内部运算溢出，导致后续缓冲区操作使用错误的大小",
            "info_leak": "攻击者通过正常系统调用接口读取包含未初始化内核内存的返回数据",
            "deadlock": "特定的系统调用或操作序列导致锁获取顺序违反，使系统挂起",
            "privilege_escalation": "非特权用户通过特定操作路径绕过权限检查，获取更高权限",
            "DoS": "攻击者通过构造畸形输入或特定操作序列触发内核断言失败或资源耗尽",
        }
        base = _trigger_template.get(vt, "需进一步分析触发路径")
        parts.append(base)

        if result.affected_functions:
            func_list = "、".join(result.affected_functions[:3])
            parts.append(f"触发路径涉及函数: {func_list}")

        if result.affected_subsystem and result.affected_subsystem != "unknown":
            parts.append(
                f"漏洞入口位于 {result.affected_subsystem} 子系统的用户态接口")

        return "。".join(parts) + "。"

    def _deterministic_exploit_conditions(self,
                                          result: VulnAnalysis) -> str:
        _conditions = {
            "UAF": "需要精确控制对象释放与再次访问的时序。通常要求攻击者能触发特定的释放路径，并在对象被重新分配前引用该内存。如果涉及网络或文件系统操作，可能需要特定的权限或网络条件",
            "OOB": "需要能够控制导致越界的长度/索引参数。如果参数来自用户空间输入，利用门槛较低；如果来自内核内部计算，则需要间接控制",
            "NULL_deref": "需要触发返回 NULL 的错误路径。在大多数现代内核配置中，NULL 解引用导致 panic 而非代码执行，利用难度较高。但在某些旧配置或特定架构上可能可被利用",
            "race_condition": "需要多核环境并能并发执行相关操作。竞态窗口通常很小，利用需要大量重复尝试或精确的时序控制",
            "integer_overflow": "需要控制参与运算的输入值。如果溢出发生在用户可控参数的处理路径上，利用门槛相对较低",
            "info_leak": "通常利用条件简单，只需调用特定系统调用接口。但泄露的信息可能需要配合其他漏洞才能实现完整利用",
            "privilege_escalation": "通常需要本地访问权限。具体条件取决于权限检查被绕过的方式",
            "DoS": "利用条件通常较简单，只需构造特定输入触发内核崩溃。对系统可用性的威胁直接",
        }
        cond = _conditions.get(result.vuln_type,
                               "需结合具体代码路径分析利用条件")
        return cond

    def _deterministic_impact(self, cve_info: CveInfo,
                              result: VulnAnalysis) -> str:
        _impact = {
            "UAF": "可能导致任意代码执行、内核权限提升或信息泄露。攻击者可通过堆喷射 (heap spraying) 控制被释放对象的内存内容，劫持控制流",
            "OOB": "越界读可导致内核地址或敏感数据泄露；越界写可导致任意代码执行或权限提升。影响取决于越界访问的偏移量和目标内存的内容",
            "NULL_deref": "通常导致内核 Oops 或 Panic，影响系统可用性。在极少数配置下可能被利用进行权限提升",
            "race_condition": "可能导致数据损坏、权限提升或拒绝服务。由于竞态条件的不确定性，影响范围取决于具体的共享资源类型",
            "integer_overflow": "可间接导致缓冲区溢出，进而引发任意代码执行或信息泄露",
            "info_leak": "泄露内核地址可以绕过 KASLR 保护，泄露敏感数据可能导致隐私泄露。通常作为漏洞利用链中的信息收集阶段",
            "privilege_escalation": "非特权用户可获取 root 权限，对系统安全构成直接、严重的威胁",
            "DoS": "导致系统崩溃或服务不可用。在服务器场景下可能造成业务中断",
            "deadlock": "导致系统挂起，只能通过重启恢复。在高并发服务场景下影响较大",
        }
        sev_cn = {"critical": "严重", "high": "高危",
                  "medium": "中危", "low": "低危"}
        parts: List[str] = []

        impact_base = _impact.get(result.vuln_type,
                                  "具体影响需结合代码路径分析")
        parts.append(impact_base)

        sev = result.severity
        s = sev_cn.get(sev, sev)
        parts.append(f"该漏洞严重度为 {s}")

        if result.affected_subsystem and result.affected_subsystem != "unknown":
            parts.append(
                f"影响 {result.affected_subsystem} 子系统"
                f"的所有使用场景")

        return "。".join(parts) + "。"

    def _deterministic_detection(self, result: VulnAnalysis) -> str:
        _methods = {
            "UAF": "推荐使用 KASAN (Kernel Address Sanitizer) 的 use-after-free 检测模式进行运行时检测。开启 CONFIG_KASAN=y 编译内核后，复现漏洞触发路径即可捕获。同时建议审计涉及函数的引用计数管理路径，检查 kfree/put 调用后是否存在悬挂引用",
            "OOB": "推荐使用 KASAN 的 out-of-bounds 检测模式，配合 UBSAN (CONFIG_UBSAN=y) 检测整数溢出。通过 syzkaller 等 fuzzer 生成边界值测试用例，覆盖长度/索引参数的极端值",
            "NULL_deref": "KASAN 可以检测 NULL 指针解引用。建议使用 syzkaller fuzzing 覆盖错误处理路径，并审计所有可能返回 NULL 的函数调用点是否有充分的检查",
            "race_condition": "推荐使用 KCSAN (Kernel Concurrency Sanitizer, CONFIG_KCSAN=y) 或 KTSAN 进行并发错误检测。通过多线程压力测试配合 KCSAN 报告定位数据竞争点",
            "integer_overflow": "推荐使用 UBSAN (CONFIG_UBSAN=y, CONFIG_UBSAN_SANITIZE_ALL=y) 检测整数溢出。审计涉及用户输入参数的算术运算路径",
            "info_leak": "推荐使用 KMSAN (Kernel Memory Sanitizer) 检测未初始化内存的使用。审计涉及 copy_to_user 的代码路径，确认所有返回给用户空间的缓冲区都已正确初始化",
            "deadlock": "推荐使用 lockdep (CONFIG_PROVE_LOCKING=y) 检测锁序违反。审计锁获取路径，构造并发测试场景验证锁的正确性",
            "privilege_escalation": "安全审计权限检查逻辑，验证所有特权操作路径是否有正确的 capability/权限检查。使用非特权用户进行边界测试",
            "DoS": "使用 syzkaller 或其他 fuzzer 进行异常输入测试。审计 BUG_ON/WARN_ON 的触发条件，检查是否可由用户态输入控制",
        }
        method = _methods.get(result.vuln_type,
                              "建议综合使用 KASAN + syzkaller fuzzing + 代码审计进行漏洞验证")
        return method

    # ── LLM 增强 ─────────────────────────────────────────────────────

    def _enhance_with_llm(self, cve_info: CveInfo,
                          patch: Optional[PatchInfo],
                          result: VulnAnalysis):
        desc = cve_info.description[:1000]
        diff_snippet = ""
        if patch and patch.diff_code:
            diff_snippet = patch.diff_code[:2000]

        prompt = (
            f"## CVE: {cve_info.cve_id}\n"
            f"## 漏洞类型 (工具判定): {result.vuln_type}\n"
            f"## CVE 描述:\n{desc}\n\n"
        )
        if diff_snippet:
            prompt += f"## 修复补丁 (部分):\n```diff\n{diff_snippet}\n```\n\n"

        prompt += (
            "请用 JSON 格式回答以下问题:\n"
            '{\n'
            '  "root_cause": "技术根因 (2-3 句话)",\n'
            '  "trigger_path": "漏洞触发路径描述",\n'
            '  "exploit_conditions": "利用条件",\n'
            '  "impact_description": "影响描述",\n'
            '  "detection_method": "推荐的漏洞检测/验证方法"\n'
            '}\n'
            "请用中文回答。"
        )

        resp = self.llm.chat_json(
            prompt,
            system="你是 Linux 内核安全漏洞分析专家。",
            max_tokens=1500,
        )
        if resp:
            result.root_cause = resp.get("root_cause", result.root_cause)
            result.trigger_path = resp.get("trigger_path", "")
            result.exploit_conditions = resp.get("exploit_conditions", "")
            result.impact_description = resp.get("impact_description", "")
            result.detection_method = resp.get(
                "detection_method", result.detection_method
            )

    # ── 辅助 ─────────────────────────────────────────────────────────

    @staticmethod
    def _build_corpus(cve_info: CveInfo,
                      patch: Optional[PatchInfo]) -> str:
        parts = [cve_info.description or ""]
        if patch:
            parts.append(patch.subject or "")
            parts.append(patch.commit_msg or "")
            if patch.diff_code:
                parts.append(patch.diff_code[:3000])
        return "\n".join(parts)
