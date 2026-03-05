"""
LLM 智能分析模块
为 validate 命令提供差异分析能力，解释工具输出与真实结果的偏差原因。
兼容 OpenAI 接口 (含 DeepSeek / Azure / 本地部署等)。
"""

import os
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class LLMAnalyzer:
    """基于 LLM 的验证差异分析器"""

    def __init__(self, config):
        self.enabled = config.enabled
        self.api_key = config.api_key or os.environ.get("LLM_API_KEY", "")
        self.base_url = config.base_url.rstrip("/")
        self.model = config.model
        self.max_tokens = config.max_tokens
        self.temperature = config.temperature
        self.timeout = config.timeout

        if self.enabled and not self.api_key:
            logger.warning("LLM 已启用但未配置 api_key (config.yaml 或 LLM_API_KEY 环境变量)")
            self.enabled = False

    def analyze_validate_diff(self, context: dict) -> Optional[str]:
        """
        分析 validate 结果与真实记录的差异。
        context 包含: cve_id, fix_patch_summary, dryrun_detail,
                      tool_prereqs, known_prereqs_info, known_fix_diff_summary
        返回 LLM 生成的分析文本，失败返回 None。
        """
        if not self.enabled:
            return None

        prompt = self._build_prompt(context)
        try:
            return self._call_api(prompt)
        except Exception as e:
            logger.error("LLM 分析失败: %s", e)
            return None

    def _build_prompt(self, ctx: dict) -> str:
        parts = [
            "你是一位 Linux 内核安全补丁回溯专家。以下是一个 CVE 补丁验证的详细结果。"
            "请分析工具输出与真实合入记录之间的差异，解释不一致的原因，并给出改进建议。",
            "",
            f"## CVE: {ctx.get('cve_id', 'N/A')}",
            "",
        ]

        fix_summary = ctx.get("fix_patch_summary", "")
        if fix_summary:
            parts.append("## 社区修复补丁摘要")
            parts.append(fix_summary)
            parts.append("")

        dr = ctx.get("dryrun_detail", "")
        if dr:
            parts.append("## DryRun (git apply --check) 结果")
            parts.append(dr)
            parts.append("")

        tool_prereqs = ctx.get("tool_prereqs", "")
        if tool_prereqs:
            parts.append("## 工具推荐的前置依赖补丁")
            parts.append(tool_prereqs)
            parts.append("")

        known_info = ctx.get("known_prereqs_info", "")
        if known_info:
            parts.append("## 实际合入的前置补丁 (真值)")
            parts.append(known_info)
            parts.append("")

        known_fix = ctx.get("known_fix_diff_summary", "")
        if known_fix:
            parts.append("## 本地仓库中真实修复 commit 的 diff 摘要")
            parts.append(known_fix)
            parts.append("")

        issues = ctx.get("issues", [])
        if issues:
            parts.append("## 验证中发现的问题")
            for issue in issues:
                parts.append(f"- {issue}")
            parts.append("")

        parts.append("## 请分析")
        parts.append("1. 逐项分析每个验证失败点的根因")
        parts.append("2. 工具推荐的前置依赖与真实情况的差异原因")
        parts.append("3. DryRun 预测不准确的可能原因 (如有)")
        parts.append("4. 具体的改进建议")
        parts.append("")
        parts.append("请用中文回答，条理清晰，控制在 500 字以内。")

        return "\n".join(parts)

    def _call_api(self, prompt: str) -> str:
        import urllib.request
        import ssl

        url = f"{self.base_url}/chat/completions"
        payload = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        ctx = ssl.create_default_context()

        with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "").strip()
        return ""
