"""
AI 辅助补丁生成 — 用 LLM 生成最小化修改的补丁

当所有自动策略失败时，调用 LLM 分析 mainline patch 和目标文件的实际代码，
生成一个最小化修改的补丁（仅改变必要的 context 行）。
"""

import logging
import json
from typing import Optional, List, Dict
from core.models import PatchInfo

logger = logging.getLogger(__name__)


class AIPatchGenerator:
    """AI 辅助补丁生成"""

    def __init__(self, llm_client=None):
        """
        llm_client: OpenAI 兼容的 LLM 客户端
        """
        self.llm_client = llm_client

    def generate_patch(self, mainline_patch: str,
                       target_file_content: str,
                       conflict_analysis: Dict,
                       target_file_path: str) -> Optional[str]:
        """
        生成最小化修改的补丁。

        Args:
            mainline_patch: mainline 的原始补丁内容
            target_file_content: 目标文件的实际内容
            conflict_analysis: 冲突分析结果（包含 hunks 信息）
            target_file_path: 目标文件路径

        Returns:
            生成的补丁内容，或 None 如果生成失败
        """
        if not self.llm_client:
            logger.warning("LLM 客户端未配置，无法生成补丁")
            return None

        # 构建 prompt
        prompt = self._build_prompt(
            mainline_patch, target_file_content,
            conflict_analysis, target_file_path
        )

        try:
            response = self.llm_client.chat.completions.create(
                model=self.llm_client.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "你是一个 Linux 内核补丁专家。你的任务是分析 mainline 补丁和目标文件的实际代码，"
                            "生成一个最小化修改的补丁。补丁应该只改变必要的 context 行，保留所有的 + 行（新增代码）。"
                            "输出必须是有效的 unified diff 格式。"
                        )
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=4000,
            )

            patch_content = response.choices[0].message.content.strip()

            # 验证补丁格式
            if not self._validate_patch_format(patch_content):
                logger.warning("生成的补丁格式无效")
                return None

            logger.info("AI 补丁生成成功")
            return patch_content

        except Exception as e:
            logger.error(f"AI 补丁生成失败: {e}")
            return None

    def _build_prompt(self, mainline_patch: str,
                      target_file_content: str,
                      conflict_analysis: Dict,
                      target_file_path: str) -> str:
        """构建 LLM prompt"""

        # 提取冲突 hunk 信息
        hunks_info = conflict_analysis.get("hunks", [])
        hunk_summary = "\n".join([
            f"  - Hunk {i+1}: {h.get('severity', 'L3')} - {h.get('reason', 'unknown')}"
            for i, h in enumerate(hunks_info[:5])  # 最多显示 5 个
        ])

        prompt = f"""
## 任务

分析以下 mainline 补丁和目标文件的实际代码，生成一个最小化修改的补丁。

## Mainline 补丁

```diff
{mainline_patch[:2000]}
```

## 目标文件路径

{target_file_path}

## 目标文件内容（前 2000 字符）

```c
{target_file_content[:2000]}
```

## 冲突分析

{hunk_summary}

## 要求

1. 分析 mainline 补丁的每个 hunk
2. 在目标文件中找到对应的代码位置
3. 生成一个新的补丁，其中：
   - 所有 + 行（新增代码）保持不变
   - - 行（删除代码）替换为目标文件中的实际内容
   - context 行（空格开头）调整为目标文件中的实际内容
4. 输出必须是有效的 unified diff 格式

## 输出格式

只输出补丁内容，不要包含任何解释或额外文本。补丁应该以 `diff --git` 开头。
"""
        return prompt

    def _validate_patch_format(self, patch_content: str) -> bool:
        """验证补丁格式"""
        lines = patch_content.strip().split("\n")

        # 检查是否包含 diff 头
        has_diff_header = any(l.startswith("diff --git") for l in lines)
        if not has_diff_header:
            return False

        # 检查是否包含 hunk 头
        has_hunk_header = any(l.startswith("@@") for l in lines)
        if not has_hunk_header:
            return False

        # 检查是否包含 +/- 行
        has_changes = any(l.startswith("+") or l.startswith("-") for l in lines)
        if not has_changes:
            return False

        return True

    def analyze_conflict_for_ai(self, conflict_hunks: List[Dict]) -> str:
        """
        为 AI 生成冲突分析摘要
        """
        summary = []
        for i, hunk in enumerate(conflict_hunks[:5]):
            severity = hunk.get("severity", "L3")
            reason = hunk.get("reason", "unknown")
            similarity = hunk.get("similarity", 0)
            location = hunk.get("location", "unknown")

            summary.append(
                f"Hunk {i+1}: {severity} (相似度 {similarity:.1%}) at line {location}\n"
                f"  原因: {reason}"
            )

        return "\n".join(summary)
