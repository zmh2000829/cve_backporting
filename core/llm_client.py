"""
统一 LLM 客户端 — 封装 OpenAI 兼容 API 调用

提供 chat() 和 chat_json() 两个核心方法，供所有 Agent 使用。
无 LLM 时 graceful fallback：chat() 返回 None，chat_json() 返回 None。
"""

import json
import logging
import os
import ssl
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class LLMClient:
    """统一的 LLM 调用封装，兼容 OpenAI / DeepSeek / Azure / 本地部署"""

    def __init__(self, config=None):
        if config is None:
            self.enabled = False
            self._api_key = ""
            self._base_url = ""
            self._model = ""
            self._max_tokens = 2000
            self._temperature = 0.3
            self._timeout = 60
            return

        self.enabled = config.enabled
        self._api_key = config.api_key or os.environ.get("LLM_API_KEY", "")
        self._base_url = (config.base_url or "").rstrip("/")
        self._model = config.model or ""
        self._max_tokens = config.max_tokens or 2000
        self._temperature = config.temperature if config.temperature is not None else 0.3
        self._timeout = config.timeout or 60

        if self.enabled and not self._api_key:
            logger.warning("LLM 已启用但未配置 api_key，自动降级为确定性模式")
            self.enabled = False

    def chat(self, prompt: str, *,
             system: str = "",
             temperature: Optional[float] = None,
             max_tokens: Optional[int] = None) -> Optional[str]:
        """
        发送聊天请求，返回文本回复。LLM 不可用时返回 None。

        Args:
            prompt: 用户消息
            system: 系统消息 (可选)
            temperature: 覆盖默认温度
            max_tokens: 覆盖默认最大 token 数
        """
        if not self.enabled:
            return None

        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            return self._call(messages,
                              temperature=temperature or self._temperature,
                              max_tokens=max_tokens or self._max_tokens)
        except Exception as e:
            logger.error("LLM chat 失败: %s", e)
            return None

    def chat_json(self, prompt: str, *,
                  system: str = "",
                  temperature: Optional[float] = None,
                  max_tokens: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        发送聊天请求并解析 JSON 回复。LLM 不可用或解析失败时返回 None。
        prompt 中应明确要求返回 JSON 格式。
        """
        raw = self.chat(prompt, system=system,
                        temperature=temperature, max_tokens=max_tokens)
        if raw is None:
            return None

        text = raw.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = lines[1:]  # remove opening ```json or ```
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.warning("LLM 返回的内容无法解析为 JSON (前 200 字符): %s",
                           text[:200])
            return None

    def _call(self, messages: List[Dict[str, str]], *,
              temperature: float, max_tokens: int) -> str:
        url = f"{self._base_url}/chat/completions"
        payload = json.dumps({
            "model": self._model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
        }

        req = urllib.request.Request(url, data=payload,
                                     headers=headers, method="POST")
        ctx = ssl.create_default_context()

        with urllib.request.urlopen(req, timeout=self._timeout,
                                    context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        choices = data.get("choices", [])
        if choices:
            content = choices[0].get("message", {}).get("content")
            return (content or "").strip()
        return ""
