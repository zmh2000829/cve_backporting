"""AI advisory tasks for accuracy and conflict-handling support.

The assistant is intentionally advisory by default. It records structured
evidence for maintainers and later batch calibration, but it does not override
deterministic policy decisions unless a future gated mode explicitly allows it.
"""

import hashlib
import json
import time
from typing import Any, Dict, List, Optional


class AIAssistant:
    """Structured GLM/OpenAI-compatible advisory task runner."""

    def __init__(self, llm_client=None, ai_config=None):
        self.llm = llm_client
        self.config = ai_config

    @property
    def enabled(self) -> bool:
        mode = str(getattr(self.config, "mode", "off") or "off").lower()
        return bool(self.llm and getattr(self.llm, "enabled", False) and mode in ("advisory", "gated"))

    @property
    def mode(self) -> str:
        return str(getattr(self.config, "mode", "off") or "off").lower()

    def enhance_accuracy(
        self,
        *,
        patch,
        validation_details,
        prerequisite_patches=None,
        dependency_details=None,
    ) -> Dict[str, Any]:
        """Run advisory accuracy tasks against policy/dependency evidence."""
        evidence = self._new_evidence()
        if not self.enabled or not patch or not validation_details:
            return evidence

        tasks: List[Dict[str, Any]] = []
        rule_hits = list(getattr(getattr(validation_details, "level_decision", None), "rule_hits", []) or [])

        if bool(getattr(self.config, "enable_low_signal_adjudication", False)):
            task = self._run_low_signal_task(patch, validation_details, rule_hits)
            if task:
                tasks.append(task)

        if bool(getattr(self.config, "enable_dependency_triage", False)):
            task = self._run_dependency_task(prerequisite_patches, dependency_details)
            if task:
                tasks.append(task)

        if bool(getattr(self.config, "enable_risk_explainer", False)):
            task = self._run_risk_task(patch, validation_details, rule_hits)
            if task:
                tasks.append(task)

        evidence["tasks"] = tasks
        evidence["summary"] = [
            item.get("summary") or f"{item.get('task')}: {item.get('decision')}"
            for item in tasks
            if item.get("status") == "success"
        ][:6]
        return evidence

    def _new_evidence(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "provider": getattr(self.llm, "provider", "") if self.llm else "",
            "model": getattr(self.llm, "model", "") if self.llm else "",
            "prompt_version": getattr(self.config, "prompt_version", "ai-v1") if self.config else "ai-v1",
            "tasks": [],
            "summary": [],
        }

    def _run_low_signal_task(self, patch, validation_details, rule_hits: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        low_signal_rules = {
            "single_line_high_impact",
            "l1_api_surface",
            "p2_state_machine_control_flow",
            "p2_struct_field_data_path",
            "p2_error_path",
        }
        selected = [hit for hit in rule_hits if hit.get("rule_id") in low_signal_rules]
        changed_lines = len(self._changed_bodies(getattr(patch, "diff_code", "") or ""))
        if not selected and changed_lines > 8:
            return None
        prompt = self._build_json_prompt(
            task="low_signal_adjudication",
            instruction=(
                "判断这些规则命中是否可能属于低信号误升级。"
                "只基于给出的 diff 和规则证据，不要引入外部事实。"
            ),
            payload={
                "subject": getattr(patch, "subject", ""),
                "diff": self._clip(getattr(patch, "diff_code", "") or ""),
                "rule_hits": self._compact_rule_hits(selected or rule_hits[:6]),
                "changed_lines": changed_lines,
                "expected_decisions": ["semantic_risk", "likely_low_signal", "uncertain"],
            },
        )
        return self._run_task("low_signal_adjudication", prompt)

    def _run_dependency_task(self, prerequisite_patches, dependency_details) -> Optional[Dict[str, Any]]:
        prereqs = list(prerequisite_patches or [])
        samples = list(getattr(dependency_details, "prerequisite_evidence_samples", []) or [])
        if not prereqs and not samples:
            return None
        candidates = []
        for item in prereqs[:8]:
            candidates.append({
                "commit_id": getattr(item, "commit_id", ""),
                "subject": getattr(item, "subject", ""),
                "grade": getattr(item, "grade", ""),
                "score": getattr(item, "score", 0.0),
                "overlap_funcs": list(getattr(item, "overlap_funcs", []) or [])[:4],
                "shared_fields": list(getattr(item, "shared_fields", []) or [])[:4],
                "shared_lock_domains": list(getattr(item, "shared_lock_domains", []) or [])[:4],
                "shared_state_points": list(getattr(item, "shared_state_points", []) or [])[:4],
                "evidence_lines": list(getattr(item, "evidence_lines", []) or [])[:3],
            })
        for sample in samples[:8]:
            if isinstance(sample, dict):
                candidates.append(sample)
        prompt = self._build_json_prompt(
            task="dependency_triage",
            instruction=(
                "把前置候选分成 required/helpful/background/unrelated。"
                "不要把 weak 或单纯同文件历史直接升为 required。"
            ),
            payload={
                "counts": {
                    "strong": getattr(dependency_details, "strong_count", 0) if dependency_details else 0,
                    "medium": getattr(dependency_details, "medium_count", 0) if dependency_details else 0,
                    "weak": getattr(dependency_details, "weak_count", 0) if dependency_details else 0,
                },
                "candidates": candidates[:12],
                "expected_decisions": ["required", "helpful", "background", "unrelated", "uncertain"],
            },
        )
        return self._run_task("dependency_triage", prompt)

    def _run_risk_task(self, patch, validation_details, rule_hits: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        special = getattr(validation_details, "special_risk_report", {}) or {}
        sections = ((special.get("summary") or {}).get("triggered_sections") or [])
        risk_hits = [hit for hit in rule_hits if hit.get("severity") in ("warn", "high")]
        if not sections and not risk_hits:
            return None
        prompt = self._build_json_prompt(
            task="risk_semantic_explainer",
            instruction=(
                "解释锁、生命周期、状态机、字段或错误路径风险是否真实存在，"
                "并指出最需要人工核对的对象。"
            ),
            payload={
                "subject": getattr(patch, "subject", ""),
                "diff": self._clip(getattr(patch, "diff_code", "") or ""),
                "triggered_sections": sections,
                "risk_hits": self._compact_rule_hits(risk_hits[:8]),
                "expected_decisions": ["high_risk", "attention", "likely_low_risk", "uncertain"],
            },
        )
        return self._run_task("risk_semantic_explainer", prompt)

    def _run_task(self, task_name: str, prompt: str) -> Dict[str, Any]:
        start = time.time()
        input_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
        response = self.llm.chat_json(
            prompt,
            system=(
                "你是 Linux 内核 CVE 回移审查助手。"
                "必须只返回一个合法 JSON 对象，禁止 markdown、代码块、前后说明和多余文本。"
            ),
            temperature=0.0,
            max_tokens=min(1200, int(getattr(self.llm, "_max_tokens", 2000) or 2000)),
        )
        base = {
            "task": task_name,
            "input_hash": input_hash,
            "latency_ms": int((time.time() - start) * 1000),
            "used_for_final_decision": False,
        }
        if not isinstance(response, dict):
            return {
                **base,
                "status": "no_response",
                "decision": "uncertain",
                "confidence": 0.0,
                "summary": "AI 未返回可解析 JSON",
                "evidence_lines": [],
                "uncertainty_reason": getattr(self.llm, "last_json_error", "") or "no_json_response",
                "raw_preview": getattr(self.llm, "last_json_preview", "")[:300],
            }
        return {
            **base,
            "status": "success",
            "decision": str(response.get("decision") or response.get("verdict") or "uncertain"),
            "confidence": self._safe_confidence(response.get("confidence")),
            "summary": str(response.get("summary") or response.get("rationale") or "")[:500],
            "evidence_lines": self._list_of_strings(response.get("evidence_lines"))[:6],
            "uncertainty_reason": str(response.get("uncertainty_reason") or ""),
            "raw": {
                k: v for k, v in response.items()
                if k not in {"decision", "verdict", "confidence", "summary", "rationale", "evidence_lines", "uncertainty_reason"}
            },
        }

    def _build_json_prompt(self, *, task: str, instruction: str, payload: Dict[str, Any]) -> str:
        schema = {
            "decision": "one of expected_decisions",
            "confidence": 0.0,
            "summary": "不超过80个汉字的中文说明",
            "evidence_lines": ["最多3条，每条不超过100字符"],
            "uncertainty_reason": "不确定时填写，确定时为空字符串",
        }
        return "\n".join([
            f"任务: {task}",
            instruction,
            "返回要求: 只返回一个紧凑 JSON 对象；不要 markdown；不要代码块；不要额外解释；不要复述输入 diff。",
            "JSON schema:",
            json.dumps(schema, ensure_ascii=False),
            "合法返回示例:",
            '{"decision":"uncertain","confidence":0.3,"summary":"证据不足，需人工复核。","evidence_lines":[],"uncertainty_reason":"缺少上下文"}',
            "输入:",
            json.dumps(payload, ensure_ascii=False),
        ])

    def _clip(self, text: str) -> str:
        limit = int(getattr(self.config, "max_diff_chars", 12000) or 12000)
        return (text or "")[:max(1000, limit)]

    @staticmethod
    def _changed_bodies(diff_text: str) -> List[str]:
        return [
            line[1:].strip()
            for line in (diff_text or "").splitlines()
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
        ]

    @staticmethod
    def _compact_rule_hits(rule_hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for hit in rule_hits or []:
            out.append({
                "rule_id": hit.get("rule_id", ""),
                "severity": hit.get("severity", ""),
                "level_floor": hit.get("level_floor", ""),
                "message": hit.get("message", ""),
                "evidence": hit.get("evidence", {}),
            })
        return out

    @staticmethod
    def _safe_confidence(value) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _list_of_strings(value) -> List[str]:
        if not value:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value if item is not None]
        return [str(value)]
