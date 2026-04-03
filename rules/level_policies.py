"""L0-L5 场景编排：DryRun 基线级别 + 规则抬升策略。"""

from typing import Dict, List

from rules.base import LevelPolicy, LevelPolicyRegistry


LEVEL_ORDER: List[str] = ["L0", "L1", "L2", "L3", "L4", "L5"]
DEFAULT_LEVEL_FLOOR_BY_SEVERITY: Dict[str, str] = {
    "info": "L0",
    "warn": "L2",
    "high": "L3",
}


LEVEL_POLICIES = [
    LevelPolicy(
        level="L0",
        methods=["strict"],
        strategy="L0 确定性无害：DryRun 严格命中且无风险规则抬升，才可视为 100% 可落地、无额外语义扰动。",
        review_mode="auto-pass",
        next_action="可直接进入无害变更路径；仍建议保留最小回归验证。",
        harmless_allowed=True,
        confidence_with_llm="high",
        confidence_without_llm="high",
    ),
    LevelPolicy(
        level="L1",
        methods=["ignore-ws", "context-C1", "C1-ignore-ws"],
        strategy="L1 轻微上下文漂移：补丁本体接近原样，优先进入 LLM/人工核对‘是否仅为入参、格式、上下文微调’的低风险审查路径。",
        review_mode="llm-review",
        next_action="结合 LLM 与人工确认是否仅为上下文/入参调整；未明确前不自动标记 harmless。",
        harmless_allowed=False,
        confidence_with_llm="medium",
        confidence_without_llm="low",
    ),
    LevelPolicy(
        level="L2",
        methods=["3way"],
        strategy="L2 中等风险适配：存在合并语义或较大改动告警，需要人工对照主线 hunk 与调用面。",
        review_mode="targeted-review",
        next_action="逐 hunk 核对逻辑差异、调用点和前置依赖。",
        harmless_allowed=False,
        confidence_with_llm="medium",
        confidence_without_llm="medium",
    ),
    LevelPolicy(
        level="L3",
        methods=["regenerated"],
        strategy="L3 语义敏感变更：涉及关键结构、上下文重生成或更强规则抬升，必须做聚焦代码审查与回归测试。",
        review_mode="focused-review",
        next_action="重点审查关键数据结构、锁、返回路径和回归测试覆盖。",
        harmless_allowed=False,
        confidence_with_llm="low",
        confidence_without_llm="low",
    ),
    LevelPolicy(
        level="L4",
        methods=["conflict-adapted"],
        strategy="L4 高风险牵连：冲突适配或关键变更已沿调用链扩散，必须人工审批。",
        review_mode="manual-approval",
        next_action="需要资深维护者人工审批，并核对调用者/被调用者链路影响。",
        harmless_allowed=False,
        confidence_with_llm="low",
        confidence_without_llm="low",
    ),
    LevelPolicy(
        level="L5",
        methods=["verified-direct"],
        strategy="L5 回退/未知路径：绕过常规 apply 或方法未识别，按最高谨慎度处理。",
        review_mode="fallback-review",
        next_action="保留证据，走人工确认或补充样本验证。",
        harmless_allowed=False,
        confidence_with_llm="low",
        confidence_without_llm="low",
    ),
]


def level_rank(level: str) -> int:
    try:
        return LEVEL_ORDER.index(level)
    except ValueError:
        return len(LEVEL_ORDER) - 1


def effective_level_floor(rule_hit: Dict) -> str:
    floor = rule_hit.get("level_floor")
    if floor in LEVEL_ORDER:
        return floor
    return DEFAULT_LEVEL_FLOOR_BY_SEVERITY.get(rule_hit.get("severity", "warn"), "L2")


def derive_final_level(base_level: str, rule_hits: List[Dict]) -> str:
    final_level = base_level if base_level in LEVEL_ORDER else "L5"
    for hit in rule_hits or []:
        floor = effective_level_floor(hit)
        if level_rank(floor) > level_rank(final_level):
            final_level = floor
    return final_level


def register_level_policies(registry: LevelPolicyRegistry, config=None):
    for policy in LEVEL_POLICIES:
        registry.register(policy)
