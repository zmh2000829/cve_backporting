# AI 增强与 GLM5 接入说明

本文说明当前 AI 能力在项目中的定位、配置方式、输出字段和安全边界。`L0-L5` 分级仍以 `docs/MULTI_LEVEL_ALGORITHM.md` 为准；DryRun 适配顺序仍以 `docs/ADAPTIVE_DRYRUN.md` 为准。

---

## 1. 设计定位

AI 增强不是用模型替代确定性搜索、依赖分析、DryRun 或规则分级。当前实现把 GLM5/OpenAI-compatible 模型放在两个位置：

| 位置 | 作用 | 是否默认影响最终结论 |
| --- | --- | --- |
| 结构化 advisory task | 对弱信号误升级、前置补丁候选、风险语义做解释和裁决建议 | 否 |
| AI patch suggestion | 在确定性 DryRun 全部失败后生成候选 diff | 只有通过 `git apply --check` 后才作为高风险 `ai-generated` 候选 |

因此，AI 输出的核心价值是补充证据、排序人工关注点、解释不确定性，而不是直接把补丁判成可自动合入。

---

## 2. GLM5 配置

GLM5 通过 OpenAI-compatible endpoint 接入。建议把密钥放在本地 `config.yaml` 或环境变量中，不要写入可提交文件。

```yaml
llm:
  enabled: true
  provider: "glm"
  api_key: "${GLM_API_KEY}"
  base_url: "http://<glm5-host>:8888/v1"
  model: "GLM-5"
  max_tokens: 2000
  temperature: 0.1
  timeout: 90

ai:
  mode: "advisory"        # off / advisory / gated
  cache_enabled: true
  prompt_version: "ai-v1"
  max_candidates_for_rerank: 20
  max_diff_chars: 12000
  enable_dependency_triage: true
  enable_low_signal_adjudication: true
  enable_risk_explainer: true
  enable_conflict_patch_suggestion: false
```

字段含义：

| 字段 | 说明 |
| --- | --- |
| `llm.provider=glm` | 使用 GLM/OpenAI-compatible 调用路径 |
| `llm.api_key=${GLM_API_KEY}` | 从环境变量读取密钥；未配置时自动降级为确定性模式 |
| `ai.mode=off` | 完全关闭 AI task |
| `ai.mode=advisory` | 运行 AI task，但分析类 task 只写入 `ai_evidence` |
| `ai.mode=gated` | 预留给经过 batch validate 校准后的门控模式 |
| `enable_conflict_patch_suggestion` | 是否允许 DryRun 失败后调用 AI 生成候选补丁 |

---

## 3. 当前已实现的 AI task

| Task | 触发输入 | 输出决策 | 当前用途 |
| --- | --- | --- | --- |
| `low_signal_adjudication` | diff、规则命中、变更行数 | `semantic_risk / likely_low_signal / uncertain` | 识别普通条件、字段、日志、rename 等误升级高发样本 |
| `dependency_triage` | strong/medium/weak 前置候选证据 | `required / helpful / background / unrelated / uncertain` | 帮助区分真正前置依赖和同文件历史噪声 |
| `risk_semantic_explainer` | 风险规则、锁/生命周期/状态机/字段/错误路径命中 | `high_risk / attention / likely_low_risk / uncertain` | 给人工审查补充对象级解释 |
| `ai_patch_suggestion` | 上游 diff、目标文件上下文、冲突分析 | unified diff 候选 | 仅在确定性路径失败且显式开启时兜底 |

分析类 task 默认 `used_for_final_decision=false`。`ai_patch_suggestion` 是例外：如果候选 diff 通过确定性 `git apply --check`，会记录 `used_for_final_decision=true`，但 `apply_method=ai-generated` 仍保持高风险/L5，不进入 L0/L1 自动通道。

---

## 4. 输出字段

AI 证据统一写入 `ai_evidence`：

```json
{
  "ai_evidence": {
    "enabled": true,
    "mode": "advisory",
    "provider": "glm",
    "model": "GLM-5",
    "prompt_version": "ai-v1",
    "tasks": [
      {
        "task": "low_signal_adjudication",
        "status": "success",
        "decision": "likely_low_signal",
        "confidence": 0.81,
        "summary": "普通条件变化，暂未看到锁或生命周期语义。",
        "evidence_lines": ["if (ctx->active)"],
        "used_for_final_decision": false
      }
    ],
    "summary": ["普通条件变化，暂未看到锁或生命周期语义。"]
  }
}
```

常见位置：

| 位置 | 含义 |
| --- | --- |
| `validation_details.ai_evidence` | 分析类 advisory task 的结构化结果 |
| `dryrun_detail.ai_evidence` | AI patch suggestion 的生成、校验、拒绝或接受证据 |
| `human_friendly_summary.key_evidence.AI辅助证据` | 面向人阅读的摘要 |

---

## 5. AI 生成补丁的门禁

`ai-generated` 只表示模型生成的候选补丁通过了确定性 apply check，不表示语义已经正确。

当前门禁顺序：

1. 确定性 DryRun 路径全部失败。
2. `ai.enable_conflict_patch_suggestion=true`。
3. 能读取目标文件上下文。
4. 模型返回有效 unified diff。
5. 候选 diff 通过 `git apply --check`、`--ignore-whitespace` 或 `-C1` 中至少一种。
6. 结果标记为 `apply_method=ai-generated`。
7. Policy Engine 按 L5/高风险人工通道处理。

任何一步失败，AI patch suggestion 都不会替代原有 dryrun 失败结果。

---

## 6. 安全边界

| 边界 | 要求 |
| --- | --- |
| 密钥 | 只放本地 `config.yaml` 或环境变量，不提交到仓库 |
| 输入长度 | 受 `ai.max_diff_chars` 和目标文件上下文截断控制 |
| 可复现性 | AI task 记录 `provider`、`model`、`prompt_version`、`input_hash` |
| 自动合入 | AI 输出不应直接触发自动合入 |
| 批量校准 | 只有通过 batch validate 证明稳定收益的 task，后续才允许进入 `gated` 模式 |
