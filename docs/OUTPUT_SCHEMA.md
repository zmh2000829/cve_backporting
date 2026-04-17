# 输出 Schema 手册

本文只负责说明 JSON 输出长什么样、哪些字段必须有、每个字段该怎么读。

如果你想看 HTTP 接口请求模板，请看 `docs/API_CONTRACT.md`；如果你想看规则和等级含义，请看 `docs/MULTI_LEVEL_ALGORITHM.md` 与 `docs/RULEBOOK.md`。

---

## 1. 输出分层

| 输出层 | 典型文件 / 来源 | 作用 |
| --- | --- | --- |
| 单案例分析 | `analyze` 的 `report.json` | 回答“是否需要回移、怎么处理” |
| 单案例验证 | `validate` 的 `report.json` | 回答“工具结果与真值差多远” |
| 批量汇总 | `batch-validate` summary JSON | 回答“策略效果、分级准确率、风险分布如何” |
| 错误返回 | HTTP 错误体 | 回答“为什么请求没法执行” |

---

## 2. 单案例通用字段

| 字段 | 是否必须 | 作用 |
| --- | --- | --- |
| `cve_id` | 是 | 当前 CVE 编号 |
| `target_version` | 是 | 目标仓别名 |
| `result_status` | 是 | 状态、错误语义、不完整原因 |
| `analysis_framework` | 是 | 过程 / 证据 / 结论骨架 |
| `l0_l5` | 是 | 最终级别与 DryRun 基线级别 |
| `traceability` | 是 | 规则 profile、schema 版本、目标仓 HEAD 等追溯信息 |
| `analysis_narrative` | 建议 | 面向人的过程说明 |
| `artifacts` | 建议 | 输出目录、patch 文件路径 |

---

## 3. `result_status`

### 3.1 字段字典

| 字段 | 类型 | 是否必须 | 说明 |
| --- | --- | --- | --- |
| `state` | string | 是 | `complete` / `incomplete` / `not_applicable` / `error` |
| `error_code` | string | 建议 | 错误或特殊状态代码 |
| `user_message` | string | 是 | 面向用户的说明 |
| `technical_detail` | string | 建议 | 面向开发者的补充解释 |
| `retryable` | bool | 建议 | 是否建议重试 |
| `incomplete_reason` | string | `incomplete` 时建议 | 不完整原因 |
| `evidence_refs` | array[string] | 建议 | 对应的 CVE / commit / 线索引用 |

### 3.2 常见 `state`

| `state` | 含义 |
| --- | --- |
| `complete` | 链路执行完成，并形成稳定结论 |
| `incomplete` | 执行过，但上游情报或结论骨架不完整 |
| `not_applicable` | 目标仓已修复或当前不适用 |
| `error` | 请求或运行发生错误 |

---

## 4. `analysis_framework`

### 4.1 骨架

```json
{
  "process": {},
  "evidence": {},
  "conclusion": {}
}
```

### 4.2 三层含义

| 层 | 回答什么 |
| --- | --- |
| `process` | 工具做了哪些步骤 |
| `evidence` | 工具依据什么证据做判断 |
| `conclusion` | 最终建议是什么 |

---

## 5. `l0_l5`

### 5.1 必要字段

| 字段 | 是否必须 | 作用 |
| --- | --- | --- |
| `current_level` | 是 | 最终执行通道 |
| `base_level` | 是 | DryRun 基线级别 |
| `base_method` | 强烈建议 | `strict / 3way / regenerated / conflict-adapted ...` |
| `review_mode` | 强烈建议 | 平台和 UI 直接展示用 |
| `next_action` | 强烈建议 | 可直接映射到人工流程 |
| `reason` | 建议 | 等级结论说明 |
| `dependency_bucket` | 建议 | `independent / recommended / required` |

### 5.2 最小模板

```json
{
  "current_level": "L2",
  "base_level": "L1",
  "base_method": "context-C1",
  "review_mode": "controlled-review",
  "next_action": "逐 hunk 审查后决定是否回移"
}
```

最硬的约束：

| 约束 | 当前口径 |
| --- | --- |
| `L0-L5` 是否必须输出 | **是。单案例结果必须有 `l0_l5.current_level` 和 `l0_l5.base_level`。** |

---

## 6. `traceability`

| 字段 | 作用 |
| --- | --- |
| `report_version` / `schema_version` | 输出格式版本 |
| `generated_at` | 生成时间 |
| `policy.profile` | 使用的规则 profile |
| `policy.special_risk_rules_enabled` | P2 规则开关 |
| `target_repo.head` | 目标仓 HEAD |
| `target_repo.branch` | 目标分支 |
| `target_repo.path` | 本地仓库路径 |
| `data_sources` | 当前使用了哪些外部或本地数据源 |

---

## 7. validate 专有字段

### 7.1 `generated_vs_real`

| 字段 | 作用 |
| --- | --- |
| `verdict` | `identical / essentially_same / different / no_data` |
| `deterministic_exact_match` | 是否逐字等价 |
| `analysis` | 若存在，解释为什么有差异 |

### 7.2 `overall_pass`

| 值 | 含义 |
| --- | --- |
| `true` | 验证通过 |
| `false` | 验证未通过，或验证不完整 |

---

## 8. batch summary

### 8.1 必要字段

| 字段 | 是否必须 | 作用 |
| --- | --- | --- |
| `summary.l0_l5` | 是 | `L0-L5` 主分布 |
| `summary.strategy_effectiveness` | 是 | DryRun 家族效果统计 |
| `summary.level_accuracy` | 是 | 每级别准确率统计 |
| `summary.risk_hit_summary` | 是 | 风险命中汇总 |
| `summary.level_distribution` | 建议 | 与旧调用方兼容 |

### 8.2 `summary.l0_l5`

| 字段 | 作用 |
| --- | --- |
| `levels` | 固定级别列表 |
| `current_level_distribution` | 最终级别分布 |
| `base_level_distribution` | DryRun 基线分布 |

### 8.3 `summary.strategy_effectiveness`

| 字段 | 作用 |
| --- | --- |
| `strategies[]` | 每个策略家族的数量、占比、通过率、补丁准确率、精确匹配率 |
| `counts` | 各策略家族总数 |
| `automation` | 自动化完成占比与 unresolved 占比 |
| `definition` | 每个策略家族的归类定义 |

### 8.4 `summary.level_accuracy`

| 字段 | 作用 |
| --- | --- |
| `final_levels` | 每个最终级别的 `total / passed / acceptable_patch / exact_match / rates` |
| `base_levels` | 每个基线级别的同类统计 |
| `definitions` | `pass_rate / acceptable_patch_rate / exact_match_rate` 的定义 |

### 8.5 `summary.risk_hit_summary`

| 字段 | 作用 |
| --- | --- |
| `any_special_risk_count` | 任意专项高风险命中的样本数 |
| `critical_structure_change_count` | 关键结构变化样本数 |
| `special_risk_section_counts` | 错误路径、生命周期、状态机、字段路径等分节统计 |
| `promotion_matrix` | 样本从哪个基线级别升级到哪个最终级别 |
| `top_promotion_rules` | 主导升级的规则 |

---

## 9. 错误结构

| 顶层字段 | 说明 |
| --- | --- |
| `ok` | 固定为 `false` |
| `status_code` | HTTP 状态码 |
| `error.state` | 固定为 `error` |
| `error.error_code` | 错误码 |
| `error.user_message` | 面向用户的错误说明 |
| `error.technical_detail` | 开发者排查细节 |
| `error.route` | 当前路由 |
| `error.missing_input` | 缺失字段列表 |
| `error.hint` | 修复建议 |
| `error.suggested_fix` | 可直接照抄的修正模板 |
| `error.absolute_date` | 绝对日期，避免相对时间歧义 |

---

## 10. 推荐集成约束

| 约束 | 当前口径 |
| --- | --- |
| 单案例没有 `l0_l5` 就不算有效接入 | 平台分流必须基于最终级别 |
| batch 没有 `summary.l0_l5` / `strategy_effectiveness` / `level_accuracy` 就不算完整统计 | 否则无法做长期效果评估 |
| 不要只看 `overall_pass` | 必须结合 `l0_l5`、`result_status`、`generated_vs_real` 一起读 |
