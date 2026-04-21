# 自适应 DryRun 引擎

本文只负责解释补丁“怎么试应用、怎么适配、为什么成功或失败”。`L0-L5` 最终分级请看 `docs/MULTI_LEVEL_ALGORITHM.md`；系统整体架构请看 `docs/TECHNICAL.md`。

---

## 1. DryRun 解决什么问题

DryRun 的职责不是“判断这个 CVE 值不值得回移”，而是更具体的一个问题：

> 社区补丁拿到目标仓以后，能不能落地？如果不能，最小可行的适配路径是什么？

它主要处理以下几类差异：

| 差异类型 | 典型表现 | DryRun 处理方式 |
| --- | --- | --- |
| 纯上下文漂移 | 行号变了、邻近代码多了几行 | `context-C1`、`ignore-ws` |
| 路径迁移 | 上游文件路径与下游不同 | PathMapper 重写 diff 路径 |
| 双边都修改了同一段 | `git apply` 冲突，但代码意图仍接近 | `3way` |
| 原始 context 已经失效 | 补丁主体还在，但定位锚点变了 | `regenerated`、`verified-direct` |
| 真实冲突需要人工改写 `-` 行 | 社区 hunk 与目标文件实际内容明显分叉 | `conflict-adapted` |
| 全部确定性路径都失败 | 目标代码改写太大 | 可选 `AI-Generated` 兜底 |

---

## 2. 当前实际尝试顺序

以 `agents/dryrun.py` 的实现为准，当前主流程顺序如下：

```text
strict
  -> ignore-ws
  -> context-C1
  -> C1-ignore-ws
  -> 3way
  -> verified-direct
  -> regenerated
  -> regenerated-zero/*
  -> conflict-adapted
  -> [optional] AI-generated
```

注意两点：

| 事项 | 说明 |
| --- | --- |
| `verified-direct` 是内部强适配路径 | 它不依赖 `git apply` 成功，而是在内存中重建和验证变更 |
| `regenerated-zero/*` 会在 batch 统计中归入 `Zero-Context` 家族 | 它仍属于 `regenerated` 系列的一部分，但用户报告里会单列 |

---

## 3. 报告中的策略家族

`batch-validate` 不直接暴露所有原始 `apply_attempt`，而是聚合成以下策略家族：

| 报告中的策略家族 | 对应 `apply_method` / `apply_attempts` | 含义 |
| --- | --- | --- |
| `Strict` | `strict` | 原始补丁直接可用 |
| `Context-C1/Whitespace` | `ignore-ws`、`context-C1`、`C1-ignore-ws` | 主要是上下文或空白漂移 |
| `3-Way` | `3way` | 借助共同祖先做三方合并 |
| `Verified-Direct` | `verified-direct`、`verified-direct-exact` | 内存中定位并验证重建差异 |
| `Regenerated` | `regenerated` | 重新生成 context 后再做 `git apply --check` |
| `Zero-Context` | `regenerated-zero/*` 成功 | 直接消掉 context，把定位退化到核心 `+/-` 变更 |
| `Conflict-Adapted` | `conflict-adapted` | 结合目标文件实际内容改写 hunk |
| `AI-Generated` | `ai-generated` | AI 兜底生成候选补丁，必须已通过 apply check |
| `Unresolved` | 无法归类或整体失败 | 没有稳定适配到任何策略家族 |

---

## 4. 每个策略到底在解决什么问题

| 家族 | 核心动作 | 证据强度 | 什么时候适合 | 什么时候不应过度乐观 |
| --- | --- | --- | --- | --- |
| `Strict` | 原始补丁直接 `git apply --check` | 最强 | 目标仓上下文与上游几乎一致 | 即使 `strict` 成功，也不代表没有依赖或语义风险 |
| `Context-C1/Whitespace` | 放宽上下文或空白限制 | 强 | 代码主体没变，只是邻近 context 漂移 | 如果同时命中 API、状态机、字段规则，不能按低风险处理 |
| `3-Way` | 使用共同祖先自动合并两边修改 | 中等 | 双边都修改了同一段，但 Git 还能拼起来 | 合并成功不等于语义等价 |
| `Verified-Direct` | 在内存中定位变更点并验证生成的新 diff | 中等偏强 | `git apply` 已经不稳，但变更点仍可精确定位 | 已经进入语义适配区，不该当成“文本自然命中” |
| `Regenerated` | 用目标文件当前内容重建 context | 中等 | 原始 context 已过期，但 `+/-` 核心仍清楚 | 如果定位锚点本身可疑，必须人工复核 |
| `Zero-Context` | 去掉 context，只保留核心变更 | 中等偏弱 | context 已经被大面积改写，但核心行还可对应 | 很容易误解成“修复成功”，实际只是应用约束进一步放松 |
| `Conflict-Adapted` | 用目标文件实际行替换原 hunk 的 `-` 行 | 弱于上述策略 | 已出现真实冲突，但仍希望保留 `+` 行修复意图 | 默认应进入审批/人工审查通道 |
| `AI-Generated` | 让 LLM 结合目标代码语义生成补丁，再跑确定性 apply check | 最弱、仅兜底 | 所有确定性路径都失败且显式开启 | 不能替代确定性链路，不应当作高置信结果 |

---

## 5. 内部关键步骤

### 5.1 路径重写

在真正尝试 apply 之前，会先根据 PathMapper 重写 diff 头里的路径：

| 目的 | 例子 |
| --- | --- |
| 把上游路径改成下游路径 | `fs/smb/client/...` -> `fs/cifs/...` |
| 避免因为文件路径差异导致“根本找不到文件” | 上游存在、下游重命名后的企业分支 |

### 5.2 快速路径

首轮快速尝试是：

| 顺序 | 方法 | 作用 |
| --- | --- | --- |
| 1 | `strict` | 最强证据，先试原始补丁 |
| 2 | `ignore-ws` | 忽略空白差异 |
| 3 | `context-C1` | 放宽上下文匹配 |
| 4 | `C1-ignore-ws` | 同时放宽上下文和空白 |
| 5 | `3way` | 使用共同祖先做自动合并 |

### 5.3 强适配路径

快速路径全失败后，会进入更强的适配：

| 方法 | 核心思路 |
| --- | --- |
| `verified-direct` | 先在目标文件中精确定位变更点，再在内存里应用并生成标准 diff |
| `regenerated` | 用目标文件当前文本重建新的 patch context |
| `regenerated-zero/*` | 进一步去除 context 依赖，只保留核心变更 |
| `conflict-adapted` | 识别真实冲突 hunk 后，用目标文件实际 `-` 行重写冲突补丁 |

### 5.4 Git 3-way merge 到底是什么

`3way` 最容易被误解成“Git 判断补丁语义正确”。实际不是。

它只做三方文本合并：

```text
base   = 上游补丁基于的旧代码
theirs = 上游应用修复后的代码
ours   = 目标分支当前代码

Git 尝试把 base -> theirs 的变化搬到 ours 上
```

它比 `strict` 更宽松，因为它允许目标分支和上游补丁基线之间已经有一些差异；但它也更需要 review，因为 Git 不理解锁、状态机、错误路径、对象生命周期等语义。

| 结论 | 说明 |
| --- | --- |
| `3way` 成功 | Git 找到了可合并的文本结果 |
| `3way` 失败 | 文本冲突太强，无法自动拼接 |
| `3way` 成功但最终升到 `L3/L4` | 合并能过，但风险规则发现语义风险 |

---

## 6. `verified-direct` 的实现含义

这是当前最容易被误解的内部路径。

| 常见误解 | 实际含义 |
| --- | --- |
| “绕过 `git apply` 很危险” | 它不是盲改，而是先精确定位、再验证、再生成 diff |
| “它应该算 `L5`” | 不对。它是 DryRun 的内部强适配方法，最终分级由规则引擎决定 |
| “它比 regenerated 更随意” | 不对。它的定位和验证通常比纯文本重建更强 |

它的实际执行过程可以拆成四步：

| 步骤 | 做什么 | 失败时意味着什么 |
| --- | --- | --- |
| 1. 提取核心 hunk | 从原始补丁里取出 `-` / `+` 变更主体和少量上下文 | 补丁本身缺少可识别变更主体 |
| 2. 在目标文件定位 | 在目标分支当前文件中寻找唯一或高置信的旧代码落点 | 目标代码形态已经偏离，不能稳定定位 |
| 3. 内存应用并复核 | 不改工作区，先在内存文本中替换，再核对新增行、删除行和锚点 | 替换结果与原始修复意图不一致 |
| 4. 生成标准 diff | 把内存结果重新输出成可审查、可验证的 patch | 无法形成稳定 patch，不应继续自动判定 |

因此，`verified-direct` 不是“绕开 Git 强行通过”。它只是在 `git apply` 的上下文匹配已经不够稳时，用更直接的 hunk 定位和内存验证证明“这段核心改动还能稳定落到目标文件”。它证明的是**补丁落点和文本变更可重建**，不是证明锁、状态机、生命周期等语义天然安全。

什么时候 `verified-direct` 证据最强？

| 场景 | 原因 |
| --- | --- |
| validate 中 `generated_vs_real.deterministic_exact_match = true` | 说明工具重建出的补丁与真实修复完全一致 |
| `verified-direct-exact` | 内部校正后说明它更接近“低漂移的精确重建” |

`verified-direct` 与 `verified-direct-exact` 的区别：

| 方法 | 默认基线 | 口径 |
| --- | --- | --- |
| `verified-direct` | `L3` | 已经进入强适配路径，需要人工聚焦确认落点、上下文和语义 |
| `verified-direct-exact` | `L1` | validate 或内部校正确认生成结果与真实修复/精确落点一致，可按低漂移快速复核 |

---

## 7. `regenerated` 与 `Zero-Context` 的区别

| 项目 | `regenerated` | `Zero-Context` |
| --- | --- | --- |
| 保留 context | 是 | 否 |
| 依赖锚点 | 依赖 | 只保留核心 `+/-` 变更 |
| 证据强度 | 高于 `Zero-Context` | 低于普通 `regenerated` |
| 适用场景 | context 漂移，但仍可稳定重建 | context 已失效，但变更主体仍清楚 |

简化理解：

- `regenerated` 是“我还能补齐上下文”
- `Zero-Context` 是“上下文已经没法信了，但核心改动还可尝试落地”

---

## 8. 冲突适配怎么做

`conflict-adapted` 不是简单把冲突忽略掉，它做的是：

1. 逐 hunk 分析冲突
2. 找到目标文件中对应的实际内容
3. 用目标文件实际内容替换补丁中的 `-` 行
4. 保留补丁中的 `+` 行
5. 重新生成 diff 并再次做 `git apply --check`

它适合这种场景：

| 场景 | 说明 |
| --- | --- |
| 社区补丁删除的旧代码，在目标仓里已经被改写成另一种写法 | 不能再直接套社区 `-` 行 |
| 修复意图还清楚，但冲突主要来自旧分支代码形态不同 | 仍可保留 `+` 行修复意图 |

它为什么风险高：

| 原因 | 说明 |
| --- | --- |
| `-` 行已被重写 | 说明不再是“原始补丁文本应用” |
| 需要人工确认改写后的旧逻辑与目标仓真实语义一致 | 否则容易把修复插到错误上下文 |

---

## 9. 哪些 DryRun 场景通常准确率高

这里只讲证据最强的场景，不讲泛泛的“整体不错”。

| 场景 | 为什么通常准确率高 | 该看哪些字段 |
| --- | --- | --- |
| `Strict` 成功 | 原始补丁直接可用，文本证据最强 | `dryrun_detail.apply_method` |
| `Context-C1/Whitespace` 成功且无风险规则命中 | 差异主要是上下文或空白，不是语义改写 | `apply_method` + `rule_hits` |
| `verified-direct-exact` 且 validate 完全一致 | 工具重建结果已被真实修复验证 | `generated_vs_real.deterministic_exact_match` |
| batch 中 `strategy_effectiveness` 里的 `acceptable_patch_rate` 高 | 说明这个家族在当前样本集里稳定产出可接受补丁 | `summary.strategy_effectiveness` |

以下场景不应被宣传为“高准确率自动化”：

| 场景 | 原因 |
| --- | --- |
| `3-Way` | 合并成功不等于语义安全 |
| `Conflict-Adapted` | 已进入重写冲突上下文 |
| `AI-Generated` | 兜底路径，不是主路径 |

---

## 10. 哪些步骤会用到 LLM

DryRun 主链路本身默认是确定性的。

| 步骤 | 是否依赖 LLM |
| --- | --- |
| `strict` / `context-C1` / `3way` | 否 |
| `verified-direct` / `regenerated` / `conflict-adapted` | 否 |
| `AI-Generated` | 是 |

这意味着：

- **DryRun 的主价值来自确定性适配**
- **LLM 只在全部确定性路径都不稳时才属于兜底候选**
- **`ai-generated` 通过 apply check 后仍是高风险候选，不进入 L0/L1 自动通道**

---

## 11. 输出里怎么读 DryRun 结果

| 字段 | 含义 |
| --- | --- |
| `dryrun_detail.apply_method` | 最终成功或最接近成功的内部方法 |
| `dryrun_detail.apply_attempts` | 依次尝试过哪些路径，以及是否成功 |
| `adapted_patch` | 供后续对比或落地的 patch 文本 |
| `search_reports` | 冲突/定位阶段的搜索证据 |
| `dryrun_detail.ai_evidence` | AI 候选补丁的生成、拒绝、接受和语义差异摘要 |
| `generated_vs_real` | validate 场景下与真实修复的对比结果 |

---

## 12. 与其他文档的边界

| 如果你要看 | 去哪里 |
| --- | --- |
| DryRun 成功后为什么还会被升到 `L3/L4` | `docs/MULTI_LEVEL_ALGORITHM.md` |
| 用户如何把等级、算法、索引和关联补丁串起来读 | `docs/USER_DECISION_GUIDE.md` |
| 整个系统的 API/TUI/输出 schema | `docs/TECHNICAL.md` |
| 面向汇报的讲法 | `docs/presentation.md` |
