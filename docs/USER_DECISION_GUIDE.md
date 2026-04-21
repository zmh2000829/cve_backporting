# 用户决策指南：怎么看等级、算法、索引和关联补丁

本文从使用者视角解释四件事：

1. `L0-L5` 每个等级到底怎么判。
2. 每个等级常见对应哪些补丁适配算法。
3. 为什么要建立缓存索引。
4. 前置 / 后置关联补丁是怎么找出来的。

如果你只想看字段定义，请看 `docs/OUTPUT_SCHEMA.md`；如果你要看 DryRun 细节，请看 `docs/ADAPTIVE_DRYRUN.md`；如果你要看规则逐条说明，请看 `docs/RULEBOOK.md`。

---

## 1. 一条分析结果应该怎么读

建议按这个顺序读，不要只看一个字段：

| 顺序 | 看什么 | 回答什么 |
| --- | --- | --- |
| 1 | `result_status` | 这次分析完整吗，是否已经不适用或失败 |
| 2 | `intro_analysis` / `fix_search` | 目标仓是否可能受影响，修复是否已存在 |
| 3 | `dryrun_detail.apply_method` | 补丁是怎样落地或为什么落不下去 |
| 4 | `dependency_details` / `prerequisite_patches` | 是否需要同时看前置关联补丁 |
| 5 | `l0_l5.base_level` | 仅从补丁适配方式看，基础难度是多少 |
| 6 | `l0_l5.current_level` | 结合风险规则后，最终该走哪条处理通道 |
| 7 | `rule_hits` / `manual_review_checklist` | 为什么被升档，人工应重点看什么 |
| 8 | `validation_details.ai_evidence` / `dryrun_detail.ai_evidence` | 如果启用了 AI，模型补充了哪些 advisory 证据或候选补丁门禁 |

最容易误解的是 `base_level` 和 `current_level`：

| 字段 | 含义 |
| --- | --- |
| `base_level` | DryRun 给出的“补丁怎么落地”的基线级别 |
| `current_level` | Policy Engine 综合依赖、风险规则后的最终处理级别 |

所以 `base=L0, current=L3` 是合理的：它表示补丁文本能直接打上，但代码语义命中了高风险规则。

---

## 2. L0-L5 是执行通道，不是简单难度分

| 等级 | 用户该怎么理解 | 常见 DryRun 基线 | 常见升档原因 | 建议动作 |
| --- | --- | --- | --- | --- |
| `L0` | 原始补丁能直接落地，且没有明显额外风险 | `strict` | 通常无升档规则 | 最小验证后可直接回移 |
| `L1` | 只有轻微漂移，主要是空白或上下文差异 | `ignore-ws`、`context-C1`、`C1-ignore-ws`、`verified-direct-exact` | 轻 API 面变化、轻状态/字段信号、中等依赖提醒 | 快速人工复核 |
| `L2` | 已需要受控审查，不能当作原样回移 | `3way`，或 `L0/L1` 被规则抬升 | 错误路径、返回语义、大 hunk、调用面扩大、中等依赖 | 逐 hunk 审查 |
| `L3` | 进入语义敏感区，必须结合上下文理解 | `regenerated`、`verified-direct`，或被高风险规则抬升 | 锁、生命周期、状态机、结构体字段、强依赖 | 聚焦审查 + 回归测试 |
| `L4` | 风险已经需要审批，通常有冲突改写或传播 | `conflict-adapted` 常见 | 关键结构叠加调用链传播、强冲突适配 | 资深维护者审批 |
| `L5` | 自动化证据不足，不能稳定拍板 | unknown / none / unresolved | 上游情报断裂、补丁无法稳定定位、规则无法形成低级结论 | 补证据或专家接管 |

一个等级由两部分组成：

```text
current_level = max(DryRun 基线级别, 所有命中规则给出的 level_floor)
```

这意味着：

| 现象 | 正确解释 |
| --- | --- |
| `strict` 成功但最终是 `L3` | 文本能打上，但风险规则看到高风险语义变化 |
| `3way` 成功但最终是 `L4` | Git 能合并，不代表语义安全；可能还有调用链传播或关键结构风险 |
| `verified-direct` 不是 `L5` | 它是强适配路径，最终级别还要看规则和验证结果 |

---

## 3. DryRun 算法到底在做什么

DryRun 不是一个算法，而是一组从保守到激进的补丁落地尝试。

| 算法 | 它做了什么 | 适合什么情况 | 风险理解 |
| --- | --- | --- | --- |
| `strict` | 原始补丁直接执行 `git apply --check` | 目标仓上下文与上游基本一致 | 文本证据最强，但仍不代表无语义风险 |
| `ignore-ws` | 忽略空白差异再检查 | tab/space、缩进漂移 | 通常是轻漂移 |
| `context-C1` | 放宽上下文匹配要求 | 行号或邻近 context 有少量变化 | 代码主体仍接近 |
| `C1-ignore-ws` | 同时放宽上下文和空白 | 上下文与空白都有轻微漂移 | 仍属于轻适配 |
| `3way` | Git 用共同祖先、上游补丁和目标当前代码做三方合并 | 双边都改了相邻区域，但 Git 能拼起来 | 合并成功不等于语义等价 |
| `verified-direct` | 不依赖 `git apply`，在目标文件中定位变更点，内存应用并生成 diff | 原始 context 已失效，但核心变更点可稳定定位 | 已进入语义适配区，需要看规则和验证 |
| `regenerated` | 用目标文件当前内容重建 patch context，再验证 | context 漂移较大，但仍可重建 | 需要人工确认定位锚点 |
| `regenerated-zero/*` | 去掉 context，只保留核心 `+/-` 变更 | context 大面积失效 | 证据弱于普通 regenerated |
| `conflict-adapted` | 用目标文件真实旧行改写 hunk 的 `-` 行，保留修复 `+` 行 | 真实冲突但修复意图还清楚 | 默认应进入审批或强人工审查 |
| `AI-Generated` | LLM 兜底生成候选补丁，并再次通过 `git apply --check` | 确定性路径都失败且显式开启 AI 补丁建议 | 不是主路径，不能直接自动合入 |

### 3.1 Git 3-way merge 怎么理解

`3way` 不是“智能判断修复正确”，它只是 Git 的三方合并：

```text
base   = 上游补丁基于的旧版本
theirs = 上游修复后的版本
ours   = 目标分支当前版本

git 尝试把 base -> theirs 的变化搬到 ours 上
```

它的价值是处理“双边都改过附近代码”的场景；它的风险是 Git 只保证文本合并，不保证业务语义一定正确。所以 `3way` 通常不会低于 `L2`。

### 3.2 `verified-direct` 怎么理解

`verified-direct` 是确定性强适配路径，不是 AI 生成，也不是跳过校验。它做的是：

| 步骤 | 含义 |
| --- | --- |
| 定位 | 用原始 hunk 的删除行、增加行和上下文在目标文件中找落点 |
| 内存应用 | 在内存文本中替换目标片段，不直接改工作区 |
| 复核 | 确认应删除的旧行、应加入的新行和锚点关系成立 |
| 出 patch | 重新生成标准 diff，交给后续 validate / policy / 人工审查 |

读结果时注意两点：

| 结果 | 怎么看 |
| --- | --- |
| `apply_method=verified-direct` | 表示核心改动能被稳定重建，但 context 已经不是原样命中，默认按 `L3` 聚焦审查 |
| `apply_method=verified-direct-exact` | 表示校正确认接近精确重建，常作为 `L1` 低漂移快速复核 |

---

### 3.3 `ai_evidence` 怎么读

`ai_evidence` 是 AI 辅助证据，不是最终结论本身。

| 字段 | 怎么读 |
| --- | --- |
| `validation_details.ai_evidence.tasks[].task` | 模型做了哪类分析，例如低信号裁决、前置候选 triage、风险语义解释 |
| `decision` / `confidence` | 模型建议和置信度，只能作为审查参考 |
| `evidence_lines` | 模型引用的输入证据，人工应优先核对这些行 |
| `used_for_final_decision=false` | 当前没有直接改变最终分级 |
| `dryrun_detail.ai_evidence` | 只用于 AI 候选补丁，重点看是否通过 apply check、是否被拒绝、保留了哪些上游 `+` 行 |

看到 `likely_low_signal` 不代表系统已经自动降级；看到 `ai-generated` 也不代表系统已经给出可合入补丁。前者是降低误报的审查线索，后者是高风险候选补丁。

---

## 4. 为什么要建立缓存索引

目标内核仓库可能有几十万到上千万个 commit。每次都直接 `git log --grep`、按 subject 模糊搜索、按关键词查，会很慢，也不利于批量验证。

缓存索引的目的不是替代 Git，也不是建立完整代码语义索引，而是把常用 commit 元信息放进本地 SQLite：

| 索引内容 | 用途 |
| --- | --- |
| `commit_id` / `short_id` | 快速判断某个 commit 是否在目标分支 |
| `subject` | 快速做 subject 精确或关键词搜索 |
| `author` / `timestamp` | 输出证据、限定时间窗口、排序 |
| FTS 索引 | 加速关键词搜索和候选召回 |

索引主要服务这些链路：

| 链路 | 为什么需要索引 |
| --- | --- |
| `check-intro` / `check-fix` | 快速判断目标分支是否已有对应 commit |
| `Analysis Agent` L2 搜索 | subject 变体和关键词候选需要快速召回 |
| `batch-validate` | 批量样本重复查找时避免每次扫全仓 |
| 依赖分析时间窗口 | timestamp 可辅助限定 introduced commit 之后的候选范围 |

仍然会直接调用 Git 的地方：

| 操作 | 原因 |
| --- | --- |
| `git show` 读取 diff | diff 内容太大，不放入轻量 commit 索引 |
| `git log -- <file>` 搜索同文件历史 | 文件历史依赖路径和分支状态，直接用 Git 更可靠 |
| worktree / apply / merge 检查 | 必须在真实仓库状态上执行 |

---

## 5. 前置关联补丁是怎么找的

前置关联补丁回答的是：

> 当前 fix patch 是否依赖目标仓里其他已经发生或应该先合入的改动？

当前主链路由 `Dependency Agent` 做，步骤如下：

| 步骤 | 做什么 | 目的 |
| --- | --- | --- |
| 1 | 取 fix patch 修改文件，并通过 PathMapper 扩展等价路径 | 避免路径迁移导致漏搜 |
| 2 | 确定时间窗口：有 introduced commit 时从其时间开始，否则从仓库初始开始 | 只看可能影响本次修复的历史范围 |
| 3 | `git log -- <files>` 找时间窗口内修改同文件的 commit，排除 merge，默认最多取 50 个候选 | 构造候选关联补丁集合 |
| 4 | 排除已知 fix、intro、Fixes 标签引用的 commit | 避免把当前补丁或已知锚点当依赖 |
| 5 | 读取候选 diff，提取 hunk、函数、字段、锁域、状态点 | 构造文本和语义证据 |
| 6 | 计算 hunk 重叠、12 行内相邻 hunk、函数交集、共享字段/锁/状态 | 判断关联强度 |
| 7 | 评分并分成 `strong / medium / weak` | `strong/medium` 给 Policy Engine；`weak` 只保留为背景证据 |

分级口径：

| 级别 | 含义 | 用户动作 |
| --- | --- | --- |
| `strong` | 与 fix patch 有直接 hunk 重叠，且共享函数/字段/锁/状态，或综合评分很高 | 视为强前置，通常应先 review 或先合入 |
| `medium` | 有直接或相邻 hunk、函数交集、共享语义域，但证据没强到 required | 建议一并评估，不能草率忽略 |
| `weak` | 只有弱关联信号 | 作为背景线索，通常不阻断单 patch |

当前默认只会把最多 10 个 `strong/medium` 可操作候选放进 `prerequisite_patches`。单纯同文件、同函数名、远距离 hunk 或单一弱信号不会再把前置补丁列表膨胀到十几个；这类候选会进入 `dependency_details.weak_count` 和证据样本，用于人工参考，但不阻塞直接回移判断。

注意：前置依赖不是“只要补丁 apply 失败才存在”。有些前置补丁提供的是结构体字段、API 语义、状态初始化或锁保护，即使文本能 `strict` 应用，也可能仍然需要一并 review。

---

## 6. 后置关联补丁是怎么找的

后置关联补丁回答的是：

> 上游 fix 合入后，社区是否又追加了修正、补漏或同函数后续改动？

这部分主要在 `--deep` 链路中由 `RiskBenefitAnalyzer.find_post_patches()` 检测，当前两类证据：

| 关系 | 怎么找 | 含义 |
| --- | --- | --- |
| `followup_fix` | `git log --grep "Fixes: <fix_id>"` 反查后续 commit 是否 Fixes 当前补丁 | 社区明确认为当前 fix 后还需要追加修正 |
| `same_function` | 对 fix patch 修改函数做 `git log -S<func> -- <file>` | 后续又修改了同函数，可能是补漏、重构或相关行为变化 |

后置补丁不是默认必须合入，但它是重要审查线索：

| 情况 | 建议 |
| --- | --- |
| 有 `followup_fix` | 优先人工确认是否必须与当前 CVE 修复一起带入 |
| 有多个 `same_function` | 检查当前 fix 是否依赖后续语义调整，尤其是状态机、锁、错误路径 |
| 没有后置补丁 | 只能说明当前检测范围内未发现，不等于上游绝对没有相关讨论 |

---

## 7. 最常见误解

| 误解 | 正确理解 |
| --- | --- |
| `L0` 是“绝对安全” | `L0` 只是当前证据下的快速通道，仍需最小验证 |
| `3way` 成功就是合入成功 | 只说明文本能合并，语义仍要 review |
| `strict` 成功就不需要看依赖 | 错。依赖可能是 API、字段、状态初始化等语义依赖 |
| `weak` 依赖完全没用 | 它通常不阻断，但可作为人工背景线索 |
| 后置补丁都必须合 | 不一定。`followup_fix` 优先级高，`same_function` 需要人工判断关系 |
| 索引是为了替代 Git | 不是。索引用来加速 commit 元信息搜索，真实 diff/apply 仍依赖 Git |
