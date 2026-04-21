# 多级算法与 L0-L5 分级手册

本文只负责讲四件事：

1. 搜索 / 依赖 / 风险规则的核心算法口径
2. `L0-L5` 是怎么从 `base_level` 推到 `final_level` 的
3. 调用链、LLM 使用边界、准确率高场景
4. 什么时候应该继续保守处理

规则逐条解释请看 `docs/RULEBOOK.md`；系统边界请看 `docs/BOUNDARIES.md`；DryRun 具体顺序请看 `docs/ADAPTIVE_DRYRUN.md`；接口和 schema 请看 `docs/API_CONTRACT.md` 与 `docs/OUTPUT_SCHEMA.md`。

---

## 1. 这套分级到底在回答什么问题

系统并不是只做“补丁能不能 apply”的判断。它会把多个维度合成一个最终处理通道：

| 维度 | 回答的问题 |
| --- | --- |
| 搜索证据 | 上游修复和目标仓之间的对应关系是否稳定 |
| 依赖证据 | 当前补丁是否必须与其他补丁一起看 |
| DryRun 证据 | 原始补丁是否可直接用，还是必须适配 |
| 风险证据 | 锁、生命周期、状态机、字段、错误路径、调用链是否有风险 |

最后输出的 `L0-L5` 是执行通道，而不是“改了多少行”的简单难度分。

---

## 2. 核心算法地图

### 2.1 搜索算法

| 层级 | 算法 | 适合场景 | 证据强度 |
| --- | --- | --- | --- |
| L1 | ID 精确匹配 | commit ID 已知、上下游没有改 ID | 最强 |
| L2 | Subject 语义匹配 | backport commit 改了 subject，但仍能看出语义对应 | 中等偏强 |
| L3 | Diff 级匹配 / 包含度 | squash、改 subject、合并提交 | 中等 |
| missing-intro probe | fix patch 代码形态探测 | 上游没有 introduced commit，但有 fix patch | 启发式证据 |

`missing-intro probe` 不会伪造 introduced commit。它只把 fix patch 的 removed/added 行与目标分支当前文件对比，输出 `intro_analysis`，用于判断是否继续后续依赖分析和 DryRun。

### 2.2 前置依赖算法

| 输出 | 具体含义 | 应对动作 |
| --- | --- | --- |
| `independent` | 未发现必须额外关注的关联补丁 | 可先按单补丁处理 |
| `recommended` | 有中等依赖信号，建议同时看关联补丁 | 不宜草率直接回移 |
| `required` | 有强依赖证据，顺序错误会带来风险 | 必须把前置补丁纳入决策 |

依赖算法现在只把 `strong/medium` 作为可操作前置补丁交给规则引擎，默认最多返回 10 个。`weak` 候选仍会统计在 `dependency_details.weak_count` 和证据样本中，但不会进入 `prerequisite_patches`，避免“同文件历史很多”把一个能完全一致合入的补丁误判成需要十几个前置补丁。

### 2.3 风险规则算法

| 规则类 | 作用 |
| --- | --- |
| `admission` | 证明为什么可以留在低级别 |
| `low_level_veto` | 阻止样本误落入 `L0/L1` |
| `direct_backport_veto` | 阻止系统轻率给出“可直接回移” |
| `risk_profile` | 显式抬升锁、生命周期、状态机、字段、错误路径、调用链等风险 |

所有用户可见规则的逐条说明，请直接看 `docs/RULEBOOK.md`。

---

## 3. `base_level` 与 `final_level`

### 3.1 先分清两个概念

| 字段 | 作用 | 来源 |
| --- | --- | --- |
| `base_level` | DryRun 基线级别，表示“补丁是怎么落地的” | `apply_method` 映射 |
| `final_level` | 最终执行通道，表示“结合规则以后该怎么处理” | `base_level + rule_hits` |

核心计算公式：

```text
final_level = max(base_level, 所有命中规则给出的 level_floor)
```

### 3.2 为什么会差很多

| 组合 | 正常解释 |
| --- | --- |
| `base=L0, final=L3` | 文本上可直接应用，但风险规则看到了关键语义风险 |
| `base=L1, final=L2` | 轻漂移本身不重，但叠加 API 或错误路径变化后需要人审 |
| `base=L2, final=L4` | `3way` 能过，但风险已经沿调用链或关键结构扩散 |

---

## 4. L0-L5 总表

| 级别 | 通道定位 | 基线方法 / 进入方式 | 典型升档信号 | 推荐动作 | 用户应该怎么理解 |
| --- | --- | --- | --- | --- | --- |
| `L0` | Deterministic Fast-Track | `strict` 且命中 `direct_backport_candidate` | 任一 veto / risk 规则命中都会升档 | 最小验证后可直接回移 | 最强文本证据，且没有额外风险信号 |
| `L1` | Low-Drift Quick Review | `ignore-ws`、`context-C1`、`C1-ignore-ws`、`verified-direct-exact` | `l1_api_surface`、`recommended prereq`、轻度状态/字段信号 | 快速复核 | 主要是轻微漂移，但还不能盲目自动合 |
| `L2` | Controlled Review | `3way` 常见；或 `L0/L1` 被中等风险规则抬升 | 错误路径、API 面变化、调用链扩散、大改动、中等依赖 | 逐 hunk 审查 | 能适配，但已不是“原样回移” |
| `L3` | Semantic Review | `regenerated`、`verified-direct`；或低级别被高风险规则抬升 | 锁、生命周期、状态机、结构体字段、强依赖 | 聚焦审查 + 回归测试 | 已进入语义敏感区 |
| `L4` | Approval Gate | `conflict-adapted` 常见；或关键结构叠加传播链 | 关键结构 + propagation、强冲突适配 | 资深维护者审批 | 风险已扩散到链路级 |
| `L5` | Highest-Difficulty Escalation | 方法未知、证据断裂或自动化已到边界 | 上游情报不足、规则无法稳定给出低级结论 | 补证据、专家主导 | 最高难度级别，不应继续自动拍板 |

### 4.1 每级别的详细差异

| 维度 | `L0` | `L1` | `L2` | `L3` | `L4` | `L5` |
| --- | --- | --- | --- | --- | --- | --- |
| 文本证据强度 | 最强 | 强 | 中等 | 中等偏弱 | 弱 | 不稳定 |
| 语义风险暴露 | 低 | 低到中 | 中 | 高 | 很高 | 不可稳定判断 |
| 是否允许“可直接回移” | 可能 | 通常不直接给 | 否 | 否 | 否 | 否 |
| 是否必须人工看代码 | 通常否 | 建议是 | 是 | 是 | 是 | 必须 |
| 是否需要审批 | 否 | 否 | 否 | 视场景 | 是 | 是 |

### 4.2 每个等级通常用了哪些补丁算法

| 等级 | 常见 `apply_method` | 为什么落在这个等级 | 用户重点检查 |
| --- | --- | --- | --- |
| `L0` | `strict` | 原始 patch 在目标仓直接 `git apply --check` 通过，且没有依赖 / 风险规则抬升 | 最小编译和回归验证 |
| `L1` | `ignore-ws`、`context-C1`、`C1-ignore-ws`、`verified-direct-exact` | 主要是空白、行号或轻微 context 漂移 | 确认核心 `+/-` 行是否未变 |
| `L2` | `3way` 常见，也可能由 `strict/L1` 被规则抬升 | Git 能三方合并，或存在中等风险信号 | 逐 hunk 看合并结果、错误路径和 API 变化 |
| `L3` | `regenerated`、`verified-direct`，或被强依赖 / 高风险规则抬升 | context 已经需要重建，或命中锁、生命周期、状态机、字段等语义风险 | 聚焦语义正确性和回归测试 |
| `L4` | `conflict-adapted` 常见，或关键结构叠加调用链传播 | 已经改写冲突 hunk，或风险扩散到调用链 | 资深维护者审批，必要时手工重写 |
| `L5` | 无稳定方法、unknown、unresolved、AI 兜底候选 | 自动化证据不足或上游情报断裂 | 补证据，专家主导 |

注意：上表是“常见映射”，不是硬编码唯一来源。最终等级一定还会叠加规则命中结果。

---

## 5. 基线方法与级别映射

| `base_method` | 默认 `base_level` | 具体含义 |
| --- | --- | --- |
| `strict` | `L0` | 原始补丁直接通过 `git apply --check` |
| `ignore-ws` / `context-C1` / `C1-ignore-ws` | `L1` | 主要是上下文或空白层面的轻漂移 |
| `3way` | `L2` | Git 用共同祖先自动拼接两边修改 |
| `regenerated` / `verified-direct` | `L3` | 已进入强适配路径 |
| `conflict-adapted` | `L4` | 冲突上下文被改写后再尝试落地 |
| unknown / none | `L5` | 方法未知或证据不足 |

用户容易误解的三点：

| 常见误解 | 正确口径 |
| --- | --- |
| `strict` 成功就一定是 `L0` | 不对。规则可以把它继续抬升 |
| `3way` 成功说明补丁很安全 | 不对。它只说明 Git 把两边修改拼起来了 |
| `verified-direct` 属于 `L5` | 不对。它是内部强适配路径，最终级别由规则决定 |

---

### 5.1 `verified-direct` 的等级口径

`verified-direct` 的核心含义是：`git apply` 的原始 context 已经不够稳定，但系统仍能在目标文件中定位 hunk，先在内存中应用，再复核并生成标准 diff。它证明“核心变更可重建”，不证明语义天然安全。

| 方法 | 基线 | 说明 |
| --- | --- | --- |
| `verified-direct` | `L3` | 强适配路径，默认需要聚焦审查落点、上下文和语义 |
| `verified-direct-exact` | `L1` | validate 或内部校正确认接近精确重建，可进入低漂移快速复核 |

如果 validate 显示 `generated_vs_real.deterministic_exact_match=true`，系统可以把 `verified-direct` 的证据校正为 `verified-direct-exact`，但最终仍会叠加依赖和风险规则。

---

## 6. 核心升档规则总览

| 规则 | 常见 floor | 触发意义 |
| --- | --- | --- |
| `l1_api_surface` | `L1/L2` | 签名、入参、返回路径变化 |
| `p2_error_path` | `L2` | 错误路径、清理顺序、回滚变化 |
| `p2_lifecycle_resource` | `L2/L3` | 生命周期、资源管理、引用计数 |
| `p2_state_machine_control_flow` | `L1/L3` | 状态机、条件分支、状态字段变化 |
| `p2_struct_field_data_path` | `L1/L3` | 字段选择、数据路径、字段使用语义变化 |
| `critical_structures` | `L2/L3` | 锁、RCU、refcount、布局敏感结构 |
| `prerequisite_recommended` | `L1` | 中等依赖，需要一起看关联补丁 |
| `prerequisite_required` | `L3` | 强依赖，不应当单 patch 决策 |
| `call_chain_fanout` | `L2` | 修改函数影响面较大 |
| `call_chain_propagation` | `L2/L4` | 风险沿调用链扩散 |
| `large_change` | `L2` | patch/hunk 规模明显变大 |
| `single_line_high_impact` | `L2/L3` | 单行修改但影响控制流或同步语义 |

逐条规则请看 `docs/RULEBOOK.md`。

---

## 7. 调用链 fanout / propagation

### 7.1 术语表

| 术语 | 具体含义 |
| --- | --- |
| `caller` | 调用当前被修改函数的函数 |
| `callee` | 当前被修改函数调用的函数 |
| `fanout` | `callers + callees` 的总数 |
| `propagation` | 风险已经从当前函数扩散到上下游函数 |

### 7.2 当前默认阈值

| 配置项 | 平衡风格 | 保守风格 | 作用 |
| --- | --- | --- | --- |
| `call_chain_fanout_threshold` | `6` | `4` | 判定“影响面较大” |
| `call_chain_promotion_min_fanout` | `2` | `2` | 判定“风险已开始传播”的最小门槛 |

### 7.3 两条规则的区别

| 规则 | 触发条件 | 常见 level_floor | 用户理解 |
| --- | --- | --- | --- |
| `call_chain_fanout` | `fanout >= threshold` | `L2` | 影响面已经变宽 |
| `call_chain_propagation` | 存在 caller/callee 牵连；无关键结构时通常要求 `fanout >= 2`；有关键结构时会更激进 | `L2` 或 `L4` | 风险已经沿链路扩散 |

注意：当前调用链分析是局部图，不是全仓多跳传播分析。完整边界请看 `docs/BOUNDARIES.md`。

---

## 8. 前置和后置关联补丁算法

### 8.1 前置关联补丁

前置关联补丁由主链路的 `Dependency Agent` 分析，目标是回答“当前 fix 是否依赖其他补丁先存在”。

| 步骤 | 算法 | 说明 |
| --- | --- | --- |
| 候选召回 | `git log -- <files>` | 在 fix patch 修改文件的历史中找相关 commit，路径会经过 PathMapper 扩展 |
| 时间窗口 | introduced commit 时间 -> HEAD | 有 intro 时从 intro 时间开始；无 intro 时退化为仓库初始到 HEAD |
| 候选过滤 | 排除 merge、当前 fix、intro、Fixes 引用 | 避免把锚点误判为依赖 |
| 结构比较 | hunk 重叠、12 行内相邻 hunk、函数交集 | 找文本和局部结构上的交叉 |
| 语义标记 | 共享字段、锁域、状态点 | 捕捉文本不完全重叠但语义域相同的依赖 |
| 分级 | `strong / medium / weak` | `strong/medium` 给 Policy Engine；`weak` 只作为背景线索 |

| 依赖等级 | 进入条件的直观理解 | 对 `L0-L5` 的影响 |
| --- | --- | --- |
| `strong` | 同 hunk 或同函数/字段/锁/状态强重叠，缺失可能导致编译或语义错误 | 常触发 `prerequisite_required`，可抬到 `L3` |
| `medium` | 相邻 hunk、函数交集或共享语义域，建议一并看 | 常触发 `prerequisite_recommended`，可抬到 `L1/L2` |
| `weak` | 仅有弱相关信号 | 通常不阻断，只作为背景线索 |

默认最多返回 10 个 `strong/medium` 到 `prerequisite_patches`，并额外限制强依赖展示数量，避免历史同文件噪声把前置补丁集合膨胀成不可操作列表。

### 8.2 后置关联补丁

后置关联补丁主要在 `--deep` 链路中用于风险收益和合入建议，目标是回答“社区 fix 之后是否还有补漏或同函数后续修改”。

| 关系 | 查找方式 | 用户理解 |
| --- | --- | --- |
| `followup_fix` | `git log --grep "Fixes: <fix_id>"` 反查引用当前 fix 的后续 commit | 优先复核，可能需要一起带入 |
| `same_function` | 对 fix 修改函数做 `git log -S<func> -- <file>` | 同函数后续变化，可能是补漏、重构或语义调整 |

后置补丁不是自动“必须合入”，但它会进入 `--deep` 的关联补丁分析和合入建议。

---

## 9. 哪些功能会用到 LLM

| 功能 | 是否需要 LLM 才能运行 | 作用 |
| --- | --- | --- |
| 基础搜索 | 否 | 全确定性 |
| 依赖分析 | 否 | 全确定性 |
| DryRun | 否 | 全确定性，AI 生成仅兜底 |
| `L0-L5` 分级 | 否 | 全确定性规则 |
| 深度漏洞分析 | 否 | LLM 只增强解释 |
| 深度补丁检视 | 否 | LLM 只增强描述与 checklist |
| 风险收益评估 | 否 | LLM 只增强文本表达 |
| 合入建议 | 否 | LLM 只增强建议文本 |
| validate 差异解释 | 否 | LLM 仅补充“为什么偏差” |
| AI 兜底补丁生成 | 是 | 只有这一路必须依赖 LLM |

为什么这里强调“不依赖 LLM”：

| 原因 | 说明 |
| --- | --- |
| 分级必须可审计 | 不能把核心结论建立在不可复现输出上 |
| validate 要闭环 | 必须能重复跑并与真实修复对比 |
| 批量统计要稳定 | 不能让核心分布随着模型波动 |

---

## 10. 哪些场景准确率高

| 场景 | 为什么证据强 | 应看字段 |
| --- | --- | --- |
| 搜索命中 ID 精确匹配 | 不依赖模糊启发式 | 搜索策略 `L1` |
| `strict` 直接通过 | 原始补丁文本与目标仓高度一致 | `dryrun_detail.apply_method` |
| `Context-C1/Whitespace` 通过且无风险规则命中 | 差异主要限于上下文/空白 | `apply_method` + `rule_hits` |
| `generated_vs_real.verdict in {identical, essentially_same}` | 真值验证已说明补丁可接受 | `generated_vs_real` |
| `deterministic_exact_match = true` | 工具补丁与真实修复完全一致 | `generated_vs_real.deterministic_exact_match` |
| `L0/L1` 且无 veto / risk 规则命中 | 文本证据和规则证据都干净 | `l0_l5` + `rule_class_summary` |

不应宣传为高准确率的场景：

| 场景 | 原因 |
| --- | --- |
| `3way` | 合并成功不等于语义等价 |
| `conflict-adapted` | 已进入重写冲突上下文 |
| `AI-Generated` | 兜底路径，不是高置信主路径 |
| `L3/L4/L5` | 风险或不确定性显著提高 |

---

## 11. 哪些场景应该保守处理

| 场景 | 为什么必须保守 |
| --- | --- |
| 强依赖补丁存在 | 单 patch 已经不能独立解释 |
| 命中锁 / 生命周期 / refcount / RCU | 这是典型高风险语义修改 |
| 状态机与字段路径同时变化 | 很容易引入隐性行为回归 |
| 关键结构叠加调用链传播 | 风险已从局部放大到链路级 |
| validate 样本里 `L0` 大量被抬到 `L3/L4` | 说明样本风险密度高，不能只看文本 apply |
| 命中系统边界场景 | 如 kernel config、运行时依赖、长链传播、情报不足，应人工接管 |

---

## 12. 如何看 batch 统计

| 字段 | 用来回答什么 |
| --- | --- |
| `summary.l0_l5` | 当前样本的主分级分布如何 |
| `summary.level_distribution` | 兼容视角下的 `base_level / final_level` 分布 |
| `strategy_effectiveness` | 各 DryRun 家族的通过率和补丁准确率如何 |
| `level_accuracy` | 每个 `L0-L5` 自己的通过率和准确率如何 |
| `promotion_matrix` | 样本主要从哪一级被抬到哪一级 |
| `top_promotion_rules` | 是哪些规则在主导升级 |

字段字典请看 `docs/OUTPUT_SCHEMA.md`。

---

## 13. 文档边界

| 如果你要看 | 去哪里 |
| --- | --- |
| 用户如何读懂等级、算法、索引和关联补丁 | `docs/USER_DECISION_GUIDE.md` |
| 规则逐条说明 | `docs/RULEBOOK.md` |
| 系统边界 | `docs/BOUNDARIES.md` |
| DryRun 的具体尝试顺序、`apply_attempts`、冲突适配 | `docs/ADAPTIVE_DRYRUN.md` |
| 系统目录、TUI、验证框架 | `docs/TECHNICAL.md` |
| API 合同 | `docs/API_CONTRACT.md` |
| 输出字段字典 | `docs/OUTPUT_SCHEMA.md` |
| 面向汇报的版本 | `docs/presentation.md` |
