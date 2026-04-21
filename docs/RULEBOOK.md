# 规则手册

本文只负责解释用户可见且主导 `L0-L5` 升档的核心规则，包括规则目的、常见 floor、触发条件、典型样本和误判边界。

如果你想看 `L0-L5` 总表，请看 `docs/MULTI_LEVEL_ALGORITHM.md`；如果你想看系统边界，请看 `docs/BOUNDARIES.md`。

---

## 1. 规则怎么读

| 项目 | 含义 |
| --- | --- |
| `rule_id` | 规则唯一标识 |
| `level_floor` | 规则命中后，最终级别至少要到哪里 |
| `rule_class` | 规则类别，如 `admission / low_level_veto / direct_backport_veto / risk_profile` |
| 典型样本 | 这条规则一般在哪类补丁上命中 |
| 误判边界 | 什么时候不能把规则命中直接解释成高风险定案 |

---

## 2. 低级别准入与否决

| `rule_id` | 常见 floor | 作用 | 典型样本 | 常见误解 | 误判边界 |
| --- | --- | --- | --- | --- | --- |
| `direct_backport_candidate` | `L0` | 证明样本可以留在最低风险通道 | `strict` 成功、无 strong/medium 依赖、无专项风险、无传播、无锁/状态/错误路径阻断信号 | “strict 成功就自动 L0” | 不对。任何 veto / risk 规则都可以继续把它抬高；普通字段访问本身不再单独阻断 L0 |
| `l1_light_drift_sample` | `L1` | 证明样本属于轻漂移而不是语义改写 | 注释漂移、日志文本漂移、局部变量重命名、等价宏替换 | “L1 就是低风险放行” | 不对。`L1` 只是轻漂移起点，仍要看是否叠加 API、字段、错误路径变化 |
| `single_line_high_impact` | `L2/L3` | 阻止“小改动行数”误导成低风险 | 单行改动改变返回路径、锁操作、状态迁移 | “只改一行不可能危险” | 不对。单行就可能改变控制流或同步语义 |

---

## 3. API 与依赖相关规则

| `rule_id` | 常见 floor | 触发条件 | 典型样本 | 常见误解 | 误判边界 |
| --- | --- | --- | --- | --- | --- |
| `l1_api_surface` | `L1/L2` | 函数签名、入参、返回路径、调用约束变化 | 新增参数检查、返回值语义变化、回调签名变化 | “只是函数头变了，不算风险” | 不对。API 面变化往往会影响调用方或错误处理 |
| `prerequisite_recommended` | `L1` | 存在中等依赖信号，建议同时评估关联补丁 | 共享字段、共享状态点、共享错误路径，但不一定强到 required | “recommended 可以忽略” | 不对。它不一定禁止回移，但明确不该草率单 patch 决策 |
| `prerequisite_required` | `L3` | 依赖强到顺序错误会带来风险 | 修复依赖前置重构、前置字段初始化或状态迁移 | “只要 patch apply 成功就不需要管前置” | 不对。依赖是语义约束，不是文本 apply 约束 |

`prerequisite_patches` 只承载 `strong/medium` 可操作候选，默认最多 10 个。`weak` 候选用于解释和人工参考，不触发 `prerequisite_recommended` / `prerequisite_required`，也不应被理解成必须合入的前置补丁。

---

## 4. 专项高风险规则

| `rule_id` | 常见 floor | 触发条件 | 典型样本 | 常见误解 | 误判边界 |
| --- | --- | --- | --- | --- | --- |
| `p2_error_path` | `L2` | 错误分支、清理顺序、回滚路径变化 | `goto err`、cleanup label、错误码返回逻辑变化 | “失败路径不常走，可以忽略” | 不对。很多回归恰恰出在错误路径 |
| `p2_lifecycle_resource` | `L2/L3` | 生命周期、所有权、释放顺序、rollback 变化 | 引用计数、资源释放、对象初始化/销毁顺序变化 | “只是资源管理细节” | 不对。对象生命周期错误常导致 UAF/泄漏/双 free |
| `p2_state_machine_control_flow` | `L1/L3` | 状态字段、状态常量、条件分支、状态迁移变化 | 状态切换顺序变化、条件门槛变化 | “if 条件变了但不一定危险” | 需要结合是否真的涉及状态语义，而不是纯语法变动 |
| `p2_struct_field_data_path` | `L1/L3` | 字段选择、数据路径、字段访问语义变化 | 从一个字段切到另一个字段、字段读写路径改动 | “只是改字段名” | 需要区分纯 rename 和真实字段语义变化 |
| `critical_structures` | `L2/L3` | 锁、RCU、refcount、布局敏感结构命中 | `spin_lock`、`mutex`、`refcount`、`container_of`、`offsetof` | “只要出现 struct 就危险” | 当前已尽量去掉泛化 `struct` 误报，但布局敏感场景仍要保守处理 |

---

## 5. 调用链相关规则

| `rule_id` | 常见 floor | 触发条件 | 典型样本 | 常见误解 | 误判边界 |
| --- | --- | --- | --- | --- | --- |
| `call_chain_fanout` | `L2` | 某个修改函数的 `callers + callees >= threshold` | 影响面明显变宽的公共函数 | “fanout 大就等于语义一定危险” | 不对。它说明影响面大，不直接证明逻辑一定错 |
| `call_chain_propagation` | `L2/L4` | 风险沿 caller/callee 关系扩散；关键结构叠加时更激进 | 关键字段或锁变化影响上下游函数 | “没命中 propagation 就说明没有传播” | 不对。当前调用链是局部图，不是全仓多跳传播分析 |

---

## 6. 规模与复杂度规则

| `rule_id` | 常见 floor | 触发条件 | 典型样本 | 常见误解 | 误判边界 |
| --- | --- | --- | --- | --- | --- |
| `large_change` | `L2` | 变更行数或 hunk 规模超过当前 profile 阈值 | 大 patch、大 hunk、同一文件大量改动 | “改得多就一定危险” | 不对。它更多代表审查成本和潜在影响面变大 |

---

## 7. 规则之间怎么组合

| 组合 | 常见结果 | 解释 |
| --- | --- | --- |
| `strict` + 无其他风险规则 | `L0` | 低风险快速通道 |
| `L1 light drift` + `l1_api_surface` | `L2` | 虽然只是轻漂移，但 API 面变化阻止继续留在低级别 |
| `strict` + `p2_error_path` | `L2` | 文本 apply 干净，不代表错误路径安全 |
| `strict` + `critical_structures` | `L3` | 命中锁 / 生命周期 / refcount 等语义高风险 |
| `3way` + `call_chain_propagation` + 关键结构 | `L4` | 不只是能合并，而是风险已经扩散到链路级 |

核心公式不变：

```text
final_level = max(base_level, 所有命中规则给出的 level_floor)
```

---

## 8. 什么时候不要只看规则名

| 错误读法 | 正确读法 |
| --- | --- |
| 只看到 `call_chain_fanout` 就说“逻辑一定危险” | 应理解为“影响面变大，需要更严审查” |
| 只看到 `prerequisite_recommended` 就说“必须先带前置补丁” | 它表达的是“建议合并评估”，不是自动判死 |
| 只看到 `p2_struct_field_data_path` 就说“字段一定错” | 还要看是否是真实字段语义变化，还是 rename |
| 只看到 `large_change` 就说“风险已经很高” | 它更多是在抬审查强度，而不是单独证明语义错误 |
