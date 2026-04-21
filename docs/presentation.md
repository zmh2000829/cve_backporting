---
theme: default
class: lead
paginate: true
backgroundColor: #ffffff
---

# CVE Backporting Engine

### Linux 内核漏洞回移分析与补丁适配引擎

---

# 1. 这个项目解决什么问题

| 维护痛点 | 传统处理方式 | 本项目的解决方式 |
| --- | --- | --- |
| 找不到对应修复 | 人工翻邮件、翻 commit、比 subject | 三级搜索：`ID -> Subject -> Diff` |
| 找到补丁但打不上 | 手工改 patch、人工试错 | 多级 DryRun + 重建 + 冲突适配 |
| 打上了但不敢合 | 依赖和风险解释不统一 | `L0-L5` 分级 + 规则证据 |
| 批量处理不稳定 | 每个工程师口径不同 | `validate / batch-validate` 闭环验证 |

一句话总结：

> 项目不是只回答“有没有补丁”，而是交付“能不能回移、需不需要依赖、该走哪条审查通道”。

---

# 2. 四条主能力链路

| 能力链路 | 负责什么 | 关键输出 |
| --- | --- | --- |
| 搜索链路 | 找 fix / intro / stable backport；缺 intro 时可用 `patch_probe` 探测代码形态 | 搜索命中、候选 commit、`intro_analysis` |
| 依赖链路 | 判断 prerequisite patches | `independent / recommended / required` |
| DryRun 链路 | 评估补丁可应用性和适配路径 | `Strict / 3-Way / Regenerated / Conflict-Adapted ...` |
| 分级链路 | 把 apply 能力和风险证据转成执行通道 | `L0-L5`、`next_action` |

---

# 3. 系统结构

```text
CLI / HTTP API
      │
      ▼
commands/*
      │
      ▼
Pipeline
  ├─ Crawler Agent
  ├─ Analysis Agent
  ├─ Dependency Agent
  ├─ DryRun Agent
  └─ Policy Engine
      │
      ▼
TUI / JSON / API Response / Batch Summary
```

---

# 4. DryRun 不是一个策略，而是一组策略家族

| 家族 | 代表什么 | 典型场景 |
| --- | --- | --- |
| `Strict` | 原始补丁直接可用 | 目标仓上下文基本一致 |
| `Context-C1/Whitespace` | 轻微上下文或空白漂移 | 代码主体未改，周边行变了 |
| `3-Way` | Git 用共同祖先自动合并两边修改 | 双边都改了同一段 |
| `Verified-Direct` | 在内存中定位并验证重建 diff | `git apply` 不稳，但变更点仍清楚 |
| `Regenerated` | 用目标文件重建 patch context | 原始 context 已过期 |
| `Zero-Context` | 去掉 context，只保留核心 `+/-` 变更 | context 被大面积改写 |
| `Conflict-Adapted` | 结合目标文件实际内容重写冲突 hunk | 真实冲突但修复意图可保留 |
| `AI-Generated` | LLM 兜底生成补丁 | 全部确定性路径失败 |

`Verified-Direct` 的关键点：它先定位 hunk，再在内存中应用，复核后输出标准 diff；普通 `verified-direct` 是 `L3` 强适配基线，`verified-direct-exact` 才是可进入 `L1` 的低漂移精确重建证据。

---

# 5. L0-L5 到底是什么

`L0-L5` 不是“只看改了多少行”的难度分。

它表达的是：

```text
final_level = max(base_level, 所有命中规则给出的 level_floor)
```

所以必须分清：

| 概念 | 回答的问题 |
| --- | --- |
| `base_level` | 补丁是怎么 apply 上去的 |
| `final_level` | 综合规则后应该走哪条审查通道 |
| `direct_backport` | 是否允许输出“可直接回移” |

---

# 6. L0-L5 总表

| 级别 | 通道定位 | 典型进入方式 | 典型升档原因 | 推荐动作 |
| --- | --- | --- | --- | --- |
| `L0` | 自动快速通道 | `strict` + 无 veto / risk 命中 | 任一规则命中都可能升档 | 最小验证后可直接回移 |
| `L1` | 低漂移快速复核 | `context-C1` / `ignore-ws` / `verified-direct-exact` | API 面变化、轻依赖、轻状态/字段信号 | 快速人工复核 |
| `L2` | 受控审查通道 | `3way` 常见；或 `L0/L1` 被中等风险规则抬升 | 错误路径、大改动、调用面变化、中等依赖 | 逐 hunk 审查 |
| `L3` | 语义敏感通道 | `regenerated` / `verified-direct`；或低级别被高风险规则抬升 | 锁、生命周期、状态机、字段、强依赖 | 聚焦审查 + 回归测试 |
| `L4` | 审批通道 | `conflict-adapted` 常见；或关键结构叠加传播链 | 风险已从局部扩散到链路级 | 资深维护者审批 |
| `L5` | 专家接管通道 | 方法未知、证据不足、自动化已到边界 | 无法稳定自动拍板 | 补证据、专家主导 |

---

# 7. 什么会把样本从低级别抬升出去

| 触发信号 | 常见升级方向 | 为什么敏感 |
| --- | --- | --- |
| 中等依赖补丁 | `L0 -> L1` | 不能只按单补丁处理 |
| API 面变化 | `L1 -> L2` | 可能影响调用点或返回语义 |
| 错误路径变化 | `L0/L1 -> L2` | 异常分支最容易出回归 |
| 生命周期 / 资源管理 | `L0/L1 -> L2/L3` | 影响对象持有关系与释放顺序 |
| 锁 / refcount / RCU | `L0/L1 -> L3` | 高风险语义变化 |
| 调用链传播 | `L2/L3 -> L4` | 风险已从单点扩散到链路级 |

---

# 8. 调用链 fanout 与传播链

| 术语 | 当前实现的具体含义 |
| --- | --- |
| `caller` | 调用当前被修改函数的函数 |
| `callee` | 当前被修改函数调用的函数 |
| `fanout` | `callers + callees` 的数量总和 |
| `propagation` | 风险已经沿 caller/callee 关系扩散到上下游 |

| 配置项 | 平衡风格 | 保守风格 | 作用 |
| --- | --- | --- | --- |
| `call_chain_fanout_threshold` | `6` | `4` | 影响面是否已经明显变宽 |
| `call_chain_promotion_min_fanout` | `2` | `2` | 风险是否已开始传播 |

最关键的一句：

- `call_chain_fanout` 更像“影响面变大”
- `call_chain_propagation` 更像“风险沿链路扩散”

---

# 9. 哪些功能用到 LLM

| 功能 | 是否依赖 LLM 才能运行 | LLM 的作用 |
| --- | --- | --- |
| 搜索、依赖、DryRun、分级、validate、batch-validate | 否 | 全部有确定性实现 |
| 社区讨论摘要 | 否 | 补充社区讨论总结 |
| 漏洞深度分析 | 否 | 增强漏洞解释 |
| 补丁逻辑检视 | 否 | 增强审查描述 |
| 风险收益评估 | 否 | 增强表达 |
| 合入建议 | 否 | 增强建议与 checklist |
| validate 差异解释 | 否 | 解释“工具结果为什么和真值不同” |
| AI 兜底补丁生成 | 是 | 只在确定性链路失败时兜底 |

项目的原则是：

> 核心判定链路必须不依赖 LLM，LLM 只做增强与兜底。

---

# 10. 哪些场景准确率高

| 场景 | 为什么证据强 | 应看字段 |
| --- | --- | --- |
| 搜索命中精确 ID | 不依赖模糊启发式 | 搜索策略 `L1` |
| `Strict` 成功 | 原始补丁文本与目标仓高度一致 | `dryrun_detail.apply_method` |
| `Context-C1/Whitespace` 成功且无风险规则 | 差异主要限于上下文或空白 | `apply_method` + `rule_hits` |
| validate 中 `verdict = identical` | 工具补丁与真实修复完全一致 | `generated_vs_real.verdict` |
| validate 中 `deterministic_exact_match = true` | 真值验证已说明补丁完全等价 | `generated_vs_real.deterministic_exact_match` |

不应当被包装成“高准确率自动化”的场景：

| 场景 | 原因 |
| --- | --- |
| `3way` | 合并成功不等于语义安全 |
| `conflict-adapted` | 已进入冲突重写 |
| `AI-Generated` | 兜底路径，不是高置信主路径 |

---

# 11. 用户看到的交付形态

| 形式 | 适合谁 | 说明 |
| --- | --- | --- |
| CLI + TUI | 工程师 | 在终端看阶段进度、结论、规则证据 |
| JSON 报告 | 平台、自动化脚本 | 结构化读取 `analysis_framework`、`traceability`、`l0_l5` |
| HTTP API | 平台团队 | 通过 `/api/analyze`、`/api/validate`、`/api/batch-validate` 调用 |
| batch 汇总 | 评审、汇报 | 看策略效果、分级准确率、特殊风险统计 |

---

# 12. 该看哪份文档

| 如果问题是 | 去哪里 |
| --- | --- |
| 怎么安装、怎么跑、怎么接 API | `README_zh.md` |
| 系统目录、数据流、TUI、验证框架 | `docs/TECHNICAL.md` |
| DryRun 家族和补丁适配顺序 | `docs/ADAPTIVE_DRYRUN.md` |
| `L0-L5`、核心算法、LLM、准确率高场景 | `docs/MULTI_LEVEL_ALGORITHM.md` |
| API 请求/响应合同 | `docs/API_CONTRACT.md` |
| 输出字段字典 | `docs/OUTPUT_SCHEMA.md` |
| 规则手册 | `docs/RULEBOOK.md` |
| 系统边界与不适用场景 | `docs/BOUNDARIES.md` |

---

# 13. 核心结论

| 结论 | 含义 |
| --- | --- |
| 这是一个“从 CVE 到执行通道”的系统 | 不只是找补丁 |
| 干净样本靠确定性路径解决 | `Strict / Context` 证据最强 |
| 复杂样本靠规则把风险显式抬升 | `L0-L5` 负责分流而不是粉饰成功 |
| LLM 不是主判定入口 | 核心能力必须可复现、可审计、可验证 |
