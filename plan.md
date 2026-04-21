# CVE Backporting Engine 执行计划

> 更新：2026-04-21
>
> 目标：不改变现有核心算法主干，优先解决“用户看不懂为什么这么判”的问题，让工具稳定回答三件事：
> 1. 哪些补丁可以直接回移
> 2. 哪些补丁需要考虑或不需要考虑关联补丁
> 3. 哪些变更虽然小，但可能有较大影响

## 当前判断

- 当前最大问题不是算法分支不够多，而是“结论和证据之间没有稳定映射”。
- 低级别准确率不高，关键不是 apply 能力不够，而是正向准入条件和负向否决条件还不够硬。
- 最容易被低估的高风险点，仍然是锁、生命周期、状态机、结构体字段、错误路径。
- “单行修改”不能按行数判低风险，必须看控制流、同步语义、状态迁移和调用链扩散。
- 当前已能把 DryRun 基线和规则抬升拆开看，但还需要继续减少“证据够弱却被抬得过高”与“证据缺失导致结论留空”两类问题。
- 整体工程层面的主要问题，已经从“算法缺不缺分支”转成“实现职责交叉、输出结构双轨、测试覆盖不连续”。
- 当前用户体验的主要损耗点，不是结果不够多，而是命令参数不统一、边界状态表达不清、批量结果不够像“可执行工作清单”。
- `pipeline.py` 仍保留 fixed / stable-backport / intel-missing 等分支内早返回，导致“状态判定、证据补齐、用户结论”没有真正做到单出口收敛。
- 搜索层的关键阈值和候选保留策略仍偏硬编码，`L2=0.85`、`L3=0.70` 这种经验值还没有沉淀成可调 profile，也缺少 near-miss 解释。
- GLM5 提到的搜索阈值、失败分桶、置信度校准方向基本合理，且多数能在当前代码里找到对应风险点；但应优先通过真实样本回放闭环验证，而不是先大规模改算法。
- `FunctionAnalyzer` 已有部分去噪和 500 行大括号配对提取，但 `analyze_patch_impact()` 仍用 `func.line_number + 100` 判断函数范围，函数定义识别也仍是轻量正则，对宏、属性、多行签名、函数指针调用等内核 C 代码形态仍需要更稳的解析边界。
- `conflict-adapted` 当前定位是高风险适配通道，不应直接升级成“自动修复可信结果”；后续即使引入 AST/LLM 辅助，也必须带语义冲突说明、补丁验证和人工门禁。
- `GitRepoManager` 仍混合 git 执行、cache、FTS、search、worktree 管理和失败兜底，`report_schema` 也同时承担 schema 归一化和业务回退推断，后续容易继续出现职责漂移。
- CLI/TUI/API 虽然已经统一了主输出骨架，但展示层仍直接依赖部分 raw payload 字段，API 也缺少自描述 schema，调用方和文档仍有再次漂移风险。
- `L1` 不应天然等于“不可直接回移”；若 DryRun 仅表现为 `context-C1 / ignore-ws` 级别漂移且没有否决证据，应回到“可直接回移 + 保留最小验证”的低风险路径。

## 项目结构理解（基于代码阅读）

| 层 | 关键文件 | 当前作用 | 当前主要问题 |
|---|---|---|---|
| 入口层 | `cli.py` / `commands/*.py` / `api_server.py` | 统一 CLI、批量命令与 HTTP API 入口 | 参数归一化、错误提示和默认行为仍分散在多处，入口之间存在再次漂移风险 |
| 编排层 | `pipeline.py` / `agents/*.py` | 串联 `Crawler -> Analysis -> Dependency -> DryRun`，并承接 deep analysis | 早返回较多、原地修改状态较多，导致 fixed / incomplete / force-dryrun 路径不易单出口收敛 |
| 搜索与仓库层 | `core/git_manager.py` / `agents/analysis.py` / `core/matcher.py` | 提供 git 查询、缓存、三级搜索、diff 匹配与路径映射 | 阈值和候选保留策略仍偏硬编码，基础设施失败与算法未命中容易被混在一起 |
| 策略层 | `core/policy_engine.py` / `rules/*.py` | 负责 `base_level -> rule_hits -> final_level`，并生成 checklist 与 strategy buckets | 规则体系已可插拔，但置信度仍偏静态标签，尚未和真实样本结果做持续校准 |
| 展示与报告层 | `services/reporting.py` / `core/report_schema.py` / `core/ui.py` / `core/ui_batch.py` | 输出 friendly JSON、TUI 面板、批量统计与 traceability | 用户能看到结论，但展示层仍直接读取 raw payload，术语词典尚未做到单一真源 |

## 本轮补充建议（聚焦用户体验与准确率）

### 用户体验

| 建议 | 具体抓手 | 预期价值 |
|---|---|---|
| 单条结果首屏做成“决策卡” | 在 CLI/TUI/API 顶层固定展示 `当前状态 / 最终级别 / 主要阻塞 / 下一动作 / 三条关键证据` | 让维护者在 10 秒内完成 triage，而不是先钻 raw JSON |
| 搜索 near-miss 明确可见 | 把 `L2/L3` 最接近候选、相似度、阈值差距和落败原因直接返回 | 减少“没找到 = 目标仓没有修复”的误解，也方便调参 |
| 批量结果直接变成工作清单 | 按“可直接处理 / 需补前置 / 高风险需审批 / 情报不足待补”分组，并附典型样本 | 从统计报表升级为维护者可执行工作面板 |
| 术语和等级说明统一出厂 | 把 `L0-L5 / base_level / final_level / verified-direct / incomplete` 的用户口径收敛成同一词典 | 避免 README、presentation、CLI、API 各说各话 |

### 准确率

| 建议 | 具体抓手 | 预期价值 |
|---|---|---|
| 建真实样本回归集 | 收集 50-100 个已验证 CVE 回移案例，标注期望 `final_level / direct_backport / prerequisite / fixed-or-missed`，先覆盖 `L0/L1` 正负例再扩到全等级 | 避免“看起来命中 strict，就被误放进低风险区”，也避免阈值调整变成盲调 |
| 搜索阈值改成 profile + 回放验证 | 将 `0.85 / 0.70` 阈值、candidate limit、路径扩展策略做成 `conservative / balanced / aggressive` profile，并支持离线回放对比 | 用真实样本选 recall/precision，而不是靠经验常数 |
| 置信度从静态标签变成经验校准 | 将 `validate / batch-validate` 的真实通过率、误抬升情况、样本数回灌到 confidence 分段 | 让“为什么这么判”之外，再补上“系统有多大把握” |
| 基础设施失败与算法未命中分桶 | 把 cache miss、git timeout、branch mismatch、diff fetch failed、no candidates、below threshold 与真正搜索未命中拆开统计 | 防止把环境问题误判成算法能力问题 |
| 函数解析可靠性升级 | 为 `FunctionAnalyzer` 增加函数 `end_line`、多行签名/宏/属性/inline 支持，并对函数指针调用和无法解析场景输出 `uncertain` 标记 | 降低调用链误报/漏报对 L0-L4 分级的连锁影响 |
| 冲突适配自动解决门禁 | 在 `conflict-adapted` 之后引入 AST/LLM 辅助时，必须保留验证步骤、语义差异说明和人工审批标记 | 避免“能 apply”被误读成“语义正确” |

### 文档体系

| 建议 | 具体抓手 | 预期价值 |
|---|---|---|
| API 合同从 README 继续拆分 | 增加独立 `docs/API_CONTRACT.md`，固化请求模板、响应模板、必要字段、错误码、对接约束 | 避免 README 既做产品介绍又背接口细节，减少平台对接靠猜字段 |
| 规则说明从分级文档再拆一层 | 增加独立 `docs/RULEBOOK.md`，逐条解释 `rule_id / floor / 触发条件 / 典型样本 / 常见误解 / 误报边界` | 避免 `docs/MULTI_LEVEL_ALGORITHM.md` 再次膨胀成“大而全”文档 |
| 输出 schema 独立成册 | 将 `result_status / analysis_framework / l0_l5 / traceability / batch summary` 拆成 `docs/OUTPUT_SCHEMA.md` | 让 CLI、API、历史兼容和平台接入共享同一份字段字典 |
| 边界与不适用场景显式成册 | 增加 `docs/BOUNDARIES.md`，专门写“不解决什么、为什么不解决、系统会如何退回人工” | 防止用户把局部调用链、kernel config、运行时依赖等边界误读成算法失误 |
| 维护者操作手册单独沉淀 | 增加 `docs/PLAYBOOK.md`，按“日常 analyze / 真实 validate / 批量回归 / 高风险审批”给出操作流程 | 让结果更像工作流手册，而不只是技术说明 |
| 示例与样板集中沉淀 | 增加 `docs/EXAMPLES.md` 或 `docs/examples/`，收录真实请求/响应样板、典型 `L0-L5` case、TUI 截图和 batch 汇总样例 | 减少用户第一次接入时只能靠 README 大段文字拼理解 |

## 已完成

| 编号 | 事项 | 状态 | 说明 |
|---|---|---|---|
| D1 | `validate` 统一输出解释骨架 | ✅ | 已稳定输出 `analysis_framework.process / evidence / conclusion` |
| D2 | `validate` 输出 L0-L5 视图 | ✅ | 已提供 `l0_l5.current_level / base_level / dependency_bucket` |
| D3 | `PolicyEngine` 与 DryRun 解耦 | ✅ | 已实现 “DryRun 基线级别 + rule floor 抬升” |
| D4 | 规则体系三分类 | ✅ | 已落 `admission / low_level_veto / direct_backport_veto / risk_profile` |
| D5 | P2 专项高风险报告 | ✅ | 已输出 `special_risk_report`，覆盖锁、生命周期、状态机、字段、错误路径 |
| D6 | 调用链影响分析 | ✅ | 已输出 `function_impacts`、caller/callee 和 impact score |
| D7 | 单行高影响规则 | ✅ | 已补 `single_line_high_impact`，避免“小改动=低风险” |
| D8 | `validate` Worktree 回退验证 | ✅ | 已通过 `known_fix~1`/最早 prereq 父节点做真实验证 |
| D9 | `validate`/API 支持 mainline override | ✅ | 已支持 `mainline_fix / mainline_intro` 跳过 MITRE 情报依赖 |
| D10 | HTTP API 主链路 | ✅ | `/api/analyze`、`/api/validate`、`/api/batch-validate` 已打通 |
| D11 | 批量并行验证 | ✅ | `batch-validate` 已支持 `workers`，单仓建议 1-2 |
| D12 | `verified-direct` 内存直改路径 | ✅ | 已支持绕过 `git apply` 的内存级定位、验证和 diff 重建 |
| D13 | 批量统计兼容 friendly JSON | ✅ | 已修复 `batch-validate` 汇总层对 friendly JSON 的兼容问题，避免真实结果被统计成全 0 |
| D14 | P0 / P5 本轮真实回归 | ✅ | 2026-04-02 已完成 `unittest discover`、真实 `analyze / validate / batch-validate / invalid-request`、以及 `server --config` 启动验证 |
| D15 | API 合同独立成册 | ✅ | 已新增 `docs/API_CONTRACT.md`，收敛请求模板、响应模板、错误返回和必要字段 |
| D16 | 输出 schema 独立成册 | ✅ | 已新增 `docs/OUTPUT_SCHEMA.md`，统一字段字典和 batch summary 口径 |
| D17 | 规则手册独立化 | ✅ | 已新增 `docs/RULEBOOK.md`，把规则逐条说明从分级文档拆出 |
| D18 | 系统边界独立成册 | ✅ | 已新增 `docs/BOUNDARIES.md`，专门说明不适用场景与人工接管口径 |

## P0

| 编号 | 事项 | 状态 | 落地情况 |
|---|---|---|---|
| P0-1 | 让三类主命令都稳定回答三件事 | ✅ | `analyze / validate / batch-validate` 已统一经过 `result_status + analysis_framework`，fixed / incomplete 场景也能稳定回答“能不能直接回移 / 要不要看关联补丁 / 风险是否偏高” |
| P0-2 | 结论与证据稳定映射 | ✅ | 已新增 `core/report_schema.py`，把 `result_status -> analysis_framework.process/evidence/conclusion -> friendly JSON` 固化为统一适配层 |
| P0-3 | “已修复 / 不适用 / 情报不足”显式状态 | ✅ | 已引入统一 `result_status(state/error_code/user_message/technical_detail/retryable/incomplete_reason)`，并接入 CLI / API / friendly JSON |
| P0-4 | 批量结果缺解释时给出原因 | ✅ | `batch-validate` 已输出 `result_state_distribution / incomplete_reason_distribution`，单条结果也会返回 `incomplete_reason` |
| P0-5 | CLI/API/README 参数口径统一 | ✅ | `server` 已同时接受 `server --config` 与全局 `-c/--config`；API 错误与结果状态也统一了参数缺失/请求非法时的结构化返回 |
| P0-6 | 过程/证据去重 | ✅ | 已对 `analysis_stages / narrative.workflow / recommendations` 做去重合并，避免 fixed 场景出现多份近义描述互相打架 |
| P0-7 | Pipeline 单出口与结果终结器 | ⏳ | `pipeline.py` 仍在 fix 命中、stable backport 命中等分支直接返回；建议引入统一 `finalize_result()`，把 `result_status / analysis_framework / recommendations / stages` 的补齐放到单出口，避免 fixed/not_applicable/incomplete 路径再次漂移 |

## P1

| 编号 | 事项 | 状态 | 落地情况 |
|---|---|---|---|
| P1-1 | L0 正向准入条件继续收紧 | ✅ | `direct_backport_candidate` 已要求同时满足：无前置依赖、无传播、无关键结构、无 `special_risk`、无字段/状态/错误路径语义标记；不再因“strict 命中”自动视为可直接回移 |
| P1-2 | L0/L1 负向否决条件继续补齐 | ⏳ | 已进一步收紧 `single_line_high_impact` 的 `control_flow` 命中，纯 `return var`、低信号 `if (ret)` / 条件变量改名这类场景不再误抬升；但仍需补更多真实 L0/L1 负例样本 |
| P1-3 | L1 “轻微漂移”边界样本化 | ✅ | 已新增 `l1_light_drift_sample`，可对注释漂移、日志文本漂移、等价宏替换、局部变量重命名给出正向样本证据，避免 L1 只剩模糊描述 |
| P1-4 | 固定“可直接回移”的准入说明 | ⏳ | 需要让 L0/L1 输出明确的“为什么可直回”，而不是只输出“为什么不能直回” |
| P1-5 | 真实样本准确率回归集 | ⏳ | 现有单测更偏规则逻辑，需要收集 50-100 个已验证 CVE 回移案例，标注期望 `final_level / direct_backport / prerequisite`；先补 L0/L1 正负例，再扩到 L2-L5 |
| P1-6 | 置信度经验校准 | ⏳ | `rules/level_policies.py` 里的 `high / medium / low` 仍偏静态标签；建议结合 `validate / batch-validate` 的真实命中率、误抬升率、incomplete 比例和样本数生成校准表 |

## P2

| 编号 | 事项 | 状态 | 落地情况 |
|---|---|---|---|
| P2-1 | 锁与同步专项 | ✅ | 已输出锁对象、同步操作、保护数据对象、顺序变化 |
| P2-2 | 生命周期与资源专项 | ✅ | 已输出 ownership、release order、rollback path |
| P2-3 | 状态机与控制流专项 | ✅ | 已输出条件变化、返回路径、错误码、状态字段 |
| P2-4 | 结构体字段与数据路径专项 | ✅ | 已输出字段访问路径、读写函数、锁保护域 |
| P2-5 | 错误路径专项 | ✅ | 已输出 `goto err`、cleanup、错误码、恢复路径 |
| P2-6 | `critical_structures` 降误报 | ✅ | 已收紧 `struct` 关键词，仅在 `struct {...}` 定义和 `sizeof/offsetof/container_of` 这类布局敏感场景命中；普通 `struct foo *ctx` 不再直接抬升 |
| P2-7 | 调用链分析去噪 | ✅ | 已过滤 `sizeof/likely/ARRAY_SIZE/__builtin_*` 等伪调用，并跳过 `ops->helper()`/`.cb()` 这类成员访问伪 callee；跨文件仅连接唯一符号，减少 L0 被伪牵连抬升 |
| P2-8 | 状态机专项区分“语法变化”和“语义变化” | ✅ | 已要求看到状态字段/状态常量/状态迁移语义才进入 `state_machine_control_flow`；纯 `if (ret)` + `return -E...` 只落 `error_path`，不再误判成状态机变化 |
| P2-9 | 高风险命中与具体对象绑定 | ⏳ | 需要继续强化“锁对象/字段/状态点/错误节点”直接映射到最终结论里的展示 |
| P2-10 | `FunctionAnalyzer` 解析可靠性升级 | ✅ | 已为 `FunctionInfo` 增加 `end_line / parse_uncertain / indirect_calls`，`analyze_patch_impact()` 改用真实函数范围；已增强多行签名、返回指针、`static inline`、函数指针调用去噪，并补回归测试 |

## P3

| 编号 | 事项 | 状态 | 落地情况 |
|---|---|---|---|
| P3-1 | 关联补丁三档分类 | ✅ | 已落 `required / recommended / independent / weak_only` 分桶 |
| P3-2 | 关联补丁证据化 | ✅ | `PrerequisitePatch` 已补 `shared_fields / shared_lock_domains / shared_state_points / evidence_lines`，依赖评分和结论开始显式使用“共享字段/锁域/状态点”证据，而不只看 hunk/function overlap |
| P3-3 | “为什么不需要关联补丁”正向说明 | ⏳ | 已有 `independent_patch` 规则，但证据还不够面向用户 |
| P3-4 | 关联补丁可执行建议 | ⏳ | 需要把 `required` 场景收敛成“先带哪些补丁、为什么先带” |
| P3-5 | validate 与 batch 的 prereq 召回统计 | ⏳ | 已有 `prereq_cross_validation`，但还没有沉淀成长期趋势视图 |

## P4

| 编号 | 事项 | 状态 | 落地情况 |
|---|---|---|---|
| P4-1 | 批量评估从“数量统计”变成“问题统计” | ⏳ | 已有 level/risk/dependency 统计，但还不够回答“为什么样本被抬高” |
| P4-2 | 批量报告补“关键抬升因子占比” | ⏳ | 需要统计 prerequisite、critical structure、state machine、call chain 各自的抬升贡献 |
| P4-3 | 专项误报样本沉淀 | ⏳ | 已补 `struct` 泛化命中、成员访问伪调用、纯错误码返回误入状态机三类回归；仍需继续扩充真实社区补丁样本 |
| P4-4 | API 真实链路回归 | ✅ | 2026-04-02 已真实回归 `analyze / validate / batch-validate / invalid-request`；`tests/test_api_server.py` 也已补结构化错误与结果状态回归 |
| P4-5 | 失败样本原因分类 | ⏳ | 需要把 upstream 情报缺失、搜索未命中、准入不足、风险抬升分开统计 |
| P4-6 | 搜索 near-miss 候选可观测性 | ✅ | `SearchResult` 已输出 `near_misses`，L2/L3 候选带 `threshold / threshold_delta / passed / failure_reason`，未过线时能解释“差多少命中” |
| P4-7 | 搜索阈值与 profile 配置化 | ✅ | 已新增 `SearchConfig` 与 `conservative / balanced / aggressive` 预设，CLI 支持 `--search-profile`，API 支持 `search_profile`，结果追溯记录实际 search profile |
| P4-8 | Git / cache / search 失败原因分类 | ⏳ | 当前 cache miss、git 命令失败、branch 不匹配、diff 拉取失败经常被折叠成“没找到”；需要结构化区分失败原因，避免把基础设施问题误当成算法未命中 |
| P4-9 | 搜索 profile 回放实验台 | ⏳ | `AnalysisAgent` 当前把 threshold、candidate limit、path expansion 策略绑定在代码路径里；建议增加 profile 回放与对比输出，支持用真实样本评估阈值调整收益 |
| P4-10 | `SearchProfile` 配置模型 | ✅ | 已新增 `subject_threshold / diff_threshold / subject_candidate_limit / keyword_candidate_limit / diff_candidate_limit / file_search_limit / near_miss_limit` 字段，并提供三档预设 |
| P4-11 | `SearchFailure` 结构化模型 | ⏳ | 已新增 `SearchFailure(reason/detail/retryable/level)`，覆盖 `git_timeout / diff_fetch_failed / no_candidates / below_threshold / git_command_failed` 等主要场景；`cache_miss / branch_mismatch` 的细分统计和 batch 聚合仍待补 |
| P4-12 | 冲突自动解决验证闭环 | ⏳ | `conflict-adapted` 当前本质是“替换 - 行并保留 + 行”的高风险适配；后续可接入 AST 语义冲突检测和 `core/ai_patch_generator.py`，但生成补丁必须经过 apply、语义差异摘要、回归样本对比和人工审批门禁 |

## AI 增强专项（GLM5）

### 专项判断

- 当前项目已经有 `LLMClient`、`LLMAnalyzer`、`VulnAnalysisAgent`、`PatchReviewAgent`、`MergeAdvisorAgent` 等 LLM 增强入口，但它们主要承担“解释文本”和“deep analysis 补充”，还没有系统性进入搜索召回、依赖去噪、风险裁决和经验校准闭环。
- GLM5 的价值不应定位为“替代确定性算法”。更合理的定位是：在确定性链路已经给出候选、near-miss、弱证据或冲突上下文后，让模型做**语义重排、证据补充、弱信号裁决、失败根因归类、候选补丁建议**。
- 准确率提升的核心不是让模型直接给最终级别，而是让模型减少两类错误：一是弱信号误升级，二是真正语义相关但文本相似度不足导致的漏召回。
- 召回率提升的核心不是让模型全仓搜索，而是让模型生成更好的搜索 query、路径/符号/语义别名，并对确定性召回出的 near-miss 做语义重排。
- 所有 AI 输出必须结构化、可缓存、可回放、可验证；不能只把自然语言塞进报告，否则无法做 batch 统计和准确率闭环。
- AI 生成补丁仍必须是高风险候选路径。它只能在确定性路径失败或进入 `L5/conflict-adapted` 后参与，并且必须经过 unified diff 格式校验、`git apply --check`、语义差异摘要、validate 对比和人工审批。

### 总体架构

| 层 | 新增/改造点 | 设计要求 |
|---|---|---|
| Provider 层 | 扩展 `core/llm_client.py` 为 GLM5/OpenAI-compatible 统一客户端 | 支持 `provider=glm`、`base_url`、`model`、`api_key`、timeout、重试、JSON 强制解析、调用耗时与 token 估算 |
| AI 任务层 | 新增 `core/ai_tasks.py` 或 `agents/ai_assistant.py` | 每类任务有固定输入、固定 JSON schema、固定失败降级，不允许自由格式输出驱动主流程 |
| 缓存层 | 新增 AI response cache | cache key = prompt version + model + task + 输入 hash；支持离线回放，避免批量验证成本失控 |
| 证据层 | 新增 `ai_evidence` / `ai_decision_support` 输出块 | 记录模型建议、置信度、引用的 diff 行/候选 commit、是否影响最终级别、是否只供人工参考 |
| 策略层 | AI 只作为 advisory 或 gated promotion/demotion | 默认不直接覆盖 `final_level`；只有通过 validate 校准的任务才允许影响 rule floor 或 candidate rank |
| 评估层 | `batch-validate` 增加 AI ablation | 同一批样本分别跑 `ai=off / ai=advisory / ai=gated`，输出 precision、recall、F1、误升级率、漏召回率、成本和耗时 |

推荐配置形态：

```yaml
llm:
  enabled: true
  provider: "glm"
  api_key: "${GLM_API_KEY}"
  base_url: "https://<glm5-openai-compatible-endpoint>/v1"
  model: "GLM-5"
  max_tokens: 4000
  temperature: 0.1
  timeout: 90

ai:
  mode: "advisory"        # off / advisory / gated
  cache_enabled: true
  prompt_version: "ai-v1"
  max_candidates_for_rerank: 20
  max_diff_chars: 12000
  enable_search_rerank: true
  enable_dependency_triage: true
  enable_low_signal_adjudication: true
  enable_conflict_patch_suggestion: false
```

### 召回率提升设计

| 场景 | 当前短板 | GLM5 介入方式 | 门禁 |
|---|---|---|---|
| Subject 搜索漏召回 | backport subject 改写、企业分支 squash、缩写/子系统名变化 | `AIQueryExpansionTask` 从 CVE 描述、upstream subject、diff 文件/函数生成 5-10 个搜索 query、关键符号、子系统别名 | 只扩展 `git log --grep` / FTS query，不直接认定命中 |
| Diff 搜索 near-miss | 相似度低于阈值但语义等价 | `AISemanticRerankTask` 对 L2/L3 near-miss 候选做语义重排，输出 `same_fix / related / unrelated` | 只能在确定性候选集合内重排；命中必须保留 candidate commit 和证据行 |
| 路径迁移漏召回 | PathMapper 未覆盖新目录迁移 | `AIPathAliasTask` 基于 diff 路径、Kconfig/Makefile/子系统名推断候选路径别名 | 只作为临时 search path，命中后需真实 `git show` / diff 验证 |
| introduced commit 缺失 | 只有 fix patch，缺少 intro 真值 | `AIAffectednessProbeTask` 对 removed/added 行、目标文件片段、函数上下文做受影响判断 | 结论只能是 `affected / fixed / uncertain`，不伪造 introduced commit |
| stable backport 识别 | stable commit 与 mainline diff 有小幅改写 | `AIStableBackportMatchTask` 对候选 stable diff 和 mainline diff 做 hunk 意图匹配 | 只补充 confidence 和 rationale；最终仍以 diff containment / validate 为准 |

### 准确率提升设计

| 场景 | 当前误差来源 | GLM5 介入方式 | 对最终级别的影响 |
|---|---|---|---|
| 弱信号误升级 | 普通字段访问、普通条件变化、日志/注释/局部变量改名被规则误读 | `AILowSignalAdjudicationTask` 读取 rule hits、diff hunks、风险 marker，判断是否为语义敏感变化 | 初期只写入 `ai_evidence.low_signal`; 回放证明稳定后才允许降低 advisory risk |
| 前置补丁膨胀 | 同文件历史、相邻 hunk、函数名交集产生过多 weak/medium | `AIDependencyTriageTask` 对 top strong/medium/weak 候选判断 `required / helpful / background / unrelated` | 不能把 weak 直接升 required；可辅助降低 weak/medium 噪声和生成人工顺序 |
| 锁/生命周期/状态机漏判 | 规则只看局部 token，无法理解上下文协议 | `AIRiskSemanticTask` 对锁对象、状态字段、错误路径做语义解释，补充“为什么危险/不危险” | 只在已有确定性风险 marker 时参与提升置信度，不凭空创建高风险 |
| L0/L1 可直回解释不足 | 只知道没有命中风险，不知道为什么低风险 | `AIDirectBackportJustificationTask` 生成结构化正向证据：核心 +/- 行是否等价、上下文漂移类型、回归建议 | 不改变级别，提升可审计性和用户信任 |
| validate 偏差根因不结构化 | LLMAnalyzer 现在输出自然语言，不利于统计 | `AIValidateRootCauseTask` 输出固定 JSON：`search_miss / prereq_noise / dryrun_adaptation_error / policy_overpromotion / policy_underpromotion / intel_gap` | 进入 batch 误差分桶，用于下一轮阈值和规则调优 |

### 补丁生成与冲突适配设计

| 阶段 | 目标 | 约束 |
|---|---|---|
| AI conflict explanation | 对 `3way / verified-direct / regenerated / conflict-adapted` 的失败 hunk 生成语义差异说明 | 不生成代码，只解释目标分支旧逻辑与上游旧逻辑差异 |
| AI patch suggestion | 仅在确定性路径失败、目标文件可定位、人工显式开启时生成候选 diff | 输出必须是 unified diff，且保留原修复意图，不允许扩大修改范围 |
| Patch verifier | 对 AI diff 运行格式检查、路径检查、`git apply --check`、DryRun、规则分级 | 任一步失败则丢弃 AI patch |
| Semantic delta report | 对 AI patch 与 upstream patch 做 hunk 级差异摘要 | 明确哪些 `+` 行保留、哪些 `-` 行被目标分支代码替换 |
| Human gate | `ai-generated` 永不进入 L0/L1 自动通道 | 默认 `L5` 或审批通道，除非后续 validate 真值证明可降级 |

### 数据模型与输出

建议新增统一 AI 输出结构，避免每个模块自由扩字段：

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
        "task": "semantic_rerank",
        "status": "success",
        "input_hash": "...",
        "latency_ms": 1234,
        "decision": "same_fix",
        "confidence": 0.82,
        "affected_candidates": ["abc123..."],
        "evidence_lines": ["..."],
        "used_for_final_decision": false
      }
    ]
  }
}
```

关键原则：

- `used_for_final_decision=false` 是分析类 task 的默认值。
- 只有 `mode=gated` 且该 task 经过 batch validate 校准，才允许搜索、依赖、低信号裁决类 task 影响 rank、rule floor 或最终分级。
- `ai-generated` 补丁建议是单独的 dryrun 候选通道：只有通过确定性 `git apply --check` 才可记录 `used_for_final_decision=true`，但仍必须保持高风险/L5 和人工审批门禁。
- 所有 AI task 必须返回 `confidence`、`evidence_lines`、`uncertainty_reason`，不能只返回“是/否”。
- AI 结果必须进入 traceability，记录模型、prompt 版本和输入 hash，便于审计和复现。

### 评估指标

| 指标 | 目标 | 说明 |
|---|---|---|
| fix search recall | 显著提升 | 统计 mainline/stable fix 是否被定位；重点看 subject 改写和 squash 样本 |
| introduced / affectedness recall | 提升 | 缺 intro 时减少错误 unknown 和错误 fixed 判断 |
| prerequisite precision | 提升 | 前置补丁推荐数量下降，`required/recommended` 与真值更一致 |
| low-level precision | 提升 | `L0/L1` 的误放行率下降，误升级率也下降 |
| overpromotion rate | 下降 | 能完全一致合入的补丁不再被弱信号抬到高等级 |
| underpromotion rate | 不上升 | 降误报不能牺牲真实高风险样本 |
| AI cost / latency | 可控 | batch 输出每个 task 的调用数、耗时、缓存命中率 |

### AI 专项任务拆分

| 编号 | 事项 | 状态 | 落地方案 |
|---|---|---|---|
| AI-1 | GLM5 Provider 接入 | ⏳ | 基础已落：`LLMClient` 支持 `provider=glm`、OpenAI-compatible endpoint、`${GLM_API_KEY}`/`GLM_API_KEY` 回退和更稳的 JSON 抽取；`AIPatchGenerator` 已改走统一 `LLMClient.chat`。待补：重试、token/成本 telemetry |
| AI-2 | AI 配置与模式开关 | ⏳ | 基础已落：新增 `AIConfig` 与 `config.yaml`/`config.example.yaml` 配置项，支持 `mode=off/advisory/gated`、task 开关、候选上限、diff 截断和 prompt version。待补：CLI/API `--ai-mode` 临时覆盖 |
| AI-3 | AI response cache 与回放 | ⏳ | 新增本地 cache，按 task/model/prompt/input hash 存取；batch-validate 支持复用 AI 结果，避免重复调用 GLM5 |
| AI-4 | 结构化 AI task 基座 | ⏳ | 基础已落：新增 `core/ai_assistant.py`，统一 advisory task 的 prompt、JSON schema、失败降级、输入裁剪、输出校验和 `ai_evidence`。待补：持久化 traceability 与 prompt 独立目录 |
| AI-5 | 搜索 query expansion | ⏳ | 在 L2/L3 未命中或 below-threshold 时调用 GLM5 生成 subject/query/path/function 别名，再回到 Git/FTS 做确定性召回 |
| AI-6 | near-miss semantic rerank | ⏳ | 对 `near_misses` 和 L3 candidates 做 GLM5 语义重排，输出 `same_fix/related/unrelated`，先 advisory 展示，再用 validate 证明收益 |
| AI-7 | missing-intro affectedness probe | ⏳ | 在 `patch_probe` 证据不足时，用目标函数片段 + fix hunk 让 GLM5 输出 `affected/fixed/uncertain` 和证据行，减少情报缺失导致的召回损失 |
| AI-8 | prerequisite triage | ⏳ | advisory 基础已落：`AIAssistant` 可对 strong/medium/weak 证据样本输出 `required/helpful/background/unrelated` 建议，不影响最终级别。待补：batch 统计与排序 UI |
| AI-9 | low-signal adjudication | ⏳ | advisory 基础已落：可对普通 `if`、字段访问、return path、日志/注释/rename 这类误升级高发样本输出低信号裁决，不做自动降级。待补：真实样本回放后开放 gated |
| AI-10 | risk semantic explainer | ⏳ | advisory 基础已落：可对锁、生命周期、状态机、字段、错误路径命中输出对象级解释，进入 `validation_details.ai_evidence`。待补：CLI/TUI 专门面板 |
| AI-11 | AI patch suggestion v2 | ⏳ | 基础已落：`core/ai_patch_generator.py` 已统一走 `LLMClient`，DryRun 在确定性路径失败且显式开启 `enable_conflict_patch_suggestion` 时生成候选 diff，并必须通过 `git apply --check` 才返回 `ai-generated`。待补：validate 自动对比与审批 UI |
| AI-12 | validate root-cause JSON | ⏳ | 将 `LLMAnalyzer` 从自然语言改为结构化根因分类，进入 batch 聚合，用于反推搜索、依赖和规则误差来源 |
| AI-13 | AI ablation benchmark | ⏳ | `batch-validate` 增加 `ai=off/advisory/gated` 对照，输出 precision/recall/F1、误升级率、漏召回率、AI 调用成本和耗时 |
| AI-14 | Prompt 与 schema 版本治理 | ⏳ | 所有 prompt 进入 `prompts/` 或 `core/ai_prompts.py`，带版本号、测试样本和 JSON schema；修改 prompt 必须跑 golden 回归 |
| AI-15 | 安全与隐私门禁 | ⏳ | 增加 diff/context 最大长度、敏感路径脱敏、禁用全文件上传开关、调用日志脱敏；默认只发送 hunk 和必要上下文 |

### 推荐落地顺序

| 阶段 | 优先任务 | 目标 |
|---|---|---|
| AI 第一阶段 | AI-1 / AI-2 / AI-3 / AI-4 / AI-12 / AI-13 | 先把 GLM5 接入、结构化输出、缓存回放和评估闭环打稳；没有评估闭环前不让 AI 改最终结论 |
| AI 第二阶段 | AI-5 / AI-6 / AI-7 | 优先提升召回率：搜索扩展、near-miss 重排、missing-intro 受影响判断 |
| AI 第三阶段 | AI-8 / AI-9 / AI-10 | 再提升准确率：前置补丁去噪、弱信号裁决、高风险解释绑定 |
| AI 第四阶段 | AI-11 / AI-14 / AI-15 | 最后处理 AI 生成补丁和 prompt 治理，确保不会把兜底能力误包装成自动合入能力 |

### 验收标准

| 里程碑 | 必须满足 |
|---|---|
| GLM5 接入完成 | `llm.enabled=true` 时 deep analysis、validate root-cause、AI task runner 均可调用；无 key 或调用失败时自动降级，主流程不失败 |
| Advisory 可用 | 单条报告出现 `ai_evidence`，但 `used_for_final_decision=false`；用户能看见 AI 对 near-miss、弱信号、依赖候选的解释 |
| 召回提升可量化 | 在真实样本集上 `ai=advisory` 的候选召回率高于 `ai=off`，且误命中没有明显上升 |
| 准确率提升可量化 | 前置补丁 precision、低级别 precision、overpromotion rate 至少一项显著改善，underpromotion rate 不上升 |
| Gated 模式放开 | 只有当某个 AI task 在 batch validate 中持续稳定，才允许该 task 影响 candidate rank 或低信号降级；所有影响必须写入 traceability |

## P5

| 编号 | 事项 | 状态 | 落地情况 |
|---|---|---|---|
| P5-1 | `cli.py` 巨石拆分 | ✅ | 已抽出 `services/reporting.py`，把 `analyze/validate` 的 payload 组装、reading guide、friendly JSON 生成移出 `cli.py`，原入口保留兼容包装 |
| P5-2 | `core/ui.py` 渲染层拆分 | ✅ | 已抽出 `core/ui_batch.py`，将 `render_benchmark_report / render_batch_validate_report` 移出主文件；`core/ui.py` 保留公共部件与兼容包装 |
| P5-3 | `agents/dryrun.py` 内部结构分层 | ✅ | 已抽出 `agents/dryrun_helpers.py`，把 hunk 清洗、anchor 判断、sub-hunk 拆分等纯函数从 `DryRunAgent` 主体剥离，降低误报定位与单测门槛 |
| P5-4 | 输出模型单一真源 | ✅ | 已新增 `core/report_schema.py`，统一 `report_version/schema_version/result_status/analysis_framework`，并由 CLI/API/batch 共同复用 |
| P5-5 | 异常模型统一 | ✅ | CLI 早返回、batch incomplete、HTTP 400/404/500 已统一使用 `error_code / user_message / technical_detail / retryable` 结构化模型 |
| P5-6 | 参数与配置层收口 | ✅ | `commands/server.py` 已兼容 `server --config`，并统一回落到全局 `-c/--config`；API invalid request 也回收成同一参数错误模型 |
| P5-7 | 历史结果 schema 兼容 | ✅ | 已新增 `services/history_loader.py`，可将旧版 `analysis_results` raw JSON 迁移为 `friendly-json-v2 / result-schema-v2` |
| P5-8 | 测试发现与夹具治理 | ✅ | `tests/test_agents.py` 已补 discoverable `TestCase`；新增 `tests/test_api_server.py`、`tests/test_reports.py` 以及 `tests/fixtures/{history,golden}` |
| P5-9 | 真实链路 golden cases | ✅ | 已为 `analyze / validate / batch-validate` 增加 golden JSON fixtures，并通过公开样本 `CVE-2024-26633 / CVE-2023-46838` 做真实链路校验 |
| P5-10 | 远程情报与本地缓存边界 | ⏳ | `crawler` 对 MITRE / kernel.org 依赖较强，建议增加本地快照缓存、情报缺失兜底和离线重放能力，减少批量结果受上游波动影响 |
| P5-11 | 性能热点观测 | ⏳ | 建议为 crawler、analysis、dependency、dryrun 各阶段输出结构化耗时和候选规模，用于判断瓶颈是在网络、git、diff 搜索还是规则评估 |
| P5-12 | 并发与 worktree 资源治理 | ⏳ | 批量并发已可用，但仍建议增加 worktree 复用/清理审计、失败中断恢复和临时目录配额控制 |
| P5-13 | `GitRepoManager` 进一步拆分 | ⏳ | 当前单类同时负责 git 执行、search、cache、FTS、worktree 和失败兜底；建议至少拆成 `git_executor / search_backend / cache_store / worktree_manager` 四层，降低改动牵一发而动全身 |
| P5-14 | Pipeline stage/result reducer | ⏳ | `pipeline.py` 里 `recommendations`、`dependency_details`、stage callback、`is_fixed` 等字段在多分支内反复原地修改；建议引入阶段归并器，避免状态和结论分叉 |
| P5-15 | `report_schema` 归一化与业务回退拆分 | ⏳ | `infer_result_status()`、`_fallback_conclusion()`、`ensure_analysis_framework()` 当前既做 schema 兼容又做业务兜底；建议把“兼容转换”和“结论回退”拆开，防止隐藏策略逻辑继续堆进 schema 层 |
| P5-16 | CLI/API 请求归一化共享层 | ⏳ | `commands/analyze.py`、`commands/validate.py`、`api_server.py` 仍各自处理 `target/p2/mainline_fix/workers` 等参数；建议抽统一 request normalizer，减少入口行为漂移 |
| P5-17 | 历史报告迁移注册表 | ⏳ | `history_loader.py` 现在主要靠启发式检测 `analyze/validate`；建议引入版本化迁移注册表，显式管理 legacy schema 到 `result-schema-v2` 的转换路径 |
| P5-18 | 缓存构建与搜索结构化 telemetry | ⏳ | 目前日志里有部分耗时和数量，但还缺统一的 machine-readable telemetry；建议记录 cache build/source search/diff fetch 的耗时、候选规模、命中来源和失败点，方便真实回归与调优 |

## P6

| 编号 | 事项 | 状态 | 落地情况 |
|---|---|---|---|
| P6-1 | 边界状态用户化表达 | ⏳ | 对 `已修复 / 不受影响 / 情报不足 / 结果不完整 / 需要人工确认` 建立统一用户状态，避免当前用空字段表达 |
| P6-2 | 命令帮助与示例统一 | ⏳ | CLI 帮助、README、API 示例需要由同一模板生成，避免 `server --config` 这类文档和实际行为不一致 |
| P6-3 | `analyze` 输出补齐结论层 | ⏳ | 即使 fix 已存在，也应继续输出“为何已修复、为什么不需要回移、有哪些残余风险/证据”而不是直接留空 |
| P6-4 | 批量结果做成工作清单 | ⏳ | `batch-validate` 需要直接给出 `可直接处理 / 需补前置 / 高风险需审批 / 情报不足待补` 四类分组，而不只是分布数字 |
| P6-5 | 证据摘要去技术黑话 | ⏳ | 当前部分 warning 仍偏规则名视角，建议增加用户可读摘要，如“字段访问路径变化导致状态判断风险上升” |
| P6-6 | TUI 阶段可见性增强 | ⏳ | 建议在阶段面板中增加耗时、候选数、命中依据摘要，减少“卡住了但不知道在做什么”的感受 |
| P6-7 | API 错误返回可执行化 | ✅ | `_error_body` 与 invalid request builder 已输出 `route / hint / missing_input / suggested_fix / absolute_date`，400/404/500 不再只有错误字符串，调用方可直接修请求 |
| P6-8 | 批量统计加样本链接 | ⏳ | 批量 summary 应直接附典型样本列表，例如“哪些 CVE 导致 L4 上升、哪些命中 prerequisite_required” |
| P6-9 | 人工审查清单模板 | ✅ | `ValidationDetails.manual_review_checklist` 已落地，`L2/L3/L4/L5`、依赖补丁或高风险场景会自动生成“先看字段/锁对象/状态点/错误路径/调用链/编译回归”的清单；CLI 面板与 friendly JSON 均已展示 |
| P6-10 | 输出文件命名和目录整理 | ✅ | `analyze / validate / batch-validate / benchmark` 已改为按 `analysis_results/<run-id>/<mode>/<cve-or-target>/...` 归档；单 case 目录下统一保存 `report.json / adapted.patch / community.patch / real_fix.patch` |
| P6-11 | 中英文文档同步 | ⏳ | 当前 README、README_zh、presentation、旧结果说明存在时间差，建议建立文档同步清单，避免对外口径漂移 |
| P6-12 | 结果可追溯性 | ✅ | `analyze / validate / batch-validate` 报告已新增 `traceability`，显式记录 `report/schema version`、`generated_at`、规则 profile/开关、目标仓 `HEAD/branch/path/remote`、数据源类型与时间戳；输出目录与补丁路径也会在 `artifacts` 中回写 |
| P6-13 | UI 展示 view-model 层 | ⏳ | `core/ui.py` 和 `core/ui_batch.py` 仍直接读取大量 `validation_details / level_decision / result_status` 原始字段；建议增加稳定的 presentation view-model，降低展示层对底层 schema 细节的耦合 |
| P6-14 | API schema / 自描述能力 | ⏳ | 当前 API 已能返回结构化错误，但还缺请求/响应 schema、示例和 capability 描述；建议补 `/api/schema` 或 OpenAPI-lite 输出，减少调用方靠 README 猜字段 |
| P6-15 | 单条结果决策卡 | ⏳ | CLI/TUI/API 首屏建议固定输出“当前状态 / 最终级别 / 主要阻塞 / 下一动作 / 三条关键证据”，让结果更像可执行判断而不是技术明细转储 |
| P6-16 | 术语词典与展示协议单一真源 | ⏳ | `presentation`、README、`services/reporting.py`、`core/ui.py` 对 L0-L5 和历史 DryRun 层级仍可能存在双口径；建议抽统一术语词典和展示协议，减少解释漂移 |
| P6-17 | README 与接口文档继续拆分 | ✅ | 已新增 `docs/API_CONTRACT.md`，将请求模板、响应模板、必要字段、错误返回和对接约束从 `README_zh.md` 中继续拆出；README 只保留快速接入说明和导航 |
| P6-18 | 不适用场景文档化 | ✅ | 已新增 `docs/BOUNDARIES.md`，明确跨文件长链传播、kernel config、运行时依赖、情报缺失、宏/汇编主导语义等边界场景，并说明系统如何退回人工 |
| P6-19 | 规则手册独立化 | ✅ | 已新增 `docs/RULEBOOK.md`，逐条说明用户可见核心规则、level floor、典型样本、常见误解和误判边界；`docs/MULTI_LEVEL_ALGORITHM.md` 回到总表和算法地图定位 |
| P6-20 | 输出 schema 单一字典 | ✅ | 已新增 `docs/OUTPUT_SCHEMA.md`，独立维护 `result_status / analysis_framework / l0_l5 / traceability / batch summary / error body` 字段字典 |
| P6-21 | 示例库与截图样板 | ⏳ | 需要把 analyze / validate / batch-validate 的请求模板、返回模板、典型 L0-L5 案例和 TUI 截图集中成样板库，降低首次接入成本 |

## 建议优先顺序

| 阶段 | 优先事项 | 目标 |
|---|---|---|
| 第一阶段 | P0-7 / P6-3 / P6-1 | 先把 pipeline 单出口、fixed/incomplete 结论补齐和边界态表达收拢，避免主链路再出现“有结果但解释空心化” |
| 第二阶段 | P2-6 / P2-7 / P2-8 / P2-10 / P1-2 / P1-5 | 已完成第一轮降误报，当前重点转向继续扩真实样本、低级别负例和函数解析可靠性，防止宽匹配、伪调用链和弱语义命中继续把级别虚高 |
| 第三阶段 | P4-6 / P4-7 / P4-8 / P4-9 / P4-10 / P4-11 | 把搜索阈值、near-miss 候选和基础设施失败原因做成可观测、可解释、可调参的层，先解决“为什么没找到/为什么差一点命中” |
| 第四阶段 | AI-1 / AI-2 / AI-3 / AI-4 / AI-12 / AI-13 | 接入 GLM5 但先只做结构化 advisory、缓存和 ablation 评估；没有真实回放收益前不让 AI 改最终结论 |
| 第五阶段 | AI-5 / AI-6 / AI-7 | 用 GLM5 优先提升召回率：query expansion、near-miss semantic rerank、missing-intro affectedness probe |
| 第六阶段 | AI-8 / AI-9 / AI-10 | 用 GLM5 提升准确率：前置补丁去噪、弱信号裁决、高风险语义解释绑定 |
| 第七阶段 | P1-1 / P1-3 / P1-4 / P1-5 / P1-6 | 把 L0/L1 做成真正可信的低风险处理区，并补齐“为什么可以直接回移”以及“系统有多大把握”的正向说明 |
| 第八阶段 | P3-2 / P3-3 / P3-4 / P3-5 | 把“需不需要关联补丁”做成用户可执行判断，并能沉淀长期召回趋势 |
| 第九阶段 | P5-13 / P5-14 / P5-15 / P5-16 / P5-17 | 继续拆分 orchestration、schema 和入口归一化层，避免职责交叉重新把输出和实现拖回双轨 |
| 第十阶段 | P5-10 / P5-11 / P5-12 / P5-18 / P4-12 / AI-11 / AI-14 / AI-15 | 把远程情报、cache、worktree、telemetry、AI 补丁生成和安全门禁做成可审计的工程底座 |
| 第十一阶段 | P6-4 / P6-8 / P6-9 / P6-13 / P6-14 / P6-15 / P6-16 | 把输出结果做成真正的维护者工作清单，并给 CLI/TUI/API 提供稳定展示层、统一术语和自描述接口 |
| 第十二阶段 | P6-17 / P6-18 / P6-19 / P6-20 / P6-21 | 继续把 README、接口合同、规则手册、边界说明、样板库拆开，防止文档重新长回单文件大杂烩 |

## 北极星结果

| 目标 | 状态 | 说明 |
|---|---|---|
| 用户能直接看懂工具做了哪些分析 | ⏳ | `validate` 基本成立，`analyze` 仍需补 fixed/incomplete 路径 |
| 用户能直接看懂为什么判成“可直接回移 / 需考虑关联补丁 / 高风险” | ⏳ | 主干骨架已成型，但还缺稳定的边界态表达 |
| 用户能快速发现锁、生命周期、状态机、字段、错误路径这类真正危险的改动 | ⏳ | 专项分析已到位，下一步重点是降误报和提升证据绑定质量 |
| 用户不会再因为“只改了一行”而被误导成低风险 | ⏳ | 已有 `single_line_high_impact`，但仍需补更多真实样本验证 |
| `L0/L1` 变成真正可信的低风险处理区 | ⏳ | 还需要更强的准入条件、更硬的否决条件和更好的回归集 |
| 工程结构允许后续持续迭代而不反复引入兼容问题 | ⏳ | 需要拆巨石文件、统一 schema、补齐真实链路回归与异常模型 |
| 用户能把结果直接当作回移工作清单使用 | ⏳ | 还需要补边界状态表达、批量分组视图、审查 checklist 和结果追溯信息 |
| 用户在 CLI / API / presentation 看到的是同一套等级语言 | ⏳ | 还需要统一术语词典、展示协议和历史 DryRun 术语对外说明 |
