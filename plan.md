# CVE Backporting Engine 执行计划

> 更新：2026-04-03
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
- `GitRepoManager` 仍混合 git 执行、cache、FTS、search、worktree 管理和失败兜底，`report_schema` 也同时承担 schema 归一化和业务回退推断，后续容易继续出现职责漂移。
- CLI/TUI/API 虽然已经统一了主输出骨架，但展示层仍直接依赖部分 raw payload 字段，API 也缺少自描述 schema，调用方和文档仍有再次漂移风险。
- `L1` 不应天然等于“不可直接回移”；若 DryRun 仅表现为 `context-C1 / ignore-ws` 级别漂移且没有否决证据，应回到“可直接回移 + 保留最小验证”的低风险路径。

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
| D12 | L5 `verified-direct` | ✅ | 已支持绕过 `git apply` 的内存级定位、验证和 diff 重建 |
| D13 | 批量统计兼容 friendly JSON | ✅ | 已修复 `batch-validate` 汇总层对 friendly JSON 的兼容问题，避免真实结果被统计成全 0 |
| D14 | P0 / P5 本轮真实回归 | ✅ | 2026-04-02 已完成 `unittest discover`、真实 `analyze / validate / batch-validate / invalid-request`、以及 `server --config` 启动验证 |

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
| P1-2 | L0/L1 负向否决条件继续补齐 | ⏳ | 已进一步收紧 `single_line_high_impact` 的 `control_flow` 命中，纯 `return var` 这类 rename-only 场景不再误抬升；但仍需补更多 L0/L1 负例样本 |
| P1-3 | L1 “轻微漂移”边界样本化 | ✅ | 已新增 `l1_light_drift_sample`，可对注释漂移、日志文本漂移、等价宏替换、局部变量重命名给出正向样本证据，避免 L1 只剩模糊描述 |
| P1-4 | 固定“可直接回移”的准入说明 | ⏳ | 需要让 L0/L1 输出明确的“为什么可直回”，而不是只输出“为什么不能直回” |
| P1-5 | 低级别准确率回归集 | ⏳ | 现有单测更偏规则逻辑，需要补真实 patch 样本回归，特别是 L0/L1 正负例 |

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
| P4-6 | 搜索 near-miss 候选可观测性 | ⏳ | `analysis.py` 当前只保留有限 top candidates，且“为什么没过阈值”表达较弱；需要把接近命中的 subject/diff 候选、分数和落败原因显式输出，方便调参和人工复核 |
| P4-7 | 搜索阈值与 profile 配置化 | ⏳ | `L2 0.85 / L3 0.70` 仍是代码内经验阈值；建议沉淀为 profile 配置，并记录到结果元数据，避免不同环境下 recall/precision 无法解释 |
| P4-8 | Git / cache / search 失败原因分类 | ⏳ | 当前 cache miss、git 命令失败、branch 不匹配、diff 拉取失败经常被折叠成“没找到”；需要结构化区分失败原因，避免把基础设施问题误当成算法未命中 |

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

## 建议优先顺序

| 阶段 | 优先事项 | 目标 |
|---|---|---|
| 第一阶段 | P0-7 / P6-3 / P6-1 | 先把 pipeline 单出口、fixed/incomplete 结论补齐和边界态表达收拢，避免主链路再出现“有结果但解释空心化” |
| 第二阶段 | P2-6 / P2-7 / P2-8 / P1-2 | 已完成第一轮降误报，当前重点转向继续扩真实样本和低级别负例，防止宽匹配、伪调用链和弱语义命中继续把级别虚高 |
| 第三阶段 | P4-6 / P4-7 / P4-8 | 把搜索阈值、near-miss 候选和基础设施失败原因做成可观测、可解释、可调参的层，先解决“为什么没找到/为什么差一点命中” |
| 第四阶段 | P1-1 / P1-3 / P1-4 / P1-5 | 把 L0/L1 做成真正可信的低风险处理区，并补齐“为什么可以直接回移”的正向说明 |
| 第五阶段 | P3-2 / P3-3 / P3-4 / P3-5 | 把“需不需要关联补丁”做成用户可执行判断，并能沉淀长期召回趋势 |
| 第六阶段 | P5-13 / P5-14 / P5-15 / P5-16 / P5-17 | 继续拆分 orchestration、schema 和入口归一化层，避免职责交叉重新把输出和实现拖回双轨 |
| 第七阶段 | P5-10 / P5-11 / P5-12 / P5-18 | 把远程情报、cache、worktree、telemetry 做成可审计的工程底座，保证真实批量跑数稳定 |
| 第八阶段 | P6-4 / P6-8 / P6-9 / P6-13 / P6-14 | 把输出结果做成真正的维护者工作清单，并给 CLI/TUI/API 提供稳定展示层和自描述接口 |

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
