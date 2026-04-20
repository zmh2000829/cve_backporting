# 技术架构与接口说明

本文负责解释“系统怎么实现”，包括代码目录、数据流、TUI 和验证框架。

接口合同请看 `docs/API_CONTRACT.md`；输出字段字典请看 `docs/OUTPUT_SCHEMA.md`；系统边界请看 `docs/BOUNDARIES.md`；DryRun 细节请看 `docs/ADAPTIVE_DRYRUN.md`；`L0-L5` 与规则请看 `docs/MULTI_LEVEL_ALGORITHM.md` 和 `docs/RULEBOOK.md`。

---

## 1. 代码结构

### 1.1 目录分工

| 目录 | 作用 | 关键文件 |
| --- | --- | --- |
| `commands/` | CLI 命令入口、参数解析、运行模式分流 | `analyze.py`、`validate.py`、`checks.py`、`server.py` |
| `agents/` | 具体分析动作的执行体 | `crawler.py`、`analysis.py`、`dependency.py`、`dryrun.py` |
| `core/` | 配置、模型、UI、规则引擎、序列化、LLM 客户端 | `config.py`、`policy_engine.py`、`ui.py`、`output_serializers.py` |
| `services/` | 报告组装、输出路径、历史兼容 | `reporting.py`、`output_support.py`、`history_loader.py` |
| `rules/` | `L0-L5` 策略和规则实现 | `default_rules.py`、`level_policies.py` |
| `tests/` | 回归测试和 golden fixtures | `test_policy_engine.py`、`test_reports.py` |

### 1.2 核心文件职责

| 文件 | 作用 |
| --- | --- |
| `pipeline.py` | 主编排器，串联 crawl / search / dependency / dryrun / deep analysis；包含缺失 introduced commit 时的 `patch_probe` 受影响探测 |
| `core/config.py` | 加载配置，合并 `policy.profile` 预设，并提供 `analysis.missing_intro_*` 策略开关 |
| `core/git_manager.py` | 统一 Git 访问与 worktree 操作；支持按目标分支读取文件内容用于代码形态探测 |
| `core/models.py` | `PatchInfo`、`DryRunResult`、`LevelDecision` 等数据模型 |
| `core/policy_engine.py` | 汇总规则命中并生成 `L0-L5` |
| `core/output_serializers.py` | 单案例 / batch 的结构化输出与聚合统计 |
| `core/ui.py` | `analyze` / `validate` 的 TUI |
| `core/ui_batch.py` | `benchmark` / `batch-validate` 的 TUI |
| `services/reporting.py` | 统一 CLI/API 输出格式 |

---

## 2. 数据流

### 2.1 基础分析流

```text
CLI / HTTP API
      │
      ▼
commands/*
      │
      ▼
Pipeline.analyze(...)
  ├─ Crawler Agent
  ├─ Analysis Agent
  │   └─ missing-intro patch probe
  ├─ Dependency Agent
  ├─ DryRun Agent
  └─ Policy Engine
      │
      ▼
services/reporting.py
      │
      ├─ TUI 面板
      ├─ JSON 报告
      └─ API 返回体
```

### 2.2 validate / batch-validate 流

| 步骤 | 说明 |
| --- | --- |
| 回退到 `known_fix~1` | 构造真实未修复窗口 |
| 重新跑完整 pipeline | 不只是比 patch，而是重跑整条判断链 |
| 对比真实修复 | 形成 `generated_vs_real` 与 `solution_set_vs_real` |
| 聚合 batch 统计 | 生成策略效果、级别准确率、风险命中统计 |

### 2.3 无 introduced commit 的智能回溯

当上游 CVE 没有提供 introduced commit，但已经有 mainline fix patch 时，`Pipeline` 可按配置执行 `missing_intro_policy`：

| 策略 | 行为 | 适用场景 |
| --- | --- | --- |
| `patch_probe` | 解析 fix patch 的 removed/added 行，读取目标分支对应文件，计算文件覆盖率、removed 命中率、added 命中率 | 默认策略。适合只有 fix、没有 intro 的上游情报 |
| `assume_vulnerable` | 保持旧行为：无 intro 时直接按受影响继续依赖分析和 DryRun | 内部流程倾向“宁可多回溯，不漏补丁” |
| `strict_unknown` | 不做受影响假设，输出需人工确认 | 高保守流程，不希望自动推进低证据补丁 |

`patch_probe` 的判定口径：

| 条件 | 结论 |
| --- | --- |
| `file_coverage >= missing_intro_min_file_coverage` 且 `removed_match_rate >= missing_intro_min_removed_line_match` | 目标仍保留修复前代码形态，按受影响继续补丁回溯 |
| `added_match_rate >= missing_intro_fixed_line_threshold` 且 removed 未命中 | 目标更接近修复后形态，不再盲目判定受影响 |
| 探测信号不足 | 由 `missing_intro_assume_on_uncertain` 决定是否继续 |

探测证据会进入 `SearchResult.candidates`，并在 JSON 中暴露为 `intro_analysis`。

### 2.4 深度分析流

`--deep` 会在基础分析完成后追加以下阶段：

| 阶段 | 文件 | 作用 |
| --- | --- | --- |
| Community | `agents/community.py` | 读取社区讨论并做摘要 |
| VulnAnalysis | `agents/vuln_analysis.py` | 输出漏洞类型、触发条件、影响面 |
| PatchReview | `agents/patch_review.py` | 输出函数级改动与代码审查项 |
| RiskBenefit | `core/risk_benefit.py` | 输出风险收益描述 |
| MergeAdvisor | `agents/merge_advisor.py` | 输出合入建议与 checklist |

---

## 3. CLI 技术说明

### 3.1 命令入口

| 命令 | 入口文件 | 说明 |
| --- | --- | --- |
| `analyze` | `commands/analyze.py` | 单条或批量 CVE 分析 |
| `check-intro` | `commands/checks.py` | 引入提交检测 |
| `check-fix` | `commands/checks.py` | 修复提交检测 |
| `validate` | `commands/validate.py` | 单案例真值验证 |
| `batch-validate` | `commands/validate.py` | 批量真值验证 |
| `benchmark` | `commands/validate.py` | 基准测试 |
| `server` | `commands/server.py` | 启动 HTTP API |

### 3.2 参数覆盖

| 参数 | 作用 | 实现位置 |
| --- | --- | --- |
| `--policy-profile` | 覆盖当前命令的 `policy.profile` 与阈值 | `commands/policy_cli.py` |
| `--enable-p2` / `--disable-p2` | 控制专项高风险规则是否启用 | `commands/policy_cli.py` |
| `--deep` | 追加 v2 深度分析链路 | `commands/analyze.py`、`commands/validate.py` |

---

## 4. 缓存索引的目的

`build-cache` 会把目标分支的 commit 元信息写入本地 SQLite，并建立 FTS 索引。它解决的是“大仓库重复搜索太慢”的问题，不是替代 Git，也不是完整代码语义索引。

| 存储内容 | 主要用途 |
| --- | --- |
| `commit_id` / `short_id` | 快速判断 commit 是否在目标分支 |
| `subject` | 支撑 subject 精确搜索和关键词搜索 |
| `author` / `timestamp` | 输出证据、排序、依赖分析时间窗口 |
| FTS 虚拟表 | 加速关键词候选召回 |

| 链路 | 是否使用缓存索引 |
| --- | --- |
| `check-fix` / `check-intro` 的 ID 命中 | 优先使用缓存，未命中再查 Git 对象库 |
| `Analysis Agent` 的 subject / keyword 搜索 | 优先使用缓存和 FTS |
| `batch-validate` | 复用缓存避免每个样本重复扫全仓 |
| diff 读取、文件历史、DryRun apply、3-way merge | 不使用缓存，直接调用真实 Git 仓库 |

---

## 5. 关联补丁技术口径

### 5.1 前置关联补丁

主链路的 `Dependency Agent` 只负责前置依赖分析。它先用 fix patch 修改文件召回候选，再按文本和语义证据分级。

| 阶段 | 实现位置 | 技术口径 |
| --- | --- | --- |
| 文件扩展 | `PathMapper.expand_files()` | 同时搜索上游路径和本地迁移路径 |
| 候选召回 | `GitRepoManager.search_by_files()` | `git log -- <files>`，排除 merge，默认最多 50 个 |
| 时间窗口 | `intro_search.target_commit.timestamp` | 有 intro 时从 intro 时间开始，否则从仓库初始开始 |
| hunk 分析 | `extract_hunks_from_diff()` / `compute_hunk_overlap()` | 直接重叠和 50 行内相邻 hunk |
| 函数分析 | `extract_functions_from_diff()` | 比较 hunk header 中函数签名 |
| 语义域分析 | `_extract_semantic_markers()` | 字段、锁域、状态点交集 |
| 分级 | `strong / medium / weak` | 分数和证据类型共同决定 |

### 5.2 后置关联补丁

后置关联补丁属于 `--deep` 的风险收益 / 合入建议链路，不是主链路 prerequisite。

| 关系 | 实现位置 | 技术口径 |
| --- | --- | --- |
| `followup_fix` | `RiskBenefitAnalyzer._find_fixes_tag_followers()` | `git log --grep "Fixes: <fix_id>"` 反查后续补漏 |
| `same_function` | `RiskBenefitAnalyzer._find_same_function_followers()` | 对 fix 修改函数做 `git log -S<func> -- <file>` |

---

## 6. TUI 技术说明

### 6.1 TUI 组件

| 组件 | 代码位置 | 用途 |
| --- | --- | --- |
| `StageTracker` | `core/ui.py` | 实时显示阶段进度 |
| `render_report` | `core/ui.py` | `analyze` 主报告 |
| `render_validate_report` | `core/ui.py` | `validate` 主报告 |
| `render_batch_validate_report` | `core/ui_batch.py` | `batch-validate` 汇总表 |
| `_render_deep_report` | `cli.py` | `--deep` 的额外面板 |

### 6.2 TUI 分层

| 层级 | 作用 | 常见内容 |
| --- | --- | --- |
| 进度层 | 告诉用户“目前走到哪一步” | Stage running/success/fail |
| 结论层 | 给最终结论 | direct backport、prerequisite、risk、L0-L5 |
| 证据层 | 解释“为什么这么判” | `rule_hits`、`special_risk_report`、`dependency_details` |
| 对比层 | validate 场景专用 | `generated_vs_real` |
| 深度层 | `--deep` 专用 | 漏洞分析、补丁检视、合入建议 |

---

## 7. API 与输出的技术边界

这两块已经拆成独立文档，避免技术架构文档再次膨胀。

| 主题 | 去哪里 |
| --- | --- |
| HTTP API 请求模板、响应模板、必要字段、错误返回 | `docs/API_CONTRACT.md` |
| 单案例字段、batch summary、错误结构、字段字典 | `docs/OUTPUT_SCHEMA.md` |

---

## 8. LLM 集成边界

| 模块 | 文件 | 是否必须依赖 LLM | 作用 |
| --- | --- | --- | --- |
| CommunityAgent | `agents/community.py` | 否 | 生成社区讨论摘要 |
| VulnAnalysisAgent | `agents/vuln_analysis.py` | 否 | 增强漏洞解释 |
| PatchReviewAgent | `agents/patch_review.py` | 否 | 增强代码审查描述 |
| RiskBenefitAnalyzer | `core/risk_benefit.py` | 否 | 增强风险收益文本 |
| MergeAdvisorAgent | `agents/merge_advisor.py` | 否 | 增强建议文本与 checklist |
| LLMAnalyzer | `core/llm_analyzer.py` | 否 | 解释 validate 偏差根因 |
| AIPatchGenerator | `core/ai_patch_generator.py` | 是 | AI 兜底生成补丁 |

必须强调：

| 结论 | 原因 |
| --- | --- |
| 搜索、依赖、DryRun、分级、validate、batch 统计都不依赖 LLM | 核心链路必须可复现、可验证、可审计 |
| LLM 只负责增强或兜底 | 不能让核心结论依赖模型波动 |

---

## 9. validate / batch-validate 技术口径

### 9.1 为什么可信

| 设计点 | 作用 |
| --- | --- |
| `git worktree` 回退到 `known_fix~1` | 构造真实未修复状态 |
| 重跑完整 pipeline | 防止“只比 patch，不比判断过程” |
| 与真实修复对比 | 输出 `identical / essentially_same / different` |
| batch 聚合 | 观察长期策略效果和 `L0-L5` 准确率 |

### 9.2 推荐关注的指标

| 指标 | 说明 |
| --- | --- |
| `deterministic_exact_match` | 生成补丁与真实修复完全一致 |
| `acceptable_patch_rate` | `identical + essentially_same` 的比例 |
| `strategy_effectiveness` | 某个 DryRun 家族在样本中的通过率与准确率 |
| `level_accuracy` | 某个最终级别在样本中的通过率与准确率 |

---

## 10. 当前工程边界

| 边界 | 说明 |
| --- | --- |
| 调用链分析是局部图 | 只在本次修改文件集合内做 caller/callee 分析 |
| validate 依赖 `known_fix` | 没有真值就不能做闭环验证 |
| `AI-Generated` 不是主路径 | 它是兜底，而不是默认策略 |
| 高等级不等于 apply 能力差 | 通常表示语义风险或不确定性高 |

完整边界说明请看 `docs/BOUNDARIES.md`。

---

## 11. 文档边界

| 如果你想看 | 去哪里 |
| --- | --- |
| 用户如何读懂等级、算法、索引和关联补丁 | `docs/USER_DECISION_GUIDE.md` |
| API 请求/响应合同 | `docs/API_CONTRACT.md` |
| 输出 schema 与字段字典 | `docs/OUTPUT_SCHEMA.md` |
| DryRun 具体尝试顺序和补丁适配细节 | `docs/ADAPTIVE_DRYRUN.md` |
| `L0-L5` 总表与算法地图 | `docs/MULTI_LEVEL_ALGORITHM.md` |
| 规则手册 | `docs/RULEBOOK.md` |
| 系统边界 | `docs/BOUNDARIES.md` |
| 汇报版总览 | `docs/presentation.md` |
