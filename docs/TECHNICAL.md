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
| `pipeline.py` | 主编排器，串联 crawl / search / dependency / dryrun / deep analysis |
| `core/config.py` | 加载配置，合并 `policy.profile` 预设 |
| `core/git_manager.py` | 统一 Git 访问与 worktree 操作 |
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

### 2.3 深度分析流

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

## 4. TUI 技术说明

### 4.1 TUI 组件

| 组件 | 代码位置 | 用途 |
| --- | --- | --- |
| `StageTracker` | `core/ui.py` | 实时显示阶段进度 |
| `render_report` | `core/ui.py` | `analyze` 主报告 |
| `render_validate_report` | `core/ui.py` | `validate` 主报告 |
| `render_batch_validate_report` | `core/ui_batch.py` | `batch-validate` 汇总表 |
| `_render_deep_report` | `cli.py` | `--deep` 的额外面板 |

### 4.2 TUI 分层

| 层级 | 作用 | 常见内容 |
| --- | --- | --- |
| 进度层 | 告诉用户“目前走到哪一步” | Stage running/success/fail |
| 结论层 | 给最终结论 | direct backport、prerequisite、risk、L0-L5 |
| 证据层 | 解释“为什么这么判” | `rule_hits`、`special_risk_report`、`dependency_details` |
| 对比层 | validate 场景专用 | `generated_vs_real` |
| 深度层 | `--deep` 专用 | 漏洞分析、补丁检视、合入建议 |

---

## 5. API 与输出的技术边界

这两块已经拆成独立文档，避免技术架构文档再次膨胀。

| 主题 | 去哪里 |
| --- | --- |
| HTTP API 请求模板、响应模板、必要字段、错误返回 | `docs/API_CONTRACT.md` |
| 单案例字段、batch summary、错误结构、字段字典 | `docs/OUTPUT_SCHEMA.md` |

---

## 6. LLM 集成边界

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

## 7. validate / batch-validate 技术口径

### 7.1 为什么可信

| 设计点 | 作用 |
| --- | --- |
| `git worktree` 回退到 `known_fix~1` | 构造真实未修复状态 |
| 重跑完整 pipeline | 防止“只比 patch，不比判断过程” |
| 与真实修复对比 | 输出 `identical / essentially_same / different` |
| batch 聚合 | 观察长期策略效果和 `L0-L5` 准确率 |

### 7.2 推荐关注的指标

| 指标 | 说明 |
| --- | --- |
| `deterministic_exact_match` | 生成补丁与真实修复完全一致 |
| `acceptable_patch_rate` | `identical + essentially_same` 的比例 |
| `strategy_effectiveness` | 某个 DryRun 家族在样本中的通过率与准确率 |
| `level_accuracy` | 某个最终级别在样本中的通过率与准确率 |

---

## 8. 当前工程边界

| 边界 | 说明 |
| --- | --- |
| 调用链分析是局部图 | 只在本次修改文件集合内做 caller/callee 分析 |
| validate 依赖 `known_fix` | 没有真值就不能做闭环验证 |
| `AI-Generated` 不是主路径 | 它是兜底，而不是默认策略 |
| 高等级不等于 apply 能力差 | 通常表示语义风险或不确定性高 |

完整边界说明请看 `docs/BOUNDARIES.md`。

---

## 9. 文档边界

| 如果你想看 | 去哪里 |
| --- | --- |
| API 请求/响应合同 | `docs/API_CONTRACT.md` |
| 输出 schema 与字段字典 | `docs/OUTPUT_SCHEMA.md` |
| DryRun 具体尝试顺序和补丁适配细节 | `docs/ADAPTIVE_DRYRUN.md` |
| `L0-L5` 总表与算法地图 | `docs/MULTI_LEVEL_ALGORITHM.md` |
| 规则手册 | `docs/RULEBOOK.md` |
| 系统边界 | `docs/BOUNDARIES.md` |
| 汇报版总览 | `docs/presentation.md` |
