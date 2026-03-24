# 项目演进计划

## 1. 当前项目定位

`CVE Backporting Engine` 当前已经具备一条可运行的端到端主链路：

- CVE 情报采集：`Crawler Agent`
- 修复/引入定位：`Analysis Agent`
- 前置依赖分析：`Dependency Agent`
- 多级 DryRun 与适配：`DryRun Agent`
- 深度分析与报告增强：`--deep`、`analysis_narrative`
- 风险编排：`DryRun 基线级别 + rules/ 规则抬升`

当前规则系统已经完成第一轮收口：

- 默认级别策略位于 [rules/level_policies.py](/Users/junxiaoqiong/Workplace/cve_backporting/rules/level_policies.py)
- 默认风险规则位于 [rules/default_rules.py](/Users/junxiaoqiong/Workplace/cve_backporting/rules/default_rules.py)
- 输出字段已包含 `base_level`、`base_method`、`review_mode`、`next_action`
- `rules/` 目录已支持插件式规则扩展

这意味着项目已经从“能分析、能适配”进入“要稳定、可审计、可运营”的阶段。

---

## 2. 当前阶段的核心问题

下一步不是继续堆算法名词，而是补齐下面五类短板。

### 2.1 规则体系已成型，但还没有形成业务可运营的规则资产

当前已经有大改动、关键结构、调用链牵连、L1 API surface 等规则，但仍然存在：

- 规则主要是通用规则，缺少子系统/业务团队可独立沉淀的目录规范
- 规则示例配置此前仍散落在根级 `config.example.yaml`
- 新规则接入流程、开关、证据字段、回归要求需要进一步固化

### 2.2 L1“可无害”路径已有编排，但还没形成真正稳定的判定闭环

当前能力：

- L1 已不再自动 `harmless`
- 已提供 `review_mode=llm-review`
- 已有 `l1_api_surface` 的签名/返回路径启发式

仍然缺的部分：

- 负样本约束不够系统
- 尚未形成“规则证据 + LLM 结论 + 人工复核”三段式稳定闭环
- 还没有样本集支撑误报/漏报评估

### 2.3 调用链分析能提示风险，但边界仍局限于“修改文件集合内”

当前实现已经能识别：

- 修改函数的 `callers`
- 修改函数的 `callees`
- 跨文件调用/被调用牵连

但仍然要明确：

- 这不是全仓库调用图
- 目前更适合作为风险提示，而不是强约束决策
- 后续需要为全仓库符号索引预留升级路径

### 2.4 验证能力还没有升级为可复跑、可对外答辩的样本体系

当前仓库有：

- `validate`
- `batch-validate`
- `benchmarks.example.yaml`

仍然缺：

- 标准化样本清单
- 期望结论字段
- 误报归因标签
- 人工裁决记录格式

### 2.5 文档结构仍然偏“堆积式增长”，需要收敛为可维护文档体系

需要解决的问题：

- `plan.md` 之前更像历史流水账，不适合作为当前路线图
- 汇报材料、README、规则文档之间的口径需要统一
- 冗余文档需要及时删除，避免之后继续维护“看起来很全、实际没人用”的材料

---

## 3. 下一步演进方向

### Phase A：规则体系工程化收口

目标：把 `rules/` 从“能放规则”推进到“团队可扩展、配置可引用、回归可守门”。

#### 目标产出

- `rules/` 目录形成稳定结构：
  - Python 规则模块
  - 规则约束文档
  - 规则配置示例
- 根级 `config.example.yaml` 不再承载规则详细配置
- 新增 [rules/policy.example.yaml](/Users/junxiaoqiong/Workplace/cve_backporting/rules/policy.example.yaml) 作为规则配置样例入口
- 规则接入要求统一为：
  - 稳定 `rule_id`
  - 可开关
  - 可输出 `evidence`
  - 影响分级时显式输出 `level_floor`

#### 重点需求

- 规则配置说明与 `rules/README.md` 同步
- `README` / `presentation` / `plan` 三份材料对 `rules/` 的描述保持一致
- 插件规则接入路径固定，不再继续把默认规则堆回 `core/policy_engine.py`

#### 非目标

- 不在本阶段引入新的复杂算法
- 不把调用链分析升级为全仓库索引

### Phase B：判定质量与样本验证

目标：让 `L0-L5` 从“结构完整”升级为“结论可信”。

#### 目标产出

- 20+ CVE 小样本验证清单
- 每条样本具备如下字段：
  - CVE
  - 目标分支
  - 期望 level
  - 是否允许 warning
  - 是否需要前置补丁
  - 实际结论
  - 差异原因
  - 人工裁决
- L1 规则补齐负样本与关闭开关测试
- 关键结构 + 调用链传播误报场景补齐样本

#### 重点需求

- L0 要求严格保持“100% 可落地 + 无额外语义风险”
- L1 只进入复核通道，不宣称自动无害
- L3/L4 需要有更明确的人工审查动作建议

#### 非目标

- 不以通过率单一数字替代样本结论
- 不把有限样本包装成“全面准确率”

### Phase C：流程门禁与交付化

目标：把规则输出真正接进交付流程，而不是停留在报告层。

#### 目标产出

- 基于 `level_decision` 的审批策略建议
- L4/L5 或 `high severity` 命中时的人工审批门禁方案
- `validate` / `batch-validate` 的输出模板进一步收敛，支持专家评审与归档

#### 重点需求

- 统一 JSON schema
- 保持成功、降级、无补丁三类路径字段稳定
- 让 `level_decision.next_action` 真正服务于交付动作

### Phase D：规则生态与团队协作

目标：让业务团队能在不改核心引擎的前提下独立沉淀规则。

#### 目标产出

- 规则模板
- 子系统规则命名建议
- 规则版本化约束
- 团队级插件交付规范

#### 重点需求

- 规则失败可降级
- 规则证据可审计
- 文档与测试必须同步

---

## 4. 近期明确需求清单

以下事项应作为接下来 2~4 周的明确需求，而不是“可选优化”：

1. 建立规则配置独立样例文件，并把入口迁到 `rules/`
2. 统一根级 README、中文 README、presentation、rules 文档对规则框架的描述
3. 建立样本验证模板，停止只用口头“20+ CVE”描述目标
4. 为新规则接入补齐正例 / 反例 / 开关关闭三类测试要求
5. 给 `L1`、`L3`、`L4` 场景写清楚默认审查动作与交付建议
6. 清理冗余文档，避免继续维护无实际消费路径的材料

---

## 5. 验收标准

### 5.1 规则体系验收

- 默认规则、级别策略、规则配置样例全部位于 `rules/`
- 根级 `config.example.yaml` 不再承载详细规则配置块
- `rules/README.md`、`README.md`、`README_zh.md`、`docs/presentation.md` 对插件机制的表述一致

### 5.2 判定质量验收

- `tests/test_policy_engine.py` 持续通过
- 每条默认规则至少有：
  - 触发正例
  - 不触发反例
  - 开关关闭回退
- `L0` 不被任何风险规则误标为无害
- L1 规则能给出明确证据，而不是泛化 warning

### 5.3 样本验证验收

- 样本集具备清单、期望、实际、差异、裁决
- 报告能说明“为什么触发该级别”
- 误报与漏报能归因到具体规则或边界

### 5.4 文档治理验收

- `plan.md` 表达当前路线图，而不是历史开发日志
- `docs/presentation.md` 能直接用于当前阶段汇报
- 删除的文档不再被 README / docs 引用

---

## 6. 文档与文件治理规则

当前推荐保留的主文档职责如下：

- [README.md](/Users/junxiaoqiong/Workplace/cve_backporting/README.md)：英文总览、能力、配置入口、路线图
- [README_zh.md](/Users/junxiaoqiong/Workplace/cve_backporting/README_zh.md)：中文落地说明
- [plan.md](/Users/junxiaoqiong/Workplace/cve_backporting/plan.md)：当前阶段路线图与验收口径
- [docs/presentation.md](/Users/junxiaoqiong/Workplace/cve_backporting/docs/presentation.md)：汇报材料
- [docs/TECHNICAL.md](/Users/junxiaoqiong/Workplace/cve_backporting/docs/TECHNICAL.md)：技术说明
- [docs/ADAPTIVE_DRYRUN.md](/Users/junxiaoqiong/Workplace/cve_backporting/docs/ADAPTIVE_DRYRUN.md)：DryRun 深入算法
- [docs/MULTI_LEVEL_ALGORITHM.md](/Users/junxiaoqiong/Workplace/cve_backporting/docs/MULTI_LEVEL_ALGORITHM.md)：多级算法参考
- [rules/README.md](/Users/junxiaoqiong/Workplace/cve_backporting/rules/README.md)：规则目录说明
- [rules/policy.example.yaml](/Users/junxiaoqiong/Workplace/cve_backporting/rules/policy.example.yaml)：规则配置示例

本轮已删除的冗余文档：

- `docs/arch.md`：内容与 README / TECHNICAL / presentation 高度重叠，且不再作为主维护入口

后续原则：

- 新增文档前先判断是否能并入现有主文档
- 若一个文档不再被主入口引用，也不再作为交付材料使用，应优先删除
- `plan.md` 不再记录所有历史 phase 细节，只保留当前可执行路线图
