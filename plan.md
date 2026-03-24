# CVE Backporting Engine 演进计划（按优先级）

## 目标与约束

核心约束：
- 不改动已有核心算法主流程（crawl/search/dependency/dryrun）。
- 优先保证规则与输出可运营、可复用、可对外服务。
- 采用 API-first + 批量闭环，统一验证口径。

## P0（本轮必须完成）

- [x] 增加 `server` CLI 入口与 URL 服务（已接入 `/api/analyze`、`/api/analyzer`、`/api/validate`、`/api/batch-validate`）。
- [x] 完成 API 接口基础回归测试并生成 `UT-report.md`。
- [ ] 重写 `plan.md`：以优先级、打勾/打叉形式展示当前里程碑（本次已完成）。
- [ ] 在 `validate` 与 `batch-validate` 输出中补齐可复用的“规则驱动分级证据字段”，并统一展示 `level_decision`。
- [ ] `batch-validate` 增加 L0-L5 全局统计：
  - 场景占比（overall level distribution）
  - 成功率与失败原因按 L0-L5 分桶
  - 低级自动化优先（L0/L1）和高级别人工/建议模式清晰区分
- [ ] `batch-validate` 的策略建议：默认努力把 L0 提升至 100% 可落地（在不引入额外风险前提下）。

## P1（对交付有直接影响）

- [ ] 批量/单条 `analyze`、`validate` 的返回过程要完整：
  - 输入处理到 patch 定位到 dryrun 的全过程都可追溯
  - 规则触发、rule evidence、next_action 清晰输出
- [ ] 分析结果中“补丁关联”统一使用完整 URL（含仓库 URL + commit 对象），避免仅展示裸 `commit_id`。
- [ ] 补丁变更判断增强：
  - 判断并明确标注“无变更”场景（patch 与目标无修改）
  - 标注“仅单行修改但高影响”警告
  - 报告变更行数与风险提示（warning 级别）
- [ ] 函数级影响链增强：
  - 明确“被调用 / 调用”对当前变更的影响判断
  - 区分“有无实际影响”与“仅引用到”两类场景
  - 增加调用链传播到关键 API 的风险分数
- [ ] 数据结构与锁保护专项检测（高优先）：
  - 修改/新增数据结构字段时的兼容性评估
  - 锁变更（spinlock/mutex/rwlock/rcu 等）单独标红提示
  - 将该类变更默认抬升到更高 review level

## P2（规则治理与协作）

- [ ] 打造可插拔规则包标准文档（`rules/README.md`）：
  - 规则 `rule_id`
  - `severity` 与 `level_floor`
  - `evidence` 字段规范
  - 开关 `enabled` 与回退策略
- [ ] 完成规则变更细则（版本化）：
  - 新增/移除规则变更记录
  - 对应的正例、反例、关闭开关行为
- [ ] 将 `rules/policy.example.yaml` 作为统一配置入口，禁止在根配置散落规则配置（若有，执行清理）

## P3（工程化交付）

- [ ] 调整批量 validate 报告模板：
  - L0-L5 按级别导出的 CSV/JSON 报表
  - 高风险项（锁、数据结构、调用链）的归因字段
  - 建议动作与审批状态（pass/review/manual)
- [ ] 补充 API 文档与规则文档对齐（`README.md`、`README_zh.md`、`plan.md`）。
- [ ] 提供最小闭环：每次规则/参数变更必须配套测试与报告更新，避免文档-实现分叉。

## 运行验收（建议作为 CI 门禁）

- [ ] `batch-validate` 产出必须包含 `total/level_summary`（L0-L5）与 `coverage` 两类指标。
- [ ] 任一默认规则触发后，`analysis_narrative` 必须附带 rule evidence 与升级原因。
- [ ] 函数影响链中检测到锁变更时，结果中必须带 `severity_hint` 与 `next_action`.
- [ ] API 返回中 `GET /health` 恒定可用；错误输入必须返回标准 JSON 错误对象。
