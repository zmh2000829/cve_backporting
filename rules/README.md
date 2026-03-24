# Rules

本目录同时存放两类内容：

- **可加载的 Python 规则模块**：真正参与策略判定
- **实现约束与验收规则文档**：约束代码、测试、配置和文档同步演进

适用范围：

- 策略引擎与规则系统
- 配置模板与 profile 预设
- 测试回归门禁
- 计划状态更新与里程碑验收

使用原则：

1. `plan.md` 负责说明“做什么、为什么、做到什么程度”。
2. `rules/*.md` 负责说明“什么情况下算完成、哪些行为不允许、改动时必须同步什么”。
3. 当 `plan.md`、代码、测试、配置模板、README 之间出现冲突时，必须先修正文档与测试，再宣称任务完成。
4. 新增规则能力时，优先补充或扩展本目录中的约束，而不是仅在提交说明里口头约定。

当前 Python 模块：

- `base.py`：`RuleContext` / `PolicyRule` / `RuleRegistry` / `LevelPolicyRegistry`
- `default_rules.py`：默认大改动、关键结构、调用链、L1 API surface 规则
- `level_policies.py`：L0-L5 默认场景策略与 `level_floor` 抬升逻辑

插件约定：

1. 自定义规则建议直接放到 `rules/*.py`，并在 `config.yaml` 中声明 `policy.extra_rule_modules`。
2. 模块可通过以下任一方式暴露能力：
   - `register_rules(registry, config=None)`
   - `RULES`
   - `register_level_policies(registry, config=None)`
   - `LEVEL_POLICIES`
3. `rule_hits` 建议始终提供 `rule_id`、`severity`、`message`、`evidence`，并可选提供 `level_floor` 用于把最终场景抬升到至少某一级。
4. 规则配置示例统一放在 [rules/policy.example.yaml](/Users/junxiaoqiong/Workplace/cve_backporting/rules/policy.example.yaml)，与规则代码一起维护。

当前约束文档：

- `policy_engine_p0_p1.md`：约束 P0/P1 阶段的策略引擎、规则测试、schema 和 profile 变更方式
