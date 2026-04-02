# Policy Engine P0/P1 Rules

本规则用于约束 `core/policy_engine.py`、`core/config.py`、`tests/test_policy_engine.py` 以及相关文档在 P0/P1 阶段的演进方式。

## 1. 状态标记规则

1. 只有在“代码 + 测试 + 配置模板 + 文档”四者同步后，`plan.md` 中的条目才能标记为完成或“已落地”。
2. 不能在仓库内验证的事项，只能标记为“待样本验证 / 待外部数据验证”，不能直接写成 ✅。
3. 若能力仅为首版启发式，必须明确写出边界、误报风险和后续增强方向，不能表述为最终方案。

## 2. P0 回归与 Schema 规则

1. `ValidationDetails.rule_version` 在所有路径上必须保持一致；主版本升级后，不允许保留旧分支继续输出旧版本。
2. 无补丁、空 DryRun、未知 DryRun 方法都必须有回归测试。
3. `rule_profile` 必须反映当前实际生效的 profile，不能在降级路径中被静默重置为 `default`。
4. `rule_hits` 中的 `rule_id`、`severity`、`message`、`evidence` 必须完整；`evidence` 必须可 JSON 序列化。
5. 若规则会影响最终 L0-L5 编排，必须显式输出 `level_floor`，避免把级别抬升逻辑继续硬编码回 `core/policy_engine.py`。
6. 每次新增默认规则时，至少补三类测试：
   - 触发该规则的正例
   - 不应触发该规则的反例
   - 关闭该规则后的回退行为

## 3. P1 策略质量规则

1. `L1` 级别不得自动标记 `harmless=true`；只有 `L0` 且无 `high/warn` 规则命中时，才允许机械判定为无害。
2. `L0` 的正向准入不能只依赖 `strict`；若存在字段/状态/错误路径语义标记、`special_risk` 命中、传播证据或低置信度依赖分析，必须撤销“可直接回移候选”。
3. `L1` 的“轻微漂移”若要在文档或输出中成立，必须有样本化正向证据，不允许只写“建议人工复核”这类空泛描述。
4. `l1_api_surface` 一类启发式规则必须输出可复核证据，至少包括触发原因和对应计数/差异，不允许只给笼统告警。
5. 调用链分析在当前阶段只能宣称“修改文件集合内的跨文件分析”，不能在文案或字段中暗示已覆盖全仓库。
6. 引入新的风险规则时，默认必须支持开关控制，且能通过配置显式关闭。
7. 插件规则必须提供稳定的 `rule_id`，并使用 `register_rules(registry, config=None)` 或 `RULES` 暴露，不允许依赖隐式副作用注册。
8. 若插件要扩展级别策略，必须通过 `register_level_policies(registry, config=None)` 或 `LEVEL_POLICIES` 显式注册。

## 4. Profile 与配置规则

1. `conservative`、`balanced`、`aggressive` 的阈值必须满足由严到松的单调关系。
2. YAML 显式配置项覆盖 profile 预设的行为必须有测试保护。
3. 每次修改 profile 阈值时，必须同步更新：
   - `core/config.py`
   - `rules/policy.example.yaml`
   - 相关 README / 设计说明
   - 回归测试

## 5. 样本验证规则

1. `20+ CVE` 小样本验证不能只报告通过率，必须记录样本清单、期望结论、实际结论、差异原因和人工裁决。
2. 若样本验证依赖外部仓库，计划中必须明确“本仓库不含数据，仅提供模板/脚本/字段约束”。
3. 未形成可复跑清单前，不得把“小样本验证完成”写成已完成项。
