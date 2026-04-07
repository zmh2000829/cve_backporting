<p align="center">
  <img src="https://img.shields.io/badge/CVE-Backporting-0d1117?style=for-the-badge&logo=linux&logoColor=white&labelColor=FCC624" alt="CVE Backporting" height="36">
</p>

<h1 align="center">CVE Backporting Engine 中文说明</h1>

<p align="center">
  <strong>企业 Linux 内核 CVE 修复分析与回移自动化引擎</strong>
</p>

<p align="center">
  <em>从 CVE ID 到可执行回移方案：搜索、判定、依赖、适配、解释一体化完成。</em>
</p>

---

## 项目介绍

`CVE Backporting Engine` 是一个面向企业内核维护团队的端到端 CVE 回移（Backport）流水线。它将传统依赖专家经验、步骤分散、结果不稳定的处理方式，升级为可重复、可度量、可解释的工程流程。

系统围绕真实生产问题设计：

- 上游修复与下游分支差异大，`git apply` 经常失败
- 企业仓库存在 squash、路径迁移、上下文漂移，导致常规检索漏检
- 单条 CVE 分析耗时长，批量处理不具备一致性
- 决策依据难沉淀，跨团队协同成本高

项目核心目标：**把“找到补丁”提升为“交付可执行回移策略”**。

---

## 项目优势

### 1) 端到端自动化闭环
从 `CVE-ID` 输入开始，自动串联：

1. 多源情报抓取（MITRE / 内核源 / 镜像源）
2. 引入提交（intro）检测
3. 修复提交（fix）定位
4. hunk 级依赖分析
5. 多级 DryRun 适配验证
6. 结构化叙述输出（analysis narrative）

### 2) 三级提交搜索，解决“找不到”
搜索链路采用 `ID -> Subject -> Diff` 渐进策略：

- **L1 ID 精确匹配**：最高置信度
- **L2 Subject 语义匹配**：支持 backport 命名差异
- **L3 Diff 级匹配/包含度**：适配 squash 场景

### 3) 五层自适应 DryRun，解决“打不上”
当标准补丁应用失败时，采用渐进降级策略自动适配：

- **L0 Strict**：严格上下文匹配
- **L1 Context-C1**：放宽上下文约束
- **L2 3-Way**：三方合并
- **L3 Regenerated**：重建上下文补丁
- **L4 Conflict-Adapted**：冲突分析后适配生成

> 可选扩展：在 AI 开启时可进入 **L5 AI-Generated** 进行模型辅助补丁生成。

### 4) 七层工程化算法能力，覆盖复杂差异
在核心五层 DryRun 之外，工程实现整合了更细粒度策略（如 Verified-Direct、Zero-Context 等），形成多路径算法体系，显著提升在企业分支中的命中与适配成功率。

### 5) 可解释输出，便于审查与复盘
关键命令输出 `analysis_narrative`，包含：

- 工作流轨迹（做了什么）
- 前置依赖判断（为什么）
- 可应用性判定（成功/失败原因）
- 开发者动作建议（下一步怎么做）

同时，`analyze / validate / batch-validate` 现在统一输出顶层 `analysis_framework`：

- `process`：分析过程骨架
- `evidence`：证据骨架
- `conclusion`：结论骨架

用户可以先看这三部分，再决定是否继续下钻 `level_decision` 和 `rule_hits`。

---

## 项目优势提炼（可直接用于汇报）

### 一句话版本
**将 CVE 回移从“专家手工排查”升级为“算法驱动的标准化处置流水线”。**

### 三点版本
1. **更快**：自动化串联关键步骤，缩短单 CVE 处置周期。  
2. **更准**：多级搜索 + 多策略适配，提高补丁定位与应用成功率。  
3. **更稳**：过程可解释、结果可审计，降低个人经验依赖。

### 业务价值版本（管理视角）
- 降低安全修复 SLA 压力
- 提升批量 CVE 处置吞吐
- 降低核心工程师重复劳动
- 形成可复用的组织级安全工程资产

---

## 快速入门

### 三分钟上手路径

1. 安装依赖。
2. 在 `config.yaml` 里配置目标内核仓库路径。
3. 对目标分支执行一次 `build-cache`。
4. 先用 `analyze` 看单条 CVE 的回移结论和规则分级。
5. 已知真实修复时，再用 `validate` 对照评估工具效果。
6. 需要平台化接入时，再启动 `server` 走 HTTP API。

### 1. 环境要求
- Python 3.8+
- 本地可访问目标 Linux 内核仓库

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置目标仓库
在 `config.yaml` 中配置版本别名与路径：

```yaml
repositories:
  "5.10-hulk":
    path: "/path/to/linux"
    branch: "linux-5.10.y"
```

如需配置 `L0-L5` 策略分级与规则插件，请把 [rules/policy.example.yaml](/Users/junxiaoqiong/Workplace/cve_backporting/rules/policy.example.yaml) 中的 `policy:` 段复制到你的 `config.yaml`。

### 4. 构建提交缓存（首次必做）

```bash
python cli.py build-cache --target 5.10-hulk
```

### 5. 执行核心分析（analyze）

```bash
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
```

### 6. 命令如何选择

| 目标 | 命令 | 适用场景 |
|------|------|----------|
| 判断补丁能否直接回移，是否需要关联补丁，风险在哪 | `analyze` | 日常单条或批量 CVE 研判 |
| 判断漏洞引入提交是否已进入目标分支 | `check-intro` | 确认下游是否真正受影响 |
| 判断修复是否已经被合入 | `check-fix` | 避免重复回移 |
| 用已知真实修复验证工具输出 | `validate` | 单条样本精度验证 |
| 统计规则分桶、依赖分桶与 L0-L5 分布 | `batch-validate` | 批量策略效果评估 |
| 首次建立或刷新提交缓存 | `build-cache` | 初始化环境或仓库更新后 |
| 通过 URL 调用分析能力 | `server` | 平台对接、服务化调用 |

---

## `analyze` 核心用法（重点）

### 单条 CVE 分析

```bash
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
```

### 批量 CVE 分析

```bash
python cli.py analyze --batch cve_list.txt --target 5.10-hulk
```

`cve_list.txt` 示例：

```text
CVE-2024-26633
CVE-2024-26634
CVE-2024-26635
```

### 深度分析模式

```bash
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk --deep
```

### 仅做判定，不执行 DryRun

```bash
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk --no-dryrun
```

### analyze 结果产物

执行后会生成：
- 终端可视化阶段报告（含关键判定）
- JSON 报告（含 `analysis_narrative`）
- 若适配成功，输出 `*_adapted.patch` 补丁文件

---

## 五层自适应 DryRun（核心机制）

```text
Patch Input
  ├─ L0 Strict           -> git apply --check
  ├─ L1 Context-C1       -> git apply -C1 --check
  ├─ L2 3-Way            -> git apply --3way --check
  ├─ L3 Regenerated      -> 锚点定位 + 上下文重建
  └─ L4 Conflict-Adapted -> 冲突分析 + 适配补丁生成
```

### 为什么这五层有效
- 先用最可靠的 Git 原生路径（L0-L2）
- 再进入算法修复路径（L3-L4）处理企业分支差异
- 保持“自动化优先 + 人工可审查兜底”

### L0-L5 策略分级与可扩展规则

当前实现把“DryRun 如何成功”和“最终应走哪条审查通道”拆开了：

- `level_decision.base_level` / `base_method`：DryRun 基线
- `level_decision.level`：经过规则抬升后的最终 L0-L5 场景

最终级别的核心公式是：

```text
final_level = max(base_level, 所有命中规则给出的 level_floor)
```

这意味着 `L0-L5` 不是“补丁难度分”，也不是单独的“语义风险分”，而是下面四件事合并后的执行结论：

1. DryRun 是如何证明补丁可应用的
2. 关联补丁判断是否稳定
3. 是否命中关键语义风险
4. 最终应该走哪种审查和审批路径

需要特别统一三个口径：

- `strict` 成功，不代表最终一定是 `L0`
- `verified-direct` 当前属于 `L3` 的基线方法，不是 `L5`
- `L5` 只用于未知方法、DryRun 缺失或证据链断裂的兜底场景

#### 当前代码中的默认定义

| 级别 | 当前默认 `base_method` | 代码里的策略定义 | 审查模式 | 建议动作 |
|------|------------------------|------------------|----------|----------|
| `L0` | `strict` | 确定性无害，才允许 `harmless=true` | `auto-pass` | 可直接回移，只保留最小回归验证 |
| `L1` | `ignore-ws` / `context-C1` / `C1-ignore-ws` | 轻微上下文漂移，不自动判无害 | `llm-review` | 做轻量人工/LLM 复核 |
| `L2` | `3way` | 中等风险适配，证据不足以停留在低级别 | `targeted-review` | 逐 hunk 核对调用点、返回路径和依赖 |
| `L3` | `regenerated` / `verified-direct` | 语义敏感变更，必须做聚焦审查 | `focused-review` | 重点审查锁、字段、状态机、回归测试 |
| `L4` | `conflict-adapted` | 高风险牵连，已进入传播或冲突适配场景 | `manual-approval` | 资深维护者审批，显式看传播链 |
| `L5` | unknown / missing | 回退或未知路径，证据链最弱 | `fallback-review` | 保留证据，走人工确认或补样本验证 |

#### 汇报时建议这样解释

| 级别 | 可以直接拿去汇报的一句话定义 |
|------|----------------------------|
| `L0` | 已有最强可应用性证明，且没有额外语义风险，可进入“直接回移”通道 |
| `L1` | 只有轻微漂移，补丁意图仍清晰，但仍需轻量复核确认不是伪安全 |
| `L2` | 已能适配，但证据不足以继续停在低风险区，需要人工逐 hunk 核对 |
| `L3` | 已碰到关键语义风险，不能再按低风险回移处理，必须做聚焦审查和回归测试 |
| `L4` | 风险已经从局部 patch 扩散到调用链或冲突适配，需要资深维护者审批 |
| `L5` | 自动化证明最弱，不代表一定最危险，但系统不能替人拍板 |

#### `base_level`、`final_level`、`direct_backport` 为什么必须分开看

- `base_level`：补丁是怎么 apply 上去的
- `final_level`：综合规则后应该走哪条审查通道
- `direct_backport`：是否允许输出“可直接回移”的结论

真实样本会出现：

- `base=L0, final=L3`：文本上可 `strict` 应用，但命中了锁、字段、状态机等语义风险
- `base=L1, final=L1`：只是注释、日志、等价宏、局部变量 rename 这类轻微漂移
- `base=L2, final=L4`：`3way` 可过，但风险已经沿调用链传播，或进入冲突适配
- `base=L3, final=L3`：需要 `regenerated / verified-direct`，必须走聚焦审查

看分布时也不要只看“级别数字”：

- `L3/L4` 占比上升，很多时候说明风险证据被显式暴露出来了，不等于 apply 能力退化
- `L0/L1` 占比下降，很多时候说明低级别准入变严了，不等于工具变差
- 真正健康的目标不是把样本都压进 `L0/L1`，而是让低级别只留给证据最强的样本
- 如果出现 `base_level=L0` 很多、`final_level=L3` 也很多，不能只看两列分布；应同时看批量汇总里的 `promotion_summary`，确认到底是哪些规则在抬升
- 当前实现已经补了 `promotion_matrix / top_promotion_rules`，可以直接回答“是哪个规则把样本从 `L0` 推到了 `L3/L4`”

默认规则已经迁移到 `rules/` 目录下的 Python 模块：

- `rules/default_rules.py`：大改动、关键结构、调用链牵连、L1 API surface
- `rules/level_policies.py`：L0-L5 默认策略与 `level_floor` 抬升逻辑
- `rules/policy.example.yaml`：规则配置示例

当前规则进一步收敛为四类：

- `admission`：支持“可直接回移”或支持 L1 轻漂移判断的正向准入规则
- `low_level_veto`：阻止误入低级别处理区
- `direct_backport_veto`：阻止“可直接回移”结论
- `risk_profile`：锁、生命周期、状态机、结构体字段、错误路径、调用链传播等高风险画像规则

### 本轮新增：降低误抬升，同时继续收紧低级别准入

当前规则的目标不是放松标准，而是让“证据 -> 结论”映射更稳定：

- **`critical_structures` 不再因为任意 `struct` 文本就触发。**
  普通 `struct foo *ctx` 这类指针/引用行不再被当成布局风险；只有结构体定义变化，或 `sizeof`、`offsetof`、`container_of` 这类布局敏感操作才会命中。
- **调用链传播会过滤伪调用和成员访问伪 callee。**
  `sizeof`、`likely`、`ARRAY_SIZE`、`__builtin_*` 这类伪调用不再进入 caller/callee 关系；`ops->helper()`、`obj.cb()` 也不会被当成普通符号调用。
- **`p2_state_machine_control_flow` 现在必须看到状态语义。**
  纯 `if (ret) return -E...` 这类错误路径变化会停留在 `error_path`，不会再因为出现 `if / return` 就误判为状态机变化。
- **`p2_lifecycle_resource` 不再因为裸 `goto err/out` 就直接抬到 `L3`。**
  现在只有真正看到资源获取/释放、引用计数、持有关系或“回滚路径 + 资源线索”组合时，才会进入生命周期专项；单独的错误路径留在 `error_path/L2`。
- **`p2_struct_field_data_path` 不再因为“任何成员访问”就触发。**
  现在必须看到字段选择变化、结构体字段定义变化，或在锁/状态/错误路径语境下发生写路径漂移，才会命中字段/数据路径专项；同字段单纯改值不再被当成字段风险。
- **L0 正向准入条件更硬了。**
  `strict` 不再天然等于“可直接回移候选”。现在还要求没有前置依赖、没有传播、没有 `special_risk` 命中、没有字段/状态/错误路径语义标记，才会命中 `direct_backport_candidate`。
- **L1 不再只说“轻微漂移”，而是给出样本证据。**
  `l1_light_drift_sample` 会把注释漂移、日志文本漂移、等价宏替换、局部变量重命名这类边界样本显式写进证据。
- **关联补丁开始输出语义域证据。**
  `PrerequisitePatch` 现在会带上 `shared_fields / shared_lock_domains / shared_state_points / evidence_lines`，让“为什么建议先看关联补丁”可以落到共享字段、锁域和状态点，而不只是 hunk/function overlap。

这意味着：

- `L3/L4` 更接近真正的语义风险暴露，而不是宽匹配副作用
- `L0/L1` 的保留条件更清晰，只留给证据更强的样本
- 关联补丁判断开始从“位置接近”升级到“语义域重叠”

后续业务规则可直接放到 `rules/*.py`，并通过 `policy.extra_rule_modules` 以插件方式加载。

---

## 七层算法能力（工程实现视角）

在复杂仓库中，系统通过多策略组合形成七层（及扩展）能力体系，典型包括：

1. 严格应用检查
2. 弱化上下文检查
3. 三方合并检查
4. 锚点行定位
5. 七策略序列搜索
6. 逐行投票定位
7. 跨 hunk 偏移传播

并可叠加：
- 代码语义匹配（结构/标识符/关键词）
- 路径映射（跨版本目录迁移）
- 可选 AI 生成补丁路径

> 详细算法说明见：`docs/ADAPTIVE_DRYRUN.md` 与 `docs/MULTI_LEVEL_ALGORITHM.md`

---

## 常用命令

```bash
# 检查漏洞引入提交是否在目标分支存在
python cli.py check-intro --cve CVE-2024-26633 --target 5.10-hulk

# 检查修复是否已合入
python cli.py check-fix --cve CVE-2024-26633 --target 5.10-hulk

# 单条验证（与已知修复对比）
python cli.py validate --cve CVE-2024-26633 --target 5.10-hulk --known-fix <commit>

# 批量验证
python cli.py batch-validate --file cve_data.json --target 5.10-hulk

# 单本地仓库的推荐并行方式
python cli.py batch-validate --file cve_data.json --target 5.10-hulk --workers 2

# 启动 HTTP API 服务（analyze / validate / batch-validate）
python cli.py server --host 0.0.0.0 --port 8000

# 基准评估
python cli.py benchmark --file benchmarks.yaml --target 5.10-hulk
```

说明：`/api/analyze` 与 `/api/analyzer` 可互通，均支持 `target_version` 或 `target` 字段；所有返回均以 JSON 形式给出完整过程与规则详情。

并行建议：

- `--workers 1` 是最稳妥的默认值。
- `--workers 2` 是单本地内核仓库下的推荐值。
- 不建议一开始就超过 `4`，因为随后瓶颈通常会变成 `git worktree` 元数据、共享对象库和磁盘 I/O。
- 使用 `--deep` 时，建议 `workers` 保持在 `1` 或 `2`。
- 单仓也可以并行，因为每个 CVE 都在独立的临时 `git worktree` 中执行，不会共享同一个 checkout 工作树。

## CLI 代码结构

当前 CLI 已按命令拆分，用户命令保持不变，内部职责更清晰：

- `cli.py`：保留统一入口、公共参数和共享 runtime helper
- `commands/analyze.py`：`analyze`
- `commands/checks.py`：`check-intro` / `check-fix`
- `commands/validate.py`：`validate` / `benchmark` / `batch-validate`
- `commands/maintenance.py`：`build-cache` / `search`
- `commands/server.py`：`server`

这意味着后续新增命令或调整某个命令时，不需要继续把所有逻辑堆进一个超大 `cli.py`。

## HTTP API（server 模式）

### 启动 API 服务

```bash
python cli.py server --host 127.0.0.1 --port 8000 --config config.yaml
```

- 通用参数包含 `--host`（监听地址，默认 `127.0.0.1`）、`--port`（监听端口，默认 `8000`）、`--config`（同 CLI 的配置文件，默认 `config.yaml`）
- 路由：`GET /health`
- 路由：`POST /api/analyze`
- 路由：`POST /api/analyzer`（兼容别名）
- 路由：`POST /api/validate`
- 路由：`POST /api/batch-validate`

成功响应统一返回：

```json
{
  "ok": true,
  "data": { ... }
}
```

失败响应返回 HTTP `400/404/500`，并会补充“怎么改请求”的执行提示，例如：

```json
{
  "ok": false,
  "error": {
    "error_code": "invalid_request",
    "user_message": "缺少 CVE 标识。",
    "route": "/api/validate",
    "missing_input": ["cve_id"],
    "hint": "请求体中补充 `cve_id`。",
    "suggested_fix": {
      "target_version": "5.10-hulk",
      "cve_id": "CVE-2024-26633"
    },
    "absolute_date": "2026-04-02"
  }
}
```

### `POST /api/analyze` / `POST /api/analyzer`

```json
{
  "target_version": "5.10-hulk",
  "cve_id": "CVE-2024-26633",
  "deep": false,
  "no_dryrun": false
}
```

或批量请求：

```json
{
  "target": "5.10-hulk",
  "cves": ["CVE-2024-26633", "CVE-2024-26634"],
  "cve_ids": ["CVE-2024-26635"],
  "deep": true
}
```

`cve_id`、`cves`、`cve_ids` 会被合并并统一处理。

关键返回字段：

- `analysis_framework.process`
- `analysis_framework.evidence`
- `analysis_framework.conclusion`
- `level_decision`
- `validation_details`

### `POST /api/validate`

```json
{
  "target_version": "5.10-hulk",
  "cve_id": "CVE-2024-26633",
  "known_fix": "da23bd709b46",
  "known_prereqs": "abc111,def222",
  "mainline_fix": "aaabbb000111",
  "mainline_intro": "bbb222ccc333",
  "deep": false,
  "p2_enabled": true
}
```

`known_prereqs` 也可传数组：

```json
{
  "known_prereqs": ["abc111", "def222"]
}
```

关键返回字段：

- `analysis_framework.process`
- `analysis_framework.evidence`
- `analysis_framework.conclusion`
- `l0_l5.current_level`
- `l0_l5.base_level`
- `level_decision`
- `validation_details`

### `POST /api/batch-validate`

```json
{
  "target": "5.10-hulk",
  "deep": false,
  "workers": 2,
  "p2_enabled": true,
  "items": [
    {
      "cve_id": "CVE-2024-26633",
      "known_fix": "da23bd709b46",
      "known_prereqs": ["abc111"],
      "mainline_fix": "aaabbb000111",
      "mainline_intro": "bbb222ccc333"
    },
    {
      "cve_id": "CVE-2024-26634",
      "known_fix": "11aabbeff",
      "known_prereqs": "111,222"
    }
  ]
}
```

返回结果包含 `results` / `errors` / `summary`，并补充与 CLI 同口径的 `batch_summary`：

```json
{
  "ok": true,
  "data": {
    "operation": "batch-validate",
    "results": [],
    "errors": [],
    "summary": {
      "total": 0,
      "success": 0,
      "error": 0
    },
    "p2_enabled": true,
    "workers": 2,
    "parallel_mode": true,
    "batch_summary": {
      "l0_l5": {},
      "promotion_summary": {
        "promotion_matrix": {
          "L0->L3": 0
        },
        "top_promotion_rules": {
          "p2_lifecycle_resource": 0
        }
      },
      "deterministic_exact_match": {
        "count": 0,
        "rate": 0.0
      },
      "critical_structure_change": {
        "count": 0,
        "rate": 0.0
      },
      "manual_prerequisite_analysis": {
        "count": 0,
        "rate": 0.0
      }
    },
    "l0_l5_summary": {
      "levels": ["L0", "L1", "L2", "L3", "L4", "L5"],
      "current_level_distribution": {},
      "base_level_distribution": {}
    }
  }
}
```

`results` 中每条结果也都会包含：

- `analysis_framework`
- `l0_l5`
- `level_decision`
- `validation_details`

批量结果里建议优先同时看这三组字段：

- `batch_summary.l0_l5`
- `batch_summary.promotion_summary`
- `batch_summary.special_risk`

这样才能回答：

- 为什么 `base_level` 和 `final_level` 差异这么大
- 是哪些规则在抬升
- 这些抬升是锁/生命周期/字段/错误路径这类真实风险，还是规则过宽导致的副作用

`/api/batch-validate` 也支持可选参数 `workers`，推荐值与 CLI 一致：

- `1`：最稳妥
- `2`：单本地仓库推荐
- `deep=true` 时建议不超过 `2`

---

## 建议阅读顺序

1. `README.md`（英文总览）
2. `README_zh.md`（中文落地说明）
3. `plan.md`（当前演进方向与验收标准）
4. `docs/presentation.md`（汇报材料）
5. `docs/TECHNICAL.md`（架构与模块）
6. `docs/ADAPTIVE_DRYRUN.md`（五层 DryRun 原理）
7. `docs/MULTI_LEVEL_ALGORITHM.md`（多级算法全景）

---

## 下一步演进重点

当前阶段的主任务不是继续叠加算法分支，而是把已有能力收敛成可运营体系：

1. 把 `rules/` 变成规则代码、规则文档、规则配置样例的统一入口。
2. 建立 20+ CVE 的标准样本验证清单，验证 `L0-L5` 与 warning 判定质量。
3. 把 `level_decision` 输出真正用于人工审查、审批门禁和专家答辩材料。
4. 删除不再作为主入口维护的冗余文档，避免文档继续分叉。
