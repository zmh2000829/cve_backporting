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

当前实现把“DryRun 成功方法”和“最终策略级别”拆开了：

- `level_decision.base_level` / `base_method`：DryRun 基线
- `level_decision.level`：经过规则抬升后的最终 L0-L5 场景

也就是说，`strict` 不再天然等于最终 `L0`。如果命中关键结构、调用链牵连或大改动规则，场景会被抬升：

- `L0`：严格命中且无风险规则，才允许 `harmless=true`
- `L1`：轻微上下文漂移，进入 LLM/人工“是否无害”复核路径
- `L2`：中等风险，需人工对照 hunk / 调用面
- `L3`：关键结构或语义敏感变更，需聚焦 review + 回归测试
- `L4`：关键变更已沿调用/被调用链扩散，或冲突适配，需人工审批
- `L5`：verified-direct / 未知路径，按最高谨慎度处理

默认规则已经迁移到 `rules/` 目录下的 Python 模块：

- `rules/default_rules.py`：大改动、关键结构、调用链牵连、L1 API surface
- `rules/level_policies.py`：L0-L5 默认策略与 `level_floor` 抬升逻辑
- `rules/policy.example.yaml`：规则配置示例

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

# 基准评估
python cli.py benchmark --file benchmarks.yaml --target 5.10-hulk
```

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
