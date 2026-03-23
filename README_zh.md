# CVE Backporting Engine（中文说明）

> 面向企业 Linux 内核维护场景的 CVE 修复分析与回移（Backport）自动化引擎。

## 项目介绍

`CVE Backporting Engine` 是一个端到端的自动化流水线，用于将上游社区 CVE 修复补丁高效映射并回移到企业内核分支。它覆盖了从漏洞情报获取、修复提交定位、依赖分析、补丁可用性验证到结果解释的完整流程。

项目重点解决企业内核维护中的典型痛点：
- 上游与下游代码差异大，传统 `git apply` 容易失败
- squash commit、路径迁移、上下文漂移导致“找得到但打不上”
- 人工分析链路长、成本高、结果不稳定

通过多级搜索与多级 DryRun 策略，本项目可将 CVE 从“信息”快速转化为“可执行回移方案”。

---

## 项目优势

### 1. 端到端自动化
从 CVE 编号开始，自动完成：漏洞信息抓取 → 修复定位 → 引入提交检测 → 依赖分析 → 补丁 dry-run 验证。

### 2. 多级提交搜索能力
支持 `ID -> Subject -> Diff` 的三级搜索路径，并结合置信度评分，提高在复杂仓库中的命中率与可解释性。

### 3. 面向企业内核差异的补丁适配
内置多级自适应 DryRun 引擎（含严格匹配、宽松上下文、三方合并、重构补丁、零上下文、冲突适配等路径），并支持 AI 辅助生成（可选）。

### 4. 依赖分析更贴近真实回移流程
基于 hunk 级别重叠与函数关系进行前置依赖判定，给出强/中/弱分级，减少“补丁打上了但行为不对”的风险。

### 5. 结果可解释，便于工程决策
输出结构化叙述（analysis narrative），清楚说明：做了什么、为何如此判断、当前风险点、下一步建议。

---

## 项目优势提炼（给汇报/立项可直接复用）

- **一句话版本**：
  - 用自动化与可解释算法，把企业内核 CVE 回移从“经验驱动”升级为“流程驱动”。

- **三点版本**：
  1. **更快**：自动化替代人工串行分析，缩短 CVE 处置周期。
  2. **更准**：多级搜索 + 多策略适配，提升补丁定位和应用成功率。
  3. **更稳**：全流程有依据、有输出、有追踪，降低个人经验依赖。

- **价值版本（管理视角）**：
  - 降低安全修复 SLA 压力
  - 降低高阶内核工程师重复劳动
  - 提升批量 CVE 处理的一致性和可审计性

---

## 快速入门

### 1) 环境要求
- Python 3.8+
- 可访问目标 Linux 内核仓库（本地路径）

### 2) 安装依赖

```bash
pip install -r requirements.txt
```

### 3) 配置仓库
在 `config.yaml` 中配置目标仓库，例如：

```yaml
repositories:
  "5.10-hulk":
    path: "/path/to/linux"
    branch: "linux-5.10.y"
```

### 4) 初始化提交缓存（首次）

```bash
python cli.py build-cache --target 5.10-hulk
```

### 5) 执行 CVE 分析

```bash
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
```

---

## 常用命令

```bash
# 检查漏洞引入提交是否存在
python cli.py check-intro --cve CVE-2024-26633 --target 5.10-hulk

# 检查修复是否已合入
python cli.py check-fix --cve CVE-2024-26633 --target 5.10-hulk

# 单条验证（对比已知修复）
python cli.py validate --cve CVE-2024-26633 --target 5.10-hulk --known-fix <commit>

# 批量验证
python cli.py batch-validate --file cve_data.json --target 5.10-hulk
```

---

## 建议阅读

- 英文总览：`README.md`
- 技术文档：`docs/TECHNICAL.md`
- DryRun 算法：`docs/ADAPTIVE_DRYRUN.md`
- 多级算法说明：`docs/MULTI_LEVEL_ALGORITHM.md`
