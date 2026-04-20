<p align="center">
  <img src="https://img.shields.io/badge/CVE-Backporting-0d1117?style=for-the-badge&logo=linux&logoColor=white&labelColor=FCC624" alt="CVE Backporting" height="36">
</p>

<h1 align="center">CVE Backporting Engine 中文说明</h1>

<p align="center">
  <strong>企业 Linux 内核 CVE 修复分析与回移自动化引擎</strong>
</p>

<p align="center">
  <em>从 CVE 编号到可执行回移方案：搜索、依赖、补丁适配、L0-L5 分级、真值验证一体化完成。</em>
</p>

---

## 快速导航

| 如果你现在最关心 | 直接跳转 |
| --- | --- |
| 怎么安装和跑起来 | [环境与安装](#4-环境与安装) |
| CLI 怎么用 | [CLI 用法](#6-cli-用法) |
| HTTP API 怎么对接 | [API 快速说明](#8-http-api-用法)、[API 合同](docs/API_CONTRACT.md) |
| 输出 JSON 有哪些字段 | [输出 Schema](docs/OUTPUT_SCHEMA.md) |
| `L0-L5` 到底是什么意思 | [多级算法手册](docs/MULTI_LEVEL_ALGORITHM.md) |
| 每条规则具体在说什么 | [规则手册](docs/RULEBOOK.md) |
| 哪些场景系统本来就不该自动拍板 | [边界与不适用场景](docs/BOUNDARIES.md) |

---

## 1. 项目定位

这个项目用来解决企业内核维护中的三个核心问题：

| 现实问题 | 传统处理方式 | 本项目给出的能力 |
| --- | --- | --- |
| 找不到对应修复 | 人工查邮件、查 commit、比 subject | 三级搜索：`ID -> Subject -> Diff` |
| 找到补丁但打不上 | 手工改 patch、反复 `git apply` 试错 | 多级 DryRun + 补丁重建 + 冲突适配 |
| 打上了但不敢合 | 风险解释不统一、依赖判断靠经验 | `L0-L5` 分级 + 规则证据 + validate 闭环 |

项目的目标不是只回答“有没有补丁”，而是稳定交付以下结论：

| 结论 | 具体内容 |
| --- | --- |
| 搜索结论 | fix / intro / stable backport 是否可定位 |
| 依赖结论 | 是否存在必须或建议一并评估的 prerequisite patches |
| 适配结论 | 补丁能否直接落地，还是要走适配路径 |
| 审查结论 | 最终该走自动、轻审、人审还是审批通道 |

---

## 2. 核心能力总览

| 能力模块 | 解决什么问题 | 关键输出 |
| --- | --- | --- |
| `Crawler Agent` | 采集 CVE、上游 fix、introduced commit、版本映射 | `cve_info` |
| `Analysis Agent` | 在目标仓定位修复或引入点 | 搜索候选、搜索策略证据 |
| `Dependency Agent` | 判断 prerequisite patches | `independent / recommended / required` |
| `DryRun Agent` | 评估补丁可应用性和适配路径 | `Strict / 3-Way / Regenerated / Conflict-Adapted ...` |
| `Policy Engine` | 把证据转成 `L0-L5` 执行通道 | `base_level / final_level / next_action` |
| `validate` | 用已知真值验证单案例 | `generated_vs_real`、`overall_pass` |
| `batch-validate` | 聚合策略效果和分级准确率 | `strategy_effectiveness`、`level_accuracy` |
| `TUI` | 在终端可视化分析过程与结果 | Stage 面板、单案例面板、批量统计表 |
| `HTTP API` | 对接平台或自动化服务 | `/api/analyze`、`/api/validate`、`/api/batch-validate` |

### 2.1 当前不能稳定解决的场景

这部分必须看清楚。本项目不是“所有 CVE 都能自动给出稳定回移结论”的工具。完整说明请直接看 [边界与不适用场景](docs/BOUNDARIES.md)。

| 场景 | 为什么当前不能稳定解决 | 当前系统会怎么表现 |
| --- | --- | --- |
| 跨文件、多级、长链路传播的关键信号升级 | 当前调用链分析是局部图，主要覆盖“本次修改文件集合内”的 direct caller/callee 和有限跨文件唯一符号连接，不能稳定覆盖全仓多跳传播、跨子系统扩散和长链路数据流 | 只能部分命中 `call_chain_fanout` / `call_chain_propagation`；遇到关键结构时应按 `L3/L4` 人工审查，不应把“没继续升档”理解成全局安全 |
| 涉及 `Kconfig` / `Makefile` / `CONFIG_*` / defconfig 的 CVE | 当前没有构建期配置模型，也不判断“某个修复是否依赖特定编译选项、子系统开关或发布配置” | 可能只能看到代码补丁本身，无法稳定回答“该 CVE 在你的发行配置里是否可触发、是否需要一并改 config”；应人工结合配置审查 |
| 依赖运行时环境或外部配套的修复 | 例如依赖 sysctl、firmware、device tree、用户态协议、特定硬件初始化顺序的 CVE，单靠 patch 文本和静态代码无法完整建模 | 系统可能能找到补丁，但不能把结果当成“环境层面已闭环”；应人工补运行时验证 |
| 上游情报不足或 fix / intro 不可稳定定位 | 若缺少可靠的 mainline fix 或 stable backport 线索，后续 DryRun 和分级会失去稳定锚点；若仅缺少 introduced commit，可启用 `analysis.missing_intro_policy=patch_probe` 用 fix patch 的 removed/added 行探测目标代码形态 | 有 fix patch 时系统会输出 `intro_analysis` 证据；无有效探测信号时仍会进入不确定或人工确认通道，不能把低置信结论当成自动闭环 |
| 宏展开、生成代码、架构特定汇编主导语义的修复 | 当前主要分析 C 代码文本、diff、局部函数关系，对复杂宏语义、自动生成代码、汇编路径的行为变化没有稳定语义模型 | 可能只能得到文本级 apply 或局部规则命中；不应把它解释成“语义已被系统充分理解” |
| AI 兜底补丁生成 | `AI-Generated` 不是确定性主路径，不能替代真实搜索、依赖、DryRun 和 validate 证据 | 只能作为最后兜底候选，默认不应直接进入自动回移通道 |

一句话判断：

| 如果看到这些特征 | 正确做法 |
| --- | --- |
| 跨文件长链传播、kernel config、运行时环境依赖、情报缺失 | 不要追求“自动给结论”，而要追求“自动把风险显式抬出来” |

---

## 3. 文档怎么分工

这次文档已经拆分，不再把所有内容塞进一处：

| 文档 | 负责什么 | 适合谁看 |
| --- | --- | --- |
| [README_zh.md](README_zh.md) | 总体介绍、安装配置、CLI/TUI/API 快速入口、文档导航 | 第一次接触项目的人 |
| [docs/TECHNICAL.md](docs/TECHNICAL.md) | 系统架构、代码模块、数据流、TUI 技术说明、验证框架 | 开发者、维护者 |
| [docs/ADAPTIVE_DRYRUN.md](docs/ADAPTIVE_DRYRUN.md) | DryRun 策略家族、适配顺序、冲突适配、输出口径 | 关注补丁适配的人 |
| [docs/MULTI_LEVEL_ALGORITHM.md](docs/MULTI_LEVEL_ALGORITHM.md) | `L0-L5`、核心算法地图、调用链、LLM 使用边界、准确率高场景 | 关注策略与判定质量的人 |
| [docs/API_CONTRACT.md](docs/API_CONTRACT.md) | HTTP API 请求模板、响应模板、必要字段、错误返回、对接约束 | 平台、服务端对接者 |
| [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md) | 单案例 JSON、validate 字段、batch summary、错误结构、字段字典 | 平台、报表、数据接入方 |
| [docs/RULEBOOK.md](docs/RULEBOOK.md) | 用户可见规则、level floor、触发条件、典型样本、常见误解、误判边界 | 规则维护者、评审者 |
| [docs/BOUNDARIES.md](docs/BOUNDARIES.md) | 不适用场景、当前边界、系统如何退回人工、不可过度承诺的场景 | 维护者、管理者、对接方 |
| [docs/presentation.md](docs/presentation.md) | 面向汇报的精简版总览 | 评审、管理层、汇报场景 |

---

## 4. 环境与安装

### 4.1 环境要求

| 项目 | 要求 |
| --- | --- |
| Python | `3.8+` |
| Git | 本地可访问目标 Linux 内核仓库 |
| 仓库状态 | 能执行 `git show`、`git log`，且分支配置正确 |
| 可选 LLM | 只有在启用 AI 增强时需要 |

### 4.2 安装依赖

```bash
pip install -r requirements.txt
```

### 4.3 配置目标仓库

最小 `config.yaml`：

```yaml
repositories:
  "5.10-hulk":
    path: "/path/to/linux"
    branch: "linux-5.10.y"
```

如需启用 LLM：

```yaml
llm:
  enabled: true
  provider: "openai"
  api_key: "YOUR_KEY"
  base_url: "https://api.openai.com/v1"
  model: "gpt-4o"
```

如果上游 CVE 没有提供 introduced commit，可以通过 `analysis` 配置选择处理策略：

```yaml
analysis:
  # patch_probe: 用 fix patch 的 removed/added 行探测目标代码形态
  # assume_vulnerable: 保持旧行为，默认按受影响继续回溯
  # strict_unknown: 不做受影响假设，交给人工确认
  missing_intro_policy: "patch_probe"
  missing_intro_assume_on_uncertain: true
  missing_intro_min_removed_line_match: 0.30
  missing_intro_min_file_coverage: 0.50
  missing_intro_fixed_line_threshold: 0.70
```

`patch_probe` 的判断逻辑是：目标分支命中修复补丁的 `- removed` 行，说明仍保留修复前代码形态，继续补丁回溯；目标分支高度命中 `+ added` 行且未命中 removed 行，说明更接近修复后形态，不再盲目判定受影响。该证据会写入 `intro_analysis`。

### 4.4 首次构建缓存

```bash
python cli.py build-cache --target 5.10-hulk
```

---

## 5. 先跑哪个命令

| 目标 | 命令 | 什么时候用 |
| --- | --- | --- |
| 看单个 CVE 是否需要回移、风险在哪 | `analyze` | 日常分析主入口 |
| 检查漏洞引入提交是否存在 | `check-intro` | 确认目标分支是否真的受影响 |
| 检查修复是否已经合入 | `check-fix` | 避免重复回移 |
| 用单个案例做真值验证 | `validate` | 校验工具输出与真实 fix 的关系 |
| 批量看策略效果与分级准确率 | `batch-validate` | 规则回归、汇报、样本评估 |
| 启动服务接口 | `server` | 平台对接 |
| 跑基准测试集 | `benchmark` | 持续回归 |

---

## 6. CLI 用法

### 6.1 `analyze`

| 用途 | 命令 |
| --- | --- |
| 单条 CVE | `python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk` |
| 批量 CVE 列表 | `python cli.py analyze --batch cve_list.txt --target 5.10-hulk` |
| 深度分析 | `python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk --deep` |
| 不执行 DryRun | `python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk --no-dryrun` |

`cve_list.txt` 示例：

```text
CVE-2024-26633
CVE-2024-26634
CVE-2024-26635
```

### 6.2 `check-intro`

| 用途 | 命令 |
| --- | --- |
| 按 CVE 检查 | `python cli.py check-intro --cve CVE-2024-26633 --target 5.10-hulk` |
| 按 commit 检查 | `python cli.py check-intro --commit <intro_commit> --target 5.10-hulk` |

### 6.3 `check-fix`

| 用途 | 命令 |
| --- | --- |
| 按 CVE 检查 | `python cli.py check-fix --cve CVE-2024-26633 --target 5.10-hulk` |
| 按 commit 检查 | `python cli.py check-fix --commit <fix_commit> --target 5.10-hulk` |

### 6.4 `validate`

| 用途 | 命令 |
| --- | --- |
| 基本验证 | `python cli.py validate --cve CVE-2024-26633 --target 5.10-hulk --known-fix <commit>` |
| 直接指定上游 fix | `python cli.py validate --cve CVE-2024-26633 --target 5.10-hulk --known-fix <commit> --mainline-fix <upstream_fix>` |
| 同时指定 introduced commit | `python cli.py validate --cve CVE-2024-26633 --target 5.10-hulk --known-fix <commit> --mainline-fix <fix> --mainline-intro <intro>` |
| 深度验证 | `python cli.py validate --cve CVE-2024-26633 --target 5.10-hulk --known-fix <commit> --deep` |

### 6.5 `batch-validate`

| 用途 | 命令 |
| --- | --- |
| 全量验证 | `python cli.py batch-validate --file cve_data.json --target 5.10-hulk` |
| 截取样本 | `python cli.py batch-validate --file cve_data.json --target 5.10-hulk --offset 10 --limit 20` |
| 推荐并行 | `python cli.py batch-validate --file cve_data.json --target 5.10-hulk --workers 2` |
| 深度批量验证 | `python cli.py batch-validate --file cve_data.json --target 5.10-hulk --workers 2 --deep` |

### 6.6 `server`

```bash
python cli.py server --host 127.0.0.1 --port 8000
```

### 6.7 CLI 参数模板

如果你是把本项目接到脚本、流水线或平台任务里，建议按下面的字段模板准备命令参数：

| 命令 | 必填参数 | 常用可选参数 | 返回产物 |
| --- | --- | --- | --- |
| `analyze` | `--target` + `--cve` 或 `--batch` | `--deep`、`--no-dryrun`、`--policy-profile`、`--enable-p2` / `--disable-p2` | TUI + `report.json` |
| `check-intro` | `--target` + `--cve` 或 `--commit` | 无 | TUI |
| `check-fix` | `--target` + `--cve` 或 `--commit` | 无 | TUI |
| `validate` | `--target` + `--cve` + `--known-fix` | `--mainline-fix`、`--mainline-intro`、`--deep`、`--policy-profile`、`--enable-p2` / `--disable-p2` | TUI + `report.json` + patch artifacts |
| `batch-validate` | `--target` + `--file` | `--offset`、`--limit`、`--workers`、`--deep`、`--policy-profile`、`--enable-p2` / `--disable-p2` | TUI + batch summary JSON |
| `server` | 无 | `--host`、`--port` | HTTP API 服务 |

推荐把命令参数整理成统一模板：

```bash
python cli.py analyze \
  --cve <CVE-ID> \
  --target <TARGET_ALIAS> \
  --policy-profile <balanced|conservative> \
  [--deep] \
  [--no-dryrun]
```

```bash
python cli.py validate \
  --cve <CVE-ID> \
  --target <TARGET_ALIAS> \
  --known-fix <TARGET_FIX_COMMIT> \
  [--mainline-fix <UPSTREAM_FIX_COMMIT>] \
  [--mainline-intro <UPSTREAM_INTRO_COMMIT>] \
  [--policy-profile <balanced|conservative>] \
  [--deep]
```

```bash
python cli.py batch-validate \
  --file <CVE_DATA_JSON> \
  --target <TARGET_ALIAS> \
  [--workers 2] \
  [--offset 0] \
  [--limit 50] \
  [--policy-profile <balanced|conservative>] \
  [--deep]
```

### 6.8 CLI 输出模板

CLI 会同时给你两类输出：

| 输出形态 | 用途 | 说明 |
| --- | --- | --- |
| TUI 面板 | 人工阅读 | 适合工程师在终端直接看结论 |
| JSON 文件 | 程序对接 | 默认写入 `analysis_results/<run-id>/...` |

README 里只保留最关键读取口径：

| 输出 | 最少先看什么 |
| --- | --- |
| `analyze/report.json` | `result_status`、`l0_l5`、`analysis_framework.conclusion` |
| `validate/report.json` | `l0_l5`、`generated_vs_real`、`overall_pass` |
| `batch summary` | `summary.l0_l5`、`summary.strategy_effectiveness`、`summary.level_accuracy` |

最硬的约束只有一条：

| 对接要求 | 口径 |
| --- | --- |
| `L0-L5` 是否必须输出 | **是。单案例 JSON 必须包含 `l0_l5.current_level` 和 `l0_l5.base_level`；批量 summary 必须包含 `summary.l0_l5`。** |

详细字段模板和完整 JSON 示例请直接看 [输出 Schema 手册](docs/OUTPUT_SCHEMA.md)。

---

## 7. TUI 终端界面说明

默认 CLI 输出不是单纯日志，而是 Rich 风格的 TUI 面板。

| 场景 | 终端里会看到什么 | 作用 |
| --- | --- | --- |
| `analyze` | Stage 进度 + 单案例结论面板 | 看当前分析进度和最终结论 |
| `check-intro` / `check-fix` | 多策略命中面板 | 看三级搜索的命中情况 |
| `validate` | 单案例验证结论 + patch 对比 + 分级信息 | 看工具与真值的关系 |
| `batch-validate` | 多级策略统计表 + `L0-L5` 准确率表 | 看策略分布和整体准确率 |
| `--deep` | 漏洞分析 / 补丁检视 / 风险收益 / 合入建议面板 | 看更细的技术建议 |

| TUI 组件 | 代码位置 | 说明 |
| --- | --- | --- |
| `StageTracker` | `core/ui.py` | 统一阶段进度显示 |
| `render_report` | `core/ui.py` | `analyze` 主报告 |
| `render_validate_report` | `core/ui.py` | `validate` 主报告 |
| `render_batch_validate_report` | `core/ui_batch.py` | `batch-validate` 汇总报告 |
| `_render_deep_report` | `cli.py` | `--deep` 面板 |

---

## 8. HTTP API 用法

完整请求/响应合同、错误码和必要字段请直接看 [API 合同](docs/API_CONTRACT.md)。本章只保留 README 层面的快速接入说明。

### 8.1 启动服务

```bash
python cli.py server --host 127.0.0.1 --port 8000
```

### 8.2 路由总览

| 路由 | 作用 | 最少必填字段 |
| --- | --- | --- |
| `POST /api/analyze` | 单条或多条 CVE 分析 | `target_version` + `cve_id` 或 `cves` / `cve_ids` |
| `POST /api/analyzer` | `analyze` 兼容别名 | 同上 |
| `POST /api/validate` | 单条真值验证 | `target_version` + `cve_id` + `known_fix` |
| `POST /api/batch-validate` | 批量真值验证 | `target_version` + `items[]` |
| `GET /health` | 存活检查 | 无 |

### 8.3 最小请求模板

#### `/api/analyze`

```json
{
  "target_version": "5.10-hulk",
  "cve_id": "CVE-2024-26633",
  "deep": false
}
```

#### `/api/validate`

```json
{
  "target_version": "5.10-hulk",
  "cve_id": "CVE-2024-26633",
  "known_fix": "da23bd709b46",
  "mainline_fix": "d375b98e0248",
  "mainline_intro": "fbfa743a9d2a"
}
```

#### `/api/batch-validate`

```json
{
  "target_version": "5.10-hulk",
  "workers": 2,
  "items": [
    {
      "cve_id": "CVE-2024-26633",
      "known_fix": "da23bd709b46"
    }
  ]
}
```

README 里只保留最小字段视图：

| 路由 | 必填字段 | 可选字段 | 说明 |
| --- | --- | --- | --- |
| `POST /api/analyze` | `target_version` + `cve_id` | `deep`、`no_dryrun`、`enable_p2` / `disable_p2` | 支持 `cves` / `cve_ids` 批量 |
| `POST /api/validate` | `target_version` + `cve_id` + `known_fix` | `known_fixes`、`known_prereqs`、`mainline_fix`、`mainline_intro`、`deep`、`enable_p2` / `disable_p2` | `known_fix` 可是单个 commit 或逗号分隔字符串 |
| `POST /api/batch-validate` | `target_version` + `items[]` | `workers`、`deep`、`enable_p2` / `disable_p2` | `items[*]` 至少要有 `cve_id` + `known_fix` |

### 8.4 API 返回里先看什么

| 字段 | 作用 |
| --- | --- |
| `result_status` | 当前结果是否完整、是否报错、是否不适用 |
| `analysis_framework` | 过程 / 证据 / 结论骨架 |
| `intro_analysis` | introduced commit 缺失或检测时的受影响判断证据，包含策略、置信度、文件覆盖率和 removed/added 行命中率 |
| `l0_l5` | `base_level`、`current_level`、`review_mode` |
| `analysis_narrative` | 面向人的过程说明 |
| `traceability` | 规则 profile、目标仓 HEAD、数据源等追溯信息 |

推荐对接顺序：

| 场景 | 先看哪些字段 |
| --- | --- |
| 单条分析 | `results[0].l0_l5 -> results[0].result_status -> results[0].analysis_framework.conclusion` |
| 单条验证 | `l0_l5 -> result_status -> generated_vs_real -> summary` |
| 批量验证 | `summary.l0_l5 -> summary.strategy_effectiveness -> summary.level_accuracy -> results[*].l0_l5` |

详细请求模板、完整响应示例、错误码和必要字段约束请直接看 [API 合同](docs/API_CONTRACT.md) 和 [输出 Schema 手册](docs/OUTPUT_SCHEMA.md)。

---

## 9. 策略风格参数

CLI 当前主推两种用户可见风格，通过 `--policy-profile` 指定。它只影响当前命令，优先级高于 `config.yaml` 里的 `policy.profile`。

| 风格 | 参数 | 大改动阈值 | 大 hunk 阈值 | 调用链 fanout 阈值 | 适合场景 |
| --- | --- | --- | --- | --- | --- |
| 保守风格 | `--policy-profile conservative` | `40` 行 | `4` | `4` | 发布前、敏感子系统、安全优先 |
| 平衡风格 | `--policy-profile balanced` | `80` 行 | `8` | `6` | 日常分析、常规批量验证 |

示例：

```bash
python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk --policy-profile conservative
python cli.py batch-validate --file cve_data.json --target 5.10-hulk --workers 2 --policy-profile balanced
```

---

## 10. 哪些功能会用到 LLM

项目的核心判定链路默认是确定性的。LLM 只负责增强或兜底。

| 功能 | 是否依赖 LLM 才能运行 | 没有 LLM 时会怎样 |
| --- | --- | --- |
| 搜索、依赖、DryRun、分级、validate、batch-validate | 否 | 正常运行 |
| 社区讨论摘要 | 否 | 只保留确定性抓取结果 |
| 漏洞深度分析 | 否 | 输出确定性规则版 |
| 补丁逻辑检视 | 否 | 输出确定性审查项 |
| 风险收益评估 | 否 | 输出确定性评分与说明 |
| 合入建议 | 否 | 输出确定性建议 |
| validate 差异解释 | 否 | 不再生成 LLM 差异总结 |
| AI 兜底补丁生成 | 是 | 不进入 AI-generated 路径 |

一句话总结：

- **核心判断不依赖 LLM**
- **LLM 主要用于增强解释和 AI 兜底补丁生成**

---

## 11. 哪些场景准确率高

这里只讲当前实现里证据最强的场景：

| 场景 | 为什么证据强 | 应看字段 |
| --- | --- | --- |
| 搜索命中精确 ID | 不依赖模糊启发式 | 搜索策略 `L1` |
| `Strict` 直接通过 | 原始补丁文本与目标仓高度一致 | `dryrun_detail.apply_method` |
| `Context-C1/Whitespace` 通过且无风险规则命中 | 差异主要限于上下文或空白 | `apply_method` + `rule_hits` |
| validate 中 `verdict = identical` | 工具补丁与真实修复完全一致 | `generated_vs_real.verdict` |
| validate 中 `deterministic_exact_match = true` | 工具补丁与真实修复逐字等价 | `generated_vs_real.deterministic_exact_match` |
| batch 中某个策略家族 `acceptable_patch_rate` 高 | 说明该策略家族在当前样本集里稳定产生可接受补丁 | `summary.strategy_effectiveness` |

不应被解释成“高准确率自动化”的场景：

| 场景 | 原因 |
| --- | --- |
| `3way` | 合并成功不等于语义安全 |
| `conflict-adapted` | 已进入冲突重写 |
| `AI-Generated` | 兜底路径，不是高置信主路径 |
| `L3/L4/L5` | 风险或不确定性已经显著抬高 |

---

## 12. 输出目录与产物

默认输出目录是 `analysis_results/<run-id>/...`。

| 模式 | 典型输出 |
| --- | --- |
| `analyze` | `report.json`、适配补丁、分析叙述 |
| `validate` | `report.json`、`community.patch`、`real_fix.patch`、`adapted.patch` |
| `batch-validate` | 批量汇总 JSON、每个 CVE 的 case 目录、策略/分级统计 |
| `--deep` | 额外的 `deep_report.json` 与深度分析结构 |

---

## 13. 建议阅读顺序

| 如果你想知道 | 去哪里 |
| --- | --- |
| 系统整体怎么用 | [README_zh.md](README_zh.md) |
| 系统架构、数据流、TUI、验证框架 | [docs/TECHNICAL.md](docs/TECHNICAL.md) |
| DryRun 具体怎么尝试、怎么适配 | [docs/ADAPTIVE_DRYRUN.md](docs/ADAPTIVE_DRYRUN.md) |
| `L0-L5`、核心算法、调用链、LLM 使用边界、准确率高场景 | [docs/MULTI_LEVEL_ALGORITHM.md](docs/MULTI_LEVEL_ALGORITHM.md) |
| API 请求/响应合同、错误返回、必要字段 | [docs/API_CONTRACT.md](docs/API_CONTRACT.md) |
| 输出字段字典、batch summary、错误结构 | [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md) |
| 规则手册、level floor、误判边界 | [docs/RULEBOOK.md](docs/RULEBOOK.md) |
| 不适用场景、系统边界、人工接管建议 | [docs/BOUNDARIES.md](docs/BOUNDARIES.md) |
| 对外汇报怎么讲 | [docs/presentation.md](docs/presentation.md) |
