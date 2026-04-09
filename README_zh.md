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

---

## 3. 文档怎么分工

这次文档已经拆分，不再把所有内容塞进一处：

| 文档 | 负责什么 | 适合谁看 |
| --- | --- | --- |
| `README_zh.md` | 总体介绍、安装配置、CLI/TUI/API 使用方法、文档导航 | 第一次接触项目的人 |
| `docs/TECHNICAL.md` | 系统架构、代码模块、数据流、输出 schema、API/TUI 技术说明 | 开发者、维护者 |
| `docs/ADAPTIVE_DRYRUN.md` | DryRun 策略家族、适配顺序、冲突适配、输出口径 | 关注补丁适配的人 |
| `docs/MULTI_LEVEL_ALGORITHM.md` | `L0-L5`、规则体系、调用链、LLM 使用边界、准确率高场景 | 关注策略与判定质量的人 |
| `docs/presentation.md` | 面向汇报的精简版总览 | 评审、管理层、汇报场景 |

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

程序对接时，应以 JSON 文件为准。最小读取模板如下。

#### `analyze` 的 `report.json`

```json
{
  "cve_id": "CVE-2024-26633",
  "target_version": "5.10-hulk",
  "result_status": {
    "state": "complete"
  },
  "analysis_framework": {
    "process": {},
    "evidence": {},
    "conclusion": {}
  },
  "l0_l5": {
    "current_level": "L2",
    "base_level": "L1",
    "base_method": "context-C1",
    "review_mode": "controlled-review",
    "next_action": "逐 hunk 审查后决定是否回移"
  },
  "traceability": {
    "policy": {
      "profile": "balanced"
    }
  }
}
```

#### `validate` 的 `report.json`

```json
{
  "cve_id": "CVE-2024-26633",
  "target_version": "5.10-hulk",
  "overall_pass": true,
  "result_status": {
    "state": "complete"
  },
  "analysis_framework": {
    "process": {},
    "evidence": {},
    "conclusion": {}
  },
  "l0_l5": {
    "current_level": "L1",
    "base_level": "L1",
    "base_method": "context-C1",
    "review_mode": "quick-review",
    "next_action": "快速人工复核"
  },
  "generated_vs_real": {
    "verdict": "identical",
    "deterministic_exact_match": true
  },
  "traceability": {
    "policy": {
      "profile": "balanced"
    }
  }
}
```

#### `batch-validate` 的 summary JSON

```json
{
  "summary": {
    "l0_l5": {
      "levels": ["L0", "L1", "L2", "L3", "L4", "L5"],
      "current_level_distribution": {
        "L0": 0,
        "L1": 5,
        "L2": 7,
        "L3": 15,
        "L4": 3,
        "L5": 0
      },
      "base_level_distribution": {
        "L0": 14,
        "L1": 8,
        "L2": 0,
        "L3": 8,
        "L4": 0,
        "L5": 0
      }
    },
    "strategy_effectiveness": {},
    "level_accuracy": {}
  }
}
```

这里最重要的约束只有一条：

| 对接要求 | 口径 |
| --- | --- |
| `L0-L5` 是否必须输出 | **是。单案例 JSON 必须包含 `l0_l5.current_level` 和 `l0_l5.base_level`；批量 summary 必须包含 `summary.l0_l5` 分布。缺失应视为对接不完整。** |

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

如需直接按字段对接，而不是照抄示例，可以按下面这张表准备请求体：

| 路由 | 必填字段 | 可选字段 | 说明 |
| --- | --- | --- | --- |
| `POST /api/analyze` | `target_version` + `cve_id` | `deep`、`no_dryrun`、`enable_p2` / `disable_p2` | 支持 `cves` / `cve_ids` 批量 |
| `POST /api/validate` | `target_version` + `cve_id` + `known_fix` | `known_fixes`、`known_prereqs`、`mainline_fix`、`mainline_intro`、`deep`、`enable_p2` / `disable_p2` | `known_fix` 可是单个 commit 或逗号分隔字符串 |
| `POST /api/batch-validate` | `target_version` + `items[]` | `workers`、`deep`、`enable_p2` / `disable_p2` | `items[*]` 至少要有 `cve_id` + `known_fix` |

### 8.4 返回模板与必要字段

先说明一个对接约束：

| 约束 | 当前口径 |
| --- | --- |
| 单案例结果必要字段 | `result_status`、`analysis_framework`、`l0_l5`、`traceability` |
| `L0-L5` 是否必须输出 | **是。所有单案例结果都必须有 `l0_l5.current_level` 和 `l0_l5.base_level`；缺失应视为无效集成。** |
| 批量统计必要字段 | `summary.l0_l5`、`summary.level_distribution`、`summary.risk_hit_summary`，以及报告文件里的 `strategy_effectiveness`、`level_accuracy` |

其中 `l0_l5` 建议按下面这组字段读取：

| 字段 | 是否必须 | 作用 |
| --- | --- | --- |
| `l0_l5.current_level` | 是 | 最终执行通道，平台分流时优先看它 |
| `l0_l5.base_level` | 是 | DryRun 基线级别，解释“补丁是怎么落地的” |
| `l0_l5.base_method` | 强烈建议 | 对应 `strict / 3way / regenerated ...` |
| `l0_l5.review_mode` | 强烈建议 | 终端、平台 UI 都适合直接展示 |
| `l0_l5.next_action` | 强烈建议 | 可直接映射到人工流程 |

#### `/api/analyze` 返回模板

```json
{
  "ok": true,
  "operation": "analyze",
  "p2_enabled": true,
  "summary": {
    "total": 1
  },
  "results": [
    {
      "cve_id": "CVE-2024-26633",
      "target_version": "5.10-hulk",
      "result_status": {
        "state": "complete",
        "user_message": "分析完成"
      },
      "analysis_framework": {
        "process": {},
        "evidence": {},
        "conclusion": {}
      },
      "l0_l5": {
        "current_level": "L2",
        "base_level": "L1",
        "base_method": "context-C1",
        "review_mode": "controlled-review",
        "next_action": "逐 hunk 审查后决定是否回移"
      },
      "traceability": {
        "policy": {
          "profile": "balanced"
        }
      }
    }
  ]
}
```

#### `/api/validate` 返回模板

```json
{
  "cve_id": "CVE-2024-26633",
  "target_version": "5.10-hulk",
  "overall_pass": true,
  "summary": "验证通过",
  "result_status": {
    "state": "complete",
    "user_message": "验证完成"
  },
  "analysis_framework": {
    "process": {},
    "evidence": {},
    "conclusion": {}
  },
  "l0_l5": {
    "current_level": "L1",
    "base_level": "L1",
    "base_method": "context-C1",
    "review_mode": "quick-review",
    "next_action": "快速人工复核"
  },
  "generated_vs_real": {
    "verdict": "identical",
    "deterministic_exact_match": true
  },
  "traceability": {
    "policy": {
      "profile": "balanced"
    }
  }
}
```

#### `/api/batch-validate` 返回模板

```json
{
  "ok": true,
  "operation": "batch-validate",
  "workers": 2,
  "parallel_mode": true,
  "results": [
    {
      "cve_id": "CVE-2024-26633",
      "l0_l5": {
        "current_level": "L3",
        "base_level": "L2"
      },
      "overall_pass": true
    }
  ],
  "summary": {
    "total": 1,
    "success": 1,
    "error": 0,
    "l0_l5": {
      "levels": ["L0", "L1", "L2", "L3", "L4", "L5"],
      "current_level_distribution": {
        "L0": 0,
        "L1": 0,
        "L2": 0,
        "L3": 1,
        "L4": 0,
        "L5": 0
      },
      "base_level_distribution": {
        "L0": 0,
        "L1": 0,
        "L2": 1,
        "L3": 0,
        "L4": 0,
        "L5": 0
      }
    },
    "level_distribution": {
      "levels": ["L0", "L1", "L2", "L3", "L4", "L5"],
      "final_level_counts": {
        "L0": 0,
        "L1": 0,
        "L2": 0,
        "L3": 1,
        "L4": 0,
        "L5": 0
      },
      "base_level_counts": {
        "L0": 0,
        "L1": 0,
        "L2": 1,
        "L3": 0,
        "L4": 0,
        "L5": 0
      }
    },
    "strategy_effectiveness": {
      "counts": {
        "Strict": 0,
        "Context-C1/Whitespace": 0,
        "3-Way": 1,
        "Verified-Direct": 0,
        "Regenerated": 0,
        "Zero-Context": 0,
        "Conflict-Adapted": 0,
        "Unresolved": 0
      }
    },
    "level_accuracy": {
      "final_levels": {
        "L3": {
          "total": 1,
          "passed": 1,
          "acceptable_patch": 1,
          "exact_match": 0,
          "pass_rate": 1.0,
          "acceptable_patch_rate": 1.0,
          "exact_match_rate": 0.0
        }
      }
    },
    "risk_hit_summary": {
      "any_special_risk": {
        "count": 1
      }
    }
  }
}
```

### 8.5 API 返回里先看什么

| 字段 | 作用 |
| --- | --- |
| `result_status` | 当前结果是否完整、是否报错、是否不适用 |
| `analysis_framework` | 过程 / 证据 / 结论骨架 |
| `l0_l5` | `base_level`、`current_level`、`review_mode` |
| `analysis_narrative` | 面向人的过程说明 |
| `traceability` | 规则 profile、目标仓 HEAD、数据源等追溯信息 |

推荐对接顺序：

| 场景 | 先看哪些字段 |
| --- | --- |
| 单条分析 | `results[0].l0_l5 -> results[0].result_status -> results[0].analysis_framework.conclusion` |
| 单条验证 | `l0_l5 -> result_status -> generated_vs_real -> summary` |
| 批量验证 | `summary.l0_l5 -> summary.strategy_effectiveness -> summary.level_accuracy -> results[*].l0_l5` |

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
| 系统整体怎么用 | `README_zh.md` |
| 系统架构、TUI、API、输出 schema | `docs/TECHNICAL.md` |
| DryRun 具体怎么尝试、怎么适配 | `docs/ADAPTIVE_DRYRUN.md` |
| `L0-L5`、规则、调用链、LLM 使用边界、准确率高场景 | `docs/MULTI_LEVEL_ALGORITHM.md` |
| 对外汇报怎么讲 | `docs/presentation.md` |
