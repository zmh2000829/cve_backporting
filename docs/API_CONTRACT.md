# HTTP API 合同

本文只负责说明 HTTP API 如何对接，包括请求字段、响应字段、必要输出、错误返回和对接约束。

如果你想看系统架构和 TUI，请看 `docs/TECHNICAL.md`；如果你想看字段字典，请看 `docs/OUTPUT_SCHEMA.md`。

---

## 1. 路由总览

| 方法 | 路由 | 作用 | 最小必填 |
| --- | --- | --- | --- |
| `GET` | `/health` | 健康检查 | 无 |
| `POST` | `/api/analyze` | 单条或多条 CVE 分析 | `target_version` + `cve_id` 或 `cves` / `cve_ids` |
| `POST` | `/api/analyzer` | `analyze` 兼容别名 | 同上 |
| `POST` | `/api/validate` | 单条真值验证 | `target_version` + `cve_id` + `known_fix` |
| `POST` | `/api/batch-validate` | 批量真值验证 | `target_version` + `items[]` |

---

## 2. 通用请求约束

| 项目 | 当前口径 |
| --- | --- |
| 目标仓字段 | 统一接受 `target_version`，兼容 `target`、`repo` |
| CVE 字段 | 单条用 `cve_id`，批量也兼容 `cves`、`cve_ids` |
| P2 风险规则开关 | 接受 `enable_p2` / `disable_p2` |
| 深度分析 | `deep=true` 时追加 community / vuln analysis / patch review / risk benefit / merge advisor |
| AI 增强 | 当前由服务端 `config.yaml` 控制；API 请求暂不直接传密钥、endpoint 或 `ai.mode` |
| 策略风格 | API 当前不直接暴露 `policy-profile` 字符串；按配置文件和开关行为运行 |

---

## 3. `POST /api/analyze`

### 3.1 请求字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `target_version` / `target` / `repo` | 是 | 目标仓别名 |
| `cve_id` | 单条时是 | 单条 CVE |
| `cves` / `cve_ids` | 批量时是 | 多条 CVE 列表 |
| `deep` | 否 | 是否追加深度分析 |
| `no_dryrun` | 否 | 是否跳过 DryRun |
| `enable_p2` / `disable_p2` | 否 | 是否启用专项高风险规则 |

### 3.2 最小请求模板

```json
{
  "target_version": "5.10-hulk",
  "cve_id": "CVE-2024-26633",
  "deep": false
}
```

### 3.3 最小响应模板

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

---

## 4. `POST /api/validate`

### 4.1 请求字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `target_version` | 是 | 目标仓别名 |
| `cve_id` | 是 | CVE 编号 |
| `known_fix` / `known_fixes` | 是 | 已知真实修复 commit |
| `known_prereqs` | 否 | 已知前置依赖 commit 列表 |
| `mainline_fix` | 否 | 显式指定上游 fix commit |
| `mainline_intro` | 否 | 显式指定上游 introduced commit |
| `deep` | 否 | 是否追加深度分析 |
| `enable_p2` / `disable_p2` | 否 | 是否启用专项高风险规则 |

如果未传 `mainline_intro`，且上游 CVE 也没有 introduced commit，服务端按配置文件中的 `analysis.missing_intro_policy` 处理。默认 `patch_probe` 会使用 fix patch 的 removed/added 行探测目标代码形态，并把证据写入响应的 `intro_analysis`。

### 4.2 最小请求模板

```json
{
  "target_version": "5.10-hulk",
  "cve_id": "CVE-2024-26633",
  "known_fix": "da23bd709b46",
  "mainline_fix": "d375b98e0248",
  "mainline_intro": "fbfa743a9d2a"
}
```

### 4.3 最小响应模板

```json
{
  "cve_id": "CVE-2024-26633",
  "target_version": "5.10-hulk",
  "overall_pass": true,
  "summary": "验证完成",
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

---

## 5. `POST /api/batch-validate`

### 5.1 请求字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `target_version` | 是 | 目标仓别名 |
| `items[]` | 是 | 每项至少包含 `cve_id` 和 `known_fix` |
| `workers` | 否 | 并发数；`deep=true` 时会压到 `<= 2` |
| `deep` | 否 | 是否追加深度分析 |
| `enable_p2` / `disable_p2` | 否 | 是否启用专项高风险规则 |

### 5.2 单项 `items[*]` 模板

```json
{
  "cve_id": "CVE-2024-26633",
  "known_fix": "da23bd709b46",
  "known_prereqs": [],
  "mainline_fix": "d375b98e0248",
  "mainline_intro": "fbfa743a9d2a"
}
```

### 5.3 最小请求模板

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

### 5.4 最小响应模板

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
    "strategy_effectiveness": {},
    "level_accuracy": {},
    "risk_hit_summary": {}
  }
}
```

---

## 6. 必要输出字段

### 6.1 单案例结果

| 字段 | 是否必须 | 说明 |
| --- | --- | --- |
| `result_status` | 是 | 当前结果状态，不允许靠空字段猜测 |
| `analysis_framework` | 是 | 过程 / 证据 / 结论骨架 |
| `intro_analysis` | 建议 | introduced commit 缺失或检测时的受影响判断证据；`missing_intro_patch_probe` 表示基于 fix patch 代码形态探测，不等于找到了真实 intro commit |
| `l0_l5.current_level` | 是 | 最终执行通道 |
| `l0_l5.base_level` | 是 | DryRun 基线级别 |
| `validation_details.ai_evidence` | 可选 | GLM5/LLM advisory task 输出；未启用 AI 时为空 |
| `dryrun_detail.ai_evidence` | 可选 | AI patch suggestion 的生成与 apply-check 证据 |
| `traceability` | 是 | 规则 profile、schema 版本、目标仓追溯 |

### 6.2 批量汇总

| 字段 | 是否必须 | 说明 |
| --- | --- | --- |
| `summary.l0_l5` | 是 | `L0-L5` 分布主视图 |
| `summary.level_distribution` | 兼容层建议保留 | 便于旧调用方继续读取 |
| `summary.strategy_effectiveness` | 是 | DryRun 家族数量、占比、通过率、补丁准确率 |
| `summary.level_accuracy` | 是 | 每个 `L0-L5` 的通过率和补丁准确率 |
| `summary.risk_hit_summary` | 是 | 特殊风险命中统计 |

最硬的一条约束：

| 对接要求 | 当前口径 |
| --- | --- |
| `L0-L5` 是否必须输出 | **是。所有单案例结果必须有 `l0_l5.current_level` 和 `l0_l5.base_level`；所有 batch summary 必须有 `summary.l0_l5`。缺失应视为无效集成。** |

---

## 7. 错误返回

### 7.1 HTTP 错误体

```json
{
  "ok": false,
  "status_code": 400,
  "error": {
    "state": "error",
    "error_code": "invalid_request",
    "user_message": "missing cve_id",
    "technical_detail": "missing cve_id",
    "retryable": false,
    "route": "/api/validate",
    "missing_input": ["cve_id"],
    "hint": "请补充必要字段后重试",
    "suggested_fix": {
      "target_version": "5.10-hulk",
      "cve_id": "CVE-2024-26633"
    },
    "absolute_date": "2026-04-09"
  }
}
```

### 7.2 常见错误码

| 错误码 | 场景 |
| --- | --- |
| `invalid_request` | 请求字段缺失或格式错误 |
| `already_fixed` | analyze 判断目标仓已包含修复 |
| `not_vulnerable` | analyze 判断目标仓无稳定漏洞引入证据 |
| `missing_fix_patch` | 缺少上游 fix patch 信息 |
| `missing_decision_skeleton` | 过程执行过，但未形成稳定结论骨架 |
| `validation_incomplete` | validate 链路未形成稳定解释 |
| `validation_mismatch` | validate 执行完成，但工具结果与真值存在偏差 |

---

## 8. 推荐读取顺序

| 场景 | 先读什么 |
| --- | --- |
| 单条 analyze | `results[0].l0_l5 -> results[0].result_status -> results[0].analysis_framework.conclusion` |
| 单条 validate | `l0_l5 -> result_status -> generated_vs_real -> summary` |
| batch-validate | `summary.l0_l5 -> summary.strategy_effectiveness -> summary.level_accuracy -> results[*].l0_l5` |
