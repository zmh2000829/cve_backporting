# API 接口测试报告（UT）

日期：2026-03-24

## 变更目标

本次验证覆盖“服务化接口”能力（`server` CLI + URL API），确保：

1. `analyze / analyzer`、`validate`、`batch-validate` 可通过 HTTP 调用。
2. 返回内容包含结构化信息（包括规则信息、阶段信息、补丁关联信息）。
3. 异常输入返回明确错误码与错误信息（400 / 404）。

## 测试环境

- Python：3.x（项目默认环境）
- 测试方式：`unittest` + 本地 `ThreadingHTTPServer`
- 运行命令：
  - `python -m unittest tests.test_api_server`

## 覆盖范围

- `api_server.py`
  - 路由分发
  - 参数校验
  - 错误处理
  - handler 注入/替换（通过 mock，避免真实仓库依赖）
- `cli.py`
  - `server` 子命令启动
  - 返回体包含 URL/API 兼容字段（依赖现有 `run_analyze_payload` 与 `_run_single_validate` 结构）

## 测试用例

| 用例ID | Endpoint | Method | 场景 | 预期 | 实测 |
|---|---|---|---|---|---|
| TC-01 | `/api/analyzer` | POST | 标准 analyze 请求（别名） | 200，返回 `ok=true` 与 `results` | PASS |
| TC-02 | `/api/analyze` | POST | 标准 analyze 请求 | 200，返回 `ok=true` 与 `results` | PASS |
| TC-03 | `/api/validate` | POST | 标准 validate 请求 | 200，返回 `ok=true` 与校验结果 | PASS |
| TC-04 | `/api/batch-validate` | POST | 标准 batch 请求 | 200，返回 `ok=true` 与结果列表 | PASS |
| TC-05 | `/health` | GET | 健康检查 | 200，`service` 可用 | PASS |
| TC-06 | `/api/analyze` | POST | 缺失 `cve_id` | 400，返回 `missing cve_id / cves / cve_ids` | PASS |
| TC-07 | `/api/validate` | POST | 缺失 `cve_id` | 400，返回 `missing cve_id` | PASS |
| TC-08 | `/api/batch-validate` | POST | 缺失 `items` | 400，返回 `missing items` | PASS |
| TC-09 | `/api/analyze` | POST | 非法 JSON | 400，`invalid json` | PASS |
| TC-10 | `/api/unknown` | POST | 未定义路由 | 404 | PASS |

## 备注

- 依赖 heavy 逻辑（真实仓库分析）尚未在该套件中直接执行，测试通过 mock 注入 `cli` 层函数，以隔离外部 Git 仓库变量。
- 该报告关注“接口契约”与“路由/错误语义”的回归。真实端到端算法回归仍保留原有 `tests/test_agents.py` 与 `tests/test_policy_engine.py` 机制。

## 结论

本次 API 接口测试通过率：`10/10（100%）`。  
服务路由和关键参数校验行为可用，`server` CLI 与 URL 调用链路已就绪。
