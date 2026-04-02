#!/usr/bin/env python3
"""HTTP API 网关：将 analyze / validate / batch-validate 映射为 URL 接口。"""

import copy
import json
import logging
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict

from core.config import ConfigLoader
from core.git_manager import GitRepoManager
from core.models import CveInfo
from core.output_serializers import (
    aggregate_batch_validate_summary,
    aggregate_l0_l5_levels,
    build_l0_l5_view,
)
from core.report_schema import make_result_status

import cli

logger = logging.getLogger("cve_api")

AnalyzeHandler = Callable[[Dict[str, Any], object], Dict[str, Any]]

POST_ROUTES = {
    "/api/analyze",
    "/api/analyzer",
    "/api/validate",
    "/api/batch-validate",
}


def _coerce_target(payload: Dict[str, Any]) -> str:
    if not payload:
        return ""
    return (payload.get("target_version")
            or payload.get("target")
            or payload.get("repo")).strip()


def _coerce_cve_list(payload: Dict[str, Any]) -> list:
    cves = []
    if payload.get("cve_id"):
        cves.append(payload["cve_id"])
    if isinstance(payload.get("cves"), list):
        cves.extend([str(v).strip() for v in payload["cves"] if str(v).strip()])
    if isinstance(payload.get("cve_ids"), list):
        cves.extend([str(v).strip() for v in payload["cve_ids"] if str(v).strip()])
    return cves


def _coerce_prereqs(payload: Dict[str, Any]) -> list:
    raw = payload.get("known_prereqs", [])
    if isinstance(raw, str):
        return cli._coerce_commit_list(raw)
    if isinstance(raw, list):
        return cli._coerce_commit_list(raw)
    return []


def _coerce_workers(payload: Dict[str, Any], deep: bool = False) -> int:
    try:
        workers = int(payload.get("workers", 1) or 1)
    except Exception:
        workers = 1
    workers = max(1, min(workers, 4))
    if deep and workers > 2:
        workers = 2
    return workers


def _build_mainline_cve_info(payload: Dict[str, Any], cve_id: str) -> CveInfo:
    mainline_fix = (payload.get("mainline_fix") or "").strip()
    mainline_intro = (payload.get("mainline_intro") or "").strip()
    if not mainline_fix:
        return None

    fix_commits = [{"commit_id": mainline_fix, "subject": ""}]
    intro_commits = ([{"commit_id": mainline_intro, "subject": ""}]
                     if mainline_intro else [])
    return CveInfo(
        cve_id=cve_id,
        fix_commits=fix_commits,
        mainline_fix_commit=mainline_fix,
        introduced_commits=intro_commits,
    )


def _config_with_request_overrides(config, payload: Dict[str, Any]):
    cfg = copy.deepcopy(config)
    if not getattr(cfg, "policy", None):
        return cfg

    p2_enabled = payload.get("p2_enabled")
    if p2_enabled is None and "enable_p2" in payload:
        p2_enabled = bool(payload.get("enable_p2"))
    if p2_enabled is None and payload.get("disable_p2") is True:
        p2_enabled = False
    if p2_enabled is not None:
        cfg.policy.special_risk_rules_enabled = bool(p2_enabled)
    return cfg


def _default_analyze_handler(payload: Dict[str, Any], config):
    cfg = _config_with_request_overrides(config, payload)
    target = _coerce_target(payload)
    if not target:
        raise ValueError("missing target_version")

    cves = _coerce_cve_list(payload)
    if not cves:
        raise ValueError("missing cve_id / cves / cve_ids")

    deep = bool(payload.get("deep", False))
    enable_dryrun = not bool(payload.get("no_dryrun", False))
    results = []
    for cve_id in cves:
        results.append(
            cli.run_analyze_payload(
                cve_id,
                target_version=target,
                config=cfg,
                enable_dryrun=enable_dryrun,
                deep=deep,
            )
        )

    return {
        "ok": True,
        "operation": "analyze",
        "p2_enabled": bool(getattr(cfg.policy, "special_risk_rules_enabled", True)) if getattr(cfg, "policy", None) else True,
        "results": results,
        "summary": {
            "total": len(results),
        },
    }


def _default_validate_handler(payload: Dict[str, Any], config):
    cfg = _config_with_request_overrides(config, payload)
    target = _coerce_target(payload)
    if not target:
        raise ValueError("missing target_version")
    cve_id = (payload.get("cve_id") or "").strip()
    if not cve_id:
        raise ValueError("missing cve_id")
    known_fix = (payload.get("known_fix") or "").strip()
    if not known_fix:
        raise ValueError("missing known_fix")

    known_prereqs = _coerce_prereqs(payload)
    deep = bool(payload.get("deep", False))

    cve_info = _build_mainline_cve_info(payload, cve_id)

    result = cli._run_single_validate(
        cfg, cve_id, target, known_fix, known_prereqs,
        show_stages=False, cve_info=cve_info, deep=deep)
    result["l0_l5"] = build_l0_l5_view(result)
    result["p2_enabled"] = bool(getattr(cfg.policy, "special_risk_rules_enabled", True)) if getattr(cfg, "policy", None) else True
    return result


def _default_batch_validate_handler(payload: Dict[str, Any], config):
    cfg = _config_with_request_overrides(config, payload)
    target = _coerce_target(payload)
    if not target:
        raise ValueError("missing target_version")
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        raise ValueError("missing items")

    deep = bool(payload.get("deep", False))
    workers = _coerce_workers(payload, deep=deep)
    git_mgr = cli._make_git_mgr(cfg, target) if workers == 1 else None
    results = []
    errors = []

    def _run_item(idx, item):
        if not isinstance(item, dict):
            return {"index": idx, "error": {"index": idx, "reason": "invalid item"}}
        cve_id = (item.get("cve_id") or "").strip()
        known_fix = (item.get("known_fix") or "").strip()
        if not cve_id or not known_fix:
            return {"index": idx, "error": {"index": idx, "cve_id": cve_id, "reason": "missing cve_id or known_fix"}}

        known_prereqs = cli._coerce_commit_list(item.get("known_prereqs", []))
        cve_info = None
        mainline_fix = (item.get("mainline_fix") or "").strip()
        if mainline_fix:
            intro = (item.get("mainline_intro") or "").strip()
            cve_info = CveInfo(
                cve_id=cve_id,
                fix_commits=[{"commit_id": mainline_fix, "subject": ""}],
                mainline_fix_commit=mainline_fix,
                introduced_commits=[{"commit_id": intro, "subject": ""}] if intro else [],
            )

        local_git_mgr = git_mgr if git_mgr is not None else GitRepoManager(cfg.repositories, use_cache=False)
        result = cli._run_single_validate(
            cfg, cve_id, target, known_fix, known_prereqs,
            git_mgr=local_git_mgr, show_stages=False, cve_info=cve_info,
            deep=deep,
        )
        result["l0_l5"] = build_l0_l5_view(result)
        return {"index": idx, "result": result}

    if workers == 1:
        for idx, item in enumerate(items, 1):
            try:
                out = _run_item(idx, item)
                if out.get("error"):
                    errors.append(out["error"])
                else:
                    results.append(out["result"])
            except Exception as exc:
                cve_id = item.get("cve_id") if isinstance(item, dict) else ""
                logger.exception("batch validate item failed: %s %s", cve_id, exc)
                errors.append({"index": idx, "cve_id": cve_id, "reason": str(exc)})
    else:
        ordered = {}
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="api-batch-validate") as executor:
            future_map = {
                executor.submit(_run_item, idx, item): (idx, item)
                for idx, item in enumerate(items, 1)
            }
            for future in as_completed(future_map):
                idx, item = future_map[future]
                try:
                    out = future.result()
                    if out.get("error"):
                        errors.append(out["error"])
                    else:
                        ordered[idx] = out["result"]
                except Exception as exc:
                    cve_id = item.get("cve_id") if isinstance(item, dict) else ""
                    logger.exception("batch validate item failed: %s %s", cve_id, exc)
                    errors.append({"index": idx, "cve_id": cve_id, "reason": str(exc)})
        results = [ordered[idx] for idx in sorted(ordered)]

    l0_l5_summary = aggregate_l0_l5_levels(results)
    batch_summary = aggregate_batch_validate_summary([
        cli._prepare_validate_json(result) for result in results
    ])
    return {
        "ok": True,
        "operation": "batch-validate",
        "p2_enabled": bool(getattr(cfg.policy, "special_risk_rules_enabled", True)) if getattr(cfg, "policy", None) else True,
        "workers": workers,
        "parallel_mode": workers > 1,
        "results": results,
        "errors": errors,
        "summary": {
            "total": len(results) + len(errors),
            "success": len(results),
            "error": len(errors),
            "statistics": batch_summary.get("statistics", {}),
            "level_distribution": batch_summary.get("level_distribution", {
                "levels": l0_l5_summary.get("levels", ["L0", "L1", "L2", "L3", "L4", "L5"]),
                "final_level_counts": l0_l5_summary.get("current_level_distribution", {}),
                "base_level_counts": l0_l5_summary.get("base_level_distribution", {}),
            }),
            "risk_hit_summary": batch_summary.get("risk_hit_summary", {
                "any_special_risk": {
                    "count": (batch_summary.get("special_risk") or {}).get("any_special_risk_count", 0),
                },
                "critical_structure_change": batch_summary.get("critical_structure_change", {}),
                "special_risk_section_counts": (batch_summary.get("special_risk") or {}).get("section_counts", {}),
            }),
            "manual_prerequisite_analysis": batch_summary.get("manual_prerequisite_analysis", {}),
            "verdict_distribution": batch_summary.get("verdict_distribution", {}),
        },
        "l0_l5_summary": l0_l5_summary,
        "batch_summary": batch_summary,
    }


ANALYZE_HANDLER: AnalyzeHandler = _default_analyze_handler
VALIDATE_HANDLER: AnalyzeHandler = _default_validate_handler
BATCH_VALIDATE_HANDLER: AnalyzeHandler = _default_batch_validate_handler


def _json_response(status_code: int, body: Dict[str, Any]) -> bytes:
    payload = json.dumps(body, ensure_ascii=False, indent=2)
    return payload.encode("utf-8")


def _error_body(error_code: str, user_message: str, *, technical_detail: str = "", retryable: bool = False, status_code: int = None) -> Dict[str, Any]:
    body = {
        "ok": False,
        "error": make_result_status(
            state="error",
            error_code=error_code,
            user_message=user_message,
            technical_detail=technical_detail or user_message,
            retryable=retryable,
        ),
    }
    if status_code is not None:
        body["status_code"] = status_code
    return body


class APIRequestHandler(BaseHTTPRequestHandler):
    server_version = "cve-api/1.0"

    def _send_json(self, status_code: int, body: Dict[str, Any]):
        data = _json_response(status_code, body)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"invalid json: {exc}") from exc

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"ok": True, "service": "cve-backporting-api"})
            return
        if self.path == "/":
            self._send_json(200, {
                "ok": True,
                "service": "cve-backporting-api",
                "routes": sorted(POST_ROUTES | {"GET /health"}),
            })
            return
        self._send_json(404, _error_body("not_found", "路由不存在。", technical_detail=self.path, status_code=404))

    def do_POST(self):
        route = self.path.split("?", 1)[0]
        if route not in POST_ROUTES:
            self._send_json(404, _error_body("not_found", "路由不存在。", technical_detail=route, status_code=404))
            return

        try:
            payload = self._read_json()
        except ValueError as exc:
            self._send_json(400, _error_body("invalid_json", "请求体不是合法 JSON。", technical_detail=str(exc), status_code=400))
            return

        try:
            cfg = self.server.config
            if route == "/api/analyzer":
                result = ANALYZE_HANDLER(payload, cfg)
            elif route == "/api/analyze":
                result = ANALYZE_HANDLER(payload, cfg)
            elif route == "/api/validate":
                result = VALIDATE_HANDLER(payload, cfg)
            else:
                result = BATCH_VALIDATE_HANDLER(payload, cfg)
        except ValueError as exc:
            self._send_json(400, _error_body("invalid_request", str(exc), technical_detail=str(exc), status_code=400))
            return
        except Exception as exc:
            logger.exception("request failed route=%s", route)
            self._send_json(500, _error_body(
                "internal_error",
                "请求处理失败。",
                technical_detail=f"{exc}\n{traceback.format_exc()}",
                retryable=True,
                status_code=500,
            ))
            return

        self._send_json(200, {"ok": True, "data": result})


def create_api_server(host: str, port: int, config_path: str = "config.yaml"):
    cfg = ConfigLoader.load(config_path)

    class _Server(ThreadingHTTPServer):
        allow_reuse_address = True

    httpd = _Server((host, port), APIRequestHandler)
    httpd.config = cfg
    return httpd


def run_api_server(host: str, port: int, config_path: str = "config.yaml"):
    httpd = create_api_server(host, port, config_path=config_path)
    httpd.serve_forever()
