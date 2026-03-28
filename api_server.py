#!/usr/bin/env python3
"""HTTP API 网关：将 analyze / validate / batch-validate 映射为 URL 接口。"""

import copy
import json
import logging
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict

from core.config import ConfigLoader
from core.models import CveInfo
from core.output_serializers import (
    aggregate_batch_validate_summary,
    aggregate_l0_l5_levels,
    build_l0_l5_view,
)

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
    git_mgr = cli._make_git_mgr(cfg, target)
    results = []
    errors = []

    for idx, item in enumerate(items, 1):
        if not isinstance(item, dict):
            errors.append({"index": idx, "reason": "invalid item"})
            continue
        cve_id = (item.get("cve_id") or "").strip()
        known_fix = (item.get("known_fix") or "").strip()
        if not cve_id or not known_fix:
            errors.append({"index": idx, "cve_id": cve_id, "reason": "missing cve_id or known_fix"})
            continue

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

        try:
            result = cli._run_single_validate(
                cfg, cve_id, target, known_fix, known_prereqs,
                git_mgr=git_mgr, show_stages=False, cve_info=cve_info,
                deep=deep,
            )
            result["l0_l5"] = build_l0_l5_view(result)
            results.append(result)
        except Exception as exc:
            logger.exception("batch validate item failed: %s %s", cve_id, exc)
            errors.append({"index": idx, "cve_id": cve_id, "reason": str(exc)})

    l0_l5_summary = aggregate_l0_l5_levels(results)
    batch_summary = aggregate_batch_validate_summary([
        cli._prepare_validate_json(result) for result in results
    ])
    return {
        "ok": True,
        "operation": "batch-validate",
        "p2_enabled": bool(getattr(cfg.policy, "special_risk_rules_enabled", True)) if getattr(cfg, "policy", None) else True,
        "results": results,
        "errors": errors,
        "summary": {
            "total": len(results) + len(errors),
            "success": len(results),
            "error": len(errors),
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
        self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        route = self.path.split("?", 1)[0]
        if route not in POST_ROUTES:
            self._send_json(404, {"ok": False, "error": "not found"})
            return

        try:
            payload = self._read_json()
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
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
            self._send_json(400, {"ok": False, "error": str(exc)})
            return
        except Exception as exc:
            logger.exception("request failed route=%s", route)
            self._send_json(500, {"ok": False, "error": str(exc), "trace": traceback.format_exc()})
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
