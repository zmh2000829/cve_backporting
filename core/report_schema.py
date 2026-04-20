"""统一报告 schema、结果状态与回退解释骨架。"""

from typing import Any, Dict, List


REPORT_VERSION = "friendly-json-v2"
REPORT_SCHEMA_VERSION = "result-schema-v2"

_STAGE_LABELS = {
    "crawler_cve": "Crawler 获取 CVE 信息",
    "crawler_patch": "Crawler 获取修复补丁",
    "analysis_intro": "Analysis 搜索引入 commit",
    "analysis_fix": "Analysis 搜索修复 commit",
    "analysis_bp": "Analysis 检查 stable backport",
    "dependency": "Dependency 分析关联补丁",
    "dryrun": "DryRun 试应用",
    "community": "Community 收集社区讨论",
    "vuln_analysis": "VulnAnalysis 漏洞深度分析",
    "patch_review": "PatchReview 补丁逻辑检视",
    "risk_benefit": "RiskBenefit 风险收益评估",
    "merge_advice": "MergeAdvisor 合入建议",
}

_STAGE_STATUS_LABELS = {
    "success": "完成",
    "warn": "完成但有告警",
    "fail": "失败",
    "skip": "跳过",
}

_HIGH_RISK_APPLY_METHODS = {
    "regenerated",
    "conflict-adapted",
    "verified-direct",
}

_ATTENTION_APPLY_METHODS = {
    "context-C1",
    "C1-ignore-ws",
    "3way",
    "ignore-ws",
}


def dedupe_strings(items: List[Any]) -> List[str]:
    seen = set()
    out = []
    for item in items or []:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def dedupe_stage_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for event in events or []:
        if not isinstance(event, dict):
            continue
        key = (
            event.get("stage", ""),
            event.get("status", ""),
            str(event.get("detail", "")).strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(event))
    return out


def stage_events_to_workflow(events: List[Dict[str, Any]]) -> List[str]:
    steps = []
    for event in dedupe_stage_events(events):
        status = event.get("status", "")
        if status not in _STAGE_STATUS_LABELS:
            continue
        stage = event.get("stage", "")
        detail = str(event.get("detail", "")).strip()
        label = _STAGE_LABELS.get(stage, stage or "阶段")
        line = f"{label}: {_STAGE_STATUS_LABELS[status]}"
        if detail:
            line += f" ({detail})"
        steps.append(line)
    return dedupe_strings(steps)


def make_result_status(
    *,
    state: str,
    error_code: str = "",
    user_message: str = "",
    technical_detail: str = "",
    retryable: bool = False,
    incomplete_reason: str = "",
    evidence_refs: List[str] = None,
) -> Dict[str, Any]:
    return {
        "state": state or "complete",
        "error_code": error_code or "",
        "user_message": user_message or "",
        "technical_detail": technical_detail or "",
        "retryable": bool(retryable),
        "incomplete_reason": incomplete_reason or "",
        "evidence_refs": dedupe_strings(evidence_refs or []),
    }


def normalize_result_status(status: Dict[str, Any]) -> Dict[str, Any]:
    base = make_result_status(state="complete")
    if isinstance(status, dict):
        base.update({
            "state": str(status.get("state", base["state"]) or base["state"]),
            "error_code": str(status.get("error_code", "" ) or ""),
            "user_message": str(status.get("user_message", "") or ""),
            "technical_detail": str(status.get("technical_detail", "") or ""),
            "retryable": bool(status.get("retryable", False)),
            "incomplete_reason": str(status.get("incomplete_reason", "") or ""),
            "evidence_refs": dedupe_strings(status.get("evidence_refs", [])),
        })
    return base


def _infer_prereq_counts(payload: Dict[str, Any], *, validate_mode: bool = False) -> Dict[str, int]:
    counts = {"strong": 0, "medium": 0, "weak": 0, "total": 0}
    items = payload.get("prerequisite_patches") or []
    if not items and validate_mode:
        items = payload.get("tool_prereqs") or []

    for item in items:
        grade = ""
        if isinstance(item, dict):
            grade = str(item.get("grade", "")).strip()
        else:
            grade = str(getattr(item, "grade", "")).strip()
        if grade == "strong":
            counts["strong"] += 1
        elif grade == "medium":
            counts["medium"] += 1
        elif grade:
            counts["weak"] += 1
        elif validate_mode and items:
            counts["medium"] += 1
    counts["total"] = counts["strong"] + counts["medium"] + counts["weak"]
    return counts


def infer_result_status(payload: Dict[str, Any], mode: str) -> Dict[str, Any]:
    current = normalize_result_status(payload.get("result_status"))
    if current.get("user_message") or current.get("error_code"):
        return current

    cve_id = payload.get("cve_id", "")
    evidence = [cve_id] if cve_id else []
    if mode == "analyze":
        if payload.get("is_fixed"):
            commit_id = ""
            fix_detail = payload.get("fix_patch_detail") or {}
            if isinstance(fix_detail, dict):
                commit_id = fix_detail.get("commit_id", "")
            return make_result_status(
                state="not_applicable",
                error_code="already_fixed",
                user_message="目标仓库已包含修复，当前无需再回移该补丁。",
                technical_detail=f"analyze 结果显示 is_fixed=true；fix_commit={commit_id[:12] or 'unknown'}",
                evidence_refs=evidence + ([commit_id[:12]] if commit_id else []),
            )
        if payload.get("is_vulnerable") is False:
            return make_result_status(
                state="not_applicable",
                error_code="not_vulnerable",
                user_message="目标仓库没有稳定命中漏洞引入证据，当前补丁不适用。",
                technical_detail="introduced_search 未找到或显式判定 is_vulnerable=false",
                evidence_refs=evidence,
            )
        if not (payload.get("fix_patch_detail") or payload.get("analysis_framework")):
            return make_result_status(
                state="incomplete",
                error_code="missing_fix_patch",
                user_message="上游修复补丁信息不足，当前无法给出稳定结论。",
                technical_detail="缺少 fix_patch_detail 与 analysis_framework，通常意味着上游情报或补丁抓取不完整。",
                retryable=True,
                incomplete_reason="missing_fix_patch",
                evidence_refs=evidence,
            )
        if not payload.get("analysis_framework") and not payload.get("level_decision"):
            return make_result_status(
                state="incomplete",
                error_code="missing_decision_skeleton",
                user_message="分析已执行，但结论和证据之间没有形成稳定映射。",
                technical_detail="缺少 analysis_framework / level_decision，常见于 fixed 早返回或上游信息不完整。",
                retryable=True,
                incomplete_reason="missing_decision_skeleton",
                evidence_refs=evidence,
            )
        return make_result_status(
            state="complete",
            user_message="分析完成。",
            technical_detail="已形成可读的过程、证据和结论骨架。",
            evidence_refs=evidence,
        )

    summary = str(payload.get("summary", "") or "")
    if (
        payload.get("overall_pass") is False
        and not payload.get("analysis_framework")
        and not payload.get("level_decision")
        and not payload.get("issues")
        and not payload.get("dryrun_detail")
        and not payload.get("tool_prereqs")
        and not payload.get("summary")
    ):
        return make_result_status(
            state="incomplete",
            error_code="validation_incomplete",
            user_message=summary or "验证链路未产生稳定结论。",
            technical_detail="缺少 analysis_framework / level_decision，无法回答为什么这样判。",
            retryable=True,
            incomplete_reason="missing_validation_explanation",
            evidence_refs=evidence,
        )

    if payload.get("overall_pass") is False:
        return make_result_status(
            state="complete",
            error_code="validation_mismatch",
            user_message=summary or "验证未通过。",
            technical_detail="验证流程完成，但工具输出与已知修复存在偏差。",
            evidence_refs=evidence,
        )

    return make_result_status(
        state="complete",
        user_message=summary or "验证完成。",
        technical_detail="验证流程已完成。",
        evidence_refs=evidence,
    )


def _fallback_conclusion(payload: Dict[str, Any], mode: str, result_status: Dict[str, Any]) -> Dict[str, Any]:
    prereq_counts = _infer_prereq_counts(payload, validate_mode=(mode == "validate"))
    dryrun = payload.get("dryrun_detail") or {}
    apply_method = str(dryrun.get("apply_method", "") or "")
    issues = dedupe_strings(payload.get("issues", []))
    level_decision = payload.get("level_decision") or {}
    rule_hits = list(level_decision.get("rule_hits") or [])
    rule_classes = {hit.get("rule_class", "") for hit in rule_hits if isinstance(hit, dict)}
    low_drift_direct = (
        level_decision.get("level") == "L1"
        and level_decision.get("base_level") == "L1"
        and prereq_counts["total"] == 0
        and not issues
        and apply_method in _ATTENTION_APPLY_METHODS
        and not (rule_classes & {"low_level_veto", "direct_backport_veto", "risk_profile"})
    )

    if result_status["state"] == "not_applicable":
        return {
            "direct_backport": {
                "status": "not_applicable",
                "summary": result_status["user_message"],
            },
            "prerequisite": {
                "status": "not_applicable",
                "summary": "当前场景无需继续判断关联补丁。",
                "counts": prereq_counts,
            },
            "risk": {
                "status": "not_applicable",
                "summary": "当前场景不再进入回移执行阶段，风险评估仅作参考。",
            },
            "final": {
                "level": (payload.get("level_decision") or {}).get("level", ""),
                "base_level": (payload.get("level_decision") or {}).get("base_level", ""),
                "review_mode": (payload.get("level_decision") or {}).get("review_mode", ""),
                "next_action": "记录为已修复/不适用即可。",
                "harmless": (payload.get("level_decision") or {}).get("harmless"),
                "reason": result_status["technical_detail"] or result_status["user_message"],
            },
        }

    if result_status["state"] == "incomplete":
        return {
            "direct_backport": {
                "status": "insufficient_intel",
                "summary": "情报不足，暂时不能回答是否可直接回移。",
            },
            "prerequisite": {
                "status": "insufficient_intel",
                "summary": "情报不足，暂时不能稳定判断关联补丁。",
                "counts": prereq_counts,
            },
            "risk": {
                "status": "insufficient_intel",
                "summary": "情报不足，风险画像不完整。",
            },
            "final": {
                "level": (payload.get("level_decision") or {}).get("level", ""),
                "base_level": (payload.get("level_decision") or {}).get("base_level", ""),
                "review_mode": "needs-more-data",
                "next_action": "补充上游 fix / intro 信息后重试。",
                "harmless": False,
                "reason": result_status["technical_detail"] or result_status["user_message"],
            },
        }

    if prereq_counts["strong"]:
        prereq_status = "required"
        prereq_summary = f"发现 {prereq_counts['strong']} 个强依赖前置补丁，不能忽略关联补丁。"
        direct_status = "blocked"
        direct_summary = "存在强依赖前置补丁，当前不建议直接回移。"
    elif prereq_counts["medium"]:
        prereq_status = "recommended"
        prereq_summary = f"发现 {prereq_counts['medium']} 个中等依赖，建议一起核对关联补丁。"
        direct_status = "blocked" if mode == "validate" else "review"
        direct_summary = "补丁主体可读，但存在关联补丁信号，建议人工复核后再决定是否直接回移。"
    elif prereq_counts["weak"]:
        prereq_status = "weak_only"
        prereq_summary = f"仅发现 {prereq_counts['weak']} 个弱关联补丁，可按需复核。"
        direct_status = "review"
        direct_summary = "没有明显强依赖，但仍建议结合上下文做一次快速复核。"
    elif low_drift_direct:
        prereq_status = "independent"
        prereq_summary = "未发现必须优先处理的关联补丁。"
        direct_status = "direct"
        direct_summary = "当前仅见上下文/空白级别漂移，补丁可直接回移，建议保留最小编译与回归验证。"
    else:
        prereq_status = "independent"
        prereq_summary = "未发现必须优先处理的关联补丁。"
        direct_status = "review"
        direct_summary = "从现有证据看可按独立补丁评估，但仍需结合规则证据确认。"

    if issues or apply_method in _HIGH_RISK_APPLY_METHODS:
        risk_status = "high"
        risk_summary = "当前结果存在明显偏差、重生成或冲突适配痕迹，应按高风险处理。"
    elif apply_method in _ATTENTION_APPLY_METHODS or prereq_counts["total"]:
        risk_status = "attention"
        risk_summary = "补丁虽可继续评估，但存在上下文适配或关联补丁信号，需要重点关注。"
    else:
        risk_status = "low"
        risk_summary = "当前未发现显著额外高风险信号。"

    return {
        "direct_backport": {
            "status": direct_status,
            "summary": direct_summary,
        },
        "prerequisite": {
            "status": prereq_status,
            "summary": prereq_summary,
            "counts": prereq_counts,
        },
        "risk": {
            "status": risk_status,
            "summary": risk_summary,
        },
        "final": {
            "level": (payload.get("level_decision") or {}).get("level", ""),
            "base_level": (payload.get("level_decision") or {}).get("base_level", ""),
            "review_mode": (payload.get("level_decision") or {}).get("review_mode", ""),
            "next_action": (
                (payload.get("level_decision") or {}).get("next_action")
                or ("先补齐上游情报后重试" if result_status["state"] == "incomplete" else "结合证据做一次人工复核")
            ),
            "harmless": (payload.get("level_decision") or {}).get("harmless"),
            "reason": (
                (payload.get("level_decision") or {}).get("reason")
                or result_status["technical_detail"]
                or result_status["user_message"]
            ),
        },
    }


def ensure_analysis_framework(payload: Dict[str, Any], mode: str) -> Dict[str, Any]:
    existing = payload.get("analysis_framework")
    result_status = infer_result_status(payload, mode)
    stage_steps = stage_events_to_workflow(payload.get("analysis_stages") or [])
    narrative = payload.get("analysis_narrative") or {}
    narrative_workflow = narrative.get("workflow", []) if isinstance(narrative, dict) else []

    if isinstance(existing, dict) and existing:
        framework = dict(existing)
        process = dict(framework.get("process") or {})
        process["workflow_steps"] = dedupe_strings(
            list(process.get("workflow_steps") or []) + stage_steps + list(narrative_workflow or [])
        )
        if (payload.get("level_decision") or {}).get("base_level"):
            process.setdefault("base_level", (payload.get("level_decision") or {}).get("base_level", ""))
        if (payload.get("level_decision") or {}).get("base_method"):
            process.setdefault("base_method", (payload.get("level_decision") or {}).get("base_method", ""))
        if (payload.get("level_decision") or {}).get("level"):
            process.setdefault("final_level", (payload.get("level_decision") or {}).get("level", ""))

        evidence = dict(framework.get("evidence") or {})
        evidence["prerequisite_patches"] = list(evidence.get("prerequisite_patches") or payload.get("prerequisite_patches") or payload.get("tool_prereqs") or [])
        evidence["compatibility_mode"] = "native"
        if payload.get("dryrun_detail"):
            evidence.setdefault("dryrun_detail", payload.get("dryrun_detail"))

        framework["process"] = process
        framework["evidence"] = evidence
        framework["conclusion"] = framework.get("conclusion") or _fallback_conclusion(payload, mode, result_status)
        framework["result_status"] = result_status
        return framework

    evidence = {
        "compatibility_mode": "inferred",
        "introduced": {
            "found": payload.get("is_vulnerable"),
            "analysis": payload.get("intro_analysis") or {},
        },
        "fixed": {"found": payload.get("is_fixed")},
        "prerequisite_patches": list(payload.get("prerequisite_patches") or payload.get("tool_prereqs") or []),
        "dryrun_detail": payload.get("dryrun_detail") or {},
        "issues": dedupe_strings(payload.get("issues", [])),
        "lock_objects": [],
        "fields": [],
        "state_points": [],
        "error_path_nodes": [],
        "admission_rules": [],
        "low_level_veto_rules": [],
        "direct_backport_veto_rules": [],
        "risk_profile_rules": [],
    }

    return {
        "process": {
            "workflow_steps": dedupe_strings(stage_steps + list(narrative_workflow or [])),
            "base_level": (payload.get("level_decision") or {}).get("base_level", ""),
            "base_method": (payload.get("level_decision") or {}).get("base_method", ""),
            "final_level": (payload.get("level_decision") or {}).get("level", ""),
        },
        "evidence": evidence,
        "conclusion": _fallback_conclusion(payload, mode, result_status),
        "result_status": result_status,
    }


def enrich_result_payload(payload: Dict[str, Any], mode: str) -> Dict[str, Any]:
    normalized = dict(payload or {})
    normalized["analysis_stages"] = dedupe_stage_events(normalized.get("analysis_stages") or [])
    normalized["recommendations"] = dedupe_strings(normalized.get("recommendations") or [])
    result_status = infer_result_status(normalized, mode)
    normalized["result_status"] = result_status
    normalized["analysis_framework"] = ensure_analysis_framework(normalized, mode)

    narrative = normalized.get("analysis_narrative")
    if isinstance(narrative, dict):
        workflow = dedupe_strings(narrative.get("workflow", []))
        if workflow:
            narrative = dict(narrative)
            narrative["workflow"] = workflow
            normalized["analysis_narrative"] = narrative

    return normalized


def build_report_envelope(
    mode: str,
    *,
    reading_guide: Dict[str, Any],
    summary: Dict[str, Any],
    technical_details: Dict[str, Any],
    extra: Dict[str, Any] = None,
) -> Dict[str, Any]:
    payload = {
        "report_version": REPORT_VERSION,
        "schema_version": REPORT_SCHEMA_VERSION,
        "mode": mode,
        "reading_guide": reading_guide,
        "summary": summary,
        "technical_details": technical_details,
    }
    if extra:
        payload.update(extra)
    return payload
