"""CLI/API 共用的 analyze/validate 报告组装。"""

from datetime import datetime

from core.output_serializers import (
    build_l0_l5_view,
    collect_prereq_patches,
    collect_rules_metadata,
    serialize_commit_reference,
    serialize_dependency_details,
    serialize_function_impacts,
    serialize_level_decision,
    serialize_validation_details,
)
from core.report_schema import (
    REPORT_SCHEMA_VERSION,
    REPORT_VERSION,
    build_report_envelope,
    dedupe_strings,
    enrich_result_payload,
)
from services.output_support import build_repo_traceability


def status_to_cn(kind: str, status: str) -> str:
    mapping = {
        "direct_backport": {
            "direct": "可直接回移",
            "review": "接近可直接回移，但建议复核",
            "blocked": "不建议直接回移",
            "not_applicable": "当前不适用",
            "insufficient_intel": "情报不足",
            "unknown": "暂未形成稳定结论",
        },
        "prerequisite": {
            "required": "必须考虑关联补丁",
            "recommended": "建议考虑关联补丁",
            "weak_only": "仅弱关联，可按需复核",
            "independent": "可不优先考虑关联补丁",
            "not_applicable": "当前不适用",
            "insufficient_intel": "情报不足",
            "unknown": "暂未形成稳定结论",
        },
        "risk": {
            "high": "高风险",
            "attention": "需要重点关注",
            "low": "未发现显著额外风险",
            "not_applicable": "当前不适用",
            "insufficient_intel": "情报不足",
            "unknown": "暂未形成稳定结论",
        },
    }
    return mapping.get(kind, {}).get(status or "", status or "未知")


def build_json_reading_guide(mode: str) -> dict:
    common = {
        "purpose": "本文件已按“先看结论、再看证据、最后看技术细节”的顺序重组，优先阅读 summary。",
        "recommended_order": [
            "1. summary.overview：先看漏洞、目标分支、最终结论",
            "2. summary.conclusion：看是否可直接回移、是否要考虑关联补丁、风险是否偏高",
            "3. summary.key_evidence：看锁对象、字段、状态点、错误路径等关键证据",
            "4. technical_details：需要深挖时再看完整技术明细",
        ],
        "field_explanations": {
            "result_status": "统一状态卡，显式区分已修复、不适用、情报不足、验证偏差等场景。",
            "analysis_framework": "统一的过程 + 证据 + 结论骨架，用于快速理解工具为什么这么判。",
            "l0_l5": "最终 L0-L5 级别与 DryRun 基线级别。L0/L1 更偏低风险，L3/L4/L5 更需要人工关注。",
            "special_risk_report": "P2 专项高风险分析，重点看锁、生命周期、状态机、结构体字段、错误路径。",
            "level_decision": "最终级别、下一步动作和规则抬升原因。",
            "manual_review_checklist": "自动生成的人工审查清单。L2-L5、关联补丁或高风险场景会显式给出先看什么。",
            "traceability": "结果追溯信息，记录规则 profile、开关、目标仓 HEAD、生成时间和 schema 版本。",
            "artifacts": "本次运行的输出路径索引，包括 run_id、报告文件和补丁文件位置。",
        },
    }
    if mode == "validate":
        common["field_explanations"]["generated_vs_real"] = "工具生成补丁与真实修复补丁的本质对比结果。"
    return common


def _normalize_rule_messages(items) -> list:
    out = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        msg = item.get("message", "")
        if msg:
            out.append(msg)
    return dedupe_strings(out)[:6]


def _summarize_prereq_evidence(items) -> list:
    out = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        labels = []
        if item.get("shared_lock_domains"):
            labels.append("锁域")
        if item.get("shared_fields"):
            labels.append("字段")
        if item.get("shared_state_points"):
            labels.append("状态点")
        if not labels:
            continue
        commit_id = str(item.get("commit_id", ""))[:12]
        subject = str(item.get("subject", ""))
        out.append(f"{commit_id} {subject}（共享{'/'.join(labels)}）".strip())
    return dedupe_strings(out)[:6]


def _resolve_manual_review_checklist(data: dict) -> list:
    validation_details = data.get("validation_details") or {}
    if isinstance(validation_details, dict):
        checklist = validation_details.get("manual_review_checklist") or []
        if checklist:
            return dedupe_strings(checklist)[:8]

    dependency_details = data.get("dependency_details") or {}
    if isinstance(dependency_details, dict):
        checklist = dependency_details.get("manual_review_checklist") or []
        if checklist:
            return dedupe_strings(checklist)[:8]

    checklist = data.get("manual_review_checklist") or []
    return dedupe_strings(checklist)[:8]


def _build_traceability_section(data: dict, mode: str) -> dict:
    traceability = dict(data.get("traceability") or {})
    rules = data.get("rules") or {}
    validation_details = data.get("validation_details") or {}
    target_repo = dict(traceability.get("target_repo") or {})
    policy = dict(traceability.get("policy") or {})

    policy.setdefault("profile", validation_details.get("rule_profile") or rules.get("profile") or "default")
    policy.setdefault("rule_version", validation_details.get("rule_version") or "")
    policy.setdefault("rule_switches", rules.get("policy_overrides") or {})

    generated_at = traceability.get("generated_at") or ""
    source_timestamps = dict(traceability.get("source_timestamps") or {})
    if generated_at:
        source_timestamps.setdefault("report_generated_at", generated_at)
    if target_repo.get("head_commit_time"):
        source_timestamps.setdefault("target_repo_head_at", target_repo.get("head_commit_time"))

    return {
        "mode": mode,
        "target_version": data.get("target_version") or data.get("target", ""),
        "generated_at": generated_at,
        "report_version": REPORT_VERSION,
        "schema_version": REPORT_SCHEMA_VERSION,
        "policy": policy,
        "target_repo": target_repo,
        "data_sources": list(traceability.get("data_sources") or []),
        "source_timestamps": source_timestamps,
    }


def _build_artifacts_section(data: dict) -> dict:
    artifacts = dict(data.get("artifacts") or {})
    patch_files = dict(artifacts.get("patch_files") or {})
    if data.get("patch_file"):
        patch_files.setdefault("adapted_patch", data.get("patch_file"))
    if data.get("community_patch_file"):
        patch_files.setdefault("community_patch", data.get("community_patch_file"))
    if data.get("real_fix_patch_file"):
        patch_files.setdefault("real_fix_patch", data.get("real_fix_patch_file"))
    if patch_files:
        artifacts["patch_files"] = patch_files
    return artifacts


def build_human_friendly_summary(data: dict, mode: str) -> dict:
    data = enrich_result_payload(data, mode)
    framework = data.get("analysis_framework") or {}
    process = framework.get("process") or {}
    evidence = framework.get("evidence") or {}
    conclusion = framework.get("conclusion") or {}
    result_status = data.get("result_status") or {}
    manual_review_checklist = _resolve_manual_review_checklist(data)
    level = (data.get("l0_l5") or {}).get("current_level") or (data.get("level_decision") or {}).get("level") or "未知"
    base_level = (data.get("l0_l5") or {}).get("base_level") or (data.get("level_decision") or {}).get("base_level") or "未知"

    overview = {
        "cve_id": data.get("cve_id", ""),
        "target_version": data.get("target_version") or data.get("target", ""),
        "结果状态": result_status.get("state", "complete"),
        "状态说明": result_status.get("user_message", ""),
        "最终级别": level,
        "基线级别": base_level,
    }
    if mode == "analyze":
        overview.update({
            "漏洞是否已引入": "是" if data.get("is_vulnerable") else "否/未确认",
            "修复是否已存在": "是" if data.get("is_fixed") else "否",
            "DryRun是否通过": "是" if data.get("dry_run_clean") else "否/未执行",
        })
    else:
        actual_fix_count = len(data.get("known_fix_commits") or [])
        if not actual_fix_count and data.get("known_fix"):
            actual_fix_count = 1
        overview.update({
            "验证是否通过": "是" if data.get("overall_pass") else "否",
            "真实修复commit": data.get("known_fix", ""),
            "实际fix数量": actual_fix_count,
            "结论摘要": data.get("summary", ""),
        })

    summary = {
        "overview": overview,
        "status": result_status,
        "conclusion": {
            "是否可直接回移": {
                "状态": status_to_cn("direct_backport", (conclusion.get("direct_backport") or {}).get("status", "")),
                "说明": (conclusion.get("direct_backport") or {}).get("summary", ""),
            },
            "是否需要关联补丁": {
                "状态": status_to_cn("prerequisite", (conclusion.get("prerequisite") or {}).get("status", "")),
                "说明": (conclusion.get("prerequisite") or {}).get("summary", ""),
            },
            "风险判断": {
                "状态": status_to_cn("risk", (conclusion.get("risk") or {}).get("status", "")),
                "说明": (conclusion.get("risk") or {}).get("summary", ""),
            },
            "下一步建议": (conclusion.get("final") or {}).get("next_action", ""),
        },
        "process": {
            "说明": "下面是工具实际走过的分析步骤，建议从上到下阅读。",
            "workflow_steps": dedupe_strings(process.get("workflow_steps") or []),
        },
        "key_evidence": {
            "准入规则命中": _normalize_rule_messages(evidence.get("admission_rules")),
            "低级别否决命中": _normalize_rule_messages(evidence.get("low_level_veto_rules")),
            "直接回移否决命中": _normalize_rule_messages(evidence.get("direct_backport_veto_rules")),
            "高风险画像命中": _normalize_rule_messages(evidence.get("risk_profile_rules")),
            "关联补丁证据": _summarize_prereq_evidence(evidence.get("prerequisite_patches")),
            "锁对象": (evidence.get("lock_objects") or [])[:8],
            "关键字段": (evidence.get("fields") or [])[:8],
            "状态点": (evidence.get("state_points") or [])[:8],
            "错误路径节点": (evidence.get("error_path_nodes") or [])[:8],
            "状态证据": result_status.get("evidence_refs", []),
        },
        "manual_review_checklist": manual_review_checklist,
    }

    if mode == "validate":
        generated = data.get("generated_vs_real") or {}
        summary["patch_quality"] = {
            "比较范围": generated.get("compare_scope", "single_fix"),
            "工具补丁与真实修复关系": generated.get("verdict", ""),
            "核心相似度": generated.get("core_similarity", 0),
            "比较来源": generated.get("compare_source", ""),
        }
        solution_set = data.get("solution_set_vs_real") or {}
        if solution_set:
            summary["solution_set_quality"] = {
                "比较范围": solution_set.get("compare_scope", "solution_set"),
                "工具预测解集与实际解集关系": solution_set.get("verdict", ""),
                "核心相似度": solution_set.get("core_similarity", 0),
                "比较来源": solution_set.get("compare_source", ""),
            }
        recalibration = data.get("accuracy_recalibration") or {}
        if recalibration.get("applied"):
            summary["level_recalibration"] = {
                "状态": "已校正",
                "说明": recalibration.get("reason", ""),
                "原级别": recalibration.get("original_level", ""),
                "校正后级别": recalibration.get("adjusted_level", ""),
            }

    return summary


def build_analyze_payload(
    result,
    pipe,
    config,
    target: str,
    *,
    stage_events: list = None,
    policy_config=None,
    deep_analysis=None,
    narrative_builder=None,
    deep_serializer=None,
):
    prereqs = collect_prereq_patches(
        result.prerequisite_patches, config, pipe.git_mgr, target)

    cve_commit_urls = {}
    if result.cve_info and result.cve_info.version_commit_mapping:
        for ver, cid in result.cve_info.version_commit_mapping.items():
            cve_commit_urls[ver] = serialize_commit_reference(
                config, pipe.git_mgr, target, cid, extra={"version": ver}
            )

    dr_detail = {}
    if result.dry_run:
        dr = result.dry_run
        dr_detail = {
            "applies_cleanly": dr.applies_cleanly,
            "apply_method": dr.apply_method,
            "conflicting_files": dr.conflicting_files,
            "error_output": dr.error_output[:500] if dr.error_output else "",
            "has_adapted_patch": bool(dr.adapted_patch),
            "apply_attempts": dr.apply_attempts,
        }

    fix_patch_detail = {}
    if result.fix_patch:
        fp = result.fix_patch
        fix_patch_detail = serialize_commit_reference(
            config, pipe.git_mgr, target, fp.commit_id,
            extra={
                "subject": fp.subject,
                "author": fp.author,
                "modified_files": fp.modified_files,
                "diff_lines": len((fp.diff_code or "").splitlines()),
            }
        )

    narrative = {}
    if narrative_builder:
        try:
            narrative = narrative_builder(
                result, dr_detail, {}, {}, is_validate=False)
        except Exception:
            narrative = {}

    valid_details = serialize_validation_details(result.validation_details)
    dependency_details = serialize_dependency_details(result.dependency_details)
    payload = {
        "cve_id": result.cve_id,
        "target_version": target,
        "is_vulnerable": result.is_vulnerable,
        "is_fixed": result.is_fixed,
        "dry_run_clean": result.dry_run.applies_cleanly if result.dry_run else None,
        "dryrun_detail": dr_detail,
        "prerequisite_patches": prereqs,
        "version_commit_mapping_urls": cve_commit_urls,
        "rules": collect_rules_metadata(
            policy_config,
            level_decision=result.level_decision,
            validation_details=valid_details,
        ),
        "analysis_narrative": narrative,
        "analysis_framework": valid_details.get("decision_skeleton", {}) if isinstance(valid_details, dict) else {},
        "recommendations": dedupe_strings(result.recommendations or []),
        "analysis_stages": stage_events or [],
        "fix_patch_detail": fix_patch_detail,
        "level_decision": serialize_level_decision(result.level_decision),
        "validation_details": valid_details,
        "dependency_details": dependency_details,
        "manual_review_checklist": valid_details.get("manual_review_checklist", []),
        "function_impacts": serialize_function_impacts(result.function_impacts),
        "traceability": {
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "target_repo": build_repo_traceability(config, pipe.git_mgr, target),
            "policy": {
                "profile": getattr(policy_config, "profile", "default") if policy_config else "default",
                "rule_version": valid_details.get("rule_version", ""),
                "rule_switches": (collect_rules_metadata(policy_config).get("policy_overrides") if policy_config else {}),
            },
            "data_sources": ["target_repo", "community_fix_patch", "analysis_pipeline"],
        },
    }
    payload["l0_l5"] = build_l0_l5_view(payload)
    if deep_analysis is not None and deep_serializer is not None:
        payload["deep_analysis"] = deep_serializer(deep_analysis)

    return enrich_result_payload(payload, "analyze")


def prepare_analyze_json(payload: dict) -> dict:
    payload = enrich_result_payload(payload, "analyze")
    return build_report_envelope(
        "analyze",
        reading_guide=build_json_reading_guide("analyze"),
        summary=build_human_friendly_summary(payload, "analyze"),
        technical_details={
            "result_status": payload.get("result_status", {}),
            "analysis_framework": payload.get("analysis_framework", {}),
            "l0_l5": payload.get("l0_l5", {}),
            "level_decision": payload.get("level_decision", {}),
            "validation_details": payload.get("validation_details", {}),
            "dependency_details": payload.get("dependency_details", {}),
            "dryrun_detail": payload.get("dryrun_detail", {}),
            "function_impacts": payload.get("function_impacts", []),
            "prerequisite_patches": payload.get("prerequisite_patches", []),
            "fix_patch_detail": payload.get("fix_patch_detail", {}),
            "analysis_stages": payload.get("analysis_stages", []),
            "rules": payload.get("rules", {}),
            "analysis_narrative": payload.get("analysis_narrative", {}),
            "recommendations": payload.get("recommendations", []),
            "manual_review_checklist": _resolve_manual_review_checklist(payload),
            "deep_analysis": payload.get("deep_analysis"),
        },
        extra={
            "manual_review_checklist": _resolve_manual_review_checklist(payload),
            "traceability": _build_traceability_section(payload, "analyze"),
            "artifacts": _build_artifacts_section(payload),
        },
    )


def prepare_validate_json(result: dict, *, deep_serializer=None) -> dict:
    raw = {}
    for key, value in (result or {}).items():
        if key == "deep_analysis" and value is not None and deep_serializer is not None:
            raw["deep_analysis"] = deep_serializer(value)
        else:
            raw[key] = value

    validation_details = raw.get("validation_details") or {}
    if not raw.get("analysis_framework") and isinstance(validation_details, dict):
        raw["analysis_framework"] = validation_details.get("decision_skeleton", {}) or {}

    raw = enrich_result_payload(raw, "validate")
    return build_report_envelope(
        "validate",
        reading_guide=build_json_reading_guide("validate"),
        summary=build_human_friendly_summary(raw, "validate"),
        technical_details={
            "result_status": raw.get("result_status", {}),
            "checks": raw.get("checks", {}),
            "issues": raw.get("issues", []),
            "analysis_framework": raw.get("analysis_framework", {}),
            "l0_l5": raw.get("l0_l5", {}),
            "level_decision": raw.get("level_decision", {}),
            "validation_details": raw.get("validation_details", {}),
            "dependency_details": raw.get("dependency_details", {}),
            "dryrun_detail": raw.get("dryrun_detail", {}),
            "function_impacts": raw.get("function_impacts", []),
            "generated_vs_real": raw.get("generated_vs_real", {}),
            "generated_patch_vs_primary_fix": raw.get("generated_patch_vs_primary_fix", {}),
            "solution_set_vs_real": raw.get("solution_set_vs_real", {}),
            "accuracy_recalibration": raw.get("accuracy_recalibration", {}),
            "diff_comparison": raw.get("diff_comparison", {}),
            "tool_prereqs": raw.get("tool_prereqs", []),
            "tool_prereqs_for_compare": raw.get("tool_prereqs_for_compare", []),
            "known_fix_commits": raw.get("known_fix_commits", []),
            "known_fixs_detail": raw.get("known_fixs_detail", []),
            "actual_solution_commits": raw.get("actual_solution_commits", []),
            "actual_solution_detail": raw.get("actual_solution_detail", []),
            "known_prereqs_detail": raw.get("known_prereqs_detail", []),
            "analysis_stages": raw.get("analysis_stages", []),
            "analysis_narrative": raw.get("analysis_narrative", {}),
            "rules": raw.get("rules", {}),
            "manual_review_checklist": _resolve_manual_review_checklist(raw),
            "deep_analysis": raw.get("deep_analysis"),
        },
        extra={
            "manual_review_checklist": _resolve_manual_review_checklist(raw),
            "traceability": _build_traceability_section(raw, "validate"),
            "artifacts": _build_artifacts_section(raw),
        },
    )
