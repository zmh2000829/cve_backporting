"""输出序列化与规则元数据聚合。

将 CLI/API/UI 共用的结果序列化逻辑集中，避免在 cli.py 中反复拼装。
"""

from collections import Counter
from dataclasses import asdict
import re
from urllib.parse import urlparse


def coerce_commit_url_base(value: str) -> str:
    if not value:
        return ""
    v = value.strip().rstrip("/")
    if v.endswith(".git"):
        v = v[:-4]
    return v


def build_commit_url_from_remote(remote_url: str, commit_id: str) -> str:
    if not remote_url or not commit_id:
        return ""
    candidate = coerce_commit_url_base(remote_url.strip())
    if not candidate:
        return ""

    if candidate.startswith("git@") or candidate.startswith("ssh://git@"):
        m = re.match(r"^(?:ssh://)?git@(?P<host>[^:]+):(?P<path>.+)$", candidate)
        if m:
            host = m.group("host")
            path = coerce_commit_url_base(m.group("path")).lstrip("/")
            base = f"https://{host}/{path}"
        else:
            base = candidate
    elif "://" in candidate:
        parsed = urlparse(candidate)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    else:
        base = candidate

    base = coerce_commit_url_base(base)
    if "://" in base:
        parsed = urlparse(base)
        host = parsed.netloc.lower()
    elif "@" in base and ":" in base.split("@", 1)[1]:
        host = base.split("@", 1)[1].split(":", 1)[0].lower()
    else:
        host = ""

    if "github.com" in host:
        return f"{base}/commit/{commit_id}"
    if "gitlab.com" in host:
        return f"{base}/-/commit/{commit_id}"
    if "bitbucket.org" in host:
        return f"{base}/commits/{commit_id}"
    return f"{base}/commit/{commit_id}"


def resolve_repo_config(config, target: str) -> dict:
    rc = config.repositories.get(target, {})
    if isinstance(rc, dict):
        return rc
    return {"path": rc} if rc else {}


def resolve_commit_url(config, git_mgr, target: str, commit_id: str) -> str:
    if not commit_id:
        return ""

    rc = resolve_repo_config(config, target)
    tmpl = (
        rc.get("commit_url_template")
        or rc.get("commit_url")
        or rc.get("web_url")
        or rc.get("url")
        or rc.get("remote_url")
    )

    if tmpl:
        try:
            return tmpl.format(
                commit=commit_id,
                commit_id=commit_id,
                short_commit=commit_id[:12],
                cve_repo=target,
                target=target,
            )
        except Exception:
            url = coerce_commit_url_base(tmpl)
            if any(s in url.lower() for s in ("http://", "https://", "git@")):
                return build_commit_url_from_remote(url, commit_id)

    try:
        remote = git_mgr.run_git(["git", "remote", "get-url", "origin"], target, timeout=10)
    except Exception:
        remote = None
    if remote:
        return build_commit_url_from_remote(remote, commit_id)
    return ""


def serialize_commit_reference(config, git_mgr, target: str, commit_id: str, *, extra: dict = None) -> dict:
    cid = (commit_id or "").strip()
    if not cid:
        return {"commit_id": "", "commit_id_short": ""}
    data = {"commit_id": cid, "commit_id_short": cid[:12]}
    if extra:
        data.update(extra)
    url = resolve_commit_url(config, git_mgr, target, cid)
    if url:
        data["commit_url"] = url
    return data


def collect_prereq_patches(patches, config, git_mgr, target: str):
    out = []
    for patch in patches or []:
        item = asdict(patch) if hasattr(patch, "__dict__") else dict(patch)
        item.update(serialize_commit_reference(config, git_mgr, target, item.get("commit_id", "")))
        out.append(item)
    return out


def collect_level_policies():
    try:
        from rules.level_policies import LEVEL_POLICIES
    except Exception:
        return []

    out = []
    for policy in LEVEL_POLICIES:
        out.append({
            "level": policy.level,
            "methods": list(getattr(policy, "methods", [])),
            "strategy": getattr(policy, "strategy", ""),
            "review_mode": getattr(policy, "review_mode", ""),
            "next_action": getattr(policy, "next_action", ""),
            "confidence_with_llm": getattr(policy, "confidence_with_llm", ""),
            "confidence_without_llm": getattr(policy, "confidence_without_llm", ""),
        })
    return out


def serialize_level_decision(level_decision) -> dict:
    if not level_decision:
        return {}
    if isinstance(level_decision, dict):
        return dict(level_decision)
    if hasattr(level_decision, "__dict__"):
        return asdict(level_decision)
    return {}


def serialize_validation_details(validation_details) -> dict:
    if not validation_details:
        return {}
    if isinstance(validation_details, dict):
        return dict(validation_details)
    return {
        "workflow_steps": getattr(validation_details, "workflow_steps", []),
        "special_risk_report": getattr(validation_details, "special_risk_report", {}),
        "warnings": getattr(validation_details, "warnings", []),
        "rule_profile": getattr(validation_details, "rule_profile", ""),
        "rule_version": getattr(validation_details, "rule_version", ""),
        "strategy_buckets": getattr(validation_details, "strategy_buckets", {}),
        "decision_skeleton": getattr(validation_details, "decision_skeleton", {}),
        "manual_review_checklist": getattr(validation_details, "manual_review_checklist", []),
    }


def serialize_function_impacts(function_impacts) -> list:
    return [fi.__dict__ for fi in (function_impacts or [])]


def serialize_dependency_details(details) -> dict:
    if not details:
        return {}
    if isinstance(details, dict):
        return dict(details)
    if hasattr(details, "__dict__"):
        return asdict(details)
    return {}


def collect_rules_metadata(policy_config, level_decision=None, validation_details=None):
    payload = {
        "profile": getattr(policy_config, "profile", "default") if policy_config else "default",
        "enabled": bool(getattr(policy_config, "enabled", True)),
        "policy_overrides": {
            "special_risk_rules_enabled": bool(getattr(policy_config, "special_risk_rules_enabled", True)),
            "large_change_rules_enabled": bool(getattr(policy_config, "large_change_rules_enabled", True)),
            "call_chain_rules_enabled": bool(getattr(policy_config, "call_chain_rules_enabled", True)),
            "critical_structure_rules_enabled": bool(getattr(policy_config, "critical_structure_rules_enabled", True)),
            "l1_api_surface_rules_enabled": bool(getattr(policy_config, "l1_api_surface_rules_enabled", True)),
            "large_change_line_threshold": getattr(policy_config, "large_change_line_threshold", 80),
            "large_hunk_threshold": getattr(policy_config, "large_hunk_threshold", 8),
            "call_chain_fanout_threshold": getattr(policy_config, "call_chain_fanout_threshold", 6),
            "l1_return_line_delta_threshold": getattr(policy_config, "l1_return_line_delta_threshold", 2),
        },
        "level_policies": collect_level_policies(),
    }

    serialized_validation = serialize_validation_details(validation_details)
    if serialized_validation:
        payload["validation_context"] = serialized_validation

    serialized_level = serialize_level_decision(level_decision)
    if serialized_level:
        payload["level_decision"] = serialized_level
        payload["rule_hits"] = list(serialized_level.get("rule_hits", []) or [])
        payload["rule_class_summary"] = {
            "admission": sum(1 for hit in payload["rule_hits"] if hit.get("rule_class") == "admission"),
            "low_level_veto": sum(1 for hit in payload["rule_hits"] if hit.get("rule_class") == "low_level_veto"),
            "direct_backport_veto": sum(1 for hit in payload["rule_hits"] if hit.get("rule_class") == "direct_backport_veto"),
            "risk_profile": sum(1 for hit in payload["rule_hits"] if hit.get("rule_class") == "risk_profile"),
        }
        payload["rule_taxonomy"] = {
            "admission": "用于支持可直接回移的正向准入规则",
            "low_level_veto": "用于阻止误入 L0/L1 等低级别处理区的否决规则",
            "direct_backport_veto": "用于阻止“可直接回移”结论的否决规则",
            "risk_profile": "用于识别锁、生命周期、状态机、结构体字段、错误路径等高风险画像规则",
        }

    return payload


def aggregate_strategy_buckets(results: list) -> dict:
    level_counter = Counter()
    dependency_counter = Counter()
    rule_type_counter = Counter()
    rule_class_counter = Counter()
    level_by_dependency = Counter()
    level_by_rule_type = Counter()
    level_by_rule_class = Counter()

    for result in results or []:
        if not isinstance(result, dict):
            continue
        validation_details = result.get("validation_details") or {}
        strategy_buckets = validation_details.get("strategy_buckets") or {}
        level = strategy_buckets.get("level") or (result.get("level_decision") or {}).get("level", "")
        dependency_bucket = strategy_buckets.get("dependency_bucket", "")
        rule_type_bucket = strategy_buckets.get("rule_type_bucket", []) or []
        rule_class_bucket = strategy_buckets.get("rule_class_bucket", []) or []

        if level:
            level_counter[level] += 1
        if dependency_bucket:
            dependency_counter[dependency_bucket] += 1
            if level:
                level_by_dependency[f"{dependency_bucket}:{level}"] += 1
        for item in rule_type_bucket:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            rule_type, count = item[0], item[1]
            rule_type_counter[rule_type] += int(count or 0)
            if level:
                level_by_rule_type[f"{rule_type}:{level}"] += int(count or 0)
        for item in rule_class_bucket:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            rule_class, count = item[0], item[1]
            rule_class_counter[rule_class] += int(count or 0)
            if level:
                level_by_rule_class[f"{rule_class}:{level}"] += int(count or 0)

    return {
        "level_distribution": dict(sorted(level_counter.items())),
        "dependency_distribution": dict(sorted(dependency_counter.items())),
        "rule_type_distribution": dict(sorted(rule_type_counter.items())),
        "rule_class_distribution": dict(sorted(rule_class_counter.items())),
        "level_by_dependency": dict(sorted(level_by_dependency.items())),
        "level_by_rule_type": dict(sorted(level_by_rule_type.items())),
        "level_by_rule_class": dict(sorted(level_by_rule_class.items())),
    }


def _normalize_aggregatable_result(result: dict) -> dict:
    """兼容 raw validate result 与 friendly-json validate report 两种形态。"""
    if not isinstance(result, dict):
        return {}

    technical = result.get("technical_details")
    if not isinstance(technical, dict):
        return result

    summary = result.get("summary") or {}
    overview = summary.get("overview") or {}
    normalized = dict(result)
    normalized["cve_id"] = normalized.get("cve_id") or overview.get("cve_id", "")

    for key in (
        "checks",
        "issues",
        "result_status",
        "analysis_framework",
        "l0_l5",
        "level_decision",
        "validation_details",
        "dryrun_detail",
        "function_impacts",
        "generated_vs_real",
        "diff_comparison",
        "tool_prereqs",
        "known_prereqs_detail",
        "analysis_stages",
        "analysis_narrative",
        "rules",
    ):
        if key not in normalized and key in technical:
            normalized[key] = technical.get(key)

    return normalized


def build_l0_l5_view(result: dict) -> dict:
    result = _normalize_aggregatable_result(result)
    if not result:
        return {}

    level_decision = serialize_level_decision(result.get("level_decision"))
    validation_details = serialize_validation_details(result.get("validation_details"))
    strategy_buckets = validation_details.get("strategy_buckets") or {}

    current_level = (
        level_decision.get("level")
        or strategy_buckets.get("level")
        or ""
    )
    base_level = (
        level_decision.get("base_level")
        or strategy_buckets.get("base_level")
        or ""
    )
    base_method = (
        level_decision.get("base_method")
        or strategy_buckets.get("base_method")
        or ""
    )

    return {
        "current_level": current_level,
        "base_level": base_level,
        "base_method": base_method,
        "review_mode": level_decision.get("review_mode", ""),
        "next_action": level_decision.get("next_action", ""),
        "harmless": level_decision.get("harmless"),
        "confidence": level_decision.get("confidence", ""),
        "reason": level_decision.get("reason", ""),
        "dependency_bucket": strategy_buckets.get("dependency_bucket", ""),
        "rule_type_bucket": strategy_buckets.get("rule_type_bucket", []) or [],
        "levels": ["L0", "L1", "L2", "L3", "L4", "L5"],
    }


def aggregate_l0_l5_levels(results: list) -> dict:
    current_counter = Counter({f"L{i}": 0 for i in range(6)})
    base_counter = Counter({f"L{i}": 0 for i in range(6)})

    for result in results or []:
        if not isinstance(result, dict):
            continue
        level_view = build_l0_l5_view(result)
        current_level = level_view.get("current_level", "")
        base_level = level_view.get("base_level", "")
        if current_level in current_counter:
            current_counter[current_level] += 1
        if base_level in base_counter:
            base_counter[base_level] += 1

    return {
        "levels": ["L0", "L1", "L2", "L3", "L4", "L5"],
        "current_level_distribution": dict(current_counter),
        "base_level_distribution": dict(base_counter),
    }


def aggregate_special_risk_metrics(results: list) -> dict:
    section_counter = Counter()
    critical_structure_change_count = 0
    any_special_risk_count = 0
    samples = {
        "critical_structure_change_cves": [],
        "manual_prereq_analysis_cves": [],
        "deterministic_exact_match_cves": [],
    }

    for result in results or []:
        normalized = _normalize_aggregatable_result(result)
        if not normalized:
            continue
        cve_id = normalized.get("cve_id", "")
        validation_details = serialize_validation_details(normalized.get("validation_details"))
        report = validation_details.get("special_risk_report") or {}
        summary = report.get("summary") or {}
        triggered_sections = summary.get("triggered_sections") or []
        if triggered_sections:
            any_special_risk_count += 1
        for section in triggered_sections:
            section_counter[section] += 1
        if summary.get("has_critical_structure_change"):
            critical_structure_change_count += 1
            if cve_id and len(samples["critical_structure_change_cves"]) < 20:
                samples["critical_structure_change_cves"].append(cve_id)

        generated = normalized.get("generated_vs_real") or {}
        if generated.get("deterministic_exact_match") and cve_id:
            if len(samples["deterministic_exact_match_cves"]) < 20:
                samples["deterministic_exact_match_cves"].append(cve_id)

        strategy_buckets = validation_details.get("strategy_buckets") or {}
        if strategy_buckets.get("dependency_bucket") in ("required", "recommended"):
            if cve_id and len(samples["manual_prereq_analysis_cves"]) < 20:
                samples["manual_prereq_analysis_cves"].append(cve_id)

    return {
        "any_special_risk_count": any_special_risk_count,
        "critical_structure_change_count": critical_structure_change_count,
        "section_counts": dict(sorted(section_counter.items())),
        "samples": samples,
    }


def aggregate_promotion_metrics(results: list) -> dict:
    from rules.level_policies import effective_level_floor, level_rank

    matrix_counter = Counter()
    delta_counter = Counter()
    rule_counter = Counter()
    promoted_count = 0

    for result in results or []:
        normalized = _normalize_aggregatable_result(result)
        if not normalized:
            continue
        level_view = build_l0_l5_view(normalized)
        current_level = level_view.get("current_level", "")
        base_level = level_view.get("base_level", "")
        if not current_level or not base_level:
            continue
        base_rank = level_rank(base_level)
        current_rank = level_rank(current_level)
        if current_rank <= base_rank:
            delta_counter[str(max(current_rank - base_rank, 0))] += 1
            continue

        promoted_count += 1
        matrix_counter[f"{base_level}->{current_level}"] += 1
        delta_counter[str(current_rank - base_rank)] += 1

        level_decision = serialize_level_decision(normalized.get("level_decision"))
        for hit in list(level_decision.get("rule_hits") or []):
            floor = effective_level_floor(hit or {})
            if level_rank(floor) > base_rank:
                rule_id = (hit or {}).get("rule_id", "") or "unknown"
                rule_counter[rule_id] += 1

    total = len(results or [])
    return {
        "promoted_count": promoted_count,
        "promotion_rate": round(promoted_count / total, 4) if total else 0.0,
        "promotion_matrix": dict(sorted(matrix_counter.items())),
        "level_delta_distribution": dict(sorted(delta_counter.items(), key=lambda item: int(item[0]))),
        "top_promotion_rules": dict(rule_counter.most_common(12)),
    }


def aggregate_batch_validate_summary(results: list) -> dict:
    level_summary = aggregate_l0_l5_levels(results)
    special_risk_summary = aggregate_special_risk_metrics(results)
    promotion_summary = aggregate_promotion_metrics(results)
    dependency_bucket_counter = Counter()
    verdict_counter = Counter()
    solution_set_verdict_counter = Counter()
    result_state_counter = Counter()
    incomplete_reason_counter = Counter()
    deterministic_exact_match_count = 0
    solution_set_exact_match_count = 0
    solution_set_case_count = 0
    manual_prereq_analysis_count = 0

    for result in results or []:
        normalized = _normalize_aggregatable_result(result)
        if not normalized:
            continue
        generated = normalized.get("generated_vs_real") or {}
        verdict = generated.get("verdict", "no_data")
        verdict_counter[verdict] += 1
        if generated.get("deterministic_exact_match"):
            deterministic_exact_match_count += 1
        solution_set = normalized.get("solution_set_vs_real") or {}
        if solution_set:
            solution_set_case_count += 1
            solution_verdict = solution_set.get("verdict", "no_data")
            solution_set_verdict_counter[solution_verdict] += 1
            if solution_set.get("deterministic_exact_match"):
                solution_set_exact_match_count += 1

        status = normalized.get("result_status") or {}
        state = status.get("state", "")
        if state:
            result_state_counter[state] += 1
        incomplete_reason = status.get("incomplete_reason", "")
        if incomplete_reason:
            incomplete_reason_counter[incomplete_reason] += 1

        validation_details = serialize_validation_details(normalized.get("validation_details"))
        strategy_buckets = validation_details.get("strategy_buckets") or {}
        dep_bucket = strategy_buckets.get("dependency_bucket", "")
        if dep_bucket:
            dependency_bucket_counter[dep_bucket] += 1
        if dep_bucket in ("required", "recommended"):
            manual_prereq_analysis_count += 1

    total = len(results or [])
    any_special_risk_count = special_risk_summary["any_special_risk_count"]
    critical_structure_change_count = special_risk_summary["critical_structure_change_count"]
    return {
        "total": total,
        "l0_l5": level_summary,
        "level_distribution": {
            "levels": level_summary.get("levels", ["L0", "L1", "L2", "L3", "L4", "L5"]),
            "final_level_counts": level_summary.get("current_level_distribution", {}),
            "base_level_counts": level_summary.get("base_level_distribution", {}),
        },
        "verdict_distribution": dict(sorted(verdict_counter.items())),
        "result_state_distribution": dict(sorted(result_state_counter.items())),
        "incomplete_reason_distribution": dict(sorted(incomplete_reason_counter.items())),
        "deterministic_exact_match": {
            "count": deterministic_exact_match_count,
            "rate": round(deterministic_exact_match_count / total, 4) if total else 0.0,
            "definition": "generated_vs_real.deterministic_exact_match == true",
        },
        "solution_set_verdict_distribution": dict(sorted(solution_set_verdict_counter.items())),
        "solution_set_deterministic_exact_match": {
            "count": solution_set_exact_match_count,
            "rate": round(solution_set_exact_match_count / solution_set_case_count, 4) if solution_set_case_count else 0.0,
            "case_count": solution_set_case_count,
            "definition": "solution_set_vs_real.deterministic_exact_match == true",
        },
        "critical_structure_change": {
            "count": critical_structure_change_count,
            "rate": round(critical_structure_change_count / total, 4) if total else 0.0,
        },
        "manual_prerequisite_analysis": {
            "count": manual_prereq_analysis_count,
            "rate": round(manual_prereq_analysis_count / total, 4) if total else 0.0,
            "dependency_bucket_distribution": dict(sorted(dependency_bucket_counter.items())),
            "definition": "strategy_buckets.dependency_bucket in {required, recommended}",
        },
        "risk_hit_summary": {
            "any_special_risk": {
                "count": any_special_risk_count,
                "rate": round(any_special_risk_count / total, 4) if total else 0.0,
            },
            "critical_structure_change": {
                "count": critical_structure_change_count,
                "rate": round(critical_structure_change_count / total, 4) if total else 0.0,
            },
            "special_risk_section_counts": dict(sorted(special_risk_summary.get("section_counts", {}).items())),
            "samples": special_risk_summary.get("samples", {}),
        },
        "promotion_summary": promotion_summary,
        "statistics": {
            "levels": level_summary.get("levels", ["L0", "L1", "L2", "L3", "L4", "L5"]),
            "final_level_counts": level_summary.get("current_level_distribution", {}),
            "base_level_counts": level_summary.get("base_level_distribution", {}),
            "critical_structure_change_count": critical_structure_change_count,
            "any_special_risk_count": any_special_risk_count,
            "manual_prerequisite_analysis_count": manual_prereq_analysis_count,
            "special_risk_section_counts": dict(sorted(special_risk_summary.get("section_counts", {}).items())),
            "promotion_matrix": promotion_summary.get("promotion_matrix", {}),
            "top_promotion_rules": promotion_summary.get("top_promotion_rules", {}),
            "result_state_distribution": dict(sorted(result_state_counter.items())),
            "incomplete_reason_distribution": dict(sorted(incomplete_reason_counter.items())),
            "solution_set_verdict_distribution": dict(sorted(solution_set_verdict_counter.items())),
            "solution_set_case_count": solution_set_case_count,
        },
        "special_risk": special_risk_summary,
    }
