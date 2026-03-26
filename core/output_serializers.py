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
        "warnings": getattr(validation_details, "warnings", []),
        "rule_profile": getattr(validation_details, "rule_profile", ""),
        "rule_version": getattr(validation_details, "rule_version", ""),
        "strategy_buckets": getattr(validation_details, "strategy_buckets", {}),
    }


def serialize_function_impacts(function_impacts) -> list:
    return [fi.__dict__ for fi in (function_impacts or [])]


def collect_rules_metadata(policy_config, level_decision=None, validation_details=None):
    payload = {
        "profile": getattr(policy_config, "profile", "default") if policy_config else "default",
        "enabled": bool(getattr(policy_config, "enabled", True)),
        "policy_overrides": {
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

    return payload


def aggregate_strategy_buckets(results: list) -> dict:
    level_counter = Counter()
    dependency_counter = Counter()
    rule_type_counter = Counter()
    level_by_dependency = Counter()
    level_by_rule_type = Counter()

    for result in results or []:
        if not isinstance(result, dict):
            continue
        validation_details = result.get("validation_details") or {}
        strategy_buckets = validation_details.get("strategy_buckets") or {}
        level = strategy_buckets.get("level") or (result.get("level_decision") or {}).get("level", "")
        dependency_bucket = strategy_buckets.get("dependency_bucket", "")
        rule_type_bucket = strategy_buckets.get("rule_type_bucket", []) or []

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

    return {
        "level_distribution": dict(sorted(level_counter.items())),
        "dependency_distribution": dict(sorted(dependency_counter.items())),
        "rule_type_distribution": dict(sorted(rule_type_counter.items())),
        "level_by_dependency": dict(sorted(level_by_dependency.items())),
        "level_by_rule_type": dict(sorted(level_by_rule_type.items())),
    }


def build_l0_l5_view(result: dict) -> dict:
    if not isinstance(result, dict):
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
