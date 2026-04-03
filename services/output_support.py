"""输出目录布局与结果追溯辅助。"""

from datetime import datetime
import os
import re


_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]+")


def make_run_id(now: datetime = None) -> str:
    current = now or datetime.now()
    return current.strftime("%Y%m%d_%H%M%S")


def sanitize_path_component(value: str, fallback: str = "unknown") -> str:
    text = str(value or "").strip()
    if not text:
        return fallback
    normalized = _SAFE_COMPONENT_RE.sub("_", text).strip("._-")
    return normalized or fallback


def ensure_mode_output_dir(base_dir: str, run_id: str, mode: str, scope: str = "") -> str:
    parts = [base_dir, sanitize_path_component(run_id, "latest"), sanitize_path_component(mode)]
    if scope:
        parts.append(sanitize_path_component(scope))
    path = os.path.join(*parts)
    os.makedirs(path, exist_ok=True)
    return path


def ensure_case_output_dir(base_dir: str, run_id: str, mode: str, cve_id: str) -> str:
    return ensure_mode_output_dir(base_dir, run_id, mode, scope=cve_id)


def build_repo_traceability(config, git_mgr, target_version: str) -> dict:
    repo_cfg = (getattr(config, "repositories", {}) or {}).get(target_version, {}) or {}
    repo_path = repo_cfg.get("path") if isinstance(repo_cfg, dict) else repo_cfg
    configured_branch = repo_cfg.get("branch", "") if isinstance(repo_cfg, dict) else ""

    def _run(cmd, timeout=10):
        if not git_mgr:
            return ""
        try:
            return (git_mgr.run_git(cmd, target_version, timeout=timeout) or "").strip()
        except Exception:
            return ""

    head_commit = _run(["git", "rev-parse", "HEAD"])
    current_branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    head_commit_time = _run(["git", "log", "-1", "--format=%cI", "HEAD"])
    remote_url = _run(["git", "remote", "get-url", "origin"])

    return {
        "target_version": target_version,
        "path": repo_path or "",
        "configured_branch": configured_branch,
        "current_branch": current_branch,
        "head_commit": head_commit,
        "head_commit_short": head_commit[:12] if head_commit else "",
        "head_commit_time": head_commit_time,
        "remote_url": remote_url,
    }
