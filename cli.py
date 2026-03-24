#!/usr/bin/env python3
"""
CVE补丁回溯分析 - 命令行工具

用法:
  python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
  python cli.py check-intro --commit <introduced_commit_id> --target 5.10-hulk
  python cli.py check-intro --cve CVE-2024-26633 --target 5.10-hulk
  python cli.py check-fix --commit <fix_commit_id> --target 5.10-hulk
  python cli.py check-fix --cve CVE-2024-26633 --target 5.10-hulk
  python cli.py validate --cve CVE-xxx --target 5.10-hulk --known-fix <commit> [--mainline-fix <commit>]
  python cli.py benchmark --file benchmarks.yaml --target 5.10-hulk
  python cli.py batch-validate --file cve_data.json --target 5.10-hulk [--offset N] [--limit N]
  python cli.py build-cache --target 5.10-hulk
  python cli.py search --commit abc123 --target 5.10-hulk
"""

import argparse
import json
import sys
import os
import logging
import tempfile
import time
from datetime import datetime
from dataclasses import asdict
import re
from urllib.parse import urlparse

from rich.console import Console, Group
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich import box

from core.config import ConfigLoader
from core.git_manager import GitRepoManager
from core.ui import (
    console, StageTracker, make_header, render_report,
    render_recommendations, render_multi_strategy, make_cache_progress,
    render_validate_report, render_benchmark_report,
    render_batch_validate_report,
)
from pipeline import Pipeline, STAGES

logger = logging.getLogger("cve_backporting")


def _setup_logging(config, quiet: bool = False):
    level = logging.WARNING if quiet else getattr(logging, config.output.log_level.upper(), logging.INFO)
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt)
    if config.output.log_file:
        fh = logging.FileHandler(config.output.log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(fmt))
        logging.getLogger().addHandler(fh)


def _make_git_mgr(config, tv: str) -> GitRepoManager:
    rc = config.repositories.get(tv)
    if not rc or not rc.get("path"):
        console.print(f"[red bold]错误:[/] 未配置版本 {tv}")
        sys.exit(1)
    return GitRepoManager(
        {tv: {"path": rc["path"], "branch": rc.get("branch")}},
        use_cache=config.cache.enabled,
    )


def _coerce_commit_list(values):
    """将配置/请求参数中的 commit 列表统一成标准 list[str]。"""
    if not values:
        return []
    if isinstance(values, str):
        return [v.strip() for v in values.split(",") if v.strip()]
    if isinstance(values, (list, tuple, set)):
        return [str(v).strip() for v in values if str(v).strip()]
    return [str(values).strip()] if str(values).strip() else []


def _coerce_commit_url_base(value: str) -> str:
    if not value:
        return ""
    v = value.strip().rstrip("/")
    if v.endswith(".git"):
        v = v[:-4]
    return v


def _build_commit_url_from_remote(remote_url: str, commit_id: str) -> str:
    if not remote_url or not commit_id:
        return ""
    candidate = _coerce_commit_url_base(remote_url.strip())
    if not candidate:
        return ""

    # git@host:group/repo 或 ssh://git@host/group/repo
    if candidate.startswith("git@") or candidate.startswith("ssh://git@"):
        m = re.match(r"^(?:ssh://)?git@(?P<host>[^:]+):(?P<path>.+)$", candidate)
        if m:
            host = m.group("host")
            path = _coerce_commit_url_base(m.group("path"))
            path = path.lstrip("/")
            base = f"https://{host}/{path}"
        else:
            base = candidate
    elif "://" in candidate:
        parsed = urlparse(candidate)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    else:
        base = candidate

    base = _coerce_commit_url_base(base)
    host = ""
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


def _resolve_repo_config(config, target: str) -> dict:
    rc = config.repositories.get(target, {})
    if isinstance(rc, dict):
        return rc
    return {"path": rc} if rc else {}


def _resolve_commit_url(config, git_mgr, target: str, commit_id: str) -> str:
    if not commit_id:
        return ""

    rc = _resolve_repo_config(config, target)
    tmpl = (rc.get("commit_url_template")
            or rc.get("commit_url")
            or rc.get("web_url")
            or rc.get("url")
            or rc.get("remote_url"))

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
            url = _coerce_commit_url_base(tmpl)
            if any(s in url.lower() for s in ("http://", "https://", "git@")):
                return _build_commit_url_from_remote(url, commit_id)

    try:
        remote = git_mgr.run_git(["git", "remote", "get-url", "origin"], target, timeout=10)
    except Exception:
        remote = None
    if remote:
        return _build_commit_url_from_remote(remote, commit_id)
    return ""


def _serialize_commit_reference(config, git_mgr, target: str, commit_id: str, *,
                               extra: dict = None) -> dict:
    cid = (commit_id or "").strip()
    if not cid:
        return {"commit_id": "", "commit_id_short": ""}
    data = {"commit_id": cid, "commit_id_short": cid[:12]}
    if extra:
        data.update(extra)
    url = _resolve_commit_url(config, git_mgr, target, cid)
    if url:
        data["commit_url"] = url
    return data


def _collect_prereq_patches(patches, config, git_mgr, target: str):
    out = []
    for p in patches or []:
        d = asdict(p) if hasattr(p, "__dict__") else dict(p)
        cid = d.get("commit_id", "")
        ref = _serialize_commit_reference(config, git_mgr, target, cid)
        d.update(ref)
        out.append(d)
    return out


def _collect_level_policies():
    try:
        from rules.level_policies import LEVEL_POLICIES
    except Exception:
        return []
    out = []
    for p in LEVEL_POLICIES:
        out.append({
            "level": p.level,
            "methods": list(getattr(p, "methods", [])),
            "strategy": getattr(p, "strategy", ""),
            "review_mode": getattr(p, "review_mode", ""),
            "next_action": getattr(p, "next_action", ""),
            "confidence_with_llm": getattr(p, "confidence_with_llm", ""),
            "confidence_without_llm": getattr(p, "confidence_without_llm", ""),
        })
    return out


def _collect_rules_metadata(policy_config, level_decision=None, validation_details=None):
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
        "level_policies": _collect_level_policies(),
    }

    if validation_details:
        payload["validation_context"] = {
            "rule_profile": validation_details.get("rule_profile", ""),
            "rule_version": validation_details.get("rule_version", ""),
            "workflow_steps": validation_details.get("workflow_steps", []),
            "warnings": validation_details.get("warnings", []),
        }

    if level_decision:
        if hasattr(level_decision, "__dict__"):
            payload["level_decision"] = asdict(level_decision)
        elif isinstance(level_decision, dict):
            payload["level_decision"] = level_decision
        if hasattr(level_decision, "rule_hits"):
            payload["rule_hits"] = list(getattr(level_decision, "rule_hits", []) or [])
        elif isinstance(level_decision, dict):
            payload["rule_hits"] = list(level_decision.get("rule_hits", []) or [])

    return payload


def _make_stage_trace_tracker(stage_callback=None):
    events = []
    starts = {}

    def track(key, status, detail=""):
        now = time.time()
        if status == "running":
            starts[key] = now
            events.append({
                "stage": key,
                "status": "running",
                "detail": detail,
                "duration_ms": 0.0,
            })
        else:
            st = starts.pop(key, None)
            duration_ms = round((now - st) * 1000, 2) if st is not None else 0.0
            events.append({
                "stage": key,
                "status": status,
                "detail": detail,
                "duration_ms": duration_ms,
            })
        if stage_callback:
            stage_callback(key, status, detail)

    return events, track


def _build_analyze_payload(result, pipe: Pipeline, config, target: str,
                          stage_events: list = None,
                          policy_config=None, deep_analysis=None):
    prereqs = _collect_prereq_patches(
        result.prerequisite_patches, config, pipe.git_mgr, target)

    cve_commit_urls = {}
    if result.cve_info and result.cve_info.version_commit_mapping:
        for ver, cid in result.cve_info.version_commit_mapping.items():
            cve_commit_urls[ver] = _serialize_commit_reference(
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
        fix_patch_detail = _serialize_commit_reference(
            config, pipe.git_mgr, target, fp.commit_id,
            extra={
                "subject": fp.subject,
                "author": fp.author,
                "modified_files": fp.modified_files,
                "diff_lines": len((fp.diff_code or "").splitlines()),
            }
        )

    try:
        narrative = _build_analysis_narrative(
            result, dr_detail, {}, {}, is_validate=False)
    except Exception:
        narrative = {}

    valid_details = {}
    if result.validation_details:
        valid_details = {
            "rule_profile": getattr(result.validation_details, "rule_profile", ""),
            "rule_version": getattr(result.validation_details, "rule_version", ""),
            "workflow_steps": getattr(result.validation_details, "workflow_steps", []),
            "warnings": getattr(result.validation_details, "warnings", []),
        }

    payload = {
        "cve_id": result.cve_id,
        "target_version": target,
        "is_vulnerable": result.is_vulnerable,
        "is_fixed": result.is_fixed,
        "dry_run_clean": result.dry_run.applies_cleanly if result.dry_run else None,
        "dryrun_detail": dr_detail,
        "prerequisite_patches": prereqs,
        "version_commit_mapping_urls": cve_commit_urls,
        "rules": _collect_rules_metadata(
            policy_config,
            level_decision=result.level_decision,
            validation_details=valid_details,
        ),
        "analysis_narrative": narrative,
        "recommendations": result.recommendations,
        "analysis_stages": stage_events or [],
        "fix_patch_detail": fix_patch_detail,
        "level_decision": result.level_decision.__dict__ if result.level_decision else {},
        "validation_details": valid_details,
        "function_impacts": [fi.__dict__ for fi in (result.function_impacts or [])],
    }
    if deep_analysis is not None:
        payload["deep_analysis"] = _v2_to_json(deep_analysis)

    return payload


def run_analyze_payload(cve_id: str, target_version: str, config, *,
                       enable_dryrun: bool = True, deep: bool = False,
                       stage_callback=None):
    git_mgr = _make_git_mgr(config, target_version)
    pipe = Pipeline(git_mgr, path_mappings=config.path_mappings,
                    llm_config=config.llm,
                    policy_config=getattr(config, "policy", None))

    stage_events, record_stage = _make_stage_trace_tracker(
        stage_callback=stage_callback)

    result = pipe.analyze(cve_id, target_version,
                          enable_dryrun=enable_dryrun,
                          on_stage=record_stage)

    deep_analysis = None
    if deep:
        deep_analysis = pipe.analyze_deep(cve_id, target_version,
                                         on_stage=record_stage)

    return _build_analyze_payload(
        result, pipe, config, target_version,
        stage_events=stage_events,
        policy_config=getattr(config, "policy", None),
        deep_analysis=deep_analysis,
    )


# ─── analyze ─────────────────────────────────────────────────────────

def cmd_analyze(args, config):
    git_mgr = _make_git_mgr(config, args.target_version)
    pipe = Pipeline(git_mgr, path_mappings=config.path_mappings,
                    llm_config=config.llm,
                    policy_config=getattr(config, "policy", None))

    cves = [args.cve_id] if args.cve_id else []
    if args.batch_file:
        with open(args.batch_file) as f:
            cves = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not cves:
        console.print("[red]请指定 --cve 或 --batch[/]")
        sys.exit(1)

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)

    deep = getattr(args, "deep", False)
    for cve_id in cves:
        if deep:
            _analyze_deep(pipe, cve_id, args.target_version, out_dir=out_dir,
                         policy_config=getattr(config, "policy", None))
        else:
            _analyze_one(pipe, cve_id, args.target_version,
                         config,
                         enable_dryrun=not args.no_dryrun, out_dir=out_dir,
                         policy_config=getattr(config, "policy", None))


def _analyze_one(pipe: Pipeline, cve_id: str, target: str,
                 enable_dryrun: bool, out_dir: str, config, policy_config=None):
    tracker = StageTracker(STAGES)
    header = make_header(cve_id, target)
    stage_events, record_stage = _make_stage_trace_tracker()

    def on_stage(key, status, detail=""):
        tracker.start(key) if status == "running" else tracker.done(key, status, detail)

    def _layout():
        return Group(header, tracker.render())

    with Live(_layout(), console=console, refresh_per_second=8) as live:
        def _update(key, status, detail=""):
            on_stage(key, status, detail)
            record_stage(key, status, detail)
            live.update(_layout())

        result = pipe.analyze(cve_id, target,
                              enable_dryrun=enable_dryrun,
                              on_stage=_update)

    console.print()
    console.print(render_report(result, policy_config=policy_config))
    console.print(render_recommendations(result))

    # 输出生成的 patch 文件
    if result.dry_run and result.dry_run.adapted_patch:
        patch_file = os.path.join(out_dir, f"{cve_id}_{target}_adapted.patch")
        with open(patch_file, "w") as f:
            f.write(result.dry_run.adapted_patch)
        console.print(f"\n[green]✔ 生成的适配补丁已保存:[/] [cyan]{patch_file}[/]")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = os.path.join(out_dir, f"{cve_id}_{target}_{ts}.json")
    payload = _build_analyze_payload(
        result, pipe, config, target,
        stage_events=stage_events,
        policy_config=policy_config)

    with open(fp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    console.print(f"[dim]报告已保存: {fp}[/]")


# ─── analyze --deep ──────────────────────────────────────────────────

def _analyze_deep(pipe, cve_id: str, target: str, out_dir: str, policy_config=None):
    """深度分析模式: v1 基础 + v2 扩展 (社区/漏洞/检视/风险/建议)"""
    from pipeline import STAGES_DEEP

    tracker = StageTracker(STAGES_DEEP)
    header = make_header(cve_id, target, extra="[bold magenta] DEEP[/]")

    def on_stage(key, status, detail=""):
        tracker.start(key) if status == "running" else tracker.done(key, status, detail)

    def _layout():
        return Group(header, tracker.render())

    with Live(_layout(), console=console, refresh_per_second=8) as live:
        def _update(key, status, detail=""):
            on_stage(key, status, detail)
            live.update(_layout())

        v2 = pipe.analyze_deep(cve_id, target, on_stage=_update)

    console.print()

    base = v2.base
    if base:
        console.print(render_report(base, policy_config=policy_config))
        console.print(render_recommendations(base))

    _render_deep_report(v2)

    if base and base.dry_run and base.dry_run.adapted_patch:
        patch_file = os.path.join(out_dir, f"{cve_id}_{target}_adapted.patch")
        with open(patch_file, "w") as f:
            f.write(base.dry_run.adapted_patch)
        console.print(f"\n[green]✔ 生成的适配补丁已保存:[/] [cyan]{patch_file}[/]")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = os.path.join(out_dir, f"{cve_id}_{target}_deep_{ts}.json")
    _save_deep_json(v2, fp)
    console.print(f"[dim]深度分析报告已保存: {fp}[/]")


def _render_dep_analysis(console, v2):
    """渲染关联补丁分析面板 — 无论有无关联补丁都输出完整分析"""
    from rich.panel import Panel
    from rich.text import Text

    base = v2.base
    if not base:
        return

    dep_text = Text()
    prereqs = base.prerequisite_patches or []
    post = v2.post_patches or []
    review = v2.patch_review
    dr = base.dry_run
    fix = base.fix_patch

    strong = [p for p in prereqs if p.grade == "strong"]
    medium = [p for p in prereqs if p.grade == "medium"]
    weak = [p for p in prereqs if p.grade == "weak"]

    # ── 前置补丁 ──────────────────────
    dep_text.append("前置补丁分析\n", style="bold underline")

    if not prereqs:
        dep_text.append("  未检测到前置依赖补丁\n", style="green")
        reasons = []
        if dr and dr.applies_cleanly:
            reasons.append(
                "补丁可在目标版本干净应用，代码上下文与上游一致，"
                "无因缺失前置补丁导致的文本冲突")
        if fix and fix.modified_files and len(fix.modified_files) <= 2:
            reasons.append(
                f"仅修改 {len(fix.modified_files)} 个文件，"
                f"改动范围集中")
        has_ds = (review and review.data_structures
                  and len(review.data_structures) > 0)
        if not has_ds:
            reasons.append(
                "未引入或依赖新的数据结构定义")
        elif has_ds:
            ds_names = [d.get("name", d["type"])
                        for d in review.data_structures[:3]]
            reasons.append(
                f"涉及的数据结构 ({', '.join(ds_names)}) "
                f"在目标版本中已存在")
        for r in reasons:
            dep_text.append(f"  • {r}\n", style="dim")
        dep_text.append(
            "  结论: 该补丁可独立合入，不依赖其他前置改动\n\n",
            style="green")
    else:
        dep_text.append(
            f"  检测到 {len(prereqs)} 个关联补丁 "
            f"(强依赖 {len(strong)} / 中依赖 {len(medium)} "
            f"/ 弱关联 {len(weak)})\n",
            style="yellow")
        if strong:
            dep_text.append(
                "  强依赖 — 缺失将导致编译失败或语义错误:\n",
                style="red bold")
            for p in strong[:5]:
                dep_text.append(f"    {p.commit_id[:12]}", style="red")
                dep_text.append(f" {p.subject}\n")
                extra = []
                if p.overlap_funcs:
                    extra.append(
                        f"共享函数: {', '.join(p.overlap_funcs[:3])}")
                if p.overlap_hunks:
                    extra.append(f"{p.overlap_hunks} 个重叠代码块")
                if p.adjacent_hunks:
                    extra.append(f"{p.adjacent_hunks} 个相邻代码块")
                if extra:
                    dep_text.append(
                        f"      {'; '.join(extra)}\n", style="dim")
        if medium:
            dep_text.append(
                "  中依赖 — 建议评估是否需要先合入:\n",
                style="yellow bold")
            for p in medium[:3]:
                dep_text.append(f"    {p.commit_id[:12]}", style="yellow")
                dep_text.append(f" {p.subject}\n")
                if p.overlap_funcs:
                    dep_text.append(
                        f"      重叠函数: "
                        f"{', '.join(p.overlap_funcs[:3])}\n",
                        style="dim")

        if dr and dr.applies_cleanly:
            dep_text.append(
                "  注: 补丁本身可干净应用，前置补丁提供的是"
                "编译/运行时依赖 (数据结构、API)，非文本冲突\n",
                style="dim italic")
        dep_text.append("\n")

    # ── 后置补丁 ──────────────────────
    dep_text.append("后置补丁分析\n", style="bold underline")

    if not post:
        dep_text.append("  未检测到后续关联补丁\n", style="green")
        dep_text.append(
            "  结论: 该修复在上游社区是自包含的，"
            "无需额外的追加修正\n", style="green")
    else:
        followups = [p for p in post if p.relation == "followup_fix"]
        same_func = [p for p in post if p.relation == "same_function"]
        dep_text.append(
            f"  检测到 {len(post)} 个后置关联补丁\n", style="yellow")
        if followups:
            dep_text.append(
                f"  后续修复 (Fixes: 标签引用本补丁，共 "
                f"{len(followups)} 个):\n", style="yellow bold")
            for p in followups[:5]:
                dep_text.append(f"    {p.commit_id[:12]}", style="yellow")
                dep_text.append(f" {p.subject}\n")
            dep_text.append(
                "    → 建议一并合入这些后续修复\n", style="dim")
        if same_func:
            dep_text.append(
                f"  同函数修改 (共 {len(same_func)} 个):\n",
                style="cyan bold")
            for p in same_func[:5]:
                dep_text.append(f"    {p.commit_id[:12]}", style="cyan")
                dep_text.append(f" {p.subject}\n")
                if p.description:
                    dep_text.append(
                        f"      {p.description}\n", style="dim")
            dep_text.append(
                "    → 建议评估是否影响修复补丁正确性\n", style="dim")

    console.print(Panel(dep_text, title="关联补丁分析",
                        border_style="cyan"))
    console.print()


def _render_deep_report(v2):
    """TUI 渲染 v2 深度分析结果 — 详细文本面板"""
    from rich.table import Table

    # ── 漏洞深度分析 ──────────────────────────────────────────────
    if v2.vuln_analysis:
        va = v2.vuln_analysis
        vuln_text = Text()
        _sev_colors = {"critical": "red bold", "high": "yellow bold",
                       "medium": "yellow", "low": "dim"}
        _sev_cn = {"critical": "严重", "high": "高危",
                   "medium": "中危", "low": "低危"}
        sev_color = _sev_colors.get(va.severity, "")
        sev_cn = _sev_cn.get(va.severity, va.severity)

        vuln_text.append("漏洞类型: ", style="bold cyan")
        vuln_text.append(f"{va.vuln_type}\n", style="bold")
        vuln_text.append("严重度: ", style="bold cyan")
        vuln_text.append(f"{sev_cn}\n", style=sev_color)
        vuln_text.append("子系统: ", style="bold cyan")
        vuln_text.append(f"{va.affected_subsystem}\n")
        if va.affected_functions:
            vuln_text.append("影响函数: ", style="bold cyan")
            vuln_text.append(f"{', '.join(va.affected_functions[:8])}\n")

        vuln_text.append("\n")
        vuln_text.append("技术根因分析\n", style="bold underline")
        vuln_text.append(f"{va.root_cause or '待分析'}\n")

        if va.trigger_path:
            vuln_text.append("\n")
            vuln_text.append("触发路径\n", style="bold underline")
            vuln_text.append(f"{va.trigger_path}\n")

        if va.exploit_conditions:
            vuln_text.append("\n")
            vuln_text.append("利用条件\n", style="bold underline")
            vuln_text.append(f"{va.exploit_conditions}\n")

        if va.impact_description:
            vuln_text.append("\n")
            vuln_text.append("影响评估\n", style="bold underline")
            vuln_text.append(f"{va.impact_description}\n")

        if va.detection_method:
            vuln_text.append("\n")
            vuln_text.append("检测与验证方法\n", style="bold underline")
            vuln_text.append(f"{va.detection_method}\n")

        vuln_text.append("\n")
        vuln_text.append("分析方式: ", style="dim")
        vuln_text.append(
            "LLM 增强分析" if va.llm_enhanced else "确定性规则分析",
            style="dim")

        console.print(Panel(vuln_text, title="漏洞深度分析",
                           border_style="red"))
        console.print()

    # ── 补丁逻辑检视 ──────────────────────────────────────────────
    if v2.patch_review:
        pr = v2.patch_review
        pr_text = Text()

        pr_text.append("修复摘要\n", style="bold underline")
        pr_text.append(f"{pr.fix_summary or '待分析'}\n")

        pr_text.append("\n")
        pr_text.append("原始漏洞触发分析\n", style="bold underline")
        pr_text.append(f"{pr.trigger_analysis or '待分析'}\n")

        pr_text.append("\n")
        pr_text.append("修复预防机制\n", style="bold underline")
        pr_text.append(f"{pr.prevention_mechanism or '待分析'}\n")

        pr_text.append("\n")
        pr_text.append("分析方式: ", style="dim")
        pr_text.append(
            "LLM 增强分析" if pr.llm_enhanced else "确定性规则分析",
            style="dim")

        console.print(Panel(pr_text, title="补丁逻辑检视",
                           border_style="cyan"))

        if pr.code_review_items:
            ri_tbl = Table(title="代码检视条目", box=box.SIMPLE,
                           padding=(0, 1))
            ri_tbl.add_column("级别", width=10)
            ri_tbl.add_column("分类", width=14)
            ri_tbl.add_column("描述")
            for item in pr.code_review_items[:10]:
                sev_style = {"critical": "red bold", "warning": "yellow",
                             "info": "dim"}.get(item.severity, "")
                ri_tbl.add_row(
                    Text(item.severity, style=sev_style),
                    item.category,
                    item.description,
                )
            console.print(ri_tbl)
        console.print()

    # ── 社区讨论 ──────────────────────────────────────────────────
    if v2.community:
        tbl = Table(title="社区讨论", box=box.SIMPLE, padding=(0, 1))
        tbl.add_column("来源", width=10)
        tbl.add_column("标题/URL", ratio=3)
        tbl.add_column("关联", width=12)
        for d in v2.community[:8]:
            tbl.add_row(d.source, d.title or d.url, d.relevance)
        console.print(tbl)
        console.print()

    # ── 关联补丁分析 (前置 + 后置) ──────────────────────────────────
    _render_dep_analysis(console, v2)

    # ── 风险收益评估 (详细文本) ────────────────────────────────────
    rec = v2.merge_recommendation
    rb = None
    if rec and hasattr(rec, 'risk_benefit') and rec.risk_benefit:
        rb = rec.risk_benefit

    if rb and (rb.merge_complexity_detail or rb.overall_detail):
        rb_text = Text()

        _dim_labels = [
            ("合入复杂度", rb.merge_complexity, rb.merge_complexity_detail),
            ("回归风险", rb.regression_risk, rb.regression_risk_detail),
            ("变更范围", rb.change_scope, rb.change_scope_detail),
            ("安全收益", rb.security_benefit, rb.security_benefit_detail),
        ]
        for dim_name, dim_val, dim_detail in _dim_labels:
            if not dim_detail:
                continue
            if dim_name == "安全收益":
                color = "green" if dim_val >= 0.5 else (
                    "yellow" if dim_val >= 0.3 else "red")
            else:
                color = "green" if dim_val < 0.3 else (
                    "yellow" if dim_val < 0.5 else "red")
            rb_text.append(f"\n{dim_detail}\n", style=color)

        if rb.overall_detail:
            rb_text.append("\n")
            rb_text.append(f"{rb.overall_detail}\n", style="bold")

        console.print(Panel(rb_text, title="风险收益评估",
                           border_style="magenta"))
        console.print()

    # ── 合入建议 ──────────────────────────────────────────────────
    if rec and hasattr(rec, 'action'):
        _action_cn = {
            "merge": "直接合入",
            "merge_with_prereqs": "合入 (需先处理前置依赖)",
            "manual_review": "需人工审查",
            "skip": "无需处理",
        }
        action_colors = {
            "merge": "green bold", "merge_with_prereqs": "yellow bold",
            "manual_review": "red bold", "skip": "dim",
        }
        color = action_colors.get(rec.action, "")
        action_cn = _action_cn.get(rec.action, rec.action)

        panel_content = Text()
        panel_content.append("建议操作: ", style="bold")
        panel_content.append(f"{action_cn}", style=color)
        panel_content.append(f" (置信度 {rec.confidence:.0%})\n")

        if rec.summary:
            panel_content.append(f"\n{rec.summary}\n")

        if hasattr(rec, 'prerequisite_actions') and rec.prerequisite_actions:
            panel_content.append("\n前置操作:\n", style="bold underline")
            for a in rec.prerequisite_actions:
                panel_content.append(f"  • {a}\n")

        if hasattr(rec, 'review_checklist') and rec.review_checklist:
            panel_content.append("\n检视清单:\n", style="bold underline")
            for c in rec.review_checklist:
                panel_content.append(f"  □ {c}\n")

        console.print(Panel(panel_content, title="合入建议",
                           border_style="blue"))


def _save_deep_json(v2, filepath: str):
    """将 v2 深度分析结果保存为 JSON"""
    from dataclasses import asdict

    base = v2.base
    data = {}

    if base:
        prereqs = [asdict(p) for p in base.prerequisite_patches] if base.prerequisite_patches else []
        dr_detail = {}
        if base.dry_run:
            dr = base.dry_run
            dr_detail = {
                "applies_cleanly": dr.applies_cleanly,
                "apply_method": dr.apply_method,
                "conflicting_files": dr.conflicting_files,
                "has_adapted_patch": bool(dr.adapted_patch),
            }
        data.update({
            "cve_id": base.cve_id,
            "target_version": base.target_version,
            "is_vulnerable": base.is_vulnerable,
            "is_fixed": base.is_fixed,
            "dryrun_detail": dr_detail,
            "prerequisite_patches": prereqs,
            "recommendations": base.recommendations,
        })

    data["deep_analysis"] = v2.to_dict()

    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def _v2_to_json(v2) -> dict:
    """将 AnalysisResultV2 序列化为 JSON 友好的 dict"""
    if v2 is None:
        return {}
    try:
        return v2.to_dict()
    except Exception:
        return {}


def _prepare_validate_json(result: dict) -> dict:
    """准备 validate 结果供 JSON 序列化 — 处理 deep_analysis 对象"""
    out = {}
    for k, v in result.items():
        if k == "deep_analysis" and v is not None:
            out["deep_analysis"] = _v2_to_json(v)
        else:
            out[k] = v
    return out


# ─── check-intro ─────────────────────────────────────────────────────

def cmd_check_intro(args, config):
    """
    检测漏洞引入commit是否存在于目标仓库。
    支持两种输入：
      --commit <id>   直接指定 mainline 引入 commit ID
      --cve <id>      从 CVE 信息自动提取引入 commit ID
    """
    from agents.crawler import CrawlerAgent
    from agents.analysis import AnalysisAgent

    git_mgr = _make_git_mgr(config, args.target_version)
    crawler = CrawlerAgent(git_mgr=git_mgr)
    from core.matcher import PathMapper
    analysis = AnalysisAgent(git_mgr, path_mapper=PathMapper(config.path_mappings))
    tv = args.target_version

    commit_ids = []

    # 如果指定了 CVE，自动提取引入 commit
    if args.cve_id:
        console.print(Panel(
            f"[bold]CVE:[/] {args.cve_id}  [bold]目标:[/] {tv}",
            title="[bold blue]漏洞引入检测 (CVE模式)[/]",
            border_style="blue", padding=(0, 2),
        ))
        with console.status("[cyan]获取CVE信息..."):
            cve = crawler.fetch_cve(args.cve_id)
        if not cve:
            console.print("[red]无法获取CVE信息[/]")
            return

        # 显示CVE信息
        from rich.table import Table
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True, show_edge=False)
        t.add_column("k", style="bold", width=16)
        t.add_column("v")
        t.add_row("CVE", cve.cve_id)
        t.add_row("描述", (cve.description[:120] + "...") if len(cve.description) > 120 else cve.description)
        ml = cve.mainline_fix_commit[:12] if cve.mainline_fix_commit else "N/A"
        t.add_row("Mainline Fix", f"[cyan]{ml}[/] ({cve.mainline_version or 'N/A'})")
        intro_id = cve.introduced_commit_id
        if intro_id:
            t.add_row("引入 Commit", f"[yellow]{intro_id[:12]}[/] [dim]({intro_id})[/]")
            commit_ids.append(intro_id)
        else:
            t.add_row("引入 Commit", "[red]CVE数据中无引入commit信息[/]")
        console.print(t)
        console.print()

        if not commit_ids:
            console.print("[yellow]该CVE没有引入commit信息，无法检测[/]")
            return

    elif args.commit_id:
        commit_ids = [args.commit_id]
        console.print(Panel(
            f"[bold]Commit:[/] {args.commit_id}  [bold]目标:[/] {tv}",
            title="[bold blue]漏洞引入检测 (Commit模式)[/]",
            border_style="blue", padding=(0, 2),
        ))
    else:
        console.print("[red]请指定 --commit 或 --cve[/]")
        return

    # 对每个引入commit运行多策略检测
    for cid in commit_ids:
        console.print(f"\n[bold]检测引入commit:[/] [cyan]{cid[:12]}[/]")

        # 获取commit补丁信息
        with console.status("[cyan]获取commit补丁信息..."):
            patch = crawler.fetch_patch(cid, tv)

        subject = patch.subject if patch else ""
        diff_code = patch.diff_code if patch else ""
        files = patch.modified_files if patch else []
        author = patch.author if patch else ""

        if patch:
            console.print(f"[dim]  Subject: {subject[:80]}[/]")
            console.print(f"[dim]  Files: {', '.join(files[:5])}[/]")
            console.print()

        # 三级策略搜索
        stages = [
            ("l1", "L1 │ ID 精确匹配"),
            ("l2", "L2 │ Subject 语义匹配"),
            ("l3", "L3 │ Diff 代码匹配"),
        ]
        tracker = StageTracker(stages)

        def _layout():
            return tracker.render()

        with Live(_layout(), console=console, refresh_per_second=8) as live:
            def _refresh():
                live.update(_layout())

            # 运行详细搜索，同时更新阶段状态
            tracker.start("l1")
            _refresh()

            msr = analysis.search_detailed(
                cid, subject, diff_code, files, author, tv)

            # 根据结果更新tracker
            for s in msr.strategies:
                key = {"L1": "l1", "L2": "l2", "L3": "l3"}[s.level]
                if s.found:
                    tracker.done(key, "success", f"{s.target_commit[:12]} ({s.confidence:.0%})")
                else:
                    tracker.done(key, "fail", s.detail[:60])
                _refresh()

        # 渲染多策略面板
        console.print()
        console.print(render_multi_strategy(msr))

        # 保存结果
        out_dir = config.output.output_dir
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fp = os.path.join(out_dir, f"check_intro_{cid[:12]}_{tv}_{ts}.json")
        with open(fp, "w", encoding="utf-8") as f:
            json.dump({
                "commit_id": cid,
                "subject": subject,
                "target_version": tv,
                "is_present": msr.is_present,
                "verdict": msr.verdict,
                "strategies": [
                    {
                        "level": s.level,
                        "name": s.name,
                        "found": s.found,
                        "confidence": s.confidence,
                        "target_commit": s.target_commit,
                        "detail": s.detail,
                        "elapsed": round(s.elapsed, 2),
                        "candidates": s.candidates[:3],
                    }
                    for s in msr.strategies
                ],
            }, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"[dim]结果已保存: {fp}[/]")


# ─── check-fix ───────────────────────────────────────────────────────

def cmd_check_fix(args, config):
    """
    检测漏洞修复commit是否已合入目标仓库。
    支持两种输入：
      --commit <id>   直接指定修复 commit ID
      --cve <id>      从 CVE 信息自动提取 mainline fix + stable backport
    """
    from agents.crawler import CrawlerAgent
    from agents.analysis import AnalysisAgent
    from core.matcher import PathMapper
    from rich.table import Table

    git_mgr = _make_git_mgr(config, args.target_version)
    crawler = CrawlerAgent(git_mgr=git_mgr)
    analysis = AnalysisAgent(git_mgr, path_mapper=PathMapper(config.path_mappings))
    tv = args.target_version

    check_list = []  # [(commit_id, label)]

    if args.cve_id:
        console.print(Panel(
            f"[bold]CVE:[/] {args.cve_id}  [bold]目标:[/] {tv}",
            title="[bold green]漏洞修复检测 (CVE模式)[/]",
            border_style="green", padding=(0, 2),
        ))
        with console.status("[cyan]获取CVE信息..."):
            cve = crawler.fetch_cve(args.cve_id)
        if not cve:
            console.print("[red]无法获取CVE信息[/]")
            return

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True, show_edge=False)
        t.add_column("k", style="bold", width=16)
        t.add_column("v")
        t.add_row("CVE", cve.cve_id)
        t.add_row("描述", (cve.description[:120] + "...") if len(cve.description) > 120 else cve.description)
        t.add_row("严重程度", cve.severity)

        if cve.mainline_fix_commit:
            ml = cve.mainline_fix_commit[:12]
            t.add_row("Mainline Fix", f"[cyan]{ml}[/] ({cve.mainline_version or 'N/A'})")
            check_list.append((cve.mainline_fix_commit, f"Mainline ({cve.mainline_version or 'N/A'})"))

        if cve.version_commit_mapping:
            ver_lines = []
            for ver, cid in cve.version_commit_mapping.items():
                ver_lines.append(f"{ver}: {cid[:12]}")
                if cid != cve.mainline_fix_commit and ver.startswith("5.10"):
                    check_list.append((cid, f"Stable backport ({ver})"))
            t.add_row("版本映射", "\n".join(ver_lines))

        if cve.introduced_commit_id:
            t.add_row("引入 Commit", f"[yellow]{cve.introduced_commit_id[:12]}[/]")

        console.print(t)
        console.print()

        if not check_list:
            console.print("[yellow]该CVE没有修复commit信息[/]")
            return

    elif args.commit_id:
        check_list = [(args.commit_id, "指定commit")]
        console.print(Panel(
            f"[bold]Commit:[/] {args.commit_id}  [bold]目标:[/] {tv}",
            title="[bold green]漏洞修复检测 (Commit模式)[/]",
            border_style="green", padding=(0, 2),
        ))
    else:
        console.print("[red]请指定 --commit 或 --cve[/]")
        return

    any_fixed = False

    for cid, label in check_list:
        console.print(f"\n[bold]检测修复commit:[/] [cyan]{cid[:12]}[/] [dim]({label})[/]")

        with console.status("[cyan]获取commit补丁信息..."):
            patch = crawler.fetch_patch(cid, tv)

        subject = patch.subject if patch else ""
        diff_code = patch.diff_code if patch else ""
        files = patch.modified_files if patch else []
        author = patch.author if patch else ""

        if patch and subject:
            console.print(f"[dim]  Subject: {subject[:80]}[/]")
            console.print(f"[dim]  Files: {', '.join(files[:5])}[/]")
            console.print()

        stages = [
            ("l1", "L1 │ ID 精确匹配"),
            ("l2", "L2 │ Subject 语义匹配"),
            ("l3", "L3 │ Diff 代码匹配"),
        ]
        tracker = StageTracker(stages)

        def _layout():
            return tracker.render()

        with Live(_layout(), console=console, refresh_per_second=8) as live:
            def _refresh():
                live.update(_layout())

            tracker.start("l1")
            _refresh()

            msr = analysis.search_detailed(
                cid, subject, diff_code, files, author, tv,
                use_containment=False)

            for s in msr.strategies:
                key = {"L1": "l1", "L2": "l2", "L3": "l3"}[s.level]
                if s.found:
                    tracker.done(key, "success", f"{s.target_commit[:12]} ({s.confidence:.0%})")
                else:
                    tracker.done(key, "fail", s.detail[:60])
                _refresh()

        console.print()
        console.print(render_multi_strategy(msr, mode="fix"))

        if msr.is_present:
            any_fixed = True

    # 汇总
    console.print()
    if any_fixed:
        console.print(Panel(
            "[green bold]结论: 修复补丁已合入目标仓库[/]",
            border_style="green", padding=(0, 2),
        ))
    else:
        console.print(Panel(
            "[red bold]结论: 修复补丁未合入目标仓库，需要 backport[/]",
            border_style="red", padding=(0, 2),
        ))

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = os.path.join(out_dir, f"check_fix_{args.cve_id or check_list[0][0][:12]}_{tv}_{ts}.json")
    with open(fp, "w", encoding="utf-8") as f:
        json.dump({
            "cve_id": args.cve_id or "",
            "target_version": tv,
            "is_fixed": any_fixed,
            "checked_commits": [
                {"commit_id": cid, "label": label}
                for cid, label in check_list
            ],
        }, f, indent=2, ensure_ascii=False, default=str)
    console.print(f"[dim]结果已保存: {fp}[/]")


# ─── validate / benchmark ────────────────────────────────────────────

def _find_rollback_commit(git_mgr, rv, known_fix, known_prereqs):
    """计算回滚目标：如果有 known_prereqs 则回滚到最早的 prereq 之前，否则回滚到 fix 之前"""
    if not known_prereqs:
        return f"{known_fix}~1"
    all_commits = list(known_prereqs) + [known_fix]
    earliest = all_commits[0]
    for c in all_commits[1:]:
        rc = git_mgr.run_git_rc(
            ["git", "merge-base", "--is-ancestor", c, earliest], rv)
        if rc == 0:
            earliest = c
    return f"{earliest}~1"


def _compare_prereqs(recommended, known_ids, git_mgr, rv):
    """
    对比工具推荐的前置依赖与真实合入记录。
    同时使用 ID 前缀匹配和 Subject 相似度匹配。
    """
    from core.matcher import subject_similarity

    rec_map = {p.commit_id[:12]: p.subject for p in recommended}
    act_map = {}
    for kid in known_ids:
        info = git_mgr.run_git(
            ["git", "log", "-1", "--format=%H\x1e%s", kid], rv, timeout=10)
        if info:
            parts = info.strip().split("\x1e")
            act_map[parts[0][:12]] = parts[1] if len(parts) > 1 else ""
        else:
            act_map[kid[:12]] = ""

    tp, fp, fn = set(), set(rec_map.keys()), set(act_map.keys())

    for rid, rsubj in rec_map.items():
        if rid in act_map:
            tp.add(rid)
            fp.discard(rid)
            fn.discard(rid)
            continue
        for aid, asubj in act_map.items():
            if aid not in fn:
                continue
            if asubj and rsubj and subject_similarity(rsubj, asubj) >= 0.80:
                tp.add(aid)
                fp.discard(rid)
                fn.discard(aid)
                break

    precision = len(tp) / len(rec_map) if rec_map else 1.0
    recall = len(tp) / len(act_map) if act_map else 1.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    return {
        "precision": precision, "recall": recall, "f1": f1,
        "true_positives": sorted(tp),
        "false_positives": sorted(fp),
        "false_negatives": sorted(fn),
    }


def _parse_diff_by_file(diff_text: str) -> dict:
    """将 unified diff 按文件拆分，返回 {filepath: diff_content}"""
    import re
    files = {}
    current_file = None
    current_lines = []
    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            if current_file:
                files[current_file] = "\n".join(current_lines)
            m = re.search(r" b/(.*)", line)
            current_file = m.group(1) if m else None
            current_lines = [line]
        elif current_file is not None:
            current_lines.append(line)
    if current_file:
        files[current_file] = "\n".join(current_lines)
    return files


def _extract_key_changes(diff_text: str, max_lines: int = 15) -> list:
    """提取 diff 中最有意义的变更行 (去除 context、header)"""
    changes = []
    for line in diff_text.split("\n"):
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+") or line.startswith("-"):
            stripped = line[1:].strip()
            if stripped and len(stripped) >= 4:
                changes.append(line)
        if len(changes) >= max_lines:
            break
    return changes


def _compare_patch_code(community_diff: str, local_diff: str) -> dict:
    """
    逐文件对比社区修复补丁和本地真实修复的代码差异。
    返回结构化对比结果:
    - overall_similarity: 总体相似度 0.0~1.0
    - per_file: 每个文件的对比详情
    - community_only_files / local_only_files: 仅一方有的文件
    - key_differences: 关键差异代码片段
    """
    from core.matcher import diff_similarity

    if not community_diff or not local_diff:
        return {"overall_similarity": 0.0, "per_file": [],
                "community_only_files": [], "local_only_files": [],
                "key_differences": [], "diagnosis": "缺少diff数据，无法对比"}

    comm_files = _parse_diff_by_file(community_diff)
    local_files = _parse_diff_by_file(local_diff)

    comm_set = set(comm_files.keys())
    local_set = set(local_files.keys())
    common = comm_set & local_set
    comm_only = sorted(comm_set - local_set)
    local_only = sorted(local_set - comm_set)

    per_file = []
    similarities = []
    key_diffs = []

    for fpath in sorted(common):
        sim = diff_similarity(comm_files[fpath], local_files[fpath])
        similarities.append(sim)

        comm_changes = _extract_key_changes(comm_files[fpath], 20)
        local_changes = _extract_key_changes(local_files[fpath], 20)
        comm_change_set = set(l[1:].strip() for l in comm_changes)
        local_change_set = set(l[1:].strip() for l in local_changes)
        only_in_community = [l for l in comm_changes
                             if l[1:].strip() not in local_change_set]
        only_in_local = [l for l in local_changes
                         if l[1:].strip() not in comm_change_set]

        per_file.append({
            "file": fpath,
            "similarity": round(sim, 3),
            "community_lines": len(comm_changes),
            "local_lines": len(local_changes),
            "only_in_community": only_in_community[:5],
            "only_in_local": only_in_local[:5],
        })

        if only_in_community or only_in_local:
            key_diffs.append({
                "file": fpath,
                "similarity": round(sim, 3),
                "community_extra": only_in_community[:3],
                "local_extra": only_in_local[:3],
            })

    overall = sum(similarities) / len(similarities) if similarities else 0.0

    return {
        "overall_similarity": round(overall, 3),
        "per_file": per_file,
        "community_only_files": comm_only,
        "local_only_files": local_only,
        "key_differences": key_diffs,
    }


def _diagnose_root_cause(diff_cmp: dict, dryrun_detail: dict,
                         known_prereqs: list, dry_run) -> list:
    """基于代码对比和 DryRun 结果生成根因诊断"""
    causes = []
    sim = diff_cmp.get("overall_similarity", 0)
    comm_only = diff_cmp.get("community_only_files", [])
    local_only = diff_cmp.get("local_only_files", [])
    applies = dryrun_detail.get("applies_cleanly", None) if dryrun_detail else None
    method = dryrun_detail.get("apply_method", "") if dryrun_detail else ""

    if sim >= 0.90:
        causes.append(
            f"社区补丁与本地修复代码高度一致 (相似度 {sim:.0%})，"
            "核心修复逻辑相同")
        if applies and method and method != "strict":
            method_desc = {
                "ignore-ws": "原始补丁存在空白格式差异 (tab/space), "
                             "通过 --ignore-whitespace 成功适配",
                "context-C1": "原始补丁的 context lines 有偏移 (中间 commit 修改了"
                              "相邻行), 已通过放宽 context 匹配 (-C1) 成功适配",
                "C1-ignore-ws": "原始补丁 context 偏移且存在空白差异, "
                                "通过 -C1 + --ignore-whitespace 成功适配",
                "3way": "原始补丁 context 偏移, 已通过 3-way merge 成功适配",
                "regenerated": "原始补丁 context 严重偏移, 已从目标文件重新生成 "
                               "context lines, 核心 +/- 改动行完全不变",
                "conflict-adapted": "中间 commit 修改了补丁涉及的同一行代码, "
                                    "已用目标文件实际内容替换补丁的 - 行、保留 + 行。"
                                    "适配补丁可应用但需人工审查语义正确性",
                "verified-direct": "原始补丁 context 严重偏移, 已在目标文件中"
                                   "直接定位变更点并验证, 完全绕过 git apply, "
                                   "核心 +/- 改动行完全不变",
            }.get(method, f"通过 {method} 适配成功")
            causes.append(f"上下文适配: {method_desc}")
        elif applies is False:
            # 检查是否有冲突分析数据
            c_hunks = dryrun_detail.get("conflict_hunks", []) if dryrun_detail else []
            if c_hunks:
                sev_counts = {}
                for h in c_hunks:
                    s = h.get("severity", "L3")
                    sev_counts[s] = sev_counts.get(s, 0) + 1
                sev_str = ", ".join(f"{k}: {v}个hunk" for k, v in sorted(sev_counts.items()))
                causes.append(
                    f"所有自动适配策略均失败, 冲突分析: {sev_str}。"
                    "中间 commit 修改了补丁涉及的同一行代码, "
                    "见下方逐 hunk 冲突详情")
            else:
                causes.append(
                    "代码一致但所有 DryRun 策略均失败 → "
                    "中间 commit 修改了补丁涉及的同一行代码, 需要人工介入")
        elif applies is True and method == "strict" and known_prereqs:
            causes.append(
                "代码一致且 strict 可干净应用，但实际修复时仍需前置补丁 → "
                "前置补丁提供的是编译/运行时依赖 (数据结构定义、API 声明等), "
                "而非文本层面的冲突")
    elif sim >= 0.60:
        causes.append(
            f"社区补丁与本地修复部分一致 (相似度 {sim:.0%})，"
            "本地修复可能包含额外适配改动")
        if comm_only:
            causes.append(
                f"社区补丁修改了本地修复未涉及的文件: "
                f"{', '.join(comm_only[:3])}")
        if local_only:
            causes.append(
                f"本地修复包含社区补丁没有的文件: "
                f"{', '.join(local_only[:3])}")
    elif sim > 0:
        causes.append(
            f"社区补丁与本地修复差异较大 (相似度仅 {sim:.0%})，"
            "本地修复很可能是完全重写或重新适配的版本")
    else:
        causes.append("无法获取代码进行对比")

    key_diffs = diff_cmp.get("key_differences", [])
    for kd in key_diffs[:2]:
        f = kd["file"]
        ce = kd.get("community_extra", [])
        le = kd.get("local_extra", [])
        if ce or le:
            detail = f"文件 {f} (相似度 {kd['similarity']:.0%}) 的关键差异: "
            if ce:
                detail += f"社区有而本地无: {ce[0][:60]}"
            if le:
                detail += f" | 本地有而社区无: {le[0][:60]}"
            causes.append(detail)

    return causes


def _build_analysis_narrative(result, dryrun_detail: dict,
                              generated_vs_real: dict,
                              diff_comparison: dict,
                              known_prereqs: list = None,
                              is_validate: bool = False) -> dict:
    """
    生成面向 CVE 补丁开发人员的可读分析过程描述。
    返回结构化 dict, 每个字段都是中文自然语言描述。
    """
    cve_info = result.cve_info
    dr = result.dry_run
    prereqs = result.prerequisite_patches or []
    fix_patch = result.fix_patch
    recs = result.recommendations or []

    # ── 1. 分析流程 (workflow) ────────────────────────────────
    workflow = []

    # Step 1: CVE 信息
    if cve_info:
        fix_id = cve_info.fix_commit_id or "未知"
        intro_id = cve_info.introduced_commit_id or "未知"
        workflow.append(
            f"1. 获取 CVE 信息: 社区修复 commit 为 {fix_id[:12]}"
            + (f", 漏洞引入 commit 为 {intro_id[:12]}"
               if intro_id != "未知" else ""))

    # Step 2: 获取补丁
    if fix_patch:
        workflow.append(
            f"2. 获取社区修复补丁: \"{fix_patch.subject}\", "
            f"涉及 {len(fix_patch.modified_files)} 个文件 "
            f"({', '.join(fix_patch.modified_files[:4])})")

    # Step 3: 引入检测
    if result.introduced_search:
        s = result.introduced_search
        if s.found:
            workflow.append(
                f"3. 漏洞引入检测: 目标仓库中找到了引入 commit "
                f"({s.target_commit[:12]}), "
                f"匹配策略={s.strategy}, "
                f"说明目标仓库受此漏洞影响")
        else:
            workflow.append(
                "3. 漏洞引入检测: 未在目标仓库中找到引入 commit, "
                "目标仓库可能不受此漏洞影响")
    else:
        workflow.append("3. 漏洞引入检测: 无引入 commit 信息, 默认认为受影响")

    # Step 4: 修复检测
    if result.fix_search:
        s = result.fix_search
        if s.found:
            workflow.append(
                f"4. 修复状态检测: 目标仓库中已存在修复 "
                f"({s.target_commit[:12]}), "
                f"匹配策略={s.strategy}")
        else:
            workflow.append(
                "4. 修复状态检测: 目标仓库中未找到修复, "
                "该漏洞尚未被修复")

    # Step 5: 前置依赖
    prereq_desc = _build_prereq_narrative(prereqs, known_prereqs)
    workflow.append(f"5. 前置依赖分析: {prereq_desc['conclusion']}")

    # Step 6: DryRun
    dryrun_desc = _build_dryrun_narrative(dr, dryrun_detail)
    workflow.append(f"6. 补丁试应用 (DryRun): {dryrun_desc['conclusion']}")

    # ── 2. 前置依赖详细分析 ───────────────────────────────────
    # (prereq_desc already built)

    # ── 3. 补丁适用性分析 ─────────────────────────────────────
    # (dryrun_desc already built)

    # ── 4. 补丁质量评估 (仅 validate) ────────────────────────
    quality_desc = {}
    if is_validate and generated_vs_real:
        quality_desc = _build_quality_narrative(
            generated_vs_real, diff_comparison)

    # ── 5. 开发者行动建议 ─────────────────────────────────────
    action = _build_action_suggestion(
        dr, prereqs, result.is_fixed, result.is_vulnerable)

    # ── 6. 策略分级与规则命中 (L0-L5) ─────────────────────────
    level_desc = {}
    if getattr(result, "level_decision", None):
        ld = result.level_decision
        level_desc = {
            "conclusion": (
                f"判定级别 {ld.level}（基线 {ld.base_level}/{ld.base_method or 'none'}），策略={ld.strategy}，"
                f"置信度={ld.confidence}，无害判定={ld.harmless}"
            ),
            "base_level": ld.base_level,
            "base_method": ld.base_method,
            "review_mode": ld.review_mode,
            "next_action": ld.next_action,
            "reason": ld.reason,
            "warnings": ld.warnings,
            "rule_hits": ld.rule_hits,
        }

    validate_detail_desc = {}
    if getattr(result, "validation_details", None):
        vd = result.validation_details
        validate_detail_desc = {
            "workflow_steps": vd.workflow_steps,
            "warnings": vd.warnings,
            "rule_profile": vd.rule_profile,
            "rule_version": vd.rule_version,
        }

    function_impact_desc = []
    for fi in getattr(result, "function_impacts", [])[:8]:
        function_impact_desc.append({
            "function": fi.function,
            "callers": fi.callers,
            "callees": fi.callees,
            "impact_score": fi.impact_score,
            "warnings": fi.warnings,
        })

    narrative = {
        "workflow": workflow,
        "prerequisite_analysis": prereq_desc,
        "patch_applicability": dryrun_desc,
        "developer_action": action,
        "level_decision": level_desc,
        "validation_details": validate_detail_desc,
        "function_impact": function_impact_desc,
    }
    if quality_desc:
        narrative["patch_quality_assessment"] = quality_desc
    return narrative


def _build_prereq_narrative(prereqs, known_prereqs=None):
    """生成前置依赖分析的详细描述"""
    if not prereqs:
        return {
            "conclusion": "无需前置补丁, 社区修复补丁可独立应用",
            "reason": (
                "工具分析了社区补丁涉及的所有文件, "
                "未发现必须先合入的其他补丁。"
                "补丁修改的函数/数据结构在目标仓库中均已存在且兼容。"),
            "details": [],
        }

    strong = [p for p in prereqs if p.grade == "strong"]
    medium = [p for p in prereqs if p.grade == "medium"]
    weak = [p for p in prereqs if p.grade not in ("strong", "medium")]

    parts = []
    if strong:
        parts.append(f"{len(strong)} 个强依赖 (必须先合入)")
    if medium:
        parts.append(f"{len(medium)} 个中等依赖 (建议先合入)")
    if weak:
        parts.append(f"{len(weak)} 个弱依赖 (可选)")

    conclusion = f"发现 {len(prereqs)} 个前置补丁: {', '.join(parts)}"
    reason = (
        "工具通过以下方式检测前置依赖: "
        "(a) 分析社区补丁的 removed 行是否依赖其他 commit 引入的代码; "
        "(b) 检查补丁修改的函数/结构体是否被其他 commit 修改过; "
        "(c) 分析相邻 hunk 的交叉引用关系。")

    details = []
    for p in prereqs[:5]:
        d = {
            "commit": p.commit_id[:12],
            "subject": p.subject,
            "grade": p.grade,
            "reason": (
                f"与修复补丁在 {p.overlap_hunks} 个 hunk 上有代码重叠, "
                f"{p.adjacent_hunks} 个 hunk 相邻"
                + (f", 共涉及函数: {', '.join(p.overlap_funcs[:3])}"
                   if p.overlap_funcs else "")),
        }
        details.append(d)

    # 如果有已知前置补丁 (validate 模式), 对比
    if known_prereqs:
        found_ids = {p.commit_id[:12] for p in prereqs}
        known_ids = {k[:12] for k in known_prereqs}
        matched = found_ids & known_ids
        missed = known_ids - found_ids
        extra = found_ids - known_ids
        if matched:
            reason += (
                f"\n与实际前置补丁对比: 命中 {len(matched)} 个 "
                f"({', '.join(matched)})")
        if missed:
            reason += (
                f", 遗漏 {len(missed)} 个 "
                f"({', '.join(missed)})")
        if extra:
            reason += (
                f", 多推荐 {len(extra)} 个 "
                f"({', '.join(extra)})")

    return {
        "conclusion": conclusion,
        "reason": reason,
        "details": details,
    }


def _build_dryrun_narrative(dr, dryrun_detail: dict):
    """生成补丁试应用的详细描述"""
    if not dr:
        return {
            "conclusion": "未执行 DryRun (可能因修复已检测到)",
            "method": "",
            "reason": "Pipeline 检测到修复可能已合入, 跳过了补丁试应用阶段。",
            "can_apply_directly": None,
        }

    method = dr.apply_method or ""
    applies = dr.applies_cleanly

    method_explanations = {
        "strict": (
            "社区补丁可以直接应用到目标仓库, 无需任何修改。"
            "这意味着目标仓库的代码上下文与社区主线完全一致, "
            "补丁的所有 context 行都能精确匹配。"),
        "ignore-ws": (
            "社区补丁与目标仓库存在空白字符差异 (tab/space/缩进), "
            "但代码逻辑完全一致。通过忽略空白差异后补丁可直接应用。"),
        "context-C1": (
            "社区补丁的上下文行与目标仓库有少量偏移 "
            "(可能是中间有其他 commit 修改了相邻行), "
            "通过放宽上下文匹配 (-C1) 后补丁可应用。"),
        "C1-ignore-ws": (
            "社区补丁同时存在上下文偏移和空白差异, "
            "通过放宽匹配+忽略空白后补丁可应用。"),
        "3way": (
            "社区补丁上下文偏移较大, 通过 3-way merge 成功应用。"
            "说明目标仓库与主线之间有较多中间修改, "
            "但不影响此补丁的核心修复逻辑。"),
        "regenerated": (
            "社区补丁的上下文行在目标仓库中已显著不同, "
            "工具在目标文件中精确定位了每个变更点, "
            "从目标文件重新生成了上下文行, 核心 +/- 改动行完全不变。"
            "重建后的补丁通过了 git apply 验证。"),
        "verified-direct": (
            "社区补丁的上下文行在目标仓库中已显著不同, "
            "工具在目标文件中直接定位了每个变更点并验证了匹配质量, "
            "然后在内存中直接修改文件内容生成了补丁。"
            "此方法完全绕过 git apply, 是最健壮的适配策略。"
            "核心 +/- 改动行完全不变。"),
        "conflict-adapted": (
            "社区补丁涉及的代码行在目标仓库中已被其他 commit 修改, "
            "工具用目标文件的实际内容替换了补丁的 - 行 (删除行), "
            "保留了 + 行 (添加行)。此补丁可应用但需人工审查。"),
    }

    if applies:
        reason = method_explanations.get(
            method,
            f"通过 {method} 策略成功应用。")
        conclusion = f"补丁可以应用 (策略: {method})"
    else:
        nc = len(dr.conflicting_files) if dr.conflicting_files else 0
        nh = len(dr.conflict_hunks) if dr.conflict_hunks else 0
        conclusion = f"补丁无法自动应用 ({nc} 个文件冲突, {nh} 个 hunk)"
        reason = (
            "工具尝试了多种策略 (严格匹配 → 忽略空白 → 放宽上下文 "
            "→ 3-way merge → 上下文重建 → 直接验证 → 冲突适配) "
            "均未成功。")
        if dr.error_output:
            err_short = dr.error_output[:200]
            reason += f"\n最后的错误信息: {err_short}"
        if nh > 0:
            sev = {}
            for h in dr.conflict_hunks:
                s = h.get("severity", "L3")
                sev[s] = sev.get(s, 0) + 1
            sev_str = ", ".join(
                f"{k}: {v}个" for k, v in sorted(sev.items()))
            reason += (
                f"\n冲突分析: {sev_str}。"
                "其中 L1=轻微可自动适配, L2=中度需审查, "
                "L3=重大需手动合入。")

    return {
        "conclusion": conclusion,
        "method": method,
        "reason": reason,
        "can_apply_directly": applies,
    }


def _build_quality_narrative(gvr: dict, diff_cmp: dict):
    """生成补丁质量评估描述 (validate 模式专用)"""
    verdict = gvr.get("verdict", "no_data")
    core_sim = gvr.get("core_similarity", 0)
    source = gvr.get("compare_source", "")

    verdict_desc = {
        "identical": "完全一致 — 工具生成的补丁与真实修复的核心改动行完全相同",
        "essentially_same": (
            "本质相同 — 核心改动逻辑一致, "
            "仅存在细微差异 (如注释、空行、格式)"),
        "partially_same": (
            "部分一致 — 部分核心改动相同, "
            "但存在缺失或多余的修改"),
        "different": "差异较大 — 工具生成的补丁与真实修复有本质区别",
        "no_data": "无法评估 — 缺少对比数据",
    }.get(verdict, verdict)

    source_desc = {
        "community_patch": (
            "对比基准: 使用社区原始补丁 (因补丁可直接应用, "
            "无需适配)"),
        "adapted_patch": (
            "对比基准: 使用工具适配后的补丁 "
            "(工具在目标文件中重新定位并重建了补丁)"),
        "adapted_patch(community)": (
            "对比基准: 使用社区原始补丁作为回退 "
            "(工具适配未产生新补丁, 行号可能不一致)"),
    }.get(source, source)

    conclusion = (
        f"核心改动相似度 {core_sim:.0%}, "
        f"评定: {verdict_desc}")
    reason = source_desc

    detail_parts = []
    for fd in gvr.get("detail", []):
        f = fd.get("file", "")
        cs = fd.get("core_similarity", 0)
        ga = fd.get("gen_added", 0)
        ra = fd.get("real_added", 0)
        ca = fd.get("common_added", 0)
        add_gen = fd.get("add_only_in_generated", [])
        add_real = fd.get("add_only_in_real", [])
        line = f"{f}: 相似度={cs:.0%}, 共同添加行={ca}/{ra}"
        if add_gen:
            line += f", 工具多出: {add_gen[0][:50]}"
        if add_real:
            line += f", 真实多出: {add_real[0][:50]}"
        detail_parts.append(line)

    return {
        "conclusion": conclusion,
        "reason": reason,
        "per_file": detail_parts,
    }


def _build_action_suggestion(dr, prereqs, is_fixed, is_vulnerable):
    """生成面向开发者的具体行动建议"""
    if is_fixed:
        return {
            "action": "无需操作",
            "reason": "修复补丁已经合入目标仓库。",
        }

    if not is_vulnerable:
        return {
            "action": "建议确认",
            "reason": (
                "未在目标仓库中找到漏洞引入 commit, "
                "目标仓库可能不受此漏洞影响。"
                "建议通过代码审查确认是否需要合入修复。"),
        }

    strong_prereqs = [p for p in prereqs if p.grade == "strong"]

    if dr and dr.applies_cleanly:
        method = dr.apply_method or ""
        if not prereqs:
            return {
                "action": "可直接合入",
                "reason": (
                    f"社区修复补丁通过 {method} 策略验证可应用, "
                    "且无前置依赖。建议直接 cherry-pick 或 "
                    "使用工具生成的适配补丁。"),
            }
        elif strong_prereqs:
            ids = ", ".join(p.commit_id[:12] for p in strong_prereqs)
            return {
                "action": "需先合入前置补丁",
                "reason": (
                    f"修复补丁本身可应用, 但依赖 "
                    f"{len(strong_prereqs)} 个强前置补丁 ({ids})。"
                    "需按顺序先合入前置补丁, 再合入修复补丁。"),
            }
        else:
            return {
                "action": "可直接合入 (建议先审查前置依赖)",
                "reason": (
                    f"修复补丁通过 {method} 验证可应用。"
                    f"工具发现 {len(prereqs)} 个可选前置补丁, "
                    "非强依赖, 但建议审查是否需要。"),
            }

    if dr and not dr.applies_cleanly:
        nc = len(dr.conflicting_files) if dr.conflicting_files else 0
        return {
            "action": "需人工适配",
            "reason": (
                f"社区修复补丁无法自动应用 "
                f"({nc} 个文件冲突)。"
                "建议: (1) 参考工具生成的冲突分析定位冲突点; "
                "(2) 手动修改补丁或 cherry-pick 后解决冲突; "
                "(3) 检查是否缺少前置补丁。"),
        }

    return {
        "action": "需进一步分析",
        "reason": "DryRun 未执行, 无法判断补丁是否可直接应用。",
    }


def _fuzzy_set_match_count(set_a: set, set_b: set,
                           threshold: float = 0.75) -> int:
    """模糊集合交集: 精确匹配优先，未匹配的用 SequenceMatcher 做模糊匹配"""
    import difflib as _dl
    exact = set_a & set_b
    count = len(exact)
    remain_a = set_a - exact
    remain_b = list(set_b - exact)
    used = set()
    for a in remain_a:
        best_r, best_idx = 0.0, -1
        for j, b in enumerate(remain_b):
            if j in used:
                continue
            r = _dl.SequenceMatcher(None, a, b).ratio()
            if r > best_r:
                best_r, best_idx = r, j
        if best_r >= threshold and best_idx >= 0:
            count += 1
            used.add(best_idx)
    return count


def _match_files_by_basename(gen_files: dict, real_files: dict,
                             already_matched: set) -> list:
    """当精确路径不匹配时，按 basename 回退匹配"""
    import os
    gen_remain = {k: v for k, v in gen_files.items() if k not in already_matched}
    real_remain = {k: v for k, v in real_files.items() if k not in already_matched}
    gen_by_bn = {}
    for p in gen_remain:
        bn = os.path.basename(p)
        gen_by_bn.setdefault(bn, []).append(p)
    real_by_bn = {}
    for p in real_remain:
        bn = os.path.basename(p)
        real_by_bn.setdefault(bn, []).append(p)
    pairs = []
    for bn in gen_by_bn.keys() & real_by_bn.keys():
        if len(gen_by_bn[bn]) == 1 and len(real_by_bn[bn]) == 1:
            pairs.append((gen_by_bn[bn][0], real_by_bn[bn][0]))
    return pairs


def _compare_generated_vs_real(generated_patch: str, real_diff: str) -> dict:
    """
    比较工具生成的适配补丁与本地真实修复补丁，判断两者是否"本质相同"。

    本质相同的定义：核心修改意图一致（即补丁的 +/- 行语义等价），
    即使 context 行、行号、空白格式存在差异。

    返回:
      verdict: "identical" / "essentially_same" / "partially_same" / "different"
      core_similarity: 核心改动行的相似度
      detail: 逐文件对比
    """
    from core.matcher import diff_similarity

    if not generated_patch or not real_diff:
        return {
            "verdict": "no_data",
            "core_similarity": 0.0,
            "overall_similarity": 0.0,
            "detail": [],
            "diagnosis": "缺少补丁数据，无法比较",
        }

    gen_files = _parse_diff_by_file(generated_patch)
    real_files = _parse_diff_by_file(real_diff)

    gen_set = set(gen_files.keys())
    real_set = set(real_files.keys())
    common = gen_set & real_set

    # basename 回退匹配: 社区路径与内部仓路径可能不同
    # (e.g., fs/cifs/connect.c vs fs/smb/client/connect.c)
    bn_pairs = _match_files_by_basename(gen_files, real_files, common)
    bn_mapped_gen = {gp for gp, _ in bn_pairs}
    bn_mapped_real = {rp for _, rp in bn_pairs}

    gen_only = sorted(gen_set - common - bn_mapped_gen)
    real_only = sorted(real_set - common - bn_mapped_real)

    file_details = []
    core_sims = []
    overall_sims = []

    all_pairs = [(f, f) for f in sorted(common)] + bn_pairs

    for gen_path, real_path in all_pairs:
        overall_sim = diff_similarity(gen_files[gen_path], real_files[real_path])
        overall_sims.append(overall_sim)

        gen_changes = _extract_key_changes(gen_files[gen_path], 200)
        real_changes = _extract_key_changes(real_files[real_path], 200)

        gen_added = [l[1:].strip() for l in gen_changes if l.startswith("+")]
        gen_removed = [l[1:].strip() for l in gen_changes if l.startswith("-")]
        real_added = [l[1:].strip() for l in real_changes if l.startswith("+")]
        real_removed = [l[1:].strip() for l in real_changes if l.startswith("-")]

        gen_add_set = set(gen_added)
        real_add_set = set(real_added)
        gen_rm_set = set(gen_removed)
        real_rm_set = set(real_removed)

        n_add_common = _fuzzy_set_match_count(gen_add_set, real_add_set)
        n_rm_common = _fuzzy_set_match_count(gen_rm_set, real_rm_set)

        total_gen = len(gen_add_set) + len(gen_rm_set)
        total_real = len(real_add_set) + len(real_rm_set)
        total_common = n_add_common + n_rm_common

        if total_gen + total_real > 0:
            core_sim = (2 * total_common) / (total_gen + total_real)
        else:
            core_sim = 1.0 if total_gen == 0 and total_real == 0 else 0.0
        core_sims.append(core_sim)

        exact_add = gen_add_set & real_add_set
        exact_rm = gen_rm_set & real_rm_set
        add_only_gen = sorted(gen_add_set - exact_add)
        add_only_real = sorted(real_add_set - exact_add)
        rm_only_gen = sorted(gen_rm_set - exact_rm)
        rm_only_real = sorted(real_rm_set - exact_rm)

        display = gen_path if gen_path == real_path else f"{gen_path} ↔ {real_path}"
        file_details.append({
            "file": display,
            "core_similarity": round(core_sim, 3),
            "overall_similarity": round(overall_sim, 3),
            "gen_added": len(gen_added),
            "real_added": len(real_added),
            "common_added": n_add_common,
            "gen_removed": len(gen_removed),
            "real_removed": len(real_removed),
            "common_removed": n_rm_common,
            "add_only_in_generated": add_only_gen[:5],
            "add_only_in_real": add_only_real[:5],
            "rm_only_in_generated": rm_only_gen[:3],
            "rm_only_in_real": rm_only_real[:3],
        })

    avg_core = sum(core_sims) / len(core_sims) if core_sims else 0.0
    avg_overall = sum(overall_sims) / len(overall_sims) if overall_sims else 0.0

    total_matched = len(common) + len(bn_pairs)
    file_coverage = total_matched / max(len(gen_set | real_set), 1)

    if avg_core >= 0.95 and file_coverage >= 0.9:
        verdict = "identical"
    elif avg_core >= 0.75 and file_coverage >= 0.7:
        verdict = "essentially_same"
    elif avg_core >= 0.40 or file_coverage >= 0.5:
        verdict = "partially_same"
    else:
        verdict = "different"

    diagnosis_parts = []
    if verdict in ("identical", "essentially_same"):
        diagnosis_parts.append(
            f"生成补丁与真实修复本质相同 (核心改动相似度 {avg_core:.0%})")
        if gen_only:
            diagnosis_parts.append(f"生成补丁额外修改了: {', '.join(gen_only[:3])}")
        if real_only:
            diagnosis_parts.append(f"真实修复额外修改了: {', '.join(real_only[:3])}")
    elif verdict == "partially_same":
        diagnosis_parts.append(
            f"生成补丁与真实修复部分一致 (核心改动相似度 {avg_core:.0%})")
        for fd in file_details:
            if fd["core_similarity"] < 0.5:
                extras = fd["add_only_in_real"][:2]
                if extras:
                    diagnosis_parts.append(
                        f"  {fd['file']}: 真实修复有额外改动 "
                        f"(如 +{extras[0][:50]})")
    else:
        diagnosis_parts.append(
            f"生成补丁与真实修复差异较大 (核心改动相似度仅 {avg_core:.0%})")

    return {
        "verdict": verdict,
        "core_similarity": round(avg_core, 3),
        "overall_similarity": round(avg_overall, 3),
        "file_coverage": round(file_coverage, 3),
        "gen_only_files": gen_only,
        "real_only_files": real_only,
        "detail": file_details,
        "diagnosis": " | ".join(diagnosis_parts),
    }


def _run_single_validate(config, cve_id, tv, known_fix, known_prereqs,
                         git_mgr=None, show_stages=True,
                         cve_info=None, deep=False, stage_callback=None):
    """执行单个 CVE 的回退验证，返回结果 dict。
    cve_info: 可选的预构建 CveInfo，提供后跳过 MITRE 爬取。
    deep: 是否同时执行 v2 深度分析。"""
    if git_mgr is None:
        git_mgr = _make_git_mgr(config, tv)

    status, _ = git_mgr.check_commit_existence(known_fix, tv)
    if status != "on_branch":
        msg = f"known_fix {known_fix[:12]} 不在目标分支 (status={status})"
        console.print(f"[red]{msg}[/]")
        return {"cve_id": cve_id, "known_fix": known_fix, "target": tv,
                "worktree_commit": "", "checks": {},
                "overall_pass": False, "summary": msg}

    rollback = _find_rollback_commit(git_mgr, tv, known_fix, known_prereqs)
    resolved = git_mgr.run_git(["git", "rev-parse", rollback], tv, timeout=10)
    rollback_hash = resolved.strip() if resolved else rollback

    wt_dir = tempfile.mkdtemp(prefix="cve_validate_")
    if not git_mgr.create_worktree(tv, rollback, wt_dir):
        console.print(f"[red]创建 worktree 失败 @ {rollback}[/]")
        return {"cve_id": cve_id, "known_fix": known_fix, "target": tv,
                "worktree_commit": rollback, "checks": {},
                "overall_pass": False, "summary": "创建worktree失败"}

    stage_events, record_stage = _make_stage_trace_tracker(stage_callback=stage_callback)

    try:
        wt_mgr = GitRepoManager(
            {tv: {"path": wt_dir, "branch": "HEAD"}},
            use_cache=False,
        )
        pipe = Pipeline(wt_mgr, path_mappings=config.path_mappings,
                        llm_config=config.llm if deep else None,
                        policy_config=getattr(config, "policy", None))

        if show_stages:
            tracker = StageTracker(STAGES)
            header = Panel(
                f"[bold]CVE:[/] {cve_id}  [bold]目标:[/] {tv}\n"
                f"[bold]回滚至:[/] {rollback_hash[:16]}  [dim](known_fix~)[/]",
                title="[bold magenta]验证模式 — 回退分析[/]",
                border_style="magenta", padding=(0, 2),
            )

            def on_stage(key, st, detail=""):
                tracker.start(key) if st == "running" else tracker.done(key, st, detail)

            def _layout():
                return Group(header, tracker.render())

            with Live(_layout(), console=console, refresh_per_second=8) as live:
                def _update(key, st, detail=""):
                    on_stage(key, st, detail)
                    live.update(_layout())
                    record_stage(key, st, detail)
                result = pipe.analyze(cve_id, tv, enable_dryrun=True,
                                      force_dryrun=True,
                                      on_stage=_update,
                                      cve_info=cve_info)
        else:
            result = pipe.analyze(cve_id, tv, enable_dryrun=True,
                                  force_dryrun=True,
                                  cve_info=cve_info,
                                  on_stage=record_stage)

        if result.cve_info is None or not result.cve_info.fix_commit_id:
            return {
                "cve_id": cve_id, "known_fix": known_fix, "target": tv,
                "worktree_commit": rollback_hash[:16] if rollback_hash else rollback,
                "checks": {}, "overall_pass": False,
                "summary": "CVE上游数据不完整(MITRE无fix commit), 无法验证",
            }

        checks = {}

        # fix_correctly_absent: 直接用 git 验证 known_fix 是否在 worktree
        # HEAD 的历史中, 避免 subject_match 在共享 git 对象库中误判。
        rc = wt_mgr.run_git_rc(
            ["git", "merge-base", "--is-ancestor", known_fix, "HEAD"],
            tv, timeout=10)
        fix_in_worktree = (rc == 0)
        checks["fix_correctly_absent"] = not fix_in_worktree

        checks["intro_detected"] = result.is_vulnerable

        intro_s = ""
        if result.introduced_search and result.introduced_search.found:
            intro_s = result.introduced_search.strategy
        checks["intro_strategy"] = intro_s

        fix_s = ""
        if result.fix_search and result.fix_search.found:
            fix_s = result.fix_search.strategy
        checks["fix_strategy"] = fix_s

        if known_prereqs:
            checks["prereq_metrics"] = _compare_prereqs(
                result.prerequisite_patches, known_prereqs, git_mgr, tv)
            checks["has_known_prereqs"] = True
        else:
            checks["has_known_prereqs"] = False

        if result.dry_run:
            if known_prereqs:
                checks["dryrun_accurate"] = not result.dry_run.applies_cleanly
            else:
                checks["dryrun_accurate"] = result.dry_run.applies_cleanly

        overall = checks.get("fix_correctly_absent", False)
        issues = []
        if not checks["fix_correctly_absent"]:
            issues.append("修复检测异常(应为未合入)")
        if not checks.get("intro_detected", True):
            issues.append("引入检测未命中")
        if checks.get("dryrun_accurate") is False:
            issues.append("DryRun预测不准")

        prereq_m = checks.get("prereq_metrics")
        if prereq_m and prereq_m["f1"] < 0.5:
            issues.append(f"前置依赖 F1 偏低 ({prereq_m['f1']:.0%})")

        # generated_vs_real 在后面计算完成后会回填到 issues，见 ★ 标记处

        # ── 收集丰富的诊断数据 ──────────────────────────────
        community_diff = ""
        fix_patch_detail = {}
        if result.fix_patch:
            fp = result.fix_patch
            community_diff = fp.diff_code or ""
            fix_patch_detail = {
                "commit_id": fp.commit_id[:12],
                "subject": fp.subject,
                "author": fp.author,
                "modified_files": fp.modified_files,
                "diff_lines": len(community_diff.splitlines()),
            }

        dryrun_detail = {}
        if result.dry_run:
            dr = result.dry_run
            applies = dr.applies_cleanly
            dryrun_detail = {
                "applies_cleanly": applies,
                "apply_method": dr.apply_method,
                "conflicting_files": dr.conflicting_files,
                "error_output": dr.error_output[:800] if dr.error_output else "",
                "stat_output": dr.stat_output[:500] if dr.stat_output else "",
                "has_adapted_patch": bool(dr.adapted_patch),
                "conflict_hunks": dr.conflict_hunks,
                "search_reports": dr.search_reports if dr.search_reports else [],
                "apply_attempts": dr.apply_attempts,
            }

        # 获取 known_fix 的完整信息(stat + diff)
        known_fix_detail = {}
        local_diff = ""
        kf_meta = git_mgr.run_git(
            ["git", "show", "--stat", "--format=%H%n%s%n%an", known_fix],
            tv, timeout=30)
        if kf_meta:
            lines = kf_meta.strip().split("\n")
            if len(lines) >= 3:
                known_fix_detail = _serialize_commit_reference(
                    config, git_mgr, tv, lines[0].strip(),
                    extra={
                        "subject": lines[1],
                        "author": lines[2],
                        "stat": "\n".join(lines[3:])[:500],
                    }
                )
        kf_raw = git_mgr.run_git(
            ["git", "show", "--format=", known_fix], tv, timeout=30)
        if kf_raw:
            local_diff = kf_raw.strip()

        # ── 核心: 代码差异对比 ───────────────────────────
        diff_comparison = _compare_patch_code(community_diff, local_diff)

        # 根因诊断
        root_cause = _diagnose_root_cause(diff_comparison, dryrun_detail,
                                          known_prereqs, result.dry_run)

        tool_prereqs_detail = [
            _serialize_commit_reference(
                config, git_mgr, tv, p.commit_id,
                extra={
                    "subject": p.subject,
                    "grade": p.grade,
                    "score": round(p.score, 2),
                    "overlap_hunks": p.overlap_hunks,
                    "adjacent_hunks": p.adjacent_hunks,
                    "overlap_funcs": p.overlap_funcs[:5],
                },
            )
            for p in (result.prerequisite_patches or [])
        ]

        known_prereqs_detail = []
        for kid in known_prereqs:
            info = git_mgr.run_git(
                ["git", "log", "-1", "--format=%H\x1e%s\x1e%an", kid],
                tv, timeout=10)
            if info:
                parts = info.strip().split("\x1e")
                known_prereqs_detail.append(_serialize_commit_reference(
                    config, git_mgr, tv, parts[0],
                    extra={
                        "subject": parts[1] if len(parts) > 1 else "",
                        "author": parts[2] if len(parts) > 2 else "",
                    },
                ))
            else:
                known_prereqs_detail.append(_serialize_commit_reference(
                    config, git_mgr, tv, kid,
                    extra={"subject": "", "author": ""}))

        recommendations = result.recommendations if result.recommendations else []

        # ── 输出补丁文件到 analysis_results/ ────────────────
        output_dir = config.output.output_dir
        os.makedirs(output_dir, exist_ok=True)

        adapted_patch = result.dry_run.adapted_patch if result.dry_run else None
        patch_file = None
        community_patch_file = None
        real_fix_patch_file = None

        if community_diff:
            community_patch_file = os.path.join(
                output_dir, f"{cve_id}_{tv}_community.patch")
            with open(community_patch_file, "w") as f:
                f.write(community_diff)
            logger.info("社区补丁已保存: %s", community_patch_file)

        if local_diff:
            real_fix_patch_file = os.path.join(
                output_dir, f"{cve_id}_{tv}_real_fix.patch")
            with open(real_fix_patch_file, "w") as f:
                f.write(local_diff)
            logger.info("真实修复补丁已保存: %s", real_fix_patch_file)

        if adapted_patch:
            patch_file = os.path.join(
                output_dir, f"{cve_id}_{tv}_adapted.patch")
            with open(patch_file, "w") as f:
                f.write(adapted_patch)
            logger.info("适配补丁已保存: %s", patch_file)

        # ── 核心: 生成补丁 vs 真实修复的本质比较 ─────────────
        # strict/C1/3way (L0-L2) 成功意味着社区补丁已能直接应用，
        # 此时 L3 重建反而可能因多次匹配而定位到错误位置，
        # 所以 L0-L2 成功时优先用社区原始补丁做比较。
        apply_method = dryrun_detail.get("apply_method", "")
        l0_l2_methods = {"strict", "ignore-ws", "context-C1",
                         "C1-ignore-ws", "3way"}
        use_community = (apply_method in l0_l2_methods
                         and community_diff and local_diff)

        generated_vs_real = {}
        if use_community:
            generated_vs_real = _compare_generated_vs_real(
                community_diff, local_diff)
            generated_vs_real["compare_source"] = "community_patch"
            generated_vs_real["note"] = (
                f"apply_method={apply_method}，社区补丁可直接应用，"
                "使用社区原始补丁做本质比较"
            )
        elif adapted_patch and local_diff:
            generated_vs_real = _compare_generated_vs_real(
                adapted_patch, local_diff)
            is_regen = apply_method in (
                "regenerated", "conflict-adapted", "verified-direct")
            generated_vs_real["compare_source"] = (
                "adapted_patch" if is_regen else "adapted_patch(community)")
        elif community_diff and local_diff:
            generated_vs_real = _compare_generated_vs_real(
                community_diff, local_diff)
            generated_vs_real["compare_source"] = "community_patch"

        # ★ 将补丁本质比较结果纳入 overall 判定
        gvr_verdict = generated_vs_real.get("verdict", "")
        gvr_core = generated_vs_real.get("core_similarity", 0)
        if gvr_verdict == "different":
            issues.append(
                f"补丁本质差异大 (verdict={gvr_verdict}, "
                f"核心相似度 {gvr_core:.0%})")
        elif gvr_verdict == "partially_same" and gvr_core < 0.5:
            issues.append(
                f"补丁仅部分一致 (核心相似度 {gvr_core:.0%})")

        # ── 构建面向开发人员的详细分析过程描述 ──────────────
        try:
            narrative = _build_analysis_narrative(
                result, dryrun_detail, generated_vs_real,
                diff_comparison, known_prereqs,
                is_validate=True)
        except Exception as e:
            logger.debug("构建分析描述异常: %s", e)
            narrative = {"error": str(e)}

        # ── v2 深度分析 (--deep) ──────────────────────────
        deep_analysis = None
        if deep and result.cve_info:
            from pipeline import STAGES_DEEP
            if show_stages:
                console.print(
                    "\n[bold magenta]── 深度分析 ──[/]")
            try:
                v2 = pipe.run_deep_on_base(result)
                deep_analysis = v2
            except Exception as e:
                logger.error("深度分析失败: %s", e)
                deep_analysis = None

        out = {
            "cve_id": cve_id, "known_fix": known_fix, "target": tv,
            "target_version": tv,
            "worktree_commit": rollback_hash[:16] if rollback_hash else rollback,
            "checks": checks,
            "overall_pass": overall and not issues,
            "summary": "; ".join(issues) if issues else "验证通过",
            "issues": issues,
            "analysis_narrative": narrative,
            "fix_patch_detail": fix_patch_detail,
            "dryrun_detail": dryrun_detail,
            "level_decision": (result.level_decision.__dict__ if result.level_decision else {}),
            "validation_details": (
                {
                    "workflow_steps": result.validation_details.workflow_steps,
                    "warnings": result.validation_details.warnings,
                    "rule_profile": result.validation_details.rule_profile,
                    "rule_version": result.validation_details.rule_version,
                } if result.validation_details else {}
            ),
            "function_impacts": [fi.__dict__ for fi in (result.function_impacts or [])],
            "known_fix_detail": known_fix_detail,
            "diff_comparison": diff_comparison,
            "generated_vs_real": generated_vs_real,
            "root_cause": root_cause,
            "tool_prereqs": tool_prereqs_detail,
            "known_prereqs_detail": known_prereqs_detail,
            "recommendations": recommendations,
            "patch_file": patch_file,
            "community_patch_file": community_patch_file,
            "real_fix_patch_file": real_fix_patch_file,
            "analysis_stages": stage_events,
            "known_prereqs": known_prereqs,
            "rules": _collect_rules_metadata(
                getattr(config, "policy", None),
                level_decision=result.level_decision,
                validation_details={
                    "rule_profile": result.validation_details.rule_profile,
                    "rule_version": result.validation_details.rule_version,
                    "workflow_steps": result.validation_details.workflow_steps,
                    "warnings": result.validation_details.warnings,
                } if result.validation_details else {},
            ),
        }
        if deep_analysis is not None:
            out["deep_analysis"] = deep_analysis
        return out

    finally:
        git_mgr.remove_worktree(tv, wt_dir)


def cmd_validate(args, config):
    """基于已修复 CVE 回退验证工具准确度"""
    tv = args.target_version
    git_mgr = _make_git_mgr(config, tv)
    known_prereqs = [p.strip() for p in args.known_prereqs.split(",")
                     if p.strip()] if args.known_prereqs else []

    cve_info = None
    mainline_fix = getattr(args, "mainline_fix", "") or ""
    mainline_intro = getattr(args, "mainline_intro", "") or ""
    if mainline_fix:
        from core.models import CveInfo
        fix_commits = [{"commit_id": mainline_fix, "subject": ""}]
        intro_commits = ([{"commit_id": mainline_intro, "subject": ""}]
                         if mainline_intro else [])
        cve_info = CveInfo(
            cve_id=args.cve_id,
            fix_commits=fix_commits,
            mainline_fix_commit=mainline_fix,
            introduced_commits=intro_commits,
        )

    info_lines = [
        f"[bold]CVE:[/] {args.cve_id}  [bold]目标:[/] {tv}",
        f"[bold]Known Fix:[/] {args.known_fix[:12]}",
        f"[bold]Known Prereqs:[/] {len(known_prereqs)} 个",
    ]
    if mainline_fix:
        info_lines.append(
            f"[bold]Mainline Fix:[/] {mainline_fix[:12]}  "
            f"[dim](跳过 MITRE 爬取)[/]")
    if mainline_intro:
        info_lines.append(
            f"[bold]Mainline Intro:[/] {mainline_intro[:12]}")
    console.print(Panel(
        "\n".join(info_lines),
        title="[bold magenta]验证框架 — 单CVE回退验证[/]",
        border_style="magenta", padding=(0, 2),
    ))

    deep = getattr(args, "deep", False)
    result = _run_single_validate(
        config, args.cve_id, tv, args.known_fix, known_prereqs,
        git_mgr=git_mgr, show_stages=True, cve_info=cve_info,
        deep=deep)

    # LLM 智能分析
    if not result.get("overall_pass"):
        if config.llm.enabled:
            from core.llm_analyzer import LLMAnalyzer
            analyzer = LLMAnalyzer(config.llm)
            if analyzer.enabled:
                diff_cmp = result.get("diff_comparison", {})
                fp_detail = result.get("fix_patch_detail", {})
                dr_detail = result.get("dryrun_detail", {})
                # 构建含实际代码差异的上下文
                code_diff_ctx = ""
                for kd in diff_cmp.get("key_differences", [])[:3]:
                    code_diff_ctx += f"\n### {kd['file']} (相似度 {kd['similarity']:.0%})\n"
                    ce = kd.get("community_extra", [])
                    le = kd.get("local_extra", [])
                    if ce:
                        code_diff_ctx += "社区补丁独有:\n" + "\n".join(
                            f"  {l}" for l in ce[:5]) + "\n"
                    if le:
                        code_diff_ctx += "本地修复独有:\n" + "\n".join(
                            f"  {l}" for l in le[:5]) + "\n"

                llm_ctx = {
                    "cve_id": args.cve_id,
                    "fix_patch_summary": (
                        f"Subject: {fp_detail.get('subject', 'N/A')}\n"
                        f"Files: {', '.join(fp_detail.get('modified_files', []))}\n"
                        f"Diff: {fp_detail.get('diff_lines', 0)} lines"
                    ) if fp_detail else "",
                    "code_diff_comparison": (
                        f"总体相似度: {diff_cmp.get('overall_similarity', 0):.0%}\n"
                        f"社区独有文件: {diff_cmp.get('community_only_files', [])}\n"
                        f"本地独有文件: {diff_cmp.get('local_only_files', [])}\n"
                        f"{code_diff_ctx}"
                    ),
                    "root_cause_diagnosis": "\n".join(
                        result.get("root_cause", [])),
                    "dryrun_detail": (
                        f"applies_cleanly: {dr_detail.get('applies_cleanly')}\n"
                        f"conflicting_files: {dr_detail.get('conflicting_files', [])}\n"
                        f"error: {dr_detail.get('error_output', '')[:400]}"
                    ) if dr_detail else "",
                    "tool_prereqs": "\n".join(
                        f"- [{p['grade']}] {p['commit_id']} {p['subject'][:60]} "
                        f"(score={p['score']}, hunks={p.get('overlap_hunks',0)})"
                        for p in result.get("tool_prereqs", [])
                    ),
                    "known_prereqs_info": "\n".join(
                        f"- {p['commit_id']} {p['subject']}"
                        for p in result.get("known_prereqs_detail", [])
                    ) if result.get("known_prereqs_detail") else "无已知前置依赖",
                    "known_fix_diff_summary": (
                        f"Subject: {result.get('known_fix_detail', {}).get('subject', '')}\n"
                        f"{result.get('known_fix_detail', {}).get('stat', '')}"
                    ),
                    "issues": result.get("issues", []),
                }
                with console.status("[cyan]LLM 正在分析验证差异..."):
                    llm_analysis = analyzer.analyze_validate_diff(llm_ctx)
                if llm_analysis:
                    result["llm_analysis"] = llm_analysis
                else:
                    result["llm_status"] = "LLM 调用失败，请检查日志"
            else:
                result["llm_status"] = "LLM api_key 未配置"
        else:
            result["llm_status"] = "LLM 未启用 (config.yaml → llm.enabled: true)"

    console.print()
    render_validate_report(result, policy_config=getattr(config, "policy", None))

    v2 = result.get("deep_analysis")
    if v2 is not None:
        console.print()
        console.print(Panel(
            "[bold]以下为 v2 深度分析结果 (漏洞/补丁检视/风险收益/合入建议)[/]",
            border_style="magenta"))
        _render_deep_report(v2)

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = os.path.join(out_dir, f"validate_{args.cve_id}_{tv}_{ts}.json")
    save_data = _prepare_validate_json(result)
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(save_data, f, indent=2, ensure_ascii=False, default=str)
    console.print(f"[dim]验证报告已保存: {fp}[/]")


def cmd_benchmark(args, config):
    """批量基准测试 — 从 YAML 文件加载已修复 CVE 列表并逐一验证"""
    import yaml

    with open(args.file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    entries = data.get("benchmarks", [])
    if not entries:
        console.print("[red]YAML 文件中无 benchmarks 条目[/]")
        return

    tv = args.target_version
    git_mgr = _make_git_mgr(config, tv)

    console.print(Panel(
        f"[bold]基准集:[/] {len(entries)} 个 CVE  [bold]目标:[/] {tv}\n"
        f"[bold]文件:[/] {args.file}",
        title="[bold cyan]Benchmark — 批量准确度度量[/]",
        border_style="cyan", padding=(0, 2),
    ))

    results = []
    for i, entry in enumerate(entries, 1):
        cve_id = entry.get("cve_id", "N/A")
        known_fix = entry.get("known_fix_commit", "")
        known_prereqs = entry.get("known_prereqs", []) or []
        notes = entry.get("notes", "")

        console.print(f"\n{'━' * 60}")
        console.print(
            f"[bold cyan][{i}/{len(entries)}][/]  {cve_id}  "
            f"[dim]fix={known_fix[:12]}  prereqs={len(known_prereqs)}[/]"
            + (f"  [dim italic]{notes}[/]" if notes else ""))

        if not known_fix:
            console.print("[yellow]  跳过: 缺少 known_fix_commit[/]")
            results.append({
                "cve_id": cve_id, "known_fix": "", "target": tv,
                "worktree_commit": "", "checks": {},
                "overall_pass": False, "summary": "缺少known_fix_commit",
            })
            continue

        r = _run_single_validate(
            config, cve_id, tv, known_fix, known_prereqs,
            git_mgr=git_mgr, show_stages=True)
        results.append(r)

        icon = "[green]✔ PASS[/]" if r.get("overall_pass") else "[red]✘ FAIL[/]"
        console.print(f"  {icon}  {r.get('summary', '')}")

    console.print(f"\n{'━' * 60}\n")
    render_benchmark_report(results, tv)

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = os.path.join(out_dir, f"benchmark_{tv}_{ts}.json")
    with open(fp, "w", encoding="utf-8") as f:
        json.dump({"target": tv, "total": len(results), "results": results},
                  f, indent=2, ensure_ascii=False, default=str)
    console.print(f"[dim]基准测试报告已保存: {fp}[/]")


# ─── batch-validate ──────────────────────────────────────────────────

def _build_cve_info_from_json(info: dict, cve_id: str):
    """从 JSON 条目构建 CveInfo，使用 mainline_fix_patchs / mainline_import_patchs"""
    from core.models import CveInfo

    mainline_fixes = info.get("mainline_fix_patchs", [])
    mainline_intros = info.get("mainline_import_patchs", [])

    fix_commits = []
    mainline_fix = ""
    for p in (mainline_fixes if isinstance(mainline_fixes, list) else []):
        if isinstance(p, dict) and p.get("commit"):
            fix_commits.append({
                "commit_id": p["commit"],
                "subject": p.get("subject", ""),
            })
            if not mainline_fix:
                mainline_fix = p["commit"]

    intro_commits = []
    for p in (mainline_intros if isinstance(mainline_intros, list) else []):
        if isinstance(p, dict) and p.get("commit"):
            intro_commits.append({
                "commit_id": p["commit"],
                "subject": p.get("subject", ""),
            })

    if not mainline_fix:
        return None

    return CveInfo(
        cve_id=cve_id,
        fix_commits=fix_commits,
        mainline_fix_commit=mainline_fix,
        introduced_commits=intro_commits,
    )


def _flush_live_report(path: str, target: str, total: int,
                       passed: list, failed: list, errors: list):
    """实时写入 JSON 报告，每完成一个 CVE 就更新"""
    done = len(passed) + len(failed) + len(errors)
    report = {
        "target": target,
        "progress": f"{done}/{total}",
        "summary": {
            "total": total,
            "done": done,
            "passed": len(passed),
            "failed": len(failed),
            "errors": len(errors),
        },
        "passed": passed,
        "failed": failed,
        "errors": errors,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)


def cmd_batch_validate(args, config):
    """批量验证 — 从 JSON 文件加载 CVE 数据并逐一验证补丁生成准确度"""
    try:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        console.print(f"[red bold]错误:[/] 无法解析 JSON 文件: {e}")
        return

    if not isinstance(data, dict):
        console.print("[red bold]错误:[/] JSON 顶层结构应为 dict "
                      "(key=CVE编号, value=CVE数据)")
        return

    tv = args.target_version
    git_mgr = _make_git_mgr(config, tv)

    # ── 解析 JSON → 按 CVE 分组 ─────────────────────────────────
    from collections import OrderedDict
    all_cve_groups = OrderedDict()
    skipped = 0
    offset = max(args.offset, 0) if hasattr(args, "offset") else 0
    limit = args.limit if args.limit and args.limit > 0 else 0

    for cve_id, info in data.items():
        try:
            if not isinstance(info, dict):
                continue
            hulk_fixes = info.get("hulk_fix_patchs", [])
            if not hulk_fixes or not isinstance(hulk_fixes, list):
                continue
            real_cve = info.get("cve_id", cve_id)
            cve_info = _build_cve_info_from_json(info, real_cve)
            mainline_fix_id = (cve_info.mainline_fix_commit
                               if cve_info else "")

            valid_fixes = []
            for fix in hulk_fixes:
                if not isinstance(fix, dict):
                    continue
                commit = fix.get("commit", "")
                if not commit or len(commit) < 8:
                    continue
                valid_fixes.append({
                    "commit": commit,
                    "subject": fix.get("subject", ""),
                    "mainline_commit": fix.get("mainline_commit", ""),
                })
            if not valid_fixes:
                continue

            # 识别主修复: mainline_commit 匹配 mainline fix 的 hulk_fix
            primary_idx = len(valid_fixes) - 1
            if mainline_fix_id:
                for idx, f in enumerate(valid_fixes):
                    if f["mainline_commit"] == mainline_fix_id:
                        primary_idx = idx
                        break

            primary_fix = valid_fixes[primary_idx]
            prereq_fixes = [f for i, f in enumerate(valid_fixes)
                            if i != primary_idx]

            all_cve_groups[real_cve] = {
                "primary_fix": primary_fix,
                "prereq_fixes": prereq_fixes,
                "all_fixes": valid_fixes,
                "cve_info": cve_info,
            }
        except Exception as e:
            skipped += 1
            logger.warning("解析 CVE 条目 %s 跳过: %s", cve_id, e)

    # offset + limit 切片
    all_keys = list(all_cve_groups.keys())
    total_available = len(all_keys)
    sliced_keys = all_keys[offset:]
    if limit:
        sliced_keys = sliced_keys[:limit]
    cve_groups = OrderedDict(
        (k, all_cve_groups[k]) for k in sliced_keys)

    if not cve_groups:
        console.print("[red]JSON 文件中未找到有效的 CVE 验证条目[/]")
        console.print(
            "[dim]要求: 每个条目需有 hulk_fix_patchs[].commit 字段[/]")
        return

    total_patches = sum(len(g["all_fixes"]) for g in cve_groups.values())
    multi_fix_cves = sum(1 for g in cve_groups.values()
                         if len(g["prereq_fixes"]) > 0)
    has_mainline = sum(1 for g in cve_groups.values() if g.get("cve_info"))
    range_desc = f"第 {offset + 1}~{offset + len(cve_groups)} 个" \
        if offset else f"共 {len(cve_groups)} 个"
    info_parts = [
        f"[bold]验证集:[/] {range_desc} CVE / {total_patches} 个补丁"
        f"  [dim](JSON 共 {total_available} 个 CVE)[/]",
        f"[bold]目标分支:[/] {tv}",
        f"[bold]数据文件:[/] {args.file}",
        f"[bold]Mainline信息:[/] {has_mainline}/{len(cve_groups)} "
        f"个 CVE 使用 JSON 提供的 mainline commit (跳过 MITRE 爬取)",
        f"[bold]统计维度:[/] 每 CVE 一次验证 "
        f"({multi_fix_cves} 个含前置补丁, 额外 fix 作为 known_prereqs)",
    ]
    if offset or limit:
        parts = []
        if offset:
            parts.append(f"offset={offset}")
        if limit:
            parts.append(f"limit={limit}")
        info_parts.append(f"[bold]范围:[/] {', '.join(parts)}")
    if skipped:
        info_parts.append(f"[yellow]跳过:[/] {skipped} 个解析异常条目")
    console.print(Panel(
        "\n".join(info_parts),
        title="[bold magenta]批量验证 — 补丁生成准确度[/]",
        border_style="magenta", padding=(0, 2),
    ))

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    live_report_path = os.path.join(
        out_dir, f"batch_validate_{tv}_{ts}.json")
    console.print(
        f"[dim]实时报告: {live_report_path} (每完成一个 CVE 自动更新)[/]")

    cve_results = []
    passed_list = []
    failed_list = []
    error_list = []

    _PASS_VERDICTS = {"identical", "essentially_same"}
    _VERDICT_ICONS = {
        "identical": "[green]✔ 完全一致[/]",
        "essentially_same": "[green]✔ 本质相同[/]",
        "partially_same": "[yellow]△ 部分一致[/]",
        "different": "[red]✘ 差异较大[/]",
        "no_data": "[dim]- 无数据[/]",
    }

    for ci, (cve_id, group) in enumerate(cve_groups.items(), 1):
        primary = group["primary_fix"]
        prereqs = group["prereq_fixes"]
        cve_info = group.get("cve_info")
        src = "JSON" if cve_info else "MITRE"

        console.print(f"\n{'━' * 60}")
        fix_desc = f"主修复={primary['commit'][:12]}"
        if prereqs:
            fix_desc += f"  前置={len(prereqs)}个"
        console.print(
            f"[bold magenta][{ci}/{len(cve_groups)}][/]  {cve_id}  "
            f"[dim]{fix_desc}  mainline={src}[/]")
        if prereqs:
            for pi, pf in enumerate(prereqs, 1):
                console.print(
                    f"  [dim]prereq[{pi}] {pf['commit'][:12]}"
                    + (f"  {pf['subject'][:40]}" if pf.get("subject") else "")
                    + "[/]")

        known_prereq_commits = [p["commit"] for p in prereqs]

        _MAX_RETRIES = 3
        deep = getattr(args, "deep", False)
        try:
            r = None
            for _attempt in range(1, _MAX_RETRIES + 1):
                r = _run_single_validate(
                    config, cve_id, tv, primary["commit"],
                    known_prereq_commits,
                    git_mgr=git_mgr, show_stages=True,
                    cve_info=cve_info, deep=deep)

                has_patch = r.get("dryrun_detail", {}).get(
                    "has_adapted_patch", False)
                gvr_v = r.get("generated_vs_real", {}).get(
                    "verdict", "no_data")
                if has_patch or gvr_v not in ("no_data", "error"):
                    break
                if _attempt < _MAX_RETRIES:
                    console.print(
                        f"  [yellow]⟳ 未生成补丁 (verdict={gvr_v}), "
                        f"重试 {_attempt}/{_MAX_RETRIES}...[/]")

            gvr = r.get("generated_vs_real", {})
            verdict = gvr.get("verdict", "no_data")
            core_sim = gvr.get("core_similarity", 0)
            method = r.get("dryrun_detail", {}).get("apply_method", "-")

            # ── 前置补丁交叉验证 ──────────────────────────────
            prereq_validation = {}
            if prereqs and r.get("dryrun_detail"):
                tool_prereqs = r.get("tool_prereqs", [])
                tool_prereq_ids = set()
                for tp in tool_prereqs:
                    cid = tp.get("commit_id", "")
                    if cid:
                        tool_prereq_ids.add(cid[:12])

                known_ids = {c[:12] for c in known_prereq_commits}

                matched = tool_prereq_ids & known_ids
                tool_only = tool_prereq_ids - known_ids
                known_only = known_ids - tool_prereq_ids

                prereq_validation = {
                    "known_prereqs": len(known_ids),
                    "tool_recommended": len(tool_prereq_ids),
                    "matched": len(matched),
                    "matched_ids": sorted(matched),
                    "tool_only": sorted(tool_only),
                    "known_only": sorted(known_only),
                }
                if known_ids:
                    recall = len(matched) / len(known_ids)
                    prereq_validation["recall"] = round(recall, 3)

                recall_v = prereq_validation.get("recall", -1)
                if recall_v >= 0:
                    rc = "[green]" if recall_v >= 0.5 else "[yellow]"
                    console.print(
                        f"  [dim]前置补丁:[/] "
                        f"已知={len(known_ids)} 工具推荐={len(tool_prereq_ids)} "
                        f"命中={len(matched)}  "
                        f"{rc}recall={recall_v:.0%}[/]")

            r["prereq_cross_validation"] = prereq_validation
            r["num_hulk_fixes"] = len(group["all_fixes"])
            cve_results.append(r)

            icon = _VERDICT_ICONS.get(verdict, f"[dim]{verdict}[/]")
            deep_hint = ""
            v2 = r.get("deep_analysis")
            if v2 is not None:
                rec = getattr(v2, "merge_recommendation", None)
                if rec and hasattr(rec, "action"):
                    _act_cn = {"merge": "直接合入",
                               "merge_with_prereqs": "合入(需前置)",
                               "manual_review": "需人工审查",
                               "skip": "无需处理"}
                    deep_hint = (
                        f"  [magenta]建议={_act_cn.get(rec.action, rec.action)}"
                        f"[/]")
            console.print(
                f"  {icon}  核心相似度={core_sim:.0%}  方法={method}"
                f"{deep_hint}")

            item = {
                "cve_id": cve_id,
                "known_fix": primary["commit"][:12],
                "verdict": verdict,
                "core_similarity": round(core_sim, 3),
                "method": method,
                "num_fixes": len(group["all_fixes"]),
                "num_prereqs": len(prereqs),
                "prereq_recall": prereq_validation.get("recall", None),
                "summary": r.get("summary", ""),
            }
            if v2 is not None:
                rec = getattr(v2, "merge_recommendation", None)
                if rec and hasattr(rec, "action"):
                    item["deep_action"] = rec.action
                    item["deep_summary"] = getattr(rec, "summary", "")
                    rb = getattr(rec, "risk_benefit", None)
                    if rb:
                        item["deep_overall_score"] = round(
                            rb.overall_score, 2)
                        item["deep_overall_detail"] = rb.overall_detail
            if verdict in _PASS_VERDICTS:
                passed_list.append(item)
            else:
                reason = r.get("summary", "")
                if verdict == "no_data":
                    reason = reason or "无补丁数据可比较"
                elif verdict == "different":
                    reason = reason or f"核心相似度仅 {core_sim:.0%}"
                elif verdict == "partially_same":
                    reason = reason or f"部分一致 (核心相似度 {core_sim:.0%})"
                item["reason"] = reason
                failed_list.append(item)

        except Exception as e:
            logger.exception("batch-validate 异常: %s %s", cve_id, e)
            console.print(f"  [red]✘ 跳过 (异常: {e})[/]")
            cve_results.append({
                "cve_id": cve_id, "known_fix": primary["commit"],
                "target": tv, "worktree_commit": "", "checks": {},
                "overall_pass": False, "summary": f"执行异常: {e}",
                "dryrun_detail": {},
                "generated_vs_real": {
                    "verdict": "error", "core_similarity": 0,
                    "file_coverage": 0},
                "num_hulk_fixes": len(group["all_fixes"]),
            })
            error_list.append({
                "cve_id": cve_id,
                "known_fix": primary["commit"][:12],
                "reason": str(e),
            })

        _flush_live_report(
            live_report_path, tv, len(cve_groups),
            passed_list, failed_list, error_list)

    console.print(f"\n{'━' * 60}\n")
    render_batch_validate_report(
        cve_results, tv, policy_config=getattr(config, "policy", None))

    serializable_results = [
        _prepare_validate_json(r) for r in cve_results]
    full_report_path = os.path.join(
        out_dir, f"batch_validate_{tv}_{ts}_full.json")
    with open(full_report_path, "w", encoding="utf-8") as f:
        json.dump({
            "target": tv,
            "total_cves": len(cve_groups),
            "total_patches": total_patches,
            "skipped_parse_errors": skipped,
            "cve_results": serializable_results,
            "cve_summary": {
                "passed": passed_list,
                "failed": failed_list,
                "errors": error_list,
            },
        }, f, indent=2, ensure_ascii=False, default=str)
    console.print(f"[dim]完整结果: {full_report_path}[/]")
    console.print(f"[dim]实时报告: {live_report_path}[/]")


# ─── build-cache ─────────────────────────────────────────────────────

def cmd_build_cache(args, config):
    git_mgr = _make_git_mgr(config, args.target_version)
    rv = args.target_version

    cached_count = git_mgr.get_cache_count(rv)
    is_full = args.full
    incremental = not is_full and cached_count > 0
    mode_label = "[yellow]全量重建[/]" if is_full else (
        "[green]增量更新[/]" if incremental else "[cyan]首次构建[/]"
    )

    console.print(Panel(
        f"[bold]目标仓库:[/] {rv}  [bold]分支:[/] {git_mgr._get_repo_branch(rv) or '当前'}\n"
        f"[bold]现有缓存:[/] {cached_count:,} commits\n"
        f"[bold]构建模式:[/] {mode_label}",
        title="[bold blue]缓存构建[/]", border_style="blue", padding=(0, 2),
    ))

    if incremental:
        latest = git_mgr.get_latest_cached_commit(rv)
        if latest:
            console.print(f"[dim]将从 {latest[:12]} 之后增量拉取新commit[/]\n")

        progress = make_cache_progress(known_total=False)
        with progress:
            task = progress.add_task("增量缓存", total=None)

            def on_progress(current, _total):
                progress.update(task, completed=current,
                                description=f"增量缓存 ({current:,} 新commits)")

            git_mgr.build_commit_cache(rv, progress_cb=on_progress, incremental=True)

        final_count = git_mgr.get_cache_count(rv)
        new_count = final_count - cached_count
        console.print(Panel(
            f"[green bold]完成![/]  新增: [bold]{new_count:,}[/]  "
            f"总缓存: [bold]{final_count:,}[/] commits",
            border_style="green", padding=(0, 2),
        ))
    else:
        console.print("[dim]正在统计分支 commit 数量 (大仓库可能需要几分钟)...[/]")
        actual_count = git_mgr.count_commits(rv)
        mx = config.cache.max_cached_commits if hasattr(config.cache, "max_cached_commits") else None

        if actual_count > 0:
            if mx and mx > actual_count:
                mx = None
            total = mx or actual_count
            console.print(f"[dim]分支共 {actual_count:,} 个commits, 将缓存 {total:,} 个[/]\n")
        else:
            total = mx or 0
            if total:
                console.print(f"[dim]commit总数未知, 将缓存最多 {total:,} 个[/]\n")
            else:
                console.print("[dim]commit总数未知, 将流式缓存全部commits[/]\n")

        known_total = total > 0
        progress = make_cache_progress(known_total=known_total)
        with progress:
            task = progress.add_task(
                "构建commit缓存",
                total=total if known_total else None,
            )

            def on_progress(current, _total):
                if known_total:
                    progress.update(task, completed=current)
                else:
                    progress.update(task, completed=current,
                                    description=f"构建commit缓存 ({current:,})")

            git_mgr.build_commit_cache(rv, max_commits=mx, progress_cb=on_progress,
                                       incremental=False)
            if known_total:
                progress.update(task, completed=total)

        final_count = git_mgr.get_cache_count(rv)
        console.print(Panel(
            f"[green bold]完成![/]  缓存: [bold]{final_count:,}[/] commits",
            border_style="green", padding=(0, 2),
        ))


# ─── search ──────────────────────────────────────────────────────────

def cmd_search(args, config):
    git_mgr = _make_git_mgr(config, args.target_version)
    r = git_mgr.find_commit_by_id(args.commit_id, args.target_version)
    if r:
        from rich.table import Table
        t = Table(title="Commit 信息", box=box.ROUNDED, border_style="cyan")
        t.add_column("字段", style="bold")
        t.add_column("值")
        t.add_row("Commit ID", r["commit_id"])
        t.add_row("Subject", r["subject"])
        t.add_row("Author", r.get("author", ""))
        t.add_row("Timestamp", str(r.get("timestamp", "")))
        console.print(t)
    else:
        console.print(f"[yellow]未找到:[/] {args.commit_id}")


# ─── server ───────────────────────────────────────────────────────


def cmd_server(args, config):
    """启动 HTTP API 服务，暴露 analyze / validate / batch-validate。"""
    from api_server import run_api_server

    host = args.host
    port = args.port
    config_path = args.config if hasattr(args, "config") else "config.yaml"

    console.print(
        f"[green]启动 API 服务:[/] {host}:{port}\n"
        f"[dim]配置文件: {config_path}\n"
        f"可用路由: /health, /api/analyze, /api/analyzer, "
        f"/api/validate, /api/batch-validate[/]"
    )
    run_api_server(host, port, config_path=config_path)


# ─── main ────────────────────────────────────────────────────────────

def main():
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("-q", "--quiet", action="store_true", help="静默模式(仅日志文件)")

    p = argparse.ArgumentParser(
        description="CVE 补丁回溯分析工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[parent],
    )
    p.add_argument("-c", "--config", default="config.yaml")
    sub = p.add_subparsers(dest="command")

    ap = sub.add_parser("analyze", help="分析CVE", parents=[parent])
    ap.add_argument("--cve", dest="cve_id")
    ap.add_argument("--batch", dest="batch_file")
    ap.add_argument("--target", dest="target_version", required=True)
    ap.add_argument("--no-dryrun", action="store_true", help="跳过dry-run检测")
    ap.add_argument("--deep", action="store_true",
                    help="深度分析模式: 漏洞分析+社区讨论+补丁检视+风险收益+合入建议")

    ip = sub.add_parser("check-intro", help="检测漏洞引入commit", parents=[parent])
    ip.add_argument("--commit", dest="commit_id", help="mainline引入commit ID")
    ip.add_argument("--cve", dest="cve_id", help="CVE ID (自动提取引入commit)")
    ip.add_argument("--target", dest="target_version", required=True)

    fp = sub.add_parser("check-fix", help="检测修复补丁是否已合入", parents=[parent])
    fp.add_argument("--commit", dest="commit_id", help="修复commit ID")
    fp.add_argument("--cve", dest="cve_id", help="CVE ID (自动提取修复commit)")
    fp.add_argument("--target", dest="target_version", required=True)

    vp = sub.add_parser("validate", help="基于已修复CVE验证工具准确度", parents=[parent])
    vp.add_argument("--cve", dest="cve_id", required=True)
    vp.add_argument("--target", dest="target_version", required=True)
    vp.add_argument("--known-fix", required=True, help="本地仓库中真实修复的commit ID")
    vp.add_argument("--known-prereqs", default="",
                    help="实际先合入的前置commit列表 (逗号分隔)")
    vp.add_argument("--mainline-fix", default="",
                    help="社区 mainline 修复 commit ID (提供后跳过 MITRE 爬取)")
    vp.add_argument("--mainline-intro", default="",
                    help="社区 mainline 引入 commit ID (可选)")
    vp.add_argument("--deep", action="store_true",
                    help="深度分析模式: 漏洞分析+补丁检视+风险收益+合入建议")

    bmp = sub.add_parser("benchmark", help="批量准确度基准测试", parents=[parent])
    bmp.add_argument("--file", required=True, help="基准测试YAML文件 (benchmarks.yaml)")
    bmp.add_argument("--target", dest="target_version", required=True)

    bvp = sub.add_parser("batch-validate",
                         help="批量验证补丁生成准确度 (JSON)", parents=[parent])
    bvp.add_argument("--file", required=True,
                     help="CVE 数据 JSON 文件 (含 hulk_fix_patchs)")
    bvp.add_argument("--target", dest="target_version", required=True)
    bvp.add_argument("--offset", type=int, default=0,
                     help="跳过前 N 个 CVE, 从第 N+1 个开始 (默认 0)")
    bvp.add_argument("--limit", type=int, default=0,
                     help="处理的 CVE 数量 (0=全部, 与 --offset 配合使用)")
    bvp.add_argument("--deep", action="store_true",
                     help="深度分析模式: 漏洞分析+补丁检视+风险收益+合入建议")

    cp = sub.add_parser("build-cache", help="构建commit缓存", parents=[parent])
    cp.add_argument("--target", dest="target_version", required=True)
    cp.add_argument("--full", action="store_true", help="强制全量重建缓存（默认增量）")

    sp = sub.add_parser("search", help="搜索commit", parents=[parent])
    sp.add_argument("--commit", dest="commit_id", required=True)
    sp.add_argument("--target", dest="target_version", required=True)

    srv = sub.add_parser("server", help="启动 HTTP API 服务", parents=[parent])
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8000)

    args = p.parse_args()
    if not args.command:
        p.print_help()
        sys.exit(1)

    config = ConfigLoader.load(args.config)
    _setup_logging(config, quiet=args.quiet)

    dispatch = {
        "analyze": cmd_analyze,
        "check-intro": cmd_check_intro,
        "check-fix": cmd_check_fix,
        "validate": cmd_validate,
        "benchmark": cmd_benchmark,
        "batch-validate": cmd_batch_validate,
        "build-cache": cmd_build_cache,
        "search": cmd_search,
        "server": cmd_server,
    }
    dispatch[args.command](args, config)


if __name__ == "__main__":
    main()
