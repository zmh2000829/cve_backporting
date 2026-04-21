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
from dataclasses import asdict, replace
import re
from services.output_support import (
    build_repo_traceability,
    ensure_case_output_dir,
    make_run_id,
)

from rich.console import Console, Group
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich import box

from core.config import ConfigLoader
from core.git_manager import GitRepoManager
from core.output_serializers import (
    aggregate_strategy_buckets,
    collect_prereq_patches,
    collect_rules_metadata,
    serialize_commit_reference,
    serialize_dependency_details,
    serialize_function_impacts,
    serialize_level_decision,
    serialize_search_result,
    serialize_validation_details,
)
from core.ui import (
    console, StageTracker, make_header, render_report,
    render_recommendations, render_multi_strategy, make_cache_progress,
    render_validate_report, render_benchmark_report,
    render_batch_validate_report,
)
from core.report_schema import enrich_result_payload, make_result_status
from pipeline import Pipeline, STAGES
from services import reporting

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


def _ai_tasks_enabled(config) -> bool:
    ai = getattr(config, "ai", None)
    mode = str(getattr(ai, "mode", "off") or "off").lower()
    if mode not in ("advisory", "gated"):
        return False
    return any(bool(getattr(ai, name, False)) for name in (
        "enable_dependency_triage",
        "enable_low_signal_adjudication",
        "enable_risk_explainer",
        "enable_conflict_patch_suggestion",
    ))


def _coerce_commit_list(values):
    """将配置/请求参数中的 commit 列表统一成标准 list[str]。"""
    if not values:
        return []
    if isinstance(values, str):
        return [v.strip() for v in values.split(",") if v.strip()]
    if isinstance(values, (list, tuple, set)):
        return [str(v).strip() for v in values if str(v).strip()]
    return [str(values).strip()] if str(values).strip() else []


def _dedupe_commit_list(values):
    seen = set()
    out = []
    for value in _coerce_commit_list(values):
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _coerce_known_fix_commits(known_fix=None, known_fixes=None):
    commits = _dedupe_commit_list(known_fixes)
    if commits:
        return commits
    return _dedupe_commit_list(known_fix)


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
    return reporting.build_analyze_payload(
        result,
        pipe,
        config,
        target,
        stage_events=stage_events,
        policy_config=policy_config,
        deep_analysis=deep_analysis,
        narrative_builder=_build_analysis_narrative,
        deep_serializer=_v2_to_json,
    )


def _build_json_reading_guide(mode: str) -> dict:
    return reporting.build_json_reading_guide(mode)


def _normalize_rule_messages(items) -> list:
    out = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        msg = item.get("message", "")
        if msg:
            out.append(msg)
    return out[:6]


def _status_to_cn(kind: str, status: str) -> str:
    return reporting.status_to_cn(kind, status)


def _build_human_friendly_summary(data: dict, mode: str) -> dict:
    return reporting.build_human_friendly_summary(data, mode)


def _prepare_analyze_json(payload: dict) -> dict:
    return reporting.prepare_analyze_json(payload)


def run_analyze_payload(cve_id: str, target_version: str, config, *,
                       enable_dryrun: bool = True, deep: bool = False,
                       stage_callback=None):
    git_mgr = _make_git_mgr(config, target_version)
    pipe = Pipeline(git_mgr, path_mappings=config.path_mappings,
                    llm_config=config.llm,
                    policy_config=getattr(config, "policy", None),
                    analysis_config=getattr(config, "analysis", None),
                    search_config=getattr(config, "search", None),
                    ai_config=getattr(config, "ai", None))

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


def _analyze_one(pipe: Pipeline, cve_id: str, target: str,
                 enable_dryrun: bool, out_dir: str, config, policy_config=None,
                 run_id: str = ""):
    tracker = StageTracker(STAGES)
    header = make_header(cve_id, target)
    stage_events, record_stage = _make_stage_trace_tracker()
    run_id = run_id or make_run_id()
    artifact_dir = ensure_case_output_dir(out_dir, run_id, "analyze", cve_id)

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
    patch_file = ""
    if result.dry_run and result.dry_run.adapted_patch:
        patch_file = os.path.join(artifact_dir, "adapted.patch")
        with open(patch_file, "w") as f:
            f.write(result.dry_run.adapted_patch)
        console.print(f"\n[green]✔ 生成的适配补丁已保存:[/] [cyan]{patch_file}[/]")

    fp = os.path.join(artifact_dir, "report.json")
    payload = _build_analyze_payload(
        result, pipe, config, target,
        stage_events=stage_events,
        policy_config=policy_config)
    payload["run_id"] = run_id
    payload["output_dir"] = artifact_dir
    payload["report_file"] = fp
    payload["patch_file"] = patch_file
    payload["artifacts"] = {
        "run_id": run_id,
        "output_dir": artifact_dir,
        "report_file": fp,
        "patch_files": {"adapted_patch": patch_file} if patch_file else {},
    }

    with open(fp, "w", encoding="utf-8") as f:
        json.dump(_prepare_analyze_json(payload), f, indent=2, ensure_ascii=False, default=str)
    console.print(f"[dim]报告已保存: {fp}[/]")


# ─── analyze --deep ──────────────────────────────────────────────────

def _analyze_deep(pipe, cve_id: str, target: str, out_dir: str, policy_config=None, run_id: str = ""):
    """深度分析模式: v1 基础 + v2 扩展 (社区/漏洞/检视/风险/建议)"""
    from pipeline import STAGES_DEEP

    tracker = StageTracker(STAGES_DEEP)
    header = make_header(cve_id, target, extra="[bold magenta] DEEP[/]")
    run_id = run_id or make_run_id()
    artifact_dir = ensure_case_output_dir(out_dir, run_id, "analyze-deep", cve_id)

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
        patch_file = os.path.join(artifact_dir, "adapted.patch")
        with open(patch_file, "w") as f:
            f.write(base.dry_run.adapted_patch)
        console.print(f"\n[green]✔ 生成的适配补丁已保存:[/] [cyan]{patch_file}[/]")

    fp = os.path.join(artifact_dir, "deep_report.json")
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
    """准备 validate 结果供 JSON 序列化 — 输出更适合用户阅读的结构。"""
    return reporting.prepare_validate_json(result, deep_serializer=_v2_to_json)


# ─── validate / benchmark ────────────────────────────────────────────

def _find_rollback_commit(git_mgr, rv, known_fixes, known_prereqs):
    """计算回滚目标：回滚到实际修复集合中最早 commit 的前一个提交。"""
    fix_commits = _coerce_known_fix_commits(known_fixes)
    all_commits = _dedupe_commit_list(list(fix_commits) + list(known_prereqs or []))
    if not all_commits:
        return "HEAD~1"
    if len(all_commits) == 1:
        return f"{all_commits[0]}~1"
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
                files.setdefault(current_file, []).append("\n".join(current_lines))
            m = re.search(r" b/(.*)", line)
            current_file = m.group(1) if m else None
            current_lines = [line]
        elif current_file is not None:
            current_lines.append(line)
    if current_file:
        files.setdefault(current_file, []).append("\n".join(current_lines))
    return {
        path: "\n".join(sections)
        for path, sections in files.items()
    }


def _combine_patch_texts(parts) -> str:
    chunks = [str(part or "").strip() for part in (parts or []) if str(part or "").strip()]
    return "\n".join(chunks).strip()


def _collect_commit_diff_bundle(config, git_mgr, tv, commit_ids):
    details = []
    diffs = []
    for commit_id in _dedupe_commit_list(commit_ids):
        meta = git_mgr.run_git(
            ["git", "show", "--stat", "--format=%H%n%s%n%an", commit_id],
            tv, timeout=30)
        detail = serialize_commit_reference(config, git_mgr, tv, commit_id, extra={"subject": "", "author": ""})
        if meta:
            lines = meta.strip().split("\n")
            if len(lines) >= 3:
                detail = serialize_commit_reference(
                    config, git_mgr, tv, lines[0].strip(),
                    extra={
                        "subject": lines[1],
                        "author": lines[2],
                        "stat": "\n".join(lines[3:])[:500],
                    },
                )

        raw = git_mgr.run_git(["git", "show", "--format=", commit_id], tv, timeout=30)
        diff_text = raw.strip() if raw else ""
        detail["diff_lines"] = len(diff_text.splitlines()) if diff_text else 0
        details.append(detail)
        if diff_text:
            diffs.append(diff_text)

    return {
        "details": details,
        "combined_diff": _combine_patch_texts(diffs),
    }


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
        if s.strategy.startswith("missing_intro"):
            if s.found:
                workflow.append(
                    f"3. 漏洞引入检测: 上游未提供引入 commit，"
                    f"使用修复补丁代码形态探测后按受影响处理 "
                    f"(策略={s.strategy}, 置信度={s.confidence:.0%})")
            else:
                workflow.append(
                    f"3. 漏洞引入检测: 上游未提供引入 commit，"
                    f"修复补丁代码形态探测未确认目标受影响 "
                    f"(策略={s.strategy}, 置信度={s.confidence:.0%})")
        elif s.found:
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
        validate_detail_desc = serialize_validation_details(result.validation_details)

    function_impact_desc = serialize_function_impacts(
        getattr(result, "function_impacts", [])[:8]
    )

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
        "predicted_solution_set": (
            "对比基准: 使用“工具生成主补丁 + 工具识别的 strong/medium 前置补丁”"
            " 与“实际 known_fix/known_prereqs 解集”做整体比较"),
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
            "deterministic_exact_match": False,
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

    deterministic_exact_match = (
        bool(all_pairs)
        and not gen_only
        and not real_only
        and all(
            fd.get("core_similarity") == 1.0
            and fd.get("overall_similarity") == 1.0
            and not fd.get("add_only_in_generated")
            and not fd.get("add_only_in_real")
            and not fd.get("rm_only_in_generated")
            and not fd.get("rm_only_in_real")
            for fd in file_details
        )
    )

    return {
        "verdict": verdict,
        "core_similarity": round(avg_core, 3),
        "overall_similarity": round(avg_overall, 3),
        "file_coverage": round(file_coverage, 3),
        "deterministic_exact_match": deterministic_exact_match,
        "gen_only_files": gen_only,
        "real_only_files": real_only,
        "detail": file_details,
        "diagnosis": " | ".join(diagnosis_parts),
    }


def _maybe_recalibrate_validate_level_from_accuracy(
    result,
    generated_vs_real: dict,
    policy_engine,
    git_mgr,
    target_version: str,
    path_mapper=None,
):
    """validate 专用: 当 verified-direct 与真实修复完全一致时，重新按低漂移场景定级。

    这里校正的是“证明链强弱”而不是补丁语义本身。verified-direct 仍表示工具绕过
    git apply 做了内存级定位，但如果 validate 已证明生成补丁与真实合入补丁完全一致，
    就不应继续把它留在最高谨慎度路径。
    """
    if not result or not generated_vs_real or not policy_engine:
        return {}
    if not getattr(result, "fix_patch", None) or not getattr(result, "dry_run", None):
        return {}
    if not getattr(result, "level_decision", None):
        return {}
    if (result.dry_run.apply_method or "") != "verified-direct":
        return {}
    if not generated_vs_real.get("deterministic_exact_match"):
        return {}

    original_level = result.level_decision.level
    original_base_level = result.level_decision.base_level
    adjusted_dryrun = replace(result.dry_run, apply_method="verified-direct-exact")
    reevaluated = policy_engine.evaluate(
        result.fix_patch,
        adjusted_dryrun,
        git_mgr,
        target_version,
        path_mapper,
        prerequisite_patches=result.prerequisite_patches,
        dependency_details=result.dependency_details,
    )
    if not reevaluated or not reevaluated.level_decision:
        return {}

    note = (
        "Validate 准确度校正: generated_vs_real 为 deterministic exact match，"
        "按 verified-direct-exact 重新评估级别。"
    )
    if note not in (reevaluated.workflow_steps or []):
        reevaluated.workflow_steps.insert(2 if len(reevaluated.workflow_steps) >= 2 else 0, note)
    reevaluated.level_decision.reason = (
        f"{reevaluated.level_decision.reason} {note}"
    ).strip()

    result.level_decision = reevaluated.level_decision
    result.validation_details = reevaluated
    result.function_impacts = reevaluated.function_impacts

    return {
        "applied": True,
        "reason": note,
        "match_verdict": generated_vs_real.get("verdict", ""),
        "deterministic_exact_match": True,
        "original_base_method": "verified-direct",
        "adjusted_base_method": reevaluated.level_decision.base_method,
        "original_base_level": original_base_level,
        "adjusted_base_level": reevaluated.level_decision.base_level,
        "original_level": original_level,
        "adjusted_level": reevaluated.level_decision.level,
    }


def _run_single_validate(config, cve_id, tv, known_fix, known_prereqs,
                         git_mgr=None, show_stages=True,
                         cve_info=None, deep=False, stage_callback=None,
                         output_dir=None, run_id: str = "",
                         known_fixes=None):
    """执行单个 CVE 的回退验证，返回结果 dict。
    cve_info: 可选的预构建 CveInfo，提供后跳过 MITRE 爬取。
    deep: 是否同时执行 v2 深度分析。"""
    if git_mgr is None:
        git_mgr = _make_git_mgr(config, tv)
    run_id = run_id or make_run_id()
    known_fix_commits = _coerce_known_fix_commits(known_fix, known_fixes)
    if not known_fix_commits:
        known_fix_commits = [known_fix]
    primary_known_fix = known_fix_commits[0]
    actual_solution_commits = _dedupe_commit_list(list(known_fix_commits) + list(known_prereqs or []))

    missing_fixes = []
    for commit_id in actual_solution_commits:
        status, _ = git_mgr.check_commit_existence(commit_id, tv)
        if status != "on_branch":
            missing_fixes.append((commit_id, status))
    if missing_fixes:
        first_commit, status = missing_fixes[0]
        msg = f"known_fix {first_commit[:12]} 不在目标分支 (status={status})"
        console.print(f"[red]{msg}[/]")
        return enrich_result_payload({
            "cve_id": cve_id, "known_fix": primary_known_fix, "known_fix_commits": known_fix_commits, "target": tv,
            "worktree_commit": "", "checks": {},
            "overall_pass": False, "summary": msg,
            "result_status": make_result_status(
                state="error",
                error_code="known_fix_not_on_branch",
                user_message=msg,
                technical_detail="; ".join(
                    f"{commit_id[:12]}:{st}" for commit_id, st in missing_fixes[:6]
                ),
                retryable=False,
                evidence_refs=[cve_id] + [commit_id[:12] for commit_id, _ in missing_fixes[:6]],
            ),
        }, "validate")

    rollback = _find_rollback_commit(git_mgr, tv, known_fix_commits, known_prereqs)
    resolved = git_mgr.run_git(["git", "rev-parse", rollback], tv, timeout=10)
    rollback_hash = resolved.strip() if resolved else rollback

    wt_dir = tempfile.mkdtemp(prefix="cve_validate_")
    if not git_mgr.create_worktree(tv, rollback, wt_dir):
        console.print(f"[red]创建 worktree 失败 @ {rollback}[/]")
        return enrich_result_payload({
            "cve_id": cve_id, "known_fix": primary_known_fix, "known_fix_commits": known_fix_commits, "target": tv,
            "worktree_commit": rollback, "checks": {},
            "overall_pass": False, "summary": "创建worktree失败",
            "result_status": make_result_status(
                state="error",
                error_code="worktree_create_failed",
                user_message="创建验证 worktree 失败。",
                technical_detail=f"rollback={rollback}",
                retryable=True,
                evidence_refs=[cve_id, rollback[:12]],
            ),
        }, "validate")

    stage_events, record_stage = _make_stage_trace_tracker(stage_callback=stage_callback)

    try:
        wt_mgr = GitRepoManager(
            {tv: {"path": wt_dir, "branch": "HEAD"}},
            use_cache=False,
        )
        pipe = Pipeline(wt_mgr, path_mappings=config.path_mappings,
                        llm_config=config.llm if (deep or _ai_tasks_enabled(config)) else None,
                        policy_config=getattr(config, "policy", None),
                        analysis_config=getattr(config, "analysis", None),
                        search_config=getattr(config, "search", None),
                        ai_config=getattr(config, "ai", None))

        if show_stages:
            tracker = StageTracker(STAGES)
            rollback_label = primary_known_fix[:16] if len(known_fix_commits) == 1 else f"{primary_known_fix[:12]} +{len(known_fix_commits)-1}"
            header = Panel(
                f"[bold]CVE:[/] {cve_id}  [bold]目标:[/] {tv}\n"
                f"[bold]回滚至:[/] {rollback_hash[:16]}  [dim]({rollback_label}~)[/]",
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
            return enrich_result_payload({
                "cve_id": cve_id, "known_fix": primary_known_fix, "known_fix_commits": known_fix_commits, "target": tv,
                "worktree_commit": rollback_hash[:16] if rollback_hash else rollback,
                "checks": {}, "overall_pass": False,
                "summary": "CVE上游数据不完整(MITRE无fix commit), 无法验证",
                "result_status": make_result_status(
                    state="incomplete",
                    error_code="missing_upstream_fix",
                    user_message="上游 CVE 情报缺少稳定的 fix commit，当前无法完成验证。",
                    technical_detail="result.cve_info 为 None 或 fix_commit_id 为空。",
                    retryable=True,
                    incomplete_reason="missing_fix_commit",
                    evidence_refs=[cve_id],
                ),
            }, "validate")

        checks = {}

        # fix_correctly_absent: 验证整个实际解集都不在回滚后的 worktree 历史中
        # HEAD 的历史中, 避免 subject_match 在共享 git 对象库中误判。
        present_actual_commits = []
        for commit_id in actual_solution_commits:
            rc = wt_mgr.run_git_rc(
                ["git", "merge-base", "--is-ancestor", commit_id, "HEAD"],
                tv, timeout=10)
            if rc == 0:
                present_actual_commits.append(commit_id[:12])
        checks["fix_correctly_absent"] = not present_actual_commits
        checks["actual_solution_commit_count"] = len(actual_solution_commits)
        checks["known_fix_commit_count"] = len(known_fix_commits)
        checks["actual_solution_commits_still_present"] = present_actual_commits

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
        primary_fix_bundle = _collect_commit_diff_bundle(config, git_mgr, tv, [primary_known_fix])
        known_fix_bundle = _collect_commit_diff_bundle(config, git_mgr, tv, known_fix_commits)
        actual_solution_bundle = _collect_commit_diff_bundle(config, git_mgr, tv, actual_solution_commits)
        known_fix_details = known_fix_bundle["details"]
        actual_solution_details = actual_solution_bundle["details"]
        known_fix_detail = known_fix_details[0] if known_fix_details else {}
        primary_local_diff = primary_fix_bundle["combined_diff"] or known_fix_bundle["combined_diff"]
        local_diff = actual_solution_bundle["combined_diff"] or known_fix_bundle["combined_diff"]

        diff_comparison = {}
        root_cause = {}

        tool_prereqs_detail = [
            serialize_commit_reference(
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
        compare_tool_prereqs = [
            p for p in (result.prerequisite_patches or [])
            if getattr(p, "grade", "") in ("strong", "medium")
        ]
        compare_tool_prereq_bundle = _collect_commit_diff_bundle(
            config, git_mgr, tv, [p.commit_id for p in compare_tool_prereqs]
        )

        known_prereqs_detail = []
        for kid in known_prereqs:
            info = git_mgr.run_git(
                ["git", "log", "-1", "--format=%H\x1e%s\x1e%an", kid],
                tv, timeout=10)
            if info:
                parts = info.strip().split("\x1e")
                known_prereqs_detail.append(serialize_commit_reference(
                    config, git_mgr, tv, parts[0],
                    extra={
                        "subject": parts[1] if len(parts) > 1 else "",
                        "author": parts[2] if len(parts) > 2 else "",
                    },
                ))
            else:
                known_prereqs_detail.append(serialize_commit_reference(
                    config, git_mgr, tv, kid,
                    extra={"subject": "", "author": ""}))

        recommendations = result.recommendations if result.recommendations else []

        # ── 输出补丁文件到 analysis_results/ ────────────────
        output_dir = output_dir or ensure_case_output_dir(config.output.output_dir, run_id, "validate", cve_id)
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

        generated_patch_for_compare = ""
        primary_compare_source = ""
        primary_compare_note = ""
        primary_generated_vs_real = {}
        if use_community:
            generated_patch_for_compare = community_diff
            primary_compare_source = "community_patch"
            primary_generated_vs_real = _compare_generated_vs_real(
                community_diff, primary_local_diff or local_diff)
            primary_compare_note = (
                f"apply_method={apply_method}，社区补丁可直接应用，"
                "使用社区原始补丁做本质比较"
            )
        elif adapted_patch and local_diff:
            generated_patch_for_compare = adapted_patch
            primary_generated_vs_real = _compare_generated_vs_real(
                adapted_patch, primary_local_diff or local_diff)
            is_regen = apply_method in (
                "regenerated", "conflict-adapted", "verified-direct")
            primary_compare_source = (
                "adapted_patch" if is_regen else "adapted_patch(community)")
        elif community_diff and local_diff:
            generated_patch_for_compare = community_diff
            primary_compare_source = "community_patch"
            primary_generated_vs_real = _compare_generated_vs_real(
                community_diff, primary_local_diff or local_diff)
        if primary_generated_vs_real:
            primary_generated_vs_real["compare_source"] = primary_compare_source
            if primary_compare_note:
                primary_generated_vs_real["note"] = primary_compare_note
            primary_generated_vs_real["compare_scope"] = "single_fix" if len(known_fix_commits) == 1 else "primary_fix"

        predicted_solution_diff = _combine_patch_texts([
            generated_patch_for_compare,
            compare_tool_prereq_bundle.get("combined_diff", ""),
        ])
        solution_set_needed = (
            len(actual_solution_commits) > 1
            or len(compare_tool_prereqs) > 0
        )
        generated_vs_real = primary_generated_vs_real
        solution_set_vs_real = {}
        if solution_set_needed and predicted_solution_diff and local_diff:
            solution_set_vs_real = _compare_generated_vs_real(
                predicted_solution_diff,
                local_diff,
            )
            solution_set_vs_real["compare_source"] = "predicted_solution_set"
            solution_set_vs_real["compare_scope"] = "solution_set"
            solution_set_vs_real["generated_components"] = {
                "main_patch_source": primary_compare_source or "community_patch",
                "tool_prereq_scope": "strong_medium_only",
                "tool_prereq_count": len(compare_tool_prereqs),
                "tool_prereq_commits": [p.commit_id[:12] for p in compare_tool_prereqs[:8]],
            }
            solution_set_vs_real["real_components"] = {
                "known_fix_count": len(known_fix_commits),
                "known_prereq_count": len(known_prereqs),
                "actual_solution_commit_count": len(actual_solution_commits),
                "actual_solution_commits": [cid[:12] for cid in actual_solution_commits[:12]],
            }
            solution_set_vs_real["note"] = (
                "按“工具生成主补丁 + 工具判定的 strong/medium 前置补丁”"
                " 对比 “实际 known_fix 集合 + known_prereqs 集合” 的整体代码修改。"
            )
        if not generated_vs_real and solution_set_vs_real:
            generated_vs_real = solution_set_vs_real

        diff_comparison = _compare_patch_code(
            generated_patch_for_compare or community_diff,
            primary_local_diff or local_diff,
        )
        root_cause = _diagnose_root_cause(diff_comparison, dryrun_detail,
                                          known_prereqs, result.dry_run)

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

        accuracy_recalibration = _maybe_recalibrate_validate_level_from_accuracy(
            result,
            generated_vs_real,
            pipe.policy_engine,
            wt_mgr,
            tv,
            getattr(pipe.dryrun, "path_mapper", None),
        )
        if accuracy_recalibration.get("applied"):
            checks["validate_level_recalibrated"] = True
            checks["validate_level_recalibration_reason"] = accuracy_recalibration.get("reason", "")
        else:
            checks["validate_level_recalibrated"] = False

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

        serialized_validation_details = serialize_validation_details(result.validation_details)
        dependency_details = serialize_dependency_details(result.dependency_details)
        intro_analysis = {}
        if result.introduced_search:
            intro_analysis = serialize_search_result(result.introduced_search)
        fix_analysis = {}
        if result.fix_search:
            fix_analysis = serialize_search_result(result.fix_search)

        out = {
            "cve_id": cve_id, "known_fix": primary_known_fix, "known_fix_commits": known_fix_commits, "target": tv,
            "target_version": tv,
            "worktree_commit": rollback_hash[:16] if rollback_hash else rollback,
            "checks": checks,
            "overall_pass": overall and not issues,
            "summary": "; ".join(issues) if issues else "验证通过",
            "issues": issues,
            "analysis_narrative": narrative,
            "analysis_framework": (
                serialized_validation_details.get("decision_skeleton", {})
                if result.validation_details else {}
            ),
            "fix_patch_detail": fix_patch_detail,
            "dryrun_detail": dryrun_detail,
            "level_decision": serialize_level_decision(result.level_decision),
            "validation_details": serialized_validation_details,
            "dependency_details": dependency_details,
            "manual_review_checklist": serialized_validation_details.get("manual_review_checklist", []),
            "function_impacts": serialize_function_impacts(result.function_impacts),
            "known_fix_detail": known_fix_detail,
            "known_fixs_detail": known_fix_details,
            "actual_solution_commits": actual_solution_commits,
            "actual_solution_detail": actual_solution_details,
            "diff_comparison": diff_comparison,
            "generated_vs_real": generated_vs_real,
            "generated_patch_vs_primary_fix": primary_generated_vs_real if solution_set_needed else {},
            "solution_set_vs_real": solution_set_vs_real,
            "accuracy_recalibration": accuracy_recalibration,
            "root_cause": root_cause,
            "tool_prereqs": tool_prereqs_detail,
            "tool_prereqs_for_compare": [p.commit_id[:12] for p in compare_tool_prereqs],
            "known_prereqs_detail": known_prereqs_detail,
            "recommendations": recommendations,
            "patch_file": patch_file,
            "community_patch_file": community_patch_file,
            "real_fix_patch_file": real_fix_patch_file,
            "analysis_stages": stage_events,
            "intro_analysis": intro_analysis,
            "fix_analysis": fix_analysis,
            "known_prereqs": known_prereqs,
            "run_id": run_id,
            "output_dir": output_dir,
            "artifacts": {
                "run_id": run_id,
                "output_dir": output_dir,
                "patch_files": {
                    key: value for key, value in {
                        "adapted_patch": patch_file,
                        "community_patch": community_patch_file,
                        "real_fix_patch": real_fix_patch_file,
                    }.items() if value
                },
            },
            "rules": collect_rules_metadata(
                getattr(config, "policy", None),
                level_decision=result.level_decision,
                validation_details=serialized_validation_details,
            ),
            "traceability": {
                "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "target_repo": build_repo_traceability(config, git_mgr, tv),
                "policy": {
                    "profile": getattr(getattr(config, "policy", None), "profile", "default") if getattr(config, "policy", None) else "default",
                    "rule_version": serialized_validation_details.get("rule_version", ""),
                    "rule_switches": (collect_rules_metadata(getattr(config, "policy", None)).get("policy_overrides") if getattr(config, "policy", None) else {}),
                },
                "search": getattr(getattr(pipe, "analysis", None), "search_profile", {}),
                "data_sources": ["target_repo", "known_fix_local", "community_fix_patch", "validate_pipeline"],
            },
        }
        if deep_analysis is not None:
            out["deep_analysis"] = deep_analysis
        return enrich_result_payload(out, "validate")

    finally:
        git_mgr.remove_worktree(tv, wt_dir)


# ─── build-cache ─────────────────────────────────────────────────────
# ─── main ────────────────────────────────────────────────────────────

def main():
    from commands import register_all

    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("-q", "--quiet", action="store_true", help="静默模式(仅日志文件)")

    p = argparse.ArgumentParser(
        description="CVE 补丁回溯分析工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[parent],
    )
    p.add_argument("-c", "--config", default="config.yaml")
    sub = p.add_subparsers(dest="command")
    dispatch = register_all(sub, parent)

    args = p.parse_args()
    if not args.command:
        p.print_help()
        sys.exit(1)

    config = ConfigLoader.load(args.config)
    _setup_logging(config, quiet=args.quiet)
    dispatch[args.command](args, config, sys.modules[__name__])


if __name__ == "__main__":
    main()
