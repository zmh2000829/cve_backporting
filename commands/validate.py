"""`validate` / `benchmark` / `batch-validate` 命令入口。"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from collections import OrderedDict
from datetime import datetime

from rich.panel import Panel

from commands.policy_cli import (
    add_p2_toggle,
    add_policy_profile_arg,
    add_search_profile_arg,
    apply_policy_cli_overrides,
)
from core.output_serializers import (
    aggregate_batch_validate_summary,
    build_l0_l5_view,
    collect_rules_metadata,
)
from core.report_schema import build_report_envelope
from services.output_support import (
    build_repo_traceability,
    ensure_case_output_dir,
    ensure_mode_output_dir,
    make_run_id,
)


def _status_to_cn(kind: str, status: str) -> str:
    mapping = {
        "direct_backport": {
            "direct": "可直接回移",
            "review": "接近可直接回移，但建议复核",
            "blocked": "不建议直接回移",
            "not_applicable": "当前不适用",
            "insufficient_intel": "情报不足",
        },
        "prerequisite": {
            "independent": "可按独立补丁处理",
            "recommended": "建议检查关联补丁",
            "required": "必须检查关联补丁",
            "weak_only": "仅弱关联，可按需复核",
            "not_applicable": "当前不适用",
            "insufficient_intel": "情报不足",
        },
        "risk": {
            "high": "高风险",
            "attention": "需要重点关注",
            "low": "未发现显著额外风险",
            "not_applicable": "当前不适用",
            "insufficient_intel": "情报不足",
        },
    }
    return mapping.get(kind, {}).get(status or "", status or "未知")


def _describe_dependency_bucket(bucket: str) -> str:
    mapping = {
        "independent": "未发现必须额外关注的关联补丁，可按独立补丁处理。",
        "recommended": "建议检查关联补丁，当前补丁不是最稳妥的“直接回移”场景。",
        "required": "存在必须关注的关联补丁，不能仅按单补丁回移处理。",
    }
    return mapping.get(bucket or "", "未形成明确的关联补丁判断。")


def _build_batch_case_summary(item: dict, result: dict) -> dict:
    framework = (result.get("analysis_framework") or {})
    process = framework.get("process") or {}
    conclusion = framework.get("conclusion") or {}
    result_status = result.get("result_status") or {}
    current_level = item.get("current_level") or "未知"
    base_level = item.get("base_level") or "未知"
    dependency_bucket = item.get("dependency_bucket") or ""
    direct_status = _status_to_cn("direct_backport", item.get("direct_backport_status", ""))
    prereq_status = _status_to_cn("prerequisite", item.get("prerequisite_status", ""))
    risk_status = _status_to_cn("risk", item.get("risk_status", ""))
    special_risk_sections = item.get("special_risk_sections") or []
    critical_structure_change = bool(item.get("critical_structure_change"))
    incomplete_reason = item.get("incomplete_reason") or result_status.get("incomplete_reason", "")

    key_hits = []
    if critical_structure_change:
        key_hits.append("命中关键结构变更")
    if special_risk_sections:
        key_hits.append("命中专项高风险: " + "、".join(special_risk_sections[:4]))
    if not key_hits:
        key_hits.append("未命中显著专项高风险")

    one_liner = f"最终级别 {current_level}，{direct_status}，{prereq_status}，风险判断为“{risk_status}”。"
    if result_status.get("state") == "incomplete":
        one_liner = f"当前结论不完整：{result_status.get('user_message', one_liner)}"
    elif result_status.get("state") == "error":
        one_liner = f"当前验证失败：{result_status.get('user_message', one_liner)}"
    elif item.get("solution_set_verdict"):
        one_liner += (
            f" 主补丁准确度={item.get('verdict') or 'unknown'}，"
            f"整套解集准确度={item.get('solution_set_verdict')}。"
        )

    return {
        "一句话结论": one_liner,
        "结论": {
            "最终级别": current_level,
            "基线级别": base_level,
            "是否可直接回移": direct_status,
            "是否需要关联补丁": prereq_status,
            "风险判断": risk_status,
            "结果状态": result_status.get("state", "complete"),
            "情报不足原因": incomplete_reason,
        },
        "为什么这样判": [
            f"DryRun 基线先给出 {base_level} 级。",
            _describe_dependency_bucket(dependency_bucket),
            "涉及锁/生命周期/状态机/结构体字段等关键结构变化。" if critical_structure_change else "未发现明显的关键结构变更信号。",
            ("专项高风险命中: " + "、".join(special_risk_sections[:4])) if special_risk_sections else "未命中专项高风险分项。",
            result_status.get("user_message", ""),
        ],
        "关键命中": {
            "关键结构变更": critical_structure_change,
            "专项高风险": special_risk_sections,
            "关联补丁分桶": dependency_bucket or "unknown",
            "结果状态": result_status.get("state", "complete"),
            "情报不足原因": incomplete_reason,
        },
        "下一步建议": ((conclusion.get("final") or {}).get("next_action", "")),
        "过程步骤": (process.get("workflow_steps") or [])[:6],
    }


def _aggregate_item_statistics(passed: list, failed: list) -> dict:
    level_counts = OrderedDict((f"L{i}", 0) for i in range(6))
    special_risk_section_counts = {}
    critical_structure_change_count = 0
    any_special_risk_count = 0
    manual_prerequisite_analysis_count = 0

    for item in list(passed or []) + list(failed or []):
        level = item.get("current_level") or ((item.get("l0_l5") or {}).get("current_level"))
        if level in level_counts:
            level_counts[level] += 1
        if item.get("critical_structure_change"):
            critical_structure_change_count += 1
        sections = item.get("special_risk_sections") or []
        if sections:
            any_special_risk_count += 1
        for section in sections:
            special_risk_section_counts[section] = special_risk_section_counts.get(section, 0) + 1
        if item.get("dependency_bucket") in ("required", "recommended"):
            manual_prerequisite_analysis_count += 1

    return {
        "level_distribution": {
            "levels": list(level_counts.keys()),
            "final_level_counts": dict(level_counts),
        },
        "risk_hit_summary": {
            "critical_structure_change_count": critical_structure_change_count,
            "any_special_risk_count": any_special_risk_count,
            "manual_prerequisite_analysis_count": manual_prerequisite_analysis_count,
            "special_risk_section_counts": dict(sorted(special_risk_section_counts.items())),
        },
    }

def register(subparsers, parent):
    validate = subparsers.add_parser("validate", help="基于已修复CVE验证工具准确度", parents=[parent])
    validate.add_argument("--cve", dest="cve_id", required=True)
    validate.add_argument("--target", dest="target_version", required=True)
    validate.add_argument("--known-fix", required=True, help="本地仓库中真实修复的 commit ID；多个可用逗号分隔")
    validate.add_argument("--known-prereqs", default="", help="实际先合入的前置commit列表 (逗号分隔)")
    validate.add_argument("--mainline-fix", default="", help="社区 mainline 修复 commit ID (提供后跳过 MITRE 爬取)")
    validate.add_argument("--mainline-intro", default="", help="社区 mainline 引入 commit ID (可选)")
    validate.add_argument("--deep", action="store_true", help="深度分析模式: 漏洞分析+补丁检视+风险收益+合入建议")
    add_policy_profile_arg(validate)
    add_search_profile_arg(validate)
    add_p2_toggle(validate)

    benchmark = subparsers.add_parser("benchmark", help="批量准确度基准测试", parents=[parent])
    benchmark.add_argument("--file", required=True, help="基准测试YAML文件 (benchmarks.yaml)")
    benchmark.add_argument("--target", dest="target_version", required=True)
    add_policy_profile_arg(benchmark)
    add_search_profile_arg(benchmark)
    add_p2_toggle(benchmark)

    batch = subparsers.add_parser("batch-validate", help="批量验证补丁生成准确度 (JSON)", parents=[parent])
    batch.add_argument("--file", required=True, help="CVE 数据 JSON 文件 (含 hulk_fix_patchs)")
    batch.add_argument("--target", dest="target_version", required=True)
    batch.add_argument("--offset", type=int, default=0, help="跳过前 N 个 CVE, 从第 N+1 个开始 (默认 0)")
    batch.add_argument("--limit", type=int, default=0, help="处理的 CVE 数量 (0=全部, 与 --offset 配合使用)")
    batch.add_argument("--workers", type=int, default=1, help="并行 worker 数 (默认 1，推荐 2，上限 4；--deep 时建议 <=2)")
    batch.add_argument("--deep", action="store_true", help="深度分析模式: 漏洞分析+补丁检视+风险收益+合入建议")
    batch.add_argument("--xlsx", action="store_true", help="额外输出 batch-validate XLSX 明细表格 (默认关闭)")
    add_policy_profile_arg(batch)
    add_search_profile_arg(batch)
    add_p2_toggle(batch)

    return {
        "validate": run_validate,
        "benchmark": run_benchmark,
        "batch-validate": run_batch_validate,
    }


def _build_cve_info_from_json(info: dict, cve_id: str):
    from core.models import CveInfo

    mainline_fixes = info.get("mainline_fix_patchs", [])
    mainline_intros = info.get("mainline_import_patchs", [])

    fix_commits = []
    mainline_fix = ""
    for patch in (mainline_fixes if isinstance(mainline_fixes, list) else []):
        if isinstance(patch, dict) and patch.get("commit"):
            fix_commits.append({
                "commit_id": patch["commit"],
                "subject": patch.get("subject", ""),
            })
            if not mainline_fix:
                mainline_fix = patch["commit"]

    intro_commits = []
    for patch in (mainline_intros if isinstance(mainline_intros, list) else []):
        if isinstance(patch, dict) and patch.get("commit"):
            intro_commits.append({
                "commit_id": patch["commit"],
                "subject": patch.get("subject", ""),
            })

    if not mainline_fix:
        return None

    return CveInfo(
        cve_id=cve_id,
        fix_commits=fix_commits,
        mainline_fix_commit=mainline_fix,
        introduced_commits=intro_commits,
    )


def _flush_live_report(path: str, target: str, total: int, passed: list, failed: list, errors: list):
    done = len(passed) + len(failed) + len(errors)
    statistics = _aggregate_item_statistics(passed, failed)
    report = {
        "target": target,
        "progress": f"{done}/{total}",
        "summary": {
            "total": total,
            "done": done,
            "passed": len(passed),
            "failed": len(failed),
            "errors": len(errors),
            "statistics": statistics,
        },
        "passed": passed,
        "failed": failed,
        "errors": errors,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)


def _resolve_batch_workers(requested: int, deep: bool = False) -> int:
    workers = max(1, int(requested or 1))
    workers = min(workers, 4)
    if deep and workers > 2:
        workers = 2
    return workers


def _make_parallel_git_mgr(config):
    from core.git_manager import GitRepoManager

    return GitRepoManager(config.repositories, use_cache=False)


def _execute_batch_validate_case(runtime, config, tv, cve_id, group, *, deep=False, git_mgr=None, show_stages=False,
                                 run_id: str = ""):
    pass_verdicts = {"identical", "essentially_same"}
    primary = group["primary_fix"]
    prereqs = group["prereq_fixes"]
    cve_info = group.get("cve_info")
    known_fix_commits = [item["commit"] for item in group.get("all_fixes", []) if item.get("commit")]
    known_prereq_commits = [p["commit"] for p in prereqs]
    worker_git_mgr = git_mgr if git_mgr is not None else _make_parallel_git_mgr(config)

    result = None
    case_output_dir = ensure_case_output_dir(config.output.output_dir, run_id or make_run_id(), "batch-validate-case", cve_id)
    for _attempt in range(1, 4):
        result = runtime._run_single_validate(
            config, cve_id, tv, primary["commit"], known_prereq_commits,
            git_mgr=worker_git_mgr, show_stages=show_stages, cve_info=cve_info,
            deep=deep,
            output_dir=case_output_dir,
            run_id=run_id,
            known_fixes=known_fix_commits,
        )
        has_patch = result.get("dryrun_detail", {}).get("has_adapted_patch", False)
        verdict = result.get("generated_vs_real", {}).get("verdict", "no_data")
        if has_patch or verdict not in ("no_data", "error"):
            break

    generated = result.get("generated_vs_real", {})
    solution_set = result.get("solution_set_vs_real", {})
    verdict = generated.get("verdict", "no_data")
    core_sim = generated.get("core_similarity", 0)
    method = result.get("dryrun_detail", {}).get("apply_method", "-")

    prereq_validation = {}
    if prereqs and result.get("dryrun_detail"):
        tool_prereqs = result.get("tool_prereqs", [])
        tool_prereq_ids = {tp.get("commit_id", "")[:12] for tp in tool_prereqs if tp.get("commit_id")}
        known_ids = {commit[:12] for commit in known_prereq_commits}
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
            prereq_validation["recall"] = round(len(matched) / len(known_ids), 3)

    result["prereq_cross_validation"] = prereq_validation
    result["num_hulk_fixes"] = len(group["all_fixes"])

    level_view = build_l0_l5_view(result)
    special_risk_summary = ((result.get("validation_details") or {}).get("special_risk_report") or {}).get("summary", {})
    conclusion = ((result.get("analysis_framework") or {}).get("conclusion") or {})
    result_status = result.get("result_status") or {}

    item = {
        "cve_id": cve_id,
        "known_fix": primary["commit"][:12],
        "verdict": verdict,
        "core_similarity": round(core_sim, 3),
        "deterministic_exact_match": bool(generated.get("deterministic_exact_match")),
        "solution_set_verdict": solution_set.get("verdict", ""),
        "solution_set_core_similarity": round(solution_set.get("core_similarity", 0), 3) if solution_set else None,
        "method": method,
        "l0_l5": level_view,
        "current_level": level_view.get("current_level", ""),
        "base_level": level_view.get("base_level", ""),
        "dependency_bucket": level_view.get("dependency_bucket", ""),
        "critical_structure_change": bool(special_risk_summary.get("has_critical_structure_change")),
        "special_risk_sections": list(special_risk_summary.get("triggered_sections") or []),
        "direct_backport_status": ((conclusion.get("direct_backport") or {}).get("status", "")),
        "prerequisite_status": ((conclusion.get("prerequisite") or {}).get("status", "")),
        "risk_status": ((conclusion.get("risk") or {}).get("status", "")),
        "result_state": result_status.get("state", "complete"),
        "incomplete_reason": result_status.get("incomplete_reason", ""),
        "num_fixes": len(group["all_fixes"]),
        "num_prereqs": len(prereqs),
        "prereq_recall": prereq_validation.get("recall", None),
        "summary": "",
        "technical_summary": result.get("summary", ""),
    }
    item["summary_cn"] = _build_batch_case_summary(item, result)
    item["summary"] = item["summary_cn"]["一句话结论"]

    v2 = result.get("deep_analysis")
    if v2 is not None:
        rec = getattr(v2, "merge_recommendation", None)
        if rec and hasattr(rec, "action"):
            item["deep_action"] = rec.action
            item["deep_summary"] = getattr(rec, "summary", "")
            rb = getattr(rec, "risk_benefit", None)
            if rb:
                item["deep_overall_score"] = round(rb.overall_score, 2)
                item["deep_overall_detail"] = rb.overall_detail

    if verdict in pass_verdicts:
        bucket = "passed"
    else:
        reason = result.get("summary", "")
        if verdict == "no_data":
            reason = reason or "无补丁数据可比较"
        elif verdict == "different":
            reason = reason or f"核心相似度仅 {core_sim:.0%}"
        elif verdict == "partially_same":
            reason = reason or f"部分一致 (核心相似度 {core_sim:.0%})"
        item["reason"] = reason
        bucket = "failed"

    return {
        "result": result,
        "bucket": bucket,
        "item": item,
        "verdict": verdict,
        "core_similarity": core_sim,
        "method": method,
    }


def _build_batch_reading_guide() -> dict:
    return {
        "purpose": "本文件已按“先看汇总结论，再看分组结果，最后看技术明细”的顺序重组，优先阅读 summary。",
        "recommended_order": [
            "1. summary.overview：先看总量、并行参数、P2 是否开启",
            "2. summary.level_distribution：看每个 L0-L5 级别有多少个",
            "3. summary.strategy_effectiveness：看 7 个确定性策略 + AI 兜底的占比和效果",
            "4. summary.level_accuracy：看每个 L0-L5 级别各自的验证通过率和补丁准确率",
            "5. summary.risk_hit_summary：看关键结构变更、专项高风险、关联补丁等统计",
            "6. result_groups.passed / failed / errors[*].summary_cn：看每个 CVE 的中文结论与原因",
            "7. technical_details.cve_results：需要深挖时再看每个 CVE 的完整技术明细",
        ],
        "field_explanations": {
            "current_level": "最终 L0-L5 级别，表示结合规则抬升后的最终场景。",
            "base_level": "DryRun 基线级别，表示规则抬升前的原始级别。",
            "strategy_effectiveness": "多级 DryRun 策略效果统计，按 presentation 中的 7 个确定性策略家族聚合。",
            "level_accuracy": "每个 L0-L5 级别的单独准确率统计，区分 overall_pass、acceptable_patch 和 exact_match。",
            "critical_structure_change": "是否涉及锁、生命周期、状态机、结构体字段等关键结构变化。",
            "special_risk_sections": "命中的专项高风险类别。",
            "summary_cn": "面向用户的中文结论块，优先阅读这一段而不是 technical_summary。",
        },
    }


def _build_batch_summary_view(tv: str, total_cves: int, total_patches: int, skipped: int, workers: int, p2_enabled: bool, batch_summary: dict) -> dict:
    l0_l5 = batch_summary.get("l0_l5", {}) or {}
    special_risk = batch_summary.get("special_risk", {}) or {}
    risk_hit_summary = batch_summary.get("risk_hit_summary", {}) or {}
    level_distribution = batch_summary.get("level_distribution", {}) or {}
    return {
        "overview": {
            "target_version": tv,
            "total_cves": total_cves,
            "total_patches": total_patches,
            "skipped_parse_errors": skipped,
            "workers": workers,
            "parallel_mode": workers > 1,
            "p2_enabled": p2_enabled,
        },
        "statistics": batch_summary.get("statistics", {}),
        "result_states": batch_summary.get("result_state_distribution", {}),
        "incomplete_reasons": batch_summary.get("incomplete_reason_distribution", {}),
        "level_distribution": {
            "levels": level_distribution.get("levels", l0_l5.get("levels", ["L0", "L1", "L2", "L3", "L4", "L5"])),
            "final_level_counts": level_distribution.get("final_level_counts", l0_l5.get("current_level_distribution", {})),
            "base_level_counts": level_distribution.get("base_level_counts", l0_l5.get("base_level_distribution", {})),
        },
        "strategy_effectiveness": batch_summary.get("strategy_effectiveness", {}),
        "level_accuracy": batch_summary.get("level_accuracy", {}),
        "risk_hit_summary": {
            "any_special_risk": risk_hit_summary.get("any_special_risk", {
                "count": special_risk.get("any_special_risk_count", 0),
            }),
            "critical_structure_change": risk_hit_summary.get("critical_structure_change", batch_summary.get("critical_structure_change", {})),
            "special_risk_section_counts": risk_hit_summary.get("special_risk_section_counts", special_risk.get("section_counts", {})),
            "manual_prerequisite_analysis": batch_summary.get("manual_prerequisite_analysis", {}),
        },
        "key_findings": {
            "deterministic_exact_match": batch_summary.get("deterministic_exact_match", {}),
            "solution_set_deterministic_exact_match": batch_summary.get("solution_set_deterministic_exact_match", {}),
            "critical_structure_change": batch_summary.get("critical_structure_change", {}),
            "manual_prerequisite_analysis": batch_summary.get("manual_prerequisite_analysis", {}),
            "special_risk_section_counts": special_risk.get("section_counts", {}),
            "special_risk_samples": special_risk.get("samples", {}),
            "verdict_distribution": batch_summary.get("verdict_distribution", {}),
            "solution_set_verdict_distribution": batch_summary.get("solution_set_verdict_distribution", {}),
        },
    }


def _prepare_batch_validate_json(tv: str, *, workers: int, total_cves: int, total_patches: int, skipped: int,
                                 p2_enabled: bool, batch_summary: dict, strategy_summary: dict,
                                 passed_list: list, failed_list: list, error_list: list, cve_results: list,
                                 traceability: dict = None, artifacts: dict = None) -> dict:
    return build_report_envelope(
        "batch-validate",
        reading_guide=_build_batch_reading_guide(),
        summary=_build_batch_summary_view(
            tv, total_cves, total_patches, skipped, workers, p2_enabled, batch_summary
        ),
        technical_details={
            "batch_summary": batch_summary,
            "strategy_summary": strategy_summary,
            "cve_results": cve_results,
        },
        extra={
            "traceability": traceability or {},
            "artifacts": artifacts or {},
            "result_groups": {
                "passed": passed_list,
                "failed": failed_list,
                "errors": error_list,
            },
        },
    )


def run_validate(args, config, runtime):
    config = apply_policy_cli_overrides(config, args)
    tv = args.target_version
    git_mgr = runtime._make_git_mgr(config, tv)
    run_id = make_run_id()
    known_fix_commits = runtime._coerce_commit_list(args.known_fix)
    primary_known_fix = known_fix_commits[0] if known_fix_commits else args.known_fix
    known_prereqs = [p.strip() for p in args.known_prereqs.split(",") if p.strip()] if args.known_prereqs else []

    cve_info = None
    mainline_fix = getattr(args, "mainline_fix", "") or ""
    mainline_intro = getattr(args, "mainline_intro", "") or ""
    if mainline_fix:
        from core.models import CveInfo

        fix_commits = [{"commit_id": mainline_fix, "subject": ""}]
        intro_commits = ([{"commit_id": mainline_intro, "subject": ""}] if mainline_intro else [])
        cve_info = CveInfo(
            cve_id=args.cve_id,
            fix_commits=fix_commits,
            mainline_fix_commit=mainline_fix,
            introduced_commits=intro_commits,
        )

    info_lines = [
        f"[bold]CVE:[/] {args.cve_id}  [bold]目标:[/] {tv}",
        f"[bold]Known Fix:[/] {primary_known_fix[:12]}" + (f"  [dim](共 {len(known_fix_commits)} 个实际 fix)[/]" if len(known_fix_commits) > 1 else ""),
        f"[bold]Known Prereqs:[/] {len(known_prereqs)} 个",
    ]
    if mainline_fix:
        info_lines.append(f"[bold]Mainline Fix:[/] {mainline_fix[:12]}  [dim](跳过 MITRE 爬取)[/]")
    if mainline_intro:
        info_lines.append(f"[bold]Mainline Intro:[/] {mainline_intro[:12]}")
    runtime.console.print(Panel(
        "\n".join(info_lines),
        title="[bold magenta]验证框架 — 单CVE回退验证[/]",
        border_style="magenta", padding=(0, 2),
    ))

    result = runtime._run_single_validate(
        config, args.cve_id, tv, primary_known_fix, known_prereqs,
        git_mgr=git_mgr, show_stages=True, cve_info=cve_info,
        deep=getattr(args, "deep", False),
        output_dir=ensure_case_output_dir(config.output.output_dir, run_id, "validate", args.cve_id),
        run_id=run_id,
        known_fixes=known_fix_commits,
    )

    if not result.get("overall_pass"):
        if config.llm.enabled:
            from core.llm_analyzer import LLMAnalyzer

            analyzer = LLMAnalyzer(config.llm)
            if analyzer.enabled:
                diff_cmp = result.get("diff_comparison", {})
                fp_detail = result.get("fix_patch_detail", {})
                dr_detail = result.get("dryrun_detail", {})
                code_diff_ctx = ""
                for kd in diff_cmp.get("key_differences", [])[:3]:
                    code_diff_ctx += f"\n### {kd['file']} (相似度 {kd['similarity']:.0%})\n"
                    ce = kd.get("community_extra", [])
                    le = kd.get("local_extra", [])
                    if ce:
                        code_diff_ctx += "社区补丁独有:\n" + "\n".join(f"  {line}" for line in ce[:5]) + "\n"
                    if le:
                        code_diff_ctx += "本地修复独有:\n" + "\n".join(f"  {line}" for line in le[:5]) + "\n"

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
                    "root_cause_diagnosis": "\n".join(result.get("root_cause", [])),
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
                with runtime.console.status("[cyan]LLM 正在分析验证差异..."):
                    llm_analysis = analyzer.analyze_validate_diff(llm_ctx)
                if llm_analysis:
                    result["llm_analysis"] = llm_analysis
                else:
                    result["llm_status"] = "LLM 调用失败，请检查日志"
            else:
                result["llm_status"] = "LLM api_key 未配置"
        else:
            result["llm_status"] = "LLM 未启用 (config.yaml → llm.enabled: true)"

    runtime.console.print()
    runtime.render_validate_report(result, policy_config=getattr(config, "policy", None))

    v2 = result.get("deep_analysis")
    if v2 is not None:
        runtime.console.print()
        runtime.console.print(Panel(
            "[bold]以下为 v2 深度分析结果 (漏洞/补丁检视/风险收益/合入建议)[/]",
            border_style="magenta"))
        runtime._render_deep_report(v2)

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)
    report_dir = ensure_case_output_dir(out_dir, run_id, "validate", args.cve_id)
    fp = os.path.join(report_dir, "report.json")
    result["report_file"] = fp
    artifacts = dict(result.get("artifacts") or {})
    artifacts.update({
        "run_id": run_id,
        "output_dir": report_dir,
        "report_file": fp,
    })
    result["artifacts"] = artifacts
    save_data = runtime._prepare_validate_json(result)
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(save_data, f, indent=2, ensure_ascii=False, default=str)
    runtime.console.print(f"[dim]验证报告已保存: {fp}[/]")


def run_benchmark(args, config, runtime):
    config = apply_policy_cli_overrides(config, args)
    import yaml

    with open(args.file, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    entries = data.get("benchmarks", [])
    if not entries:
        runtime.console.print("[red]YAML 文件中无 benchmarks 条目[/]")
        return

    tv = args.target_version
    git_mgr = runtime._make_git_mgr(config, tv)
    run_id = make_run_id()

    runtime.console.print(Panel(
        f"[bold]基准集:[/] {len(entries)} 个 CVE  [bold]目标:[/] {tv}\n"
        f"[bold]文件:[/] {args.file}",
        title="[bold cyan]Benchmark — 批量准确度度量[/]",
        border_style="cyan", padding=(0, 2),
    ))

    results = []
    for i, entry in enumerate(entries, 1):
        cve_id = entry.get("cve_id", "N/A")
        known_fix_commits = runtime._coerce_commit_list(entry.get("known_fix_commit", ""))
        known_fix = known_fix_commits[0] if known_fix_commits else ""
        known_prereqs = entry.get("known_prereqs", []) or []
        notes = entry.get("notes", "")

        runtime.console.print(f"\n{'━' * 60}")
        runtime.console.print(
            f"[bold cyan][{i}/{len(entries)}][/]  {cve_id}  "
            f"[dim]fix={known_fix[:12]}{' +' + str(len(known_fix_commits)-1) if len(known_fix_commits) > 1 else ''}  prereqs={len(known_prereqs)}[/]"
            + (f"  [dim italic]{notes}[/]" if notes else "")
        )

        if not known_fix:
            runtime.console.print("[yellow]  跳过: 缺少 known_fix_commit[/]")
            results.append({
                "cve_id": cve_id, "known_fix": "", "target": tv,
                "worktree_commit": "", "checks": {},
                "overall_pass": False, "summary": "缺少known_fix_commit",
            })
            continue

        result = runtime._run_single_validate(
            config, cve_id, tv, known_fix, known_prereqs,
            git_mgr=git_mgr, show_stages=True,
            output_dir=ensure_case_output_dir(config.output.output_dir, run_id, "benchmark-case", cve_id),
            run_id=run_id,
            known_fixes=known_fix_commits,
        )
        results.append(result)

        icon = "[green]✔ PASS[/]" if result.get("overall_pass") else "[red]✘ FAIL[/]"
        runtime.console.print(f"  {icon}  {result.get('summary', '')}")

    runtime.console.print(f"\n{'━' * 60}\n")
    runtime.render_benchmark_report(results, tv)

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)
    report_dir = ensure_mode_output_dir(out_dir, run_id, "benchmark", tv)
    fp = os.path.join(report_dir, "report.json")
    with open(fp, "w", encoding="utf-8") as f:
        json.dump({"target": tv, "total": len(results), "results": results},
                  f, indent=2, ensure_ascii=False, default=str)
    runtime.console.print(f"[dim]基准测试报告已保存: {fp}[/]")


def run_batch_validate(args, config, runtime):
    config = apply_policy_cli_overrides(config, args)
    try:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        runtime.console.print(f"[red bold]错误:[/] 无法解析 JSON 文件: {e}")
        return

    if not isinstance(data, dict):
        runtime.console.print("[red bold]错误:[/] JSON 顶层结构应为 dict (key=CVE编号, value=CVE数据)")
        return

    tv = args.target_version
    run_id = make_run_id()
    workers = _resolve_batch_workers(getattr(args, "workers", 1), getattr(args, "deep", False))
    git_mgr = runtime._make_git_mgr(config, tv) if workers == 1 else None

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
            mainline_fix_id = cve_info.mainline_fix_commit if cve_info else ""

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

            primary_idx = len(valid_fixes) - 1
            if mainline_fix_id:
                for idx, item in enumerate(valid_fixes):
                    if item["mainline_commit"] == mainline_fix_id:
                        primary_idx = idx
                        break

            primary_fix = valid_fixes[primary_idx]
            prereq_fixes = [item for idx, item in enumerate(valid_fixes) if idx != primary_idx]
            all_cve_groups[real_cve] = {
                "primary_fix": primary_fix,
                "prereq_fixes": prereq_fixes,
                "all_fixes": valid_fixes,
                "cve_info": cve_info,
            }
        except Exception as e:
            skipped += 1
            runtime.logger.warning("解析 CVE 条目 %s 跳过: %s", cve_id, e)

    all_keys = list(all_cve_groups.keys())
    total_available = len(all_keys)
    sliced_keys = all_keys[offset:]
    if limit:
        sliced_keys = sliced_keys[:limit]
    cve_groups = OrderedDict((key, all_cve_groups[key]) for key in sliced_keys)

    if not cve_groups:
        runtime.console.print("[red]JSON 文件中未找到有效的 CVE 验证条目[/]")
        runtime.console.print("[dim]要求: 每个条目需有 hulk_fix_patchs[].commit 字段[/]")
        return

    total_patches = sum(len(group["all_fixes"]) for group in cve_groups.values())
    multi_fix_cves = sum(1 for group in cve_groups.values() if len(group["prereq_fixes"]) > 0)
    has_mainline = sum(1 for group in cve_groups.values() if group.get("cve_info"))
    range_desc = f"第 {offset + 1}~{offset + len(cve_groups)} 个" if offset else f"共 {len(cve_groups)} 个"

    info_parts = [
        f"[bold]验证集:[/] {range_desc} CVE / {total_patches} 个补丁  [dim](JSON 共 {total_available} 个 CVE)[/]",
        f"[bold]目标分支:[/] {tv}",
        f"[bold]数据文件:[/] {args.file}",
        f"[bold]Mainline信息:[/] {has_mainline}/{len(cve_groups)} 个 CVE 使用 JSON 提供的 mainline commit (跳过 MITRE 爬取)",
        f"[bold]统计维度:[/] 每 CVE 一次验证 ({multi_fix_cves} 个含前置补丁, 额外 fix 作为 known_prereqs)",
        f"[bold]并行:[/] workers={workers}  [dim](推荐 2；--deep 建议 <=2；每个任务使用独立 worktree)[/]",
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
    runtime.console.print(Panel(
        "\n".join(info_parts),
        title="[bold magenta]批量验证 — 补丁生成准确度[/]",
        border_style="magenta", padding=(0, 2),
    ))

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)
    batch_report_dir = ensure_mode_output_dir(out_dir, run_id, "batch-validate", tv)
    live_report_path = os.path.join(batch_report_dir, "live_report.json")
    runtime.console.print(f"[dim]实时报告: {live_report_path} (每完成一个 CVE 自动更新)[/]")

    ordered_results = {}
    passed_list = []
    failed_list = []
    error_list = []

    pass_verdicts = {"identical", "essentially_same"}
    verdict_icons = {
        "identical": "[green]✔ 完全一致[/]",
        "essentially_same": "[green]✔ 本质相同[/]",
        "partially_same": "[yellow]△ 部分一致[/]",
        "different": "[red]✘ 差异较大[/]",
        "no_data": "[dim]- 无数据[/]",
    }

    entries = list(cve_groups.items())

    def _render_case_header(ci, cve_id, group):
        primary = group["primary_fix"]
        prereqs = group["prereq_fixes"]
        cve_info = group.get("cve_info")
        src = "JSON" if cve_info else "MITRE"
        runtime.console.print(f"\n{'━' * 60}")
        fix_desc = f"主修复={primary['commit'][:12]}"
        if prereqs:
            fix_desc += f"  前置={len(prereqs)}个"
        runtime.console.print(
            f"[bold magenta][{ci}/{len(cve_groups)}][/]  {cve_id}  "
            f"[dim]{fix_desc}  mainline={src}[/]"
        )
        if prereqs:
            for pi, pf in enumerate(prereqs, 1):
                runtime.console.print(
                    f"  [dim]prereq[{pi}] {pf['commit'][:12]}"
                    + (f"  {pf['subject'][:40]}" if pf.get("subject") else "")
                    + "[/]"
                )

    def _record_error(ci, cve_id, group, err):
        primary = group["primary_fix"]
        ordered_results[ci] = {
            "cve_id": cve_id, "known_fix": primary["commit"],
            "target": tv, "worktree_commit": "", "checks": {},
            "overall_pass": False, "summary": f"执行异常: {err}",
            "dryrun_detail": {},
            "generated_vs_real": {
                "verdict": "error", "core_similarity": 0,
                "file_coverage": 0,
            },
            "num_hulk_fixes": len(group["all_fixes"]),
        }
        error_list.append({
            "cve_id": cve_id,
            "known_fix": primary["commit"][:12],
            "reason": str(err),
        })

    if workers == 1:
        for ci, (cve_id, group) in enumerate(entries, 1):
            _render_case_header(ci, cve_id, group)
            try:
                case_out = _execute_batch_validate_case(
                    runtime, config, tv, cve_id, group,
                    deep=getattr(args, "deep", False),
                    git_mgr=git_mgr,
                    show_stages=True,
                    run_id=run_id,
                )
                ordered_results[ci] = case_out["result"]
                icon = verdict_icons.get(case_out["verdict"], f"[dim]{case_out['verdict']}[/]")
                runtime.console.print(
                    f"  {icon}  核心相似度={case_out['core_similarity']:.0%}  方法={case_out['method']}"
                )
                if case_out["bucket"] == "passed":
                    passed_list.append(case_out["item"])
                else:
                    failed_list.append(case_out["item"])
            except Exception as e:
                runtime.logger.exception("batch-validate 异常: %s %s", cve_id, e)
                runtime.console.print(f"  [red]✘ 跳过 (异常: {e})[/]")
                _record_error(ci, cve_id, group, e)
            _flush_live_report(live_report_path, tv, len(cve_groups), passed_list, failed_list, error_list)
    else:
        runtime.console.print("[dim]并行模式下将关闭单条 Live 阶段面板，避免多 worktree 输出互相覆盖。[/]")
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="batch-validate") as executor:
            future_map = {}
            for ci, (cve_id, group) in enumerate(entries, 1):
                _render_case_header(ci, cve_id, group)
                future = executor.submit(
                    _execute_batch_validate_case,
                    runtime, config, tv, cve_id, group,
                    deep=getattr(args, "deep", False),
                    git_mgr=None,
                    show_stages=False,
                    run_id=run_id,
                )
                future_map[future] = (ci, cve_id, group)

            for future in as_completed(future_map):
                ci, cve_id, group = future_map[future]
                try:
                    case_out = future.result()
                    ordered_results[ci] = case_out["result"]
                    icon = verdict_icons.get(case_out["verdict"], f"[dim]{case_out['verdict']}[/]")
                    runtime.console.print(
                        f"  [bold cyan]完成[/] [{ci}/{len(cve_groups)}] {cve_id}  {icon}  核心相似度={case_out['core_similarity']:.0%}  方法={case_out['method']}"
                    )
                    if case_out["bucket"] == "passed":
                        passed_list.append(case_out["item"])
                    else:
                        failed_list.append(case_out["item"])
                except Exception as e:
                    runtime.logger.exception("batch-validate 并行异常: %s %s", cve_id, e)
                    runtime.console.print(f"  [red]✘ 跳过[/] [{ci}/{len(cve_groups)}] {cve_id}  异常: {e}")
                    _record_error(ci, cve_id, group, e)
                _flush_live_report(live_report_path, tv, len(cve_groups), passed_list, failed_list, error_list)

    cve_results = [ordered_results[idx] for idx in sorted(ordered_results)]

    runtime.console.print(f"\n{'━' * 60}\n")
    runtime.render_batch_validate_report(cve_results, tv, policy_config=getattr(config, "policy", None))

    serializable_results = [runtime._prepare_validate_json(r) for r in cve_results]
    batch_summary = aggregate_batch_validate_summary(serializable_results)
    strategy_summary = runtime.aggregate_strategy_buckets(serializable_results)
    p2_enabled = bool(getattr(config.policy, "special_risk_rules_enabled", True)) if getattr(config, "policy", None) else True
    trace_git_mgr = git_mgr or runtime._make_git_mgr(config, tv)
    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    policy_overrides = (
        collect_rules_metadata(getattr(config, "policy", None)).get("policy_overrides", {})
        if getattr(config, "policy", None) else {}
    )
    full_report_path = os.path.join(batch_report_dir, "full_report.json")
    xlsx_report_path = ""
    if getattr(args, "xlsx", False):
        try:
            from services.batch_xlsx import write_batch_validate_xlsx

            xlsx_report_path = os.path.join(batch_report_dir, "batch_validate_summary.xlsx")
            write_batch_validate_xlsx(
                xlsx_report_path,
                cve_results,
                tv,
                batch_summary=batch_summary,
                generated_at=generated_at,
            )
        except Exception as exc:
            xlsx_report_path = ""
            runtime.logger.exception("batch-validate XLSX 导出失败: %s", exc)
            runtime.console.print(f"[red]XLSX 表格导出失败: {exc}[/]")

    artifacts = {
        "run_id": run_id,
        "output_dir": batch_report_dir,
        "report_file": full_report_path,
        "live_report_file": live_report_path,
    }
    if xlsx_report_path:
        artifacts["xlsx_report_file"] = xlsx_report_path

    with open(full_report_path, "w", encoding="utf-8") as f:
        json.dump(
            _prepare_batch_validate_json(
                tv,
                workers=workers,
                total_cves=len(cve_groups),
                total_patches=total_patches,
                skipped=skipped,
                p2_enabled=p2_enabled,
                batch_summary=batch_summary,
                strategy_summary=strategy_summary,
                passed_list=passed_list,
                failed_list=failed_list,
                error_list=error_list,
                cve_results=serializable_results,
                traceability={
                    "mode": "batch-validate",
                    "target_version": tv,
                    "generated_at": generated_at,
                    "report_version": "friendly-json-v2",
                    "schema_version": "result-schema-v2",
                    "target_repo": build_repo_traceability(config, trace_git_mgr, tv),
                    "policy": {
                        "profile": getattr(getattr(config, "policy", None), "profile", "default") if getattr(config, "policy", None) else "default",
                        "rule_switches": policy_overrides,
                    },
                    "data_sources": ["target_repo", "batch_validate_input_json", "community_fix_patch", "known_fix_local"],
                    "source_timestamps": {
                        "report_generated_at": generated_at,
                    },
                },
                artifacts=artifacts,
            ),
            f, indent=2, ensure_ascii=False, default=str
        )
    runtime.console.print(f"[dim]完整结果: {full_report_path}[/]")
    runtime.console.print(f"[dim]实时报告: {live_report_path}[/]")
    if xlsx_report_path:
        runtime.console.print(f"[dim]XLSX 表格: {xlsx_report_path}[/]")
