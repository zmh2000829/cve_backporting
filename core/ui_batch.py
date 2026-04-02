"""Batch / benchmark 报告渲染。"""

from collections import Counter

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box


def render_benchmark_report(results: list, target: str):
    from core import ui as base
    from rich.console import Group

    total = len(results)
    if total == 0:
        base.console.print("[yellow]无验证结果[/]")
        return

    intro_ok = sum(1 for result in results if result.get("checks", {}).get("intro_detected", False))
    fix_ok = sum(1 for result in results if result.get("checks", {}).get("fix_correctly_absent", False))

    prec_vals, recall_vals, f1_vals = [], [], []
    dryrun_ok, dryrun_total = 0, 0
    strategy_dist = {"L1": 0, "L2": 0, "L3": 0, "未命中": 0}

    for result in results:
        checks = result.get("checks", {})
        prereq_metrics = checks.get("prereq_metrics")
        if prereq_metrics:
            prec_vals.append(prereq_metrics["precision"])
            recall_vals.append(prereq_metrics["recall"])
            f1_vals.append(prereq_metrics["f1"])
        dryrun_accurate = checks.get("dryrun_accurate")
        if dryrun_accurate is not None:
            dryrun_total += 1
            if dryrun_accurate:
                dryrun_ok += 1
        intro_strategy = checks.get("intro_strategy", "")
        if intro_strategy in ("exact_id", "L1"):
            strategy_dist["L1"] += 1
        elif intro_strategy in ("subject_match", "L2") or intro_strategy.startswith("subject"):
            strategy_dist["L2"] += 1
        elif intro_strategy.startswith("diff") or intro_strategy.startswith("L3"):
            strategy_dist["L3"] += 1
        elif intro_strategy:
            strategy_dist["L1"] += 1
        else:
            strategy_dist["未命中"] += 1

    avg_prec = sum(prec_vals) / len(prec_vals) if prec_vals else 0
    avg_recall = sum(recall_vals) / len(recall_vals) if recall_vals else 0
    avg_f1 = sum(f1_vals) / len(f1_vals) if f1_vals else 0

    summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    summary.add_column("指标", width=24, style="bold")
    summary.add_column("值", ratio=1)
    summary.add_row("基准集规模", f"[cyan]{total}[/] 个 CVE")
    summary.add_row("目标分支", f"[cyan]{target}[/]")
    summary.add_row("", "")
    summary.add_row("引入检测准确率", f"[bold]{intro_ok}/{total}  ({intro_ok/total:.1%})[/]")
    summary.add_row("修复检测准确率", f"[bold]{fix_ok}/{total}  ({fix_ok/total:.1%})[/]")
    if prec_vals:
        summary.add_row("前置依赖 平均精确率", f"[bold]{avg_prec:.1%}[/]")
        summary.add_row("前置依赖 平均召回率", f"[bold]{avg_recall:.1%}[/]")
        summary.add_row("前置依赖 平均F1", f"[bold]{avg_f1:.1%}[/]")
    if dryrun_total:
        summary.add_row("DryRun 准确率", f"[bold]{dryrun_ok}/{dryrun_total}  ({dryrun_ok/dryrun_total:.1%})[/]")

    strategy_parts = [f"{key}: {value} ({value/total:.0%})" for key, value in strategy_dist.items() if value]
    summary.add_row("", "")
    summary.add_row("搜索策略分布", "  ".join(strategy_parts))

    detail = Table(box=box.ROUNDED, show_header=True, padding=(0, 1), expand=True)
    detail.add_column("#", width=3, justify="right", style="dim")
    detail.add_column("CVE", width=20, style="cyan")
    detail.add_column("引入", width=6, justify="center")
    detail.add_column("修复", width=6, justify="center")
    detail.add_column("精确率", width=8, justify="right")
    detail.add_column("召回率", width=8, justify="right")
    detail.add_column("DryRun", width=8, justify="center")
    detail.add_column("结果", width=6, justify="center")

    for index, result in enumerate(results, 1):
        checks = result.get("checks", {})
        intro = "[green]✔[/]" if checks.get("intro_detected") else "[red]✘[/]"
        fix = "[green]✔[/]" if checks.get("fix_correctly_absent") else "[red]✘[/]"
        prereq_metrics = checks.get("prereq_metrics")
        precision = f"{prereq_metrics['precision']:.0%}" if prereq_metrics else "-"
        recall = f"{prereq_metrics['recall']:.0%}" if prereq_metrics else "-"
        dryrun = checks.get("dryrun_accurate")
        dryrun_text = "[green]✔[/]" if dryrun else ("[red]✘[/]" if dryrun is not None else "-")
        overall = "[green]✔[/]" if result.get("overall_pass") else "[red]✘[/]"
        detail.add_row(str(index), result.get("cve_id", "?"), intro, fix, precision, recall, dryrun_text, overall)

    panel = Panel(
        Group(summary, Text(""), detail),
        title="[bold]Benchmark Report[/]",
        border_style="cyan",
        padding=(1, 2),
    )
    base.console.print(panel)


def render_batch_validate_report(results: list, target: str, policy_config=None):
    from core import ui as base
    from rich.console import Group

    total = len(results)
    if total == 0:
        base.console.print("[yellow]无验证结果[/]")
        return

    verdict_counts = {}
    level_counts = Counter()
    profile_counts = Counter()
    version_counts = Counter()
    warning_counter = Counter()
    dependency_bucket_counts = Counter()
    rule_type_bucket_counts = Counter()
    level_dependency_counts = Counter()
    level_rule_type_counts = Counter()
    result_state_counts = Counter()
    incomplete_reason_counts = Counter()
    core_sims = []
    method_counts = {}
    pass_count = 0
    prereq_recalls = []

    for result in results:
        generated = result.get("generated_vs_real", {})
        verdict = generated.get("verdict", "no_data")
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

        core_similarity = generated.get("core_similarity", 0)
        if verdict not in ("no_data", "error"):
            core_sims.append(core_similarity)

        method = result.get("dryrun_detail", {}).get("apply_method", "N/A")
        method_counts[method] = method_counts.get(method, 0) + 1

        result_status = result.get("result_status", {}) or {}
        result_state = result_status.get("state", "")
        if result_state:
            result_state_counts[result_state] += 1
        incomplete_reason = result_status.get("incomplete_reason", "")
        if incomplete_reason:
            incomplete_reason_counts[incomplete_reason] += 1

        if result.get("overall_pass"):
            pass_count += 1

        prereq_validation = result.get("prereq_cross_validation", {})
        if prereq_validation.get("recall") is not None:
            prereq_recalls.append(prereq_validation["recall"])
        level_decision = result.get("level_decision", {}) or {}
        level = level_decision.get("level", "")
        if level:
            level_counts[level] += 1
        validation_details = result.get("validation_details", {}) or {}
        if validation_details.get("rule_profile"):
            profile_counts[validation_details["rule_profile"]] += 1
        if validation_details.get("rule_version"):
            version_counts[validation_details["rule_version"]] += 1
        strategy_buckets = validation_details.get("strategy_buckets", {}) or {}
        dependency_bucket = strategy_buckets.get("dependency_bucket", "")
        if dependency_bucket:
            dependency_bucket_counts[dependency_bucket] += 1
            if level:
                level_dependency_counts[f"{dependency_bucket}:{level}"] += 1
        for rule_type, count in (strategy_buckets.get("rule_type_bucket", []) or []):
            if count:
                rule_type_bucket_counts[rule_type] += count
                if level:
                    level_rule_type_counts[f"{rule_type}:{level}"] += count
        for hit in level_decision.get("rule_hits", []) or []:
            if isinstance(hit, dict):
                warning_counter[hit.get("severity", "info")] += 1

    accurate = verdict_counts.get("identical", 0) + verdict_counts.get("essentially_same", 0)
    accuracy_rate = accurate / total if total else 0
    deterministic_exact = sum(
        1 for result in results
        if (result.get("generated_vs_real", {}) or {}).get("deterministic_exact_match")
    )
    critical_structure_count = sum(
        1 for result in results
        if ((result.get("validation_details", {}) or {}).get("special_risk_report", {}) or {}).get("summary", {}).get("has_critical_structure_change")
    )
    manual_prereq_analysis_count = sum(
        1 for result in results
        if ((result.get("validation_details", {}) or {}).get("strategy_buckets", {}) or {}).get("dependency_bucket") in ("required", "recommended")
    )
    avg_core = sum(core_sims) / len(core_sims) if core_sims else 0

    total_patches = sum(result.get("num_hulk_fixes", 1) for result in results)
    multi_fix = sum(1 for result in results if result.get("num_hulk_fixes", 1) > 1)

    summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    summary.add_column("指标", width=26, style="bold")
    summary.add_column("值", ratio=1)
    summary.add_row(
        "验证集规模",
        f"[cyan]{total}[/] 个 CVE  [dim]({total_patches} 个补丁, {multi_fix} 个含前置补丁)[/]",
    )
    summary.add_row("目标分支", f"[cyan]{target}[/]")
    summary.add_row("", "")
    accuracy_color = "green" if accuracy_rate >= 0.7 else ("yellow" if accuracy_rate >= 0.5 else "red")
    summary.add_row(
        "[bold]补丁生成准确率[/]",
        f"[{accuracy_color} bold]{accurate}/{total}  ({accuracy_rate:.1%})[/{accuracy_color} bold]"
        f"  [dim](identical + essentially_same)[/]",
    )
    summary.add_row(
        "100% 正确补丁数",
        f"[bold]{deterministic_exact}/{total} ({deterministic_exact / total:.1%})[/]  [dim](deterministic_exact_match)[/]",
    )
    summary.add_row("平均核心相似度", f"[bold]{avg_core:.1%}[/]")
    summary.add_row("工具验证通过率", f"[bold]{pass_count}/{total}  ({pass_count / total:.1%})[/]")
    if prereq_recalls:
        avg_recall = sum(prereq_recalls) / len(prereq_recalls)
        recall_color = "green" if avg_recall >= 0.5 else "yellow"
        summary.add_row(
            "前置补丁识别 recall",
            f"[{recall_color} bold]{avg_recall:.1%}[/{recall_color} bold]  [dim]({len(prereq_recalls)} 个含前置的 CVE)[/]",
        )
    summary.add_row(
        "关键结构变更数",
        f"[bold]{critical_structure_count}/{total} ({critical_structure_count / total:.1%})[/]",
    )
    summary.add_row(
        "关联补丁需人工分析",
        f"[bold]{manual_prereq_analysis_count}/{total} ({manual_prereq_analysis_count / total:.1%})[/]  [dim](dependency_bucket=required/recommended)[/]",
    )
    if result_state_counts:
        summary.add_row(
            "结果状态分布",
            "  ".join(f"{key}: {value}" for key, value in sorted(result_state_counts.items()) if value),
        )
    if incomplete_reason_counts:
        summary.add_row(
            "情报不足原因",
            "  ".join(f"{key}: {value}" for key, value in sorted(incomplete_reason_counts.items()) if value),
        )
    summary.add_row("", "")

    verdict_info = [
        ("identical", "完全一致", "green"),
        ("essentially_same", "本质相同", "green"),
        ("partially_same", "部分一致", "yellow"),
        ("different", "差异较大", "red"),
        ("no_data", "无数据", "dim"),
        ("error", "执行异常", "red"),
    ]
    verdict_parts = []
    for key, label, color in verdict_info:
        count = verdict_counts.get(key, 0)
        if count:
            verdict_parts.append(f"[{color}]{label}: {count} ({count / total:.0%})[/{color}]")
    summary.add_row("补丁判定分布", "  ".join(verdict_parts))

    method_order = ["strict", "context-C1", "3way", "regenerated", "conflict-adapted", "ai-generated", "N/A"]
    method_parts = []
    for method in method_order:
        count = method_counts.get(method, 0)
        if count:
            method_parts.append(f"{method}: {count} ({count / total:.0%})")
    for method, count in sorted(method_counts.items()):
        if method not in method_order and count:
            method_parts.append(f"{method}: {count}")
    summary.add_row("DryRun 方法分布", "  ".join(method_parts))

    if level_counts:
        summary.add_row("规则级别分布", "  ".join(f"{key}: {value}" for key, value in sorted(level_counts.items()) if value))
    if dependency_bucket_counts:
        summary.add_row("依赖类型分桶", "  ".join(f"{key}: {value}" for key, value in sorted(dependency_bucket_counts.items()) if value))
    if rule_type_bucket_counts:
        summary.add_row("规则类型分桶", "  ".join(f"{key}: {value}" for key, value in sorted(rule_type_bucket_counts.items()) if value))
    if level_dependency_counts:
        dep_pairs = [f"{key}: {value}" for key, value in sorted(level_dependency_counts.items()) if value]
        summary.add_row("级别×依赖分桶", "  ".join(dep_pairs[:8]))
    if level_rule_type_counts:
        rule_pairs = [f"{key}: {value}" for key, value in sorted(level_rule_type_counts.items()) if value]
        summary.add_row("级别×规则分桶", "  ".join(rule_pairs[:8]))
    if profile_counts:
        summary.add_row("规则 Profile", "  ".join(f"{key}: {value}" for key, value in sorted(profile_counts.items())))
    if version_counts:
        summary.add_row("规则版本", "  ".join(f"{key}: {value}" for key, value in sorted(version_counts.items())))
    if warning_counter:
        summary.add_row("规则命中标签", "  ".join(f"{key}: {value}" for key, value in sorted(warning_counter.items())))

    similarity_buckets = {">=90%": 0, "75-89%": 0, "50-74%": 0, "<50%": 0}
    for score in core_sims:
        if score >= 0.9:
            similarity_buckets[">=90%"] += 1
        elif score >= 0.75:
            similarity_buckets["75-89%"] += 1
        elif score >= 0.5:
            similarity_buckets["50-74%"] += 1
        else:
            similarity_buckets["<50%"] += 1
    if core_sims:
        summary.add_row("相似度分布", "  ".join(f"{key}: {value}" for key, value in similarity_buckets.items() if value))

    has_deep = any(result.get("deep_analysis") is not None for result in results)
    if has_deep:
        deep_actions = {}
        deep_scores = []
        for result in results:
            deep_analysis = result.get("deep_analysis")
            if deep_analysis is None:
                continue
            recommendation = getattr(deep_analysis, "merge_recommendation", None)
            if recommendation and hasattr(recommendation, "action"):
                deep_actions[recommendation.action] = deep_actions.get(recommendation.action, 0) + 1
                risk_benefit = getattr(recommendation, "risk_benefit", None)
                if risk_benefit:
                    deep_scores.append(risk_benefit.overall_score)
        if deep_actions:
            action_labels = {"merge": "直接合入", "merge_with_prereqs": "合入(需前置)", "manual_review": "需审查", "skip": "无需处理"}
            summary.add_row("", "")
            summary.add_row(
                "[bold magenta]深度分析建议分布[/]",
                "  ".join(f"[cyan]{action_labels.get(action, action)}: {count}[/]" for action, count in sorted(deep_actions.items(), key=lambda item: -item[1])),
            )
        if deep_scores:
            summary.add_row("深度分析平均评分", f"[bold]{sum(deep_scores) / len(deep_scores):.2f}/1.00[/]")

    detail = Table(box=box.ROUNDED, show_header=True, padding=(0, 1), expand=True)
    detail.add_column("#", width=3, justify="right", style="dim")
    detail.add_column("CVE", width=18, style="cyan")
    detail.add_column("方法", width=12)
    detail.add_column("核心相似度", width=10, justify="right")
    detail.add_column("判定", width=12, justify="center")
    detail.add_column("前置", width=8, justify="center")
    detail.add_column("状态", width=10, justify="center")
    detail.add_column("验证", width=5, justify="center")
    if has_deep:
        detail.add_column("深度建议", width=14, justify="center")

    verdict_style = {
        "identical": "[green]✔ 完全一致[/]",
        "essentially_same": "[green]✔ 本质相同[/]",
        "partially_same": "[yellow]△ 部分一致[/]",
        "different": "[red]✘ 差异较大[/]",
        "no_data": "[dim]- 无数据[/]",
        "error": "[red]✘ 异常[/]",
    }
    deep_style = {
        "merge": "[green bold]直接合入[/]",
        "merge_with_prereqs": "[yellow bold]合入(需前置)[/]",
        "manual_review": "[red bold]需审查[/]",
        "skip": "[dim]无需处理[/]",
    }

    for index, result in enumerate(results, 1):
        generated = result.get("generated_vs_real", {})
        verdict = generated.get("verdict", "no_data")
        score = generated.get("core_similarity", 0)
        method = result.get("dryrun_detail", {}).get("apply_method", "-")
        overall = "[green]✔[/]" if result.get("overall_pass") else "[red]✘[/]"
        result_status = result.get("result_status", {}) or {}
        state = result_status.get("state", "complete")
        prereq_validation = result.get("prereq_cross_validation", {})
        known_prereqs = prereq_validation.get("known_prereqs", 0)
        if known_prereqs > 0:
            prereq_cell = f"{prereq_validation.get('matched', 0)}/{known_prereqs}"
        else:
            prereq_cell = "[dim]-[/]"

        score_color = "green" if score >= 0.75 else ("yellow" if score >= 0.5 else "red")
        row = [
            str(index),
            result.get("cve_id", "?"),
            method,
            f"[{score_color}]{score:.1%}[/{score_color}]" if verdict not in ("no_data", "error") else "-",
            verdict_style.get(verdict, verdict),
            prereq_cell,
            state,
            overall,
        ]
        if has_deep:
            deep_analysis = result.get("deep_analysis")
            if deep_analysis is not None:
                recommendation = getattr(deep_analysis, "merge_recommendation", None)
                if recommendation and hasattr(recommendation, "action"):
                    row.append(deep_style.get(recommendation.action, recommendation.action))
                else:
                    row.append("[dim]-[/]")
            else:
                row.append("[dim]-[/]")
        detail.add_row(*row)

    report_parts = [summary, Text("")]
    level_policies = base._level_policy_table()
    if level_policies is not None:
        level_policies.title = "[bold]L0-L5 策略配置（全局）[/]"
        report_parts.append(level_policies)
        report_parts.append(Text(""))
    if policy_config is not None:
        config_panel = base._policy_config_panel(policy_config)
        if config_panel is not None:
            report_parts.append(config_panel)
            report_parts.append(Text(""))

    report_parts.append(detail)
    panel = Panel(
        Group(*report_parts),
        title="[bold]Batch Validate Report — 补丁生成准确度[/]",
        border_style="magenta",
        padding=(1, 2),
    )
    base.console.print(panel)
