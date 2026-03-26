"""`check-intro` / `check-fix` 命令入口。"""

import json
import os
from datetime import datetime

from rich.live import Live
from rich.panel import Panel
from rich import box


def register(subparsers, parent):
    intro = subparsers.add_parser("check-intro", help="检测漏洞引入commit", parents=[parent])
    intro.add_argument("--commit", dest="commit_id", help="mainline引入commit ID")
    intro.add_argument("--cve", dest="cve_id", help="CVE ID (自动提取引入commit)")
    intro.add_argument("--target", dest="target_version", required=True)

    fix = subparsers.add_parser("check-fix", help="检测修复补丁是否已合入", parents=[parent])
    fix.add_argument("--commit", dest="commit_id", help="修复commit ID")
    fix.add_argument("--cve", dest="cve_id", help="CVE ID (自动提取修复commit)")
    fix.add_argument("--target", dest="target_version", required=True)

    return {
        "check-intro": run_check_intro,
        "check-fix": run_check_fix,
    }


def run_check_intro(args, config, runtime):
    from agents.analysis import AnalysisAgent
    from agents.crawler import CrawlerAgent
    from core.matcher import PathMapper
    from rich.table import Table

    git_mgr = runtime._make_git_mgr(config, args.target_version)
    crawler = CrawlerAgent(git_mgr=git_mgr)
    analysis = AnalysisAgent(git_mgr, path_mapper=PathMapper(config.path_mappings))
    tv = args.target_version

    commit_ids = []
    if args.cve_id:
        runtime.console.print(Panel(
            f"[bold]CVE:[/] {args.cve_id}  [bold]目标:[/] {tv}",
            title="[bold blue]漏洞引入检测 (CVE模式)[/]",
            border_style="blue", padding=(0, 2),
        ))
        with runtime.console.status("[cyan]获取CVE信息..."):
            cve = crawler.fetch_cve(args.cve_id)
        if not cve:
            runtime.console.print("[red]无法获取CVE信息[/]")
            return

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True, show_edge=False)
        table.add_column("k", style="bold", width=16)
        table.add_column("v")
        table.add_row("CVE", cve.cve_id)
        table.add_row("描述", (cve.description[:120] + "...") if len(cve.description) > 120 else cve.description)
        ml = cve.mainline_fix_commit[:12] if cve.mainline_fix_commit else "N/A"
        table.add_row("Mainline Fix", f"[cyan]{ml}[/] ({cve.mainline_version or 'N/A'})")
        intro_id = cve.introduced_commit_id
        if intro_id:
            table.add_row("引入 Commit", f"[yellow]{intro_id[:12]}[/] [dim]({intro_id})[/]")
            commit_ids.append(intro_id)
        else:
            table.add_row("引入 Commit", "[red]CVE数据中无引入commit信息[/]")
        runtime.console.print(table)
        runtime.console.print()

        if not commit_ids:
            runtime.console.print("[yellow]该CVE没有引入commit信息，无法检测[/]")
            return
    elif args.commit_id:
        commit_ids = [args.commit_id]
        runtime.console.print(Panel(
            f"[bold]Commit:[/] {args.commit_id}  [bold]目标:[/] {tv}",
            title="[bold blue]漏洞引入检测 (Commit模式)[/]",
            border_style="blue", padding=(0, 2),
        ))
    else:
        runtime.console.print("[red]请指定 --commit 或 --cve[/]")
        return

    for cid in commit_ids:
        runtime.console.print(f"\n[bold]检测引入commit:[/] [cyan]{cid[:12]}[/]")
        with runtime.console.status("[cyan]获取commit补丁信息..."):
            patch = crawler.fetch_patch(cid, tv)

        subject = patch.subject if patch else ""
        diff_code = patch.diff_code if patch else ""
        files = patch.modified_files if patch else []
        author = patch.author if patch else ""

        if patch:
            runtime.console.print(f"[dim]  Subject: {subject[:80]}[/]")
            runtime.console.print(f"[dim]  Files: {', '.join(files[:5])}[/]")
            runtime.console.print()

        stages = [
            ("l1", "L1 │ ID 精确匹配"),
            ("l2", "L2 │ Subject 语义匹配"),
            ("l3", "L3 │ Diff 代码匹配"),
        ]
        tracker = runtime.StageTracker(stages)

        def _layout():
            return tracker.render()

        with Live(_layout(), console=runtime.console, refresh_per_second=8) as live:
            def _refresh():
                live.update(_layout())

            tracker.start("l1")
            _refresh()

            msr = analysis.search_detailed(cid, subject, diff_code, files, author, tv)
            for strategy in msr.strategies:
                key = {"L1": "l1", "L2": "l2", "L3": "l3"}[strategy.level]
                if strategy.found:
                    tracker.done(key, "success", f"{strategy.target_commit[:12]} ({strategy.confidence:.0%})")
                else:
                    tracker.done(key, "fail", strategy.detail[:60])
                _refresh()

        runtime.console.print()
        runtime.console.print(runtime.render_multi_strategy(msr))

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
        runtime.console.print(f"[dim]结果已保存: {fp}[/]")


def run_check_fix(args, config, runtime):
    from agents.analysis import AnalysisAgent
    from agents.crawler import CrawlerAgent
    from core.matcher import PathMapper
    from rich.table import Table

    git_mgr = runtime._make_git_mgr(config, args.target_version)
    crawler = CrawlerAgent(git_mgr=git_mgr)
    analysis = AnalysisAgent(git_mgr, path_mapper=PathMapper(config.path_mappings))
    tv = args.target_version

    check_list = []
    if args.cve_id:
        runtime.console.print(Panel(
            f"[bold]CVE:[/] {args.cve_id}  [bold]目标:[/] {tv}",
            title="[bold green]漏洞修复检测 (CVE模式)[/]",
            border_style="green", padding=(0, 2),
        ))
        with runtime.console.status("[cyan]获取CVE信息..."):
            cve = crawler.fetch_cve(args.cve_id)
        if not cve:
            runtime.console.print("[red]无法获取CVE信息[/]")
            return

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True, show_edge=False)
        table.add_column("k", style="bold", width=16)
        table.add_column("v")
        table.add_row("CVE", cve.cve_id)
        table.add_row("描述", (cve.description[:120] + "...") if len(cve.description) > 120 else cve.description)
        table.add_row("严重程度", cve.severity)

        if cve.mainline_fix_commit:
            ml = cve.mainline_fix_commit[:12]
            table.add_row("Mainline Fix", f"[cyan]{ml}[/] ({cve.mainline_version or 'N/A'})")
            check_list.append((cve.mainline_fix_commit, f"Mainline ({cve.mainline_version or 'N/A'})"))

        if cve.version_commit_mapping:
            ver_lines = []
            for ver, cid in cve.version_commit_mapping.items():
                ver_lines.append(f"{ver}: {cid[:12]}")
                if cid != cve.mainline_fix_commit and ver.startswith("5.10"):
                    check_list.append((cid, f"Stable backport ({ver})"))
            table.add_row("版本映射", "\n".join(ver_lines))

        if cve.introduced_commit_id:
            table.add_row("引入 Commit", f"[yellow]{cve.introduced_commit_id[:12]}[/]")

        runtime.console.print(table)
        runtime.console.print()

        if not check_list:
            runtime.console.print("[yellow]该CVE没有修复commit信息[/]")
            return
    elif args.commit_id:
        check_list = [(args.commit_id, "指定commit")]
        runtime.console.print(Panel(
            f"[bold]Commit:[/] {args.commit_id}  [bold]目标:[/] {tv}",
            title="[bold green]漏洞修复检测 (Commit模式)[/]",
            border_style="green", padding=(0, 2),
        ))
    else:
        runtime.console.print("[red]请指定 --commit 或 --cve[/]")
        return

    any_fixed = False
    for cid, label in check_list:
        runtime.console.print(f"\n[bold]检测修复commit:[/] [cyan]{cid[:12]}[/] [dim]({label})[/]")
        with runtime.console.status("[cyan]获取commit补丁信息..."):
            patch = crawler.fetch_patch(cid, tv)

        subject = patch.subject if patch else ""
        diff_code = patch.diff_code if patch else ""
        files = patch.modified_files if patch else []
        author = patch.author if patch else ""

        if patch and subject:
            runtime.console.print(f"[dim]  Subject: {subject[:80]}[/]")
            runtime.console.print(f"[dim]  Files: {', '.join(files[:5])}[/]")
            runtime.console.print()

        stages = [
            ("l1", "L1 │ ID 精确匹配"),
            ("l2", "L2 │ Subject 语义匹配"),
            ("l3", "L3 │ Diff 代码匹配"),
        ]
        tracker = runtime.StageTracker(stages)

        def _layout():
            return tracker.render()

        with Live(_layout(), console=runtime.console, refresh_per_second=8) as live:
            def _refresh():
                live.update(_layout())

            tracker.start("l1")
            _refresh()

            msr = analysis.search_detailed(
                cid, subject, diff_code, files, author, tv,
                use_containment=False,
            )
            for strategy in msr.strategies:
                key = {"L1": "l1", "L2": "l2", "L3": "l3"}[strategy.level]
                if strategy.found:
                    tracker.done(key, "success", f"{strategy.target_commit[:12]} ({strategy.confidence:.0%})")
                else:
                    tracker.done(key, "fail", strategy.detail[:60])
                _refresh()

        runtime.console.print()
        runtime.console.print(runtime.render_multi_strategy(msr, mode="fix"))

        if msr.is_present:
            any_fixed = True

    runtime.console.print()
    if any_fixed:
        runtime.console.print(Panel(
            "[green bold]结论: 修复补丁已合入目标仓库[/]",
            border_style="green", padding=(0, 2),
        ))
    else:
        runtime.console.print(Panel(
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
            "checked_commits": [{"commit_id": cid, "label": label} for cid, label in check_list],
        }, f, indent=2, ensure_ascii=False, default=str)
    runtime.console.print(f"[dim]结果已保存: {fp}[/]")
