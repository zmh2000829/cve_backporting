#!/usr/bin/env python3
"""
CVE补丁回溯分析 - 命令行工具

用法:
  python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
  python cli.py check-intro --commit <introduced_commit_id> --target 5.10-hulk
  python cli.py check-intro --cve CVE-2024-26633 --target 5.10-hulk
  python cli.py build-cache --target 5.10-hulk
  python cli.py search --commit abc123 --target 5.10-hulk
"""

import argparse
import json
import sys
import os
import logging
from datetime import datetime

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


# ─── analyze ─────────────────────────────────────────────────────────

def cmd_analyze(args, config):
    git_mgr = _make_git_mgr(config, args.target_version)
    pipe = Pipeline(git_mgr, path_mappings=config.path_mappings)

    cves = [args.cve_id] if args.cve_id else []
    if args.batch_file:
        with open(args.batch_file) as f:
            cves = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not cves:
        console.print("[red]请指定 --cve 或 --batch[/]")
        sys.exit(1)

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)

    for cve_id in cves:
        _analyze_one(pipe, cve_id, args.target_version,
                     enable_dryrun=not args.no_dryrun, out_dir=out_dir)


def _analyze_one(pipe: Pipeline, cve_id: str, target: str,
                 enable_dryrun: bool, out_dir: str):
    tracker = StageTracker(STAGES)
    header = make_header(cve_id, target)

    def on_stage(key, status, detail=""):
        tracker.start(key) if status == "running" else tracker.done(key, status, detail)

    def _layout():
        return Group(header, tracker.render())

    with Live(_layout(), console=console, refresh_per_second=8) as live:
        def _update(key, status, detail=""):
            on_stage(key, status, detail)
            live.update(_layout())

        result = pipe.analyze(cve_id, target,
                              enable_dryrun=enable_dryrun,
                              on_stage=_update)

    console.print()
    console.print(render_report(result))
    console.print(render_recommendations(result))

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = os.path.join(out_dir, f"{cve_id}_{target}_{ts}.json")
    from dataclasses import asdict
    prereqs = [asdict(p) for p in result.prerequisite_patches] if result.prerequisite_patches else []
    with open(fp, "w", encoding="utf-8") as f:
        json.dump({
            "cve_id": result.cve_id,
            "target_version": result.target_version,
            "is_vulnerable": result.is_vulnerable,
            "is_fixed": result.is_fixed,
            "dry_run_clean": result.dry_run.applies_cleanly if result.dry_run else None,
            "prerequisite_patches": prereqs,
            "recommendations": result.recommendations,
        }, f, indent=2, ensure_ascii=False, default=str)
    console.print(f"\n[dim]报告已保存: {fp}[/]")


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


# ─── build-cache ─────────────────────────────────────────────────────

def cmd_build_cache(args, config):
    git_mgr = _make_git_mgr(config, args.target_version)
    rv = args.target_version

    console.print(Panel(
        f"[bold]目标仓库:[/] {rv}  [bold]分支:[/] {git_mgr._get_repo_branch(rv) or '当前'}\n"
        f"[bold]现有缓存:[/] {git_mgr.get_cache_count(rv):,} commits",
        title="[bold blue]缓存构建[/]", border_style="blue", padding=(0, 2),
    ))

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

        git_mgr.build_commit_cache(rv, max_commits=mx, progress_cb=on_progress)
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

    ip = sub.add_parser("check-intro", help="检测漏洞引入commit", parents=[parent])
    ip.add_argument("--commit", dest="commit_id", help="mainline引入commit ID")
    ip.add_argument("--cve", dest="cve_id", help="CVE ID (自动提取引入commit)")
    ip.add_argument("--target", dest="target_version", required=True)

    cp = sub.add_parser("build-cache", help="构建commit缓存", parents=[parent])
    cp.add_argument("--target", dest="target_version", required=True)

    sp = sub.add_parser("search", help="搜索commit", parents=[parent])
    sp.add_argument("--commit", dest="commit_id", required=True)
    sp.add_argument("--target", dest="target_version", required=True)

    args = p.parse_args()
    if not args.command:
        p.print_help()
        sys.exit(1)

    config = ConfigLoader.load(args.config)
    _setup_logging(config, quiet=args.quiet)

    dispatch = {
        "analyze": cmd_analyze,
        "check-intro": cmd_check_intro,
        "build-cache": cmd_build_cache,
        "search": cmd_search,
    }
    dispatch[args.command](args, config)


if __name__ == "__main__":
    main()
