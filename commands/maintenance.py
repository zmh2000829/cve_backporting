"""`build-cache` / `search` 命令入口。"""

from rich import box
from rich.panel import Panel


def register(subparsers, parent):
    cache = subparsers.add_parser("build-cache", help="构建commit缓存", parents=[parent])
    cache.add_argument("--target", dest="target_version", required=True)
    cache.add_argument("--full", action="store_true", help="强制全量重建缓存（默认增量）")

    search = subparsers.add_parser("search", help="搜索commit", parents=[parent])
    search.add_argument("--commit", dest="commit_id", required=True)
    search.add_argument("--target", dest="target_version", required=True)

    return {
        "build-cache": run_build_cache,
        "search": run_search,
    }


def run_build_cache(args, config, runtime):
    git_mgr = runtime._make_git_mgr(config, args.target_version)
    rv = args.target_version

    cached_count = git_mgr.get_cache_count(rv)
    is_full = args.full
    incremental = not is_full and cached_count > 0
    mode_label = "[yellow]全量重建[/]" if is_full else (
        "[green]增量更新[/]" if incremental else "[cyan]首次构建[/]"
    )

    runtime.console.print(Panel(
        f"[bold]目标仓库:[/] {rv}  [bold]分支:[/] {git_mgr._get_repo_branch(rv) or '当前'}\n"
        f"[bold]现有缓存:[/] {cached_count:,} commits\n"
        f"[bold]构建模式:[/] {mode_label}",
        title="[bold blue]缓存构建[/]", border_style="blue", padding=(0, 2),
    ))

    if incremental:
        latest = git_mgr.get_latest_cached_commit(rv)
        if latest:
            runtime.console.print(f"[dim]将从 {latest[:12]} 之后增量拉取新commit[/]\n")

        progress = runtime.make_cache_progress(known_total=False)
        with progress:
            task = progress.add_task("增量缓存", total=None)

            def on_progress(current, _total):
                progress.update(task, completed=current, description=f"增量缓存 ({current:,} 新commits)")

            git_mgr.build_commit_cache(rv, progress_cb=on_progress, incremental=True)

        final_count = git_mgr.get_cache_count(rv)
        new_count = final_count - cached_count
        runtime.console.print(Panel(
            f"[green bold]完成![/]  新增: [bold]{new_count:,}[/]  总缓存: [bold]{final_count:,}[/] commits",
            border_style="green", padding=(0, 2),
        ))
        return

    runtime.console.print("[dim]正在统计分支 commit 数量 (大仓库可能需要几分钟)...[/]")
    actual_count = git_mgr.count_commits(rv)
    mx = config.cache.max_cached_commits if hasattr(config.cache, "max_cached_commits") else None

    if actual_count > 0:
        if mx and mx > actual_count:
            mx = None
        total = mx or actual_count
        runtime.console.print(f"[dim]分支共 {actual_count:,} 个commits, 将缓存 {total:,} 个[/]\n")
    else:
        total = mx or 0
        if total:
            runtime.console.print(f"[dim]commit总数未知, 将缓存最多 {total:,} 个[/]\n")
        else:
            runtime.console.print("[dim]commit总数未知, 将流式缓存全部commits[/]\n")

    known_total = total > 0
    progress = runtime.make_cache_progress(known_total=known_total)
    with progress:
        task = progress.add_task("构建commit缓存", total=total if known_total else None)

        def on_progress(current, _total):
            if known_total:
                progress.update(task, completed=current)
            else:
                progress.update(task, completed=current, description=f"构建commit缓存 ({current:,})")

        git_mgr.build_commit_cache(rv, max_commits=mx, progress_cb=on_progress, incremental=False)
        if known_total:
            progress.update(task, completed=total)

    final_count = git_mgr.get_cache_count(rv)
    runtime.console.print(Panel(
        f"[green bold]完成![/]  缓存: [bold]{final_count:,}[/] commits",
        border_style="green", padding=(0, 2),
    ))


def run_search(args, config, runtime):
    git_mgr = runtime._make_git_mgr(config, args.target_version)
    result = git_mgr.find_commit_by_id(args.commit_id, args.target_version)
    if result:
        from rich.table import Table

        table = Table(title="Commit 信息", box=box.ROUNDED, border_style="cyan")
        table.add_column("字段", style="bold")
        table.add_column("值")
        table.add_row("Commit ID", result["commit_id"])
        table.add_row("Subject", result["subject"])
        table.add_row("Author", result.get("author", ""))
        table.add_row("Timestamp", str(result.get("timestamp", "")))
        runtime.console.print(table)
    else:
        runtime.console.print(f"[yellow]未找到:[/] {args.commit_id}")
