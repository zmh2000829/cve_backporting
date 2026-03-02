"""
Rich 终端 UI
提供阶段状态面板、进度条、分析报告渲染
"""

import time
from typing import Optional, Callable
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn
from rich.live import Live
from rich.text import Text
from rich.columns import Columns
from rich import box

console = Console()

# ─── 阶段状态图标 ───────────────────────────────────────────────────

_ICONS = {
    "pending":  "[dim]○[/]",
    "running":  "[cyan]◉[/]",
    "success":  "[green]✔[/]",
    "fail":     "[red]✘[/]",
    "skip":     "[yellow]⊘[/]",
    "warn":     "[yellow]⚠[/]",
}


class StageTracker:
    """多阶段状态跟踪器"""

    def __init__(self, stages: list[tuple[str, str]]):
        """stages: [(key, label), ...]"""
        self.stages = stages
        self.status: dict[str, str] = {k: "pending" for k, _ in stages}
        self.details: dict[str, str] = {}
        self.timings: dict[str, float] = {}
        self._start_times: dict[str, float] = {}

    def start(self, key: str):
        self.status[key] = "running"
        self._start_times[key] = time.time()

    def done(self, key: str, status: str = "success", detail: str = ""):
        self.status[key] = status
        self.details[key] = detail
        if key in self._start_times:
            self.timings[key] = time.time() - self._start_times[key]

    def render(self) -> Table:
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1),
                  expand=True, show_edge=False)
        t.add_column("", width=3)
        t.add_column("阶段", ratio=3)
        t.add_column("详情", ratio=5)
        t.add_column("耗时", width=8, justify="right")

        for key, label in self.stages:
            icon = _ICONS.get(self.status[key], "○")
            det = self.details.get(key, "")
            elapsed = ""
            if key in self.timings:
                elapsed = f"[dim]{self.timings[key]:.1f}s[/]"
            elif self.status[key] == "running":
                elapsed = "[cyan]...[/]"

            style = ""
            if self.status[key] == "running":
                style = "bold cyan"
            elif self.status[key] == "fail":
                style = "red"

            t.add_row(icon, f"[{style}]{label}[/]" if style else label, det, elapsed)
        return t


def make_header(cve_id: str, target: str) -> Panel:
    title = Text()
    title.append("CVE 补丁回溯分析", style="bold white")
    subtitle = Text()
    subtitle.append(f"  {cve_id}", style="bold cyan")
    subtitle.append(f"  →  ", style="dim")
    subtitle.append(f"{target}", style="bold green")
    return Panel(subtitle, title=title, border_style="blue", padding=(0, 2))


def render_report(result) -> Panel:
    """渲染最终分析报告为 Rich Panel"""
    from rich.console import Group
    from core.models import AnalysisResult, PrerequisitePatch
    r: AnalysisResult = result

    grid = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, padding=(0, 1))
    grid.add_column("项目", style="bold", width=16)
    grid.add_column("内容")

    # CVE 基本信息
    if r.cve_info:
        grid.add_row("CVE", r.cve_id)
        desc = r.cve_info.description[:150]
        if len(r.cve_info.description) > 150:
            desc += "..."
        grid.add_row("描述", desc)
        sev = r.cve_info.severity
        sev_style = {"HIGH": "red bold", "CRITICAL": "red bold", "MEDIUM": "yellow", "LOW": "green"}.get(sev.upper(), "")
        grid.add_row("严重程度", f"[{sev_style}]{sev}[/]" if sev_style else sev)
        ml = r.cve_info.mainline_fix_commit[:12] if r.cve_info.mainline_fix_commit else "N/A"
        grid.add_row("Mainline Fix", f"[cyan]{ml}[/] ({r.cve_info.mainline_version or 'N/A'})")
        intro = r.cve_info.introduced_commit_id or "未知"
        grid.add_row("引入 Commit", f"[dim]{intro[:12] if intro != '未知' else intro}[/]")

    if r.fix_patch:
        grid.add_row("补丁 Subject", r.fix_patch.subject[:80])
        grid.add_row("修改文件", ", ".join(r.fix_patch.modified_files[:5]))

    grid.add_row("", "")

    # 状态
    vuln = "[red bold]是[/]" if r.is_vulnerable else "[green]未确认[/]"
    fixed = "[green bold]是[/]" if r.is_fixed else "[red bold]否[/]"
    grid.add_row("受影响", vuln)
    grid.add_row("已修复", fixed)

    # 搜索结果 + 步骤
    if r.introduced_search and r.introduced_search.found:
        s = r.introduced_search
        grid.add_row("引入定位", f"[cyan]{s.target_commit[:12]}[/] via {s.strategy} ({s.confidence:.0%})")
    if r.fix_search:
        s = r.fix_search
        if s.found:
            grid.add_row("修复定位", f"[green]{s.target_commit[:12]}[/] via {s.strategy} ({s.confidence:.0%})")
        else:
            cands = ""
            for c in s.candidates[:2]:
                sim = c.get("similarity", c.get("confidence", 0))
                cands += f"{c.get('commit_id', '')[:12]}({sim:.0%}) "
            grid.add_row("修复定位", f"[red]未合入[/]" + (f"  候选: {cands}" if cands else ""))

    # 前置依赖摘要
    if r.prerequisite_patches:
        n_s = sum(1 for p in r.prerequisite_patches if p.grade == "strong")
        n_m = sum(1 for p in r.prerequisite_patches if p.grade == "medium")
        n_w = sum(1 for p in r.prerequisite_patches if p.grade == "weak")
        parts = []
        if n_s:
            parts.append(f"[red bold]{n_s}强[/]")
        if n_m:
            parts.append(f"[yellow]{n_m}中[/]")
        if n_w:
            parts.append(f"[dim]{n_w}弱[/]")
        grid.add_row("前置依赖", " / ".join(parts) + f"  (共 {len(r.prerequisite_patches)} 个)")

    # Dry-run
    if r.dry_run:
        if r.dry_run.applies_cleanly:
            grid.add_row("Dry-Run", "[green bold]可以干净应用[/]")
        else:
            cf = ", ".join(r.dry_run.conflicting_files[:3])
            more = f" (+{len(r.dry_run.conflicting_files)-3})" if len(r.dry_run.conflicting_files) > 3 else ""
            grid.add_row("Dry-Run", f"[red]冲突[/] {cf}{more}")

    border = "green" if r.is_fixed else ("red" if r.is_vulnerable else "yellow")
    verdict = "已修复" if r.is_fixed else ("需修复" if r.is_vulnerable else "待确认")

    report_parts = [grid]

    # 搜索步骤
    for label, sr in [("引入搜索", r.introduced_search), ("修复搜索", r.fix_search)]:
        if sr and sr.steps:
            report_parts.append(Text(""))
            report_parts.append(_render_search_steps(label, sr))

    # 版本映射
    if r.cve_info and r.cve_info.version_commit_mapping:
        report_parts.append(Text(""))
        report_parts.append(_render_version_map(r.cve_info))

    # 前置依赖详情表
    if r.prerequisite_patches:
        report_parts.append(Text(""))
        report_parts.append(_render_prereq_table(r.prerequisite_patches))

    # DryRun 详情
    if r.dry_run and not r.dry_run.applies_cleanly and r.dry_run.error_output:
        report_parts.append(Text(""))
        report_parts.append(_render_dryrun_detail(r.dry_run))

    return Panel(Group(*report_parts),
                 title=f"[bold]分析报告[/]  [{border} bold]{verdict}[/]",
                 border_style=border, padding=(1, 2))


def _render_search_steps(label: str, sr) -> Table:
    """渲染搜索步骤 (L1/L2/L3)"""
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1),
              title=f"[dim]{label}[/]", expand=True, show_edge=False)
    t.add_column("", width=3)
    t.add_column("级别", width=5)
    t.add_column("详情", ratio=4)
    t.add_column("耗时", width=7, justify="right")

    for step in sr.steps:
        if step.status == "hit":
            icon = "[green]✔[/]"
        elif step.status == "miss":
            icon = "[red]✘[/]"
        else:
            icon = "[dim]⊘[/]"
        elapsed = f"[dim]{step.elapsed:.1f}s[/]" if step.elapsed > 0 else ""
        t.add_row(icon, f"[bold]{step.level}[/]", step.detail[:60], elapsed)
    return t


def _render_version_map(cve_info) -> Table:
    """渲染版本-commit映射表"""
    t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1),
              title="[dim]版本映射[/]", expand=True, show_edge=False)
    t.add_column("版本", width=14, style="bold")
    t.add_column("Commit", width=14, style="cyan")
    t.add_column("类型", width=16)

    ml_ver = cve_info.mainline_version
    for ver, cid in cve_info.version_commit_mapping.items():
        tag = "[bold]Mainline[/]" if ver == ml_ver else "Stable backport"
        t.add_row(ver, cid[:12], tag)
    return t


def _render_prereq_table(patches) -> Table:
    """渲染前置依赖详情表"""
    from core.models import PrerequisitePatch

    grade_icons = {"strong": "[red bold]强[/]", "medium": "[yellow]中[/]", "weak": "[dim]弱[/]"}

    t = Table(box=box.ROUNDED, expand=True, border_style="yellow",
              title="[bold]前置依赖[/]", title_style="bold", padding=(0, 1))
    t.add_column("#", width=3, justify="right")
    t.add_column("强度", width=5, justify="center")
    t.add_column("Commit", width=14, style="cyan")
    t.add_column("Subject", ratio=3)
    t.add_column("分值", width=6, justify="right")
    t.add_column("Hunk重叠", width=9, justify="center")
    t.add_column("重叠函数", ratio=2)

    for i, p in enumerate(patches, 1):
        grade_s = grade_icons.get(p.grade, p.grade)
        hunk_info = ""
        if p.overlap_hunks > 0:
            hunk_info = f"[red]{p.overlap_hunks}直接[/]"
        if p.adjacent_hunks > 0:
            sep = "+" if hunk_info else ""
            hunk_info += f"{sep}[yellow]{p.adjacent_hunks}相邻[/]"
        if not hunk_info:
            hunk_info = "[dim]-[/]"
        funcs = ", ".join(f[:20] for f in p.overlap_funcs[:3]) if p.overlap_funcs else "[dim]-[/]"
        score_style = "red bold" if p.score >= 0.5 else ("yellow" if p.score >= 0.2 else "dim")
        t.add_row(
            str(i), grade_s, p.commit_id[:12],
            p.subject[:50], f"[{score_style}]{p.score:.2f}[/]",
            hunk_info, funcs,
        )
        if i >= 15:
            t.add_row("", "", "", f"[dim]... 共 {len(patches)} 条[/]", "", "", "")
            break
    return t


def _render_dryrun_detail(dr) -> Panel:
    """渲染 DryRun 冲突详情"""
    lines = []
    if dr.stat_output:
        lines.append("[bold]修改统计:[/]")
        for line in dr.stat_output.strip().split("\n")[:10]:
            lines.append(f"  {line}")
        lines.append("")

    if dr.conflicting_files:
        lines.append("[bold red]冲突文件:[/]")
        for f in dr.conflicting_files:
            lines.append(f"  [red]✘[/] {f}")
        lines.append("")

    if dr.error_output:
        lines.append("[bold]错误输出:[/]")
        for line in dr.error_output.strip().split("\n")[:8]:
            lines.append(f"  [dim]{line}[/]")

    return Panel("\n".join(lines),
                 title="[bold]Dry-Run 详情[/]", border_style="red", padding=(0, 2))


def render_recommendations(result) -> Panel:
    """渲染结构化建议列表"""
    from core.models import AnalysisResult
    r: AnalysisResult = result

    lines = []
    for i, rec in enumerate(result.recommendations, 1):
        if "强依赖" in rec or "先合入" in rec:
            lines.append(f"  [red bold]{i}.[/] {rec}")
        elif "未合入" in rec or "冲突" in rec:
            lines.append(f"  [yellow]{i}.[/] {rec}")
        else:
            lines.append(f"  {i}. {rec}")
    text = "\n".join(lines) if lines else "  无建议"
    return Panel(text, title="[bold]行动建议[/]", border_style="blue", padding=(0, 2))


def render_multi_strategy(msr) -> Panel:
    """渲染多策略搜索结果面板"""
    from core.models import MultiStrategyResult
    r: MultiStrategyResult = msr

    # 源commit信息
    info = Table(box=None, show_header=False, padding=(0, 1), expand=True, show_edge=False)
    info.add_column("k", style="bold", width=14)
    info.add_column("v")
    info.add_row("Commit ID", f"[cyan]{r.commit_id[:12]}[/] [dim]({r.commit_id})[/]")
    if r.subject:
        info.add_row("Subject", r.subject[:100])
    if r.author:
        info.add_row("Author", r.author)
    if r.modified_files:
        info.add_row("修改文件", ", ".join(r.modified_files[:5])
                      + (f" (+{len(r.modified_files)-5})" if len(r.modified_files) > 5 else ""))

    # 策略结果表
    stbl = Table(box=box.ROUNDED, expand=True, border_style="blue",
                 title="[bold]三级搜索策略[/]", title_style="bold", padding=(0, 1))
    stbl.add_column("", width=3)
    stbl.add_column("策略", width=20, style="bold")
    stbl.add_column("结果", width=8)
    stbl.add_column("置信度", width=8, justify="right")
    stbl.add_column("目标 Commit", width=14)
    stbl.add_column("详情", ratio=3)
    stbl.add_column("耗时", width=7, justify="right")

    for s in r.strategies:
        if s.found:
            icon = "[green]✔[/]"
            res = "[green bold]命中[/]"
            conf = f"[green]{s.confidence:.0%}[/]"
            tgt = f"[cyan]{s.target_commit[:12]}[/]" if s.target_commit else ""
        elif s.target_commit:
            # 存在但不在分支上
            icon = "[yellow]⚠[/]"
            res = "[yellow]不在分支[/]"
            conf = "[dim]-[/]"
            tgt = f"[dim]{s.target_commit[:12]}[/]"
        else:
            icon = "[red]✘[/]"
            res = "[red]未命中[/]"
            conf = f"[dim]{s.confidence:.0%}[/]" if s.confidence > 0 else "[dim]-[/]"
            tgt = ""

        elapsed = f"[dim]{s.elapsed:.1f}s[/]"
        stbl.add_row(icon, f"{s.level} {s.name}", res, conf, tgt, s.detail[:60], elapsed)

    # 候选列表（取每个策略的top candidates）
    cand_tables = []
    for s in r.strategies:
        if s.candidates:
            ct = Table(box=box.SIMPLE, show_header=True, padding=(0, 1),
                       title=f"[dim]{s.level} 候选[/]", expand=True, show_edge=False)
            ct.add_column("Commit", width=14, style="cyan")
            ct.add_column("相似度", width=8, justify="right")
            ct.add_column("Subject", ratio=3)
            for c in s.candidates[:3]:
                sim = c.get("similarity", c.get("confidence", 0))
                sim_style = "green" if sim >= 0.85 else ("yellow" if sim >= 0.7 else "dim")
                subj = c.get("subject", c.get("type", ""))[:50]
                ct.add_row(c.get("commit_id", "")[:12], f"[{sim_style}]{sim:.0%}[/]", subj)
            cand_tables.append(ct)

    # 综合判定
    if r.is_present:
        b = r.best
        verdict_text = Text()
        verdict_text.append("  漏洞已引入  ", style="bold white on red")
        verdict_text.append(f"  最佳匹配: {b.target_commit[:12]} via {b.level} ({b.confidence:.0%})",
                            style="bold")
    else:
        verdict_text = Text()
        verdict_text.append("  未发现引入  ", style="bold white on green")
        verdict_text.append("  目标仓库中未找到该commit的对应提交", style="dim")

    # 组装
    from rich.console import Group
    parts = [info, Text(""), stbl, Text(""), verdict_text]
    for ct in cand_tables:
        parts.append(Text(""))
        parts.append(ct)

    border = "red" if r.is_present else "green"
    return Panel(Group(*parts),
                 title="[bold]漏洞引入 Commit 检测[/]",
                 border_style=border, padding=(1, 2))


def make_cache_progress(known_total: bool = True) -> Progress:
    if known_total:
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.completed:,}/{task.total:,}"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        )
    # 总数未知: spinner + 计数 + 耗时
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    )
