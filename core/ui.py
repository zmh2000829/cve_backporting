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
        if r.fix_patch.author:
            grid.add_row("补丁 Author", r.fix_patch.author)
        files_str = ", ".join(r.fix_patch.modified_files[:5])
        if len(r.fix_patch.modified_files) > 5:
            files_str += f" (+{len(r.fix_patch.modified_files)-5})"
        grid.add_row("修改文件", files_str)

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

    # 搜索过程详情（含候选列表，供人工参考）
    for label, sr in [("引入 Commit 搜索", r.introduced_search), ("修复 Commit 搜索", r.fix_search)]:
        if sr and (sr.steps or sr.candidates):
            report_parts.append(Text(""))
            report_parts.append(_render_search_detail(label, sr))

    # 版本映射
    if r.cve_info and r.cve_info.version_commit_mapping:
        report_parts.append(Text(""))
        report_parts.append(_render_version_map(r.cve_info))

    # 前置依赖详情表
    if r.prerequisite_patches:
        report_parts.append(Text(""))
        report_parts.append(_render_prereq_table(r.prerequisite_patches,
                                                  fix_files=r.fix_patch.modified_files if r.fix_patch else [],
                                                  conflict_files=r.conflict_files))

    # DryRun 详情
    if r.dry_run and not r.dry_run.applies_cleanly and r.dry_run.error_output:
        report_parts.append(Text(""))
        report_parts.append(_render_dryrun_detail(r.dry_run))

    return Panel(Group(*report_parts),
                 title=f"[bold]分析报告[/]  [{border} bold]{verdict}[/]",
                 border_style=border, padding=(1, 2))


def _render_search_detail(label: str, sr) -> Panel:
    """渲染搜索过程详情：步骤 + 候选列表"""
    from rich.console import Group

    parts = []

    # 步骤表
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1),
              expand=True, show_edge=False)
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
        t.add_row(icon, f"[bold]{step.level}[/]", step.detail[:80], elapsed)
    parts.append(t)

    # 候选列表（人工参考核心数据）
    if sr.candidates:
        parts.append(Text(""))
        ct = Table(box=box.SIMPLE, show_header=True, padding=(0, 1),
                   expand=True, show_edge=False)
        ct.add_column("#", width=3, justify="right", style="dim")
        ct.add_column("Commit", width=14, style="cyan")
        ct.add_column("相似度", width=8, justify="right")
        ct.add_column("包含度", width=8, justify="right")
        ct.add_column("匹配方式", width=12)
        ct.add_column("Subject", ratio=3)

        for i, c in enumerate(sr.candidates[:5], 1):
            sim = c.get("similarity", c.get("confidence", 0))
            sim_style = "green" if sim >= 0.85 else ("yellow" if sim >= 0.7 else "dim")
            sim_str = f"[{sim_style}]{sim:.0%}[/]"

            cont = c.get("containment")
            if cont and cont > 0:
                cont_style = "green" if cont >= 0.85 else ("yellow" if cont >= 0.7 else "dim")
                cont_str = f"[{cont_style}]{cont:.0%}[/]"
            else:
                cont_str = "[dim]-[/]"

            mtype = c.get("type", "subject")
            subj = c.get("subject", "")[:55]
            ct.add_row(str(i), c.get("commit_id", "")[:12], sim_str, cont_str, mtype, subj)
        parts.append(ct)

    border = "green" if sr.found else "dim"
    status = "[green]命中[/]" if sr.found else "[yellow]未命中[/]"
    return Panel(Group(*parts),
                 title=f"[bold]{label}[/]  {status}",
                 border_style=border, padding=(0, 2))


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


def _render_prereq_table(patches, fix_files: list = None,
                         conflict_files: list = None) -> Panel:
    """渲染前置依赖详情面板（含分析上下文）"""
    from rich.console import Group
    from core.models import PrerequisitePatch

    parts = []

    # 分析上下文信息
    if fix_files or conflict_files:
        ctx = Table(box=None, show_header=False, padding=(0, 1), expand=True, show_edge=False)
        ctx.add_column("k", style="bold", width=14)
        ctx.add_column("v")
        if fix_files:
            ctx.add_row("分析文件", ", ".join(fix_files[:6])
                        + (f" (+{len(fix_files)-6})" if len(fix_files) > 6 else ""))
        n_s = sum(1 for p in patches if p.grade == "strong")
        n_m = sum(1 for p in patches if p.grade == "medium")
        n_w = sum(1 for p in patches if p.grade == "weak")
        summary_parts = []
        if n_s:
            summary_parts.append(f"[red bold]{n_s}强[/]")
        if n_m:
            summary_parts.append(f"[yellow]{n_m}中[/]")
        if n_w:
            summary_parts.append(f"[dim]{n_w}弱[/]")
        ctx.add_row("依赖统计", " / ".join(summary_parts) + f"  (共 {len(patches)} 个)")
        parts.append(ctx)
        parts.append(Text(""))

    grade_icons = {"strong": "[red bold]强[/]", "medium": "[yellow]中[/]", "weak": "[dim]弱[/]"}

    t = Table(box=box.SIMPLE, expand=True, padding=(0, 1), show_edge=False)
    t.add_column("#", width=3, justify="right")
    t.add_column("强度", width=5, justify="center")
    t.add_column("Commit", width=14, style="cyan")
    t.add_column("Subject", ratio=3)
    t.add_column("分值", width=6, justify="right")
    t.add_column("Hunk重叠", width=12, justify="center")
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

    parts.append(t)
    return Panel(Group(*parts),
                 title="[bold]前置依赖分析[/]", border_style="yellow", padding=(0, 2))


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


def render_multi_strategy(msr, mode: str = "intro") -> Panel:
    """
    渲染多策略搜索结果面板。
    mode: "intro" — 漏洞引入检测, "fix" — 修复补丁检测
    """
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

    # 候选列表（取每个策略的top candidates，展示完整分析数据供人工参考）
    cand_tables = []
    for s in r.strategies:
        if s.candidates:
            is_l3 = s.level == "L3"
            ct = Table(box=box.SIMPLE, show_header=True, padding=(0, 1),
                       title=f"[dim]{s.level} 候选列表 (人工参考)[/]", expand=True, show_edge=False)
            ct.add_column("#", width=3, justify="right", style="dim")
            ct.add_column("Commit", width=14, style="cyan")
            ct.add_column("相似度", width=8, justify="right")
            if is_l3:
                ct.add_column("包含度", width=8, justify="right")
                ct.add_column("匹配方式", width=14)
            ct.add_column("Subject", ratio=3)

            for i, c in enumerate(s.candidates[:5], 1):
                sim = c.get("similarity", c.get("confidence", 0))
                sim_style = "green" if sim >= 0.85 else ("yellow" if sim >= 0.7 else "dim")
                subj = c.get("subject", c.get("type", ""))[:55]

                if is_l3:
                    cont = c.get("containment")
                    if cont and cont > 0:
                        cont_style = "green" if cont >= 0.85 else ("yellow" if cont >= 0.7 else "dim")
                        cont_str = f"[{cont_style}]{cont:.0%}[/]"
                    else:
                        cont_str = "[dim]-[/]"
                    mtype = c.get("type", "diff")
                    ct.add_row(str(i), c.get("commit_id", "")[:12],
                               f"[{sim_style}]{sim:.0%}[/]", cont_str, mtype, subj)
                else:
                    ct.add_row(str(i), c.get("commit_id", "")[:12],
                               f"[{sim_style}]{sim:.0%}[/]", subj)
            cand_tables.append(ct)

    # 综合判定（根据 mode 区分文案）
    verdict_text = Text()
    if mode == "fix":
        if r.is_present:
            b = r.best
            verdict_text.append("  修复已合入  ", style="bold white on green")
            verdict_text.append(f"  最佳匹配: {b.target_commit[:12]} via {b.level} ({b.confidence:.0%})",
                                style="bold")
        else:
            verdict_text.append("  修复未合入  ", style="bold white on red")
            verdict_text.append("  目标仓库中未找到该修复commit的对应提交", style="dim")
        panel_title = "[bold]修复补丁检测[/]"
        border = "green" if r.is_present else "red"
    else:
        if r.is_present:
            b = r.best
            verdict_text.append("  漏洞已引入  ", style="bold white on red")
            verdict_text.append(f"  最佳匹配: {b.target_commit[:12]} via {b.level} ({b.confidence:.0%})",
                                style="bold")
        else:
            verdict_text.append("  未发现引入  ", style="bold white on green")
            verdict_text.append("  目标仓库中未找到该commit的对应提交", style="dim")
        panel_title = "[bold]漏洞引入 Commit 检测[/]"
        border = "red" if r.is_present else "green"

    # 组装
    from rich.console import Group
    parts = [info, Text(""), stbl, Text(""), verdict_text]
    for ct in cand_tables:
        parts.append(Text(""))
        parts.append(ct)

    return Panel(Group(*parts),
                 title=panel_title,
                 border_style=border, padding=(1, 2))


def render_validate_report(result: dict):
    """渲染增强版单 CVE 验证报告，包含差异分析细节"""
    from rich.console import Group
    from rich.markdown import Markdown

    cve = result.get("cve_id", "N/A")
    known_fix = result.get("known_fix", "N/A")
    overall = result.get("overall_pass", False)
    sections = []

    # ── 1) 基本信息 ──────────────────────────────────
    info_tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), expand=True)
    info_tbl.add_column("K", width=20, style="bold")
    info_tbl.add_column("V", ratio=1)
    info_tbl.add_row("CVE", f"[cyan]{cve}[/]")
    info_tbl.add_row("Known Fix", f"[cyan]{known_fix[:12]}[/]")
    info_tbl.add_row("目标分支", result.get("target", "N/A"))
    info_tbl.add_row("Worktree Commit",
                      f"[dim]{result.get('worktree_commit', 'N/A')[:16]}[/]")
    sections.append(info_tbl)
    sections.append(Text(""))

    # ── 2) 检查结果矩阵 ──────────────────────────────
    checks = result.get("checks", {})
    ct = Table(box=box.ROUNDED, show_header=True, padding=(0, 1), expand=True)
    ct.add_column("检查项", width=26, style="bold")
    ct.add_column("结果", ratio=1)

    fix_absent = checks.get("fix_correctly_absent")
    if fix_absent is not None:
        icon = "[green]✔[/]" if fix_absent else "[red]✘[/]"
        ct.add_row("修复检测 (应为未合入)", icon)

    intro = checks.get("intro_detected")
    if intro is not None:
        icon = "[green]✔[/]" if intro else "[yellow]⊘[/]"
        ct.add_row("引入检测 (应为已引入)", icon)

    for label, key in [("引入命中策略", "intro_strategy"),
                       ("修复命中策略", "fix_strategy")]:
        v = checks.get(key, "")
        if v:
            ct.add_row(label, f"[cyan]{v}[/]")

    dryrun_ok = checks.get("dryrun_accurate")
    if dryrun_ok is not None:
        icon = "[green]✔[/]" if dryrun_ok else "[red]✘[/]"
        ct.add_row("DryRun 预测", icon)

    prereq_m = checks.get("prereq_metrics")
    if prereq_m:
        p, r, f1 = prereq_m["precision"], prereq_m["recall"], prereq_m["f1"]
        ps = "green" if p >= 0.8 else ("yellow" if p >= 0.5 else "red")
        rs = "green" if r >= 0.8 else ("yellow" if r >= 0.5 else "red")
        ct.add_row("前置依赖 精确率", f"[{ps}]{p:.1%}[/]")
        ct.add_row("前置依赖 召回率", f"[{rs}]{r:.1%}[/]")
        ct.add_row("前置依赖 F1", f"[bold]{f1:.1%}[/]")

    sections.append(ct)
    sections.append(Text(""))

    # ── 3) 社区修复补丁详情 ──────────────────────────
    fp_detail = result.get("fix_patch_detail", {})
    if fp_detail:
        fp_tbl = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 1),
                       expand=True, title="[bold]社区修复补丁[/]")
        fp_tbl.add_column("K", width=16, style="bold")
        fp_tbl.add_column("V", ratio=1)
        fp_tbl.add_row("Commit", f"[cyan]{fp_detail.get('commit_id', '')}[/]")
        fp_tbl.add_row("Subject", fp_detail.get("subject", ""))
        fp_tbl.add_row("Author", fp_detail.get("author", ""))
        files = fp_detail.get("modified_files", [])
        fp_tbl.add_row("修改文件", f"[dim]{len(files)}[/] 个")
        for f in files[:8]:
            fp_tbl.add_row("", f"  [dim]{f}[/]")
        if len(files) > 8:
            fp_tbl.add_row("", f"  [dim]... +{len(files) - 8} 更多[/]")
        fp_tbl.add_row("Diff 行数", str(fp_detail.get("diff_lines", 0)))
        sections.append(fp_tbl)
        sections.append(Text(""))

    # ── 4) 真实修复 commit 详情 ──────────────────────
    kf_detail = result.get("known_fix_detail", {})
    if kf_detail:
        kf_tbl = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 1),
                       expand=True, title="[bold]本地仓库真实修复 commit[/]")
        kf_tbl.add_column("K", width=16, style="bold")
        kf_tbl.add_column("V", ratio=1)
        kf_tbl.add_row("Commit", f"[cyan]{kf_detail.get('commit_id', '')}[/]")
        kf_tbl.add_row("Subject", kf_detail.get("subject", ""))
        kf_tbl.add_row("Author", kf_detail.get("author", ""))
        stat = kf_detail.get("stat", "")
        if stat:
            for line in stat.strip().split("\n")[:10]:
                kf_tbl.add_row("", f"[dim]{line}[/]")
        sections.append(kf_tbl)
        sections.append(Text(""))

    # ── 5) 代码差异对比 (核心诊断) ──────────────────
    diff_cmp = result.get("diff_comparison", {})
    if diff_cmp and diff_cmp.get("overall_similarity", -1) >= 0:
        sim = diff_cmp["overall_similarity"]
        if sim >= 0.9:
            sim_style = "bold green"
            sim_label = "高度一致"
        elif sim >= 0.6:
            sim_style = "bold yellow"
            sim_label = "部分一致"
        elif sim > 0:
            sim_style = "bold red"
            sim_label = "差异较大"
        else:
            sim_style = "dim"
            sim_label = "无数据"

        diff_tbl = Table(box=box.HEAVY, show_header=False, padding=(0, 1),
                         expand=True,
                         title="[bold]代码差异对比 — 社区补丁 vs 本地修复[/]")
        diff_tbl.add_column("K", width=16, style="bold")
        diff_tbl.add_column("V", ratio=1)

        bar_len = int(sim * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        diff_tbl.add_row("总体相似度",
                         f"[{sim_style}]{sim:.0%} {sim_label}[/]  [{sim_style}]{bar}[/]")

        comm_only = diff_cmp.get("community_only_files", [])
        local_only = diff_cmp.get("local_only_files", [])
        if comm_only:
            diff_tbl.add_row("[yellow]社区独有文件[/]",
                             f"[yellow]{', '.join(comm_only[:5])}[/]")
        if local_only:
            diff_tbl.add_row("[cyan]本地独有文件[/]",
                             f"[cyan]{', '.join(local_only[:5])}[/]")

        per_file = diff_cmp.get("per_file", [])
        if per_file:
            pf_tbl = Table(box=box.SIMPLE, show_header=True, padding=(0, 1),
                           expand=True)
            pf_tbl.add_column("文件", ratio=1, style="dim")
            pf_tbl.add_column("相似度", width=8)
            pf_tbl.add_column("社区行", width=7)
            pf_tbl.add_column("本地行", width=7)
            for pf in per_file[:10]:
                fs = pf["similarity"]
                fstyle = "green" if fs >= 0.9 else ("yellow" if fs >= 0.6 else "red")
                pf_tbl.add_row(
                    pf["file"],
                    f"[{fstyle}]{fs:.0%}[/]",
                    str(pf["community_lines"]),
                    str(pf["local_lines"]),
                )
            diff_tbl.add_row("", "")
            sections.append(diff_tbl)
            sections.append(pf_tbl)
        else:
            sections.append(diff_tbl)

        # 关键差异代码片段
        key_diffs = diff_cmp.get("key_differences", [])
        if key_diffs:
            for kd in key_diffs[:3]:
                f = kd["file"]
                fsim = kd["similarity"]
                snippet = Text()
                snippet.append(f"  {f}", style="bold")
                snippet.append(f" (相似度 {fsim:.0%})\n", style="dim")

                ce = kd.get("community_extra", [])
                le = kd.get("local_extra", [])
                if ce:
                    snippet.append("  社区补丁独有:\n", style="yellow")
                    for line in ce[:4]:
                        snippet.append(f"    {line}\n", style="yellow dim")
                if le:
                    snippet.append("  本地修复独有:\n", style="cyan")
                    for line in le[:4]:
                        snippet.append(f"    {line}\n", style="cyan dim")
                sections.append(snippet)
            sections.append(Text(""))

    # ── 6) 根因诊断 ──────────────────────────────────
    root_cause = result.get("root_cause", [])
    if root_cause:
        rc_text = Text()
        for i, rc in enumerate(root_cause, 1):
            rc_text.append(f"  {i}. ", style="bold")
            rc_text.append(f"{rc}\n", style="")
        sections.append(Panel(rc_text, title="[bold yellow]根因诊断[/]",
                              border_style="yellow", padding=(0, 2)))
        sections.append(Text(""))

    # ── 7) DryRun 详细分析 ───────────────────────────
    dr_detail = result.get("dryrun_detail", {})
    if dr_detail:
        applies = dr_detail.get("applies_cleanly", None)
        method = dr_detail.get("apply_method", "")
        dr_tbl = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 1),
                       expand=True, title="[bold]DryRun 详情 (多级自适应)[/]")
        dr_tbl.add_column("K", width=16, style="bold")
        dr_tbl.add_column("V", ratio=1)

        if applies:
            method_labels = {
                "strict": "[green]strict — 原始补丁可直接应用[/]",
                "context-C1": "[cyan]context-C1 — 上下文偏移已适配 (仅需1行context)[/]",
                "3way": "[cyan]3-way merge — 三方合并成功[/]",
                "regenerated": "[bold cyan]regenerated — 上下文已重新生成[/]",
            }
            status_text = method_labels.get(method, f"[green]可应用 ({method})[/]")
        else:
            status_text = "[red]所有策略均失败[/]"
        dr_tbl.add_row("应用结果", status_text)

        if method and applies:
            levels = ["strict", "context-C1", "3way", "regenerated"]
            level_display = []
            for lvl in levels:
                if lvl == method:
                    level_display.append(f"[green]✔ {lvl}[/]")
                    break
                else:
                    level_display.append(f"[red]✘ {lvl}[/]")
            dr_tbl.add_row("尝试路径", " → ".join(level_display))

        conf_files = dr_detail.get("conflicting_files", [])
        if conf_files:
            dr_tbl.add_row("冲突文件", f"[red]{len(conf_files)}[/] 个")
            for cf in conf_files[:10]:
                dr_tbl.add_row("", f"  [red]{cf}[/]")

        err = dr_detail.get("error_output", "")
        if err:
            err_lines = err.strip().split("\n")[:6]
            dr_tbl.add_row("详情", "")
            for el in err_lines:
                dr_tbl.add_row("", f"[dim]{el}[/]")

        stat = dr_detail.get("stat_output", "")
        if stat:
            stat_lines = stat.strip().split("\n")[:8]
            dr_tbl.add_row("补丁统计", "")
            for sl in stat_lines:
                dr_tbl.add_row("", f"[dim]{sl}[/]")

        has_adapted = dr_detail.get("has_adapted_patch", False)
        if has_adapted:
            dr_tbl.add_row("", "")
            dr_tbl.add_row("[bold cyan]适配补丁[/]",
                           "[bold cyan]已生成可直接应用的补丁 "
                           "(核心 +/- 改动不变, context lines 已从目标文件更新)[/]")

        sections.append(dr_tbl)
        sections.append(Text(""))

    # ── 6) 工具推荐的前置依赖 vs 真实前置依赖 ────────
    tool_prereqs = result.get("tool_prereqs", [])
    known_prereqs = result.get("known_prereqs_detail", [])

    if tool_prereqs or known_prereqs:
        cmp_tbl = Table(box=box.ROUNDED, show_header=True, padding=(0, 1),
                        expand=True, title="[bold]前置依赖对比[/]")

        if tool_prereqs:
            tp_tbl = Table(box=box.SIMPLE, show_header=True, padding=(0, 1),
                           expand=True, title="[bold cyan]工具推荐[/]")
            tp_tbl.add_column("#", width=3)
            tp_tbl.add_column("Commit", width=14, style="cyan")
            tp_tbl.add_column("Subject", ratio=1)
            tp_tbl.add_column("等级", width=8)
            tp_tbl.add_column("分数", width=6)
            tp_tbl.add_column("重叠Hunk", width=9)
            tp_tbl.add_column("重叠函数", width=12)
            for i, p in enumerate(tool_prereqs[:15], 1):
                grade = p.get("grade", "")
                gs = {"strong": "bold red", "medium": "yellow",
                      "weak": "dim"}.get(grade, "")
                funcs = ", ".join(p.get("overlap_funcs", [])[:3])
                tp_tbl.add_row(
                    str(i), p.get("commit_id", ""),
                    p.get("subject", "")[:55],
                    f"[{gs}]{grade}[/]" if gs else grade,
                    str(p.get("score", "")),
                    str(p.get("overlap_hunks", 0)),
                    funcs if funcs else "-",
                )
            if len(tool_prereqs) > 15:
                tp_tbl.add_row("...", f"+{len(tool_prereqs)-15}", "", "", "", "", "")
            sections.append(tp_tbl)
            sections.append(Text(""))

        if known_prereqs:
            kp_tbl = Table(box=box.SIMPLE, show_header=True, padding=(0, 1),
                           expand=True, title="[bold green]真实合入记录[/]")
            kp_tbl.add_column("#", width=3)
            kp_tbl.add_column("Commit", width=14, style="green")
            kp_tbl.add_column("Subject", ratio=1)
            kp_tbl.add_column("Author", width=20)
            for i, kp in enumerate(known_prereqs, 1):
                kp_tbl.add_row(
                    str(i), kp.get("commit_id", ""),
                    kp.get("subject", ""), kp.get("author", ""))
            sections.append(kp_tbl)
            sections.append(Text(""))

        # TP/FP/FN 详情
        if prereq_m:
            tp_ids = prereq_m.get("true_positives", [])
            fp_ids = prereq_m.get("false_positives", [])
            fn_ids = prereq_m.get("false_negatives", [])
            match_tbl = Table(box=box.SIMPLE, show_header=True, padding=(0, 1),
                              expand=True, title="[bold]匹配详情[/]")
            match_tbl.add_column("类别", width=18, style="bold")
            match_tbl.add_column("数量", width=6)
            match_tbl.add_column("Commit IDs", ratio=1)
            match_tbl.add_row("[green]正确推荐 (TP)[/]", f"[green]{len(tp_ids)}[/]",
                              ", ".join(s[:12] for s in tp_ids[:8]))
            match_tbl.add_row("[red]误报 (FP)[/]", f"[red]{len(fp_ids)}[/]",
                              ", ".join(s[:12] for s in fp_ids[:8]))
            match_tbl.add_row("[yellow]漏报 (FN)[/]", f"[yellow]{len(fn_ids)}[/]",
                              ", ".join(s[:12] for s in fn_ids[:8]))
            sections.append(match_tbl)
            sections.append(Text(""))

    # ── 9) LLM 分析 ─────────────────────────────────
    llm = result.get("llm_analysis", "")
    llm_status = result.get("llm_status", "")
    if llm:
        sections.append(Panel(
            Markdown(llm),
            title="[bold magenta]LLM 智能分析[/]",
            border_style="magenta", padding=(1, 2),
        ))
        sections.append(Text(""))
    elif llm_status and not overall:
        llm_hint = Text()
        llm_hint.append(f"  LLM: {llm_status}\n", style="dim")
        sections.append(llm_hint)

    # ── 8) 工具建议 ──────────────────────────────────
    recs = result.get("recommendations", [])
    if recs:
        rec_text = Text()
        for r in recs[:5]:
            rec_text.append(f"  • {r}\n", style="dim")
        sections.append(Panel(rec_text, title="[bold]工具建议[/]",
                              border_style="dim", padding=(0, 2)))
        sections.append(Text(""))

    # ── 9) 最终裁定 ──────────────────────────────────
    verdict = Text()
    if overall:
        verdict.append("  ✔ PASS  ", style="bold white on green")
    else:
        verdict.append("  ✘ FAIL  ", style="bold white on red")
    verdict.append(f"  {result.get('summary', '')}", style="dim")
    sections.append(verdict)

    p = Panel(
        Group(*sections),
        title=f"[bold]验证报告 — {cve}[/]",
        border_style="green" if overall else "red",
        padding=(1, 2),
    )
    console.print(p)


def render_benchmark_report(results: list, target: str):
    """渲染批量基准测试汇总报告"""
    total = len(results)
    if total == 0:
        console.print("[yellow]无验证结果[/]")
        return

    intro_ok = sum(1 for r in results if r.get("checks", {}).get("intro_detected", False))
    fix_ok = sum(1 for r in results if r.get("checks", {}).get("fix_correctly_absent", False))

    prec_vals, recall_vals, f1_vals = [], [], []
    dryrun_ok, dryrun_total = 0, 0
    strategy_dist = {"L1": 0, "L2": 0, "L3": 0, "未命中": 0}

    for r in results:
        checks = r.get("checks", {})
        pm = checks.get("prereq_metrics")
        if pm:
            prec_vals.append(pm["precision"])
            recall_vals.append(pm["recall"])
            f1_vals.append(pm["f1"])
        dr = checks.get("dryrun_accurate")
        if dr is not None:
            dryrun_total += 1
            if dr:
                dryrun_ok += 1
        intro_s = checks.get("intro_strategy", "")
        if intro_s in ("exact_id", "L1"):
            strategy_dist["L1"] += 1
        elif intro_s in ("subject_match", "L2") or intro_s.startswith("subject"):
            strategy_dist["L2"] += 1
        elif intro_s.startswith("diff") or intro_s.startswith("L3"):
            strategy_dist["L3"] += 1
        elif intro_s:
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

    sd_parts = [f"{k}: {v} ({v/total:.0%})" for k, v in strategy_dist.items() if v]
    summary.add_row("", "")
    summary.add_row("搜索策略分布", "  ".join(sd_parts))

    detail = Table(box=box.ROUNDED, show_header=True, padding=(0, 1), expand=True)
    detail.add_column("#", width=3, justify="right", style="dim")
    detail.add_column("CVE", width=20, style="cyan")
    detail.add_column("引入", width=6, justify="center")
    detail.add_column("修复", width=6, justify="center")
    detail.add_column("精确率", width=8, justify="right")
    detail.add_column("召回率", width=8, justify="right")
    detail.add_column("DryRun", width=8, justify="center")
    detail.add_column("结果", width=6, justify="center")

    for i, r in enumerate(results, 1):
        checks = r.get("checks", {})
        intro = "[green]✔[/]" if checks.get("intro_detected") else "[red]✘[/]"
        fix = "[green]✔[/]" if checks.get("fix_correctly_absent") else "[red]✘[/]"
        pm = checks.get("prereq_metrics")
        prec = f"{pm['precision']:.0%}" if pm else "-"
        rec = f"{pm['recall']:.0%}" if pm else "-"
        dr = checks.get("dryrun_accurate")
        drs = "[green]✔[/]" if dr else ("[red]✘[/]" if dr is not None else "-")
        overall = "[green]✔[/]" if r.get("overall_pass") else "[red]✘[/]"
        detail.add_row(str(i), r.get("cve_id", "?"), intro, fix, prec, rec, drs, overall)

    from rich.console import Group
    p = Panel(
        Group(summary, Text(""), detail),
        title="[bold]Benchmark Report[/]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(p)


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
