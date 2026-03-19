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

    # 输出生成的 patch 文件
    if result.dry_run and result.dry_run.adapted_patch:
        patch_file = os.path.join(out_dir, f"{cve_id}_{target}_adapted.patch")
        with open(patch_file, "w") as f:
            f.write(result.dry_run.adapted_patch)
        console.print(f"\n[green]✔ 生成的适配补丁已保存:[/] [cyan]{patch_file}[/]")

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
    console.print(f"[dim]报告已保存: {fp}[/]")


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
                "context-C1": "原始补丁的 context lines 有偏移 (中间 commit 修改了"
                              "相邻行), 已通过放宽 context 匹配 (-C1) 成功适配",
                "3way": "原始补丁 context 偏移, 已通过 3-way merge 成功适配",
                "regenerated": "原始补丁 context 严重偏移, 已从目标文件重新生成 "
                               "context lines, 核心 +/- 改动行完全不变",
                "conflict-adapted": "中间 commit 修改了补丁涉及的同一行代码, "
                                    "已用目标文件实际内容替换补丁的 - 行、保留 + 行。"
                                    "适配补丁可应用但需人工审查语义正确性",
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
                         cve_info=None):
    """执行单个 CVE 的回退验证，返回结果 dict。
    cve_info: 可选的预构建 CveInfo，提供后跳过 MITRE 爬取。"""
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

    try:
        wt_mgr = GitRepoManager(
            {tv: {"path": wt_dir, "branch": "HEAD"}},
            use_cache=False,
        )
        pipe = Pipeline(wt_mgr, path_mappings=config.path_mappings)

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
                result = pipe.analyze(cve_id, tv, enable_dryrun=True,
                                      on_stage=_update,
                                      cve_info=cve_info)
        else:
            result = pipe.analyze(cve_id, tv, enable_dryrun=True,
                                  cve_info=cve_info)

        if result.cve_info is None or not result.cve_info.fix_commit_id:
            return {
                "cve_id": cve_id, "known_fix": known_fix, "target": tv,
                "worktree_commit": rollback_hash[:16] if rollback_hash else rollback,
                "checks": {}, "overall_pass": False,
                "summary": "CVE上游数据不完整(MITRE无fix commit), 无法验证",
            }

        checks = {}
        checks["fix_correctly_absent"] = not result.is_fixed
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
                known_fix_detail = {
                    "commit_id": lines[0][:12],
                    "subject": lines[1],
                    "author": lines[2],
                    "stat": "\n".join(lines[3:])[:500],
                }
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
            {"commit_id": p.commit_id[:12], "subject": p.subject,
             "grade": p.grade, "score": round(p.score, 2),
             "overlap_hunks": p.overlap_hunks,
             "adjacent_hunks": p.adjacent_hunks,
             "overlap_funcs": p.overlap_funcs[:5]}
            for p in (result.prerequisite_patches or [])
        ]

        known_prereqs_detail = []
        for kid in known_prereqs:
            info = git_mgr.run_git(
                ["git", "log", "-1", "--format=%H\x1e%s\x1e%an", kid],
                tv, timeout=10)
            if info:
                parts = info.strip().split("\x1e")
                known_prereqs_detail.append({
                    "commit_id": parts[0][:12],
                    "subject": parts[1] if len(parts) > 1 else "",
                    "author": parts[2] if len(parts) > 2 else "",
                })
            else:
                known_prereqs_detail.append({"commit_id": kid[:12],
                                             "subject": "", "author": ""})

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
        l0_l2_methods = {"strict", "context-C1", "3way"}
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
            generated_vs_real["compare_source"] = "adapted_patch"
        elif community_diff and local_diff:
            generated_vs_real = _compare_generated_vs_real(
                community_diff, local_diff)
            generated_vs_real["compare_source"] = "community_patch"
            generated_vs_real["note"] = (
                "未能生成适配补丁，当前使用社区原始补丁对比 "
                "(行号可能与本地不一致，仅核心改动行有参考意义)"
            )

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

        return {
            "cve_id": cve_id, "known_fix": known_fix, "target": tv,
            "worktree_commit": rollback_hash[:16] if rollback_hash else rollback,
            "checks": checks,
            "overall_pass": overall and not issues,
            "summary": "; ".join(issues) if issues else "验证通过",
            "issues": issues,
            "fix_patch_detail": fix_patch_detail,
            "dryrun_detail": dryrun_detail,
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
        }

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

    result = _run_single_validate(
        config, args.cve_id, tv, args.known_fix, known_prereqs,
        git_mgr=git_mgr, show_stages=True, cve_info=cve_info)

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
    render_validate_report(result)

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = os.path.join(out_dir, f"validate_{args.cve_id}_{tv}_{ts}.json")
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)
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

        try:
            r = _run_single_validate(
                config, cve_id, tv, primary["commit"],
                known_prereq_commits,
                git_mgr=git_mgr, show_stages=True,
                cve_info=cve_info)

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
            console.print(
                f"  {icon}  核心相似度={core_sim:.0%}  方法={method}")

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
    render_batch_validate_report(cve_results, tv)

    full_report_path = os.path.join(
        out_dir, f"batch_validate_{tv}_{ts}_full.json")
    with open(full_report_path, "w", encoding="utf-8") as f:
        json.dump({
            "target": tv,
            "total_cves": len(cve_groups),
            "total_patches": total_patches,
            "skipped_parse_errors": skipped,
            "cve_results": cve_results,
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

    cp = sub.add_parser("build-cache", help="构建commit缓存", parents=[parent])
    cp.add_argument("--target", dest="target_version", required=True)
    cp.add_argument("--full", action="store_true", help="强制全量重建缓存（默认增量）")

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
        "check-fix": cmd_check_fix,
        "validate": cmd_validate,
        "benchmark": cmd_benchmark,
        "batch-validate": cmd_batch_validate,
        "build-cache": cmd_build_cache,
        "search": cmd_search,
    }
    dispatch[args.command](args, config)


if __name__ == "__main__":
    main()
