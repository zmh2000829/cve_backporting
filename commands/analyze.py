"""`analyze` 命令入口。"""

import os
import sys

from commands.policy_cli import (
    add_p2_toggle,
    add_policy_profile_arg,
    add_search_profile_arg,
    apply_policy_cli_overrides,
)
from services.output_support import make_run_id


def register(subparsers, parent):
    parser = subparsers.add_parser("analyze", help="分析CVE", parents=[parent])
    parser.add_argument("--cve", dest="cve_id")
    parser.add_argument("--batch", dest="batch_file")
    parser.add_argument("--target", dest="target_version", required=True)
    parser.add_argument("--no-dryrun", action="store_true", help="跳过dry-run检测")
    parser.add_argument(
        "--deep",
        action="store_true",
        help="深度分析模式: 漏洞分析+社区讨论+补丁检视+风险收益+合入建议",
    )
    add_policy_profile_arg(parser)
    add_search_profile_arg(parser)
    add_p2_toggle(parser)
    return {"analyze": run}


def run(args, config, runtime):
    config = apply_policy_cli_overrides(config, args)
    git_mgr = runtime._make_git_mgr(config, args.target_version)
    pipe = runtime.Pipeline(
        git_mgr,
        path_mappings=config.path_mappings,
        llm_config=config.llm,
        policy_config=getattr(config, "policy", None),
        analysis_config=getattr(config, "analysis", None),
        search_config=getattr(config, "search", None),
    )

    cves = [args.cve_id] if args.cve_id else []
    if args.batch_file:
        with open(args.batch_file, "r", encoding="utf-8") as f:
            cves = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not cves:
        runtime.console.print("[red]请指定 --cve 或 --batch[/]")
        sys.exit(1)

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)
    run_id = make_run_id()

    deep = getattr(args, "deep", False)
    for cve_id in cves:
        if deep:
            runtime._analyze_deep(
                pipe,
                cve_id,
                args.target_version,
                out_dir=out_dir,
                policy_config=getattr(config, "policy", None),
                run_id=run_id,
            )
        else:
            runtime._analyze_one(
                pipe,
                cve_id,
                args.target_version,
                config,
                enable_dryrun=not args.no_dryrun,
                out_dir=out_dir,
                policy_config=getattr(config, "policy", None),
                run_id=run_id,
            )
