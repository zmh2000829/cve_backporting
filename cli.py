#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE补丁回溯分析 - 命令行工具

用法:
  python cli.py analyze --cve CVE-2024-26633 --target 5.10-hulk
  python cli.py build-cache --target 5.10-hulk
  python cli.py search --commit abc123 --target 5.10-hulk
"""

import argparse
import json
import sys
import os
import logging
from datetime import datetime

from config_loader import ConfigLoader
from crawl_cve_patch import CveFetcher
from git_repo_manager import GitRepoManager
from enhanced_cve_analyzer import BackportAnalyzer

logger = logging.getLogger("cve_backporting")


def _setup_logging(config):
    level = getattr(logging, config.output.log_level.upper(), logging.INFO)
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"

    logging.basicConfig(level=level, format=fmt)

    if config.output.log_file:
        fh = logging.FileHandler(config.output.log_file, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter(fmt))
        logging.getLogger().addHandler(fh)


def _make_components(config, target_version: str):
    repo_cfg = config.repositories.get(target_version)
    if not repo_cfg or not repo_cfg.get("path"):
        logger.error("未配置版本 %s 的仓库", target_version)
        sys.exit(1)

    fetcher = CveFetcher()
    git_mgr = GitRepoManager(
        {target_version: {"path": repo_cfg["path"], "branch": repo_cfg.get("branch")}},
        use_cache=config.cache.enabled,
    )
    return fetcher, git_mgr


def cmd_analyze(args, config):
    fetcher, git_mgr = _make_components(config, args.target_version)
    analyzer = BackportAnalyzer(fetcher, git_mgr)

    cve_ids = [args.cve_id] if args.cve_id else []
    if args.batch_file:
        with open(args.batch_file, "r") as f:
            cve_ids = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if not cve_ids:
        print("请指定 --cve 或 --batch")
        sys.exit(1)

    out_dir = config.output.output_dir
    os.makedirs(out_dir, exist_ok=True)

    for cve_id in cve_ids:
        logger.info("分析 %s ...", cve_id)
        result = analyzer.analyze(cve_id, args.target_version)
        report = BackportAnalyzer.format_report(result)
        print(report)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fpath = os.path.join(out_dir, f"{cve_id}_{args.target_version}_{ts}.json")
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump({
                "cve_id": result.cve_id,
                "target_version": result.target_version,
                "is_vulnerable": result.is_vulnerable,
                "is_fixed": result.is_fixed,
                "recommendations": result.recommendations,
            }, f, indent=2, ensure_ascii=False, default=str)
        logger.info("报告已保存: %s", fpath)


def cmd_build_cache(args, config):
    _, git_mgr = _make_components(config, args.target_version)
    max_c = config.cache.max_cached_commits if hasattr(config.cache, "max_cached_commits") else None
    git_mgr.build_commit_cache(args.target_version, max_commits=max_c)


def cmd_search(args, config):
    _, git_mgr = _make_components(config, args.target_version)
    result = git_mgr.find_commit_by_id(args.commit_id, args.target_version)
    if result:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"未找到: {args.commit_id}")


def main():
    parser = argparse.ArgumentParser(description="CVE补丁回溯分析工具")
    parser.add_argument("-c", "--config", default="config.yaml", help="配置文件路径")
    sub = parser.add_subparsers(dest="command")

    ap = sub.add_parser("analyze", help="分析CVE")
    ap.add_argument("--cve", dest="cve_id")
    ap.add_argument("--batch", dest="batch_file")
    ap.add_argument("--target", dest="target_version", required=True)

    cp = sub.add_parser("build-cache", help="构建commit缓存")
    cp.add_argument("--target", dest="target_version", required=True)

    sp = sub.add_parser("search", help="搜索commit")
    sp.add_argument("--commit", dest="commit_id", required=True)
    sp.add_argument("--target", dest="target_version", required=True)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    config = ConfigLoader.load(args.config)
    _setup_logging(config)

    dispatch = {"analyze": cmd_analyze, "build-cache": cmd_build_cache, "search": cmd_search}
    dispatch[args.command](args, config)


if __name__ == "__main__":
    main()
