#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE补丁回合分析 - 命令行工具
"""

import argparse
import json
import sys
import os
from datetime import datetime
from config_loader import ConfigLoader
from enhanced_cve_analyzer import EnhancedCVEAnalyzer
from git_repo_manager import GitRepoManager
from crawl_cve_patch import Crawl_Cve_Patch
from ai_analyze import Ai_Analyze


def setup_logging(config):
    """设置日志"""
    import logging
    
    log_level = getattr(logging, config.output.log_level.upper(), logging.INFO)
    
    # 创建logger
    logger = logging.getLogger('cve_backporting')
    logger.setLevel(log_level)
    
    # 文件handler
    fh = logging.FileHandler(config.output.log_file, encoding='utf-8')
    fh.setLevel(log_level)
    
    # 控制台handler
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    
    # 格式
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    return logger


def analyze_single_cve(args, config, logger):
    """
    分析单个CVE
    """
    logger.info(f"开始分析 CVE: {args.cve_id}")
    logger.info(f"目标版本: {args.target_version}")
    
    try:
        # 实例化组件
        crawl_cve = Crawl_Cve_Patch()
        
        # 根据是否禁用AI来决定使用哪个AI分析器
        if hasattr(args, 'no_ai') and args.no_ai:
            logger.info("AI分析已禁用")
            ai_analyze = Ai_Analyze()  # 会自动使用模拟模式
        else:
            # 从配置加载AI设置
            ai_config = config.ai_analysis if hasattr(config, 'ai_analysis') else {}
            ai_analyze = Ai_Analyze(ai_config)
        
        # 初始化GitRepoManager
        repo_config = config.repositories.get(args.target_version, {})
        if not repo_config.get('path'):
            logger.error(f"配置中未找到版本 {args.target_version} 的仓库路径")
            return {
                "code": 1,
                "message": f"未配置版本 {args.target_version}"
            }
        
        git_manager = GitRepoManager(
            {args.target_version: {
                'path': repo_config['path'],
                'branch': repo_config.get('branch')
            }},
            use_cache=config.cache.enabled
        )
        
        # 创建分析器
        analyzer = EnhancedCVEAnalyzer(crawl_cve, ai_analyze, git_manager)
        
        # 执行分析
        logger.info("开始执行CVE分析...")
        result = analyzer.analyze_cve_patch_enhanced(args.cve_id, args.target_version)
        
    except Exception as e:
        logger.error(f"分析过程中出错: {e}", exc_info=True)
        result = {
            "code": 1,
            "vuln_id": args.cve_id,
            "kernel_version": args.target_version,
            "error": str(e)
        }
    
    # 保存结果
    output_dir = config.output.output_dir
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # JSON格式
    if "json" in config.output.report_formats:
        json_file = os.path.join(
            output_dir, 
            f"cve_{args.cve_id}_{args.target_version}_{timestamp}.json"
        )
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=4, ensure_ascii=False)
        logger.info(f"JSON报告已保存: {json_file}")
    
    # Markdown格式
    if "markdown" in config.output.report_formats:
        from enhanced_patch_matcher import generate_analysis_report
        markdown_file = os.path.join(
            output_dir,
            f"cve_{args.cve_id}_{args.target_version}_{timestamp}.md"
        )
        # report = generate_analysis_report(result)
        # with open(markdown_file, 'w', encoding='utf-8') as f:
        #     f.write(report)
        logger.info(f"Markdown报告已保存: {markdown_file}")
    
    # 打印摘要
    print("\n" + "="*80)
    print(f"CVE分析完成: {args.cve_id}")
    print(f"耗时: {result.get('duration', 0):.2f}秒")
    print(f"结果代码: {result.get('code', -1)}")
    print("="*80)
    
    return result


def analyze_batch_cves(args, config, logger):
    """
    批量分析CVE
    """
    logger.info(f"批量分析模式，输入文件: {args.batch_file}")
    
    # 读取CVE列表
    with open(args.batch_file, 'r', encoding='utf-8') as f:
        cve_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    logger.info(f"共 {len(cve_list)} 个CVE待分析")
    
    results = []
    success_count = 0
    fail_count = 0
    
    for idx, cve_id in enumerate(cve_list, 1):
        print(f"\n[{idx}/{len(cve_list)}] 分析 {cve_id}...")
        
        try:
            # 创建临时args
            import copy
            temp_args = copy.copy(args)
            temp_args.cve_id = cve_id
            
            result = analyze_single_cve(temp_args, config, logger)
            results.append(result)
            
            if result.get('code') == 0:
                success_count += 1
            else:
                fail_count += 1
        
        except Exception as e:
            logger.error(f"分析 {cve_id} 时出错: {e}")
            fail_count += 1
            results.append({
                "code": 1,
                "vuln_id": cve_id,
                "error": str(e)
            })
    
    # 生成汇总报告
    summary_file = os.path.join(
        config.output.output_dir,
        f"batch_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    
    summary = {
        "total": len(cve_list),
        "success": success_count,
        "failed": fail_count,
        "details": results
    }
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=4, ensure_ascii=False)
    
    print("\n" + "="*80)
    print("批量分析完成")
    print(f"  总数: {len(cve_list)}")
    print(f"  成功: {success_count}")
    print(f"  失败: {fail_count}")
    print(f"  汇总报告: {summary_file}")
    print("="*80)


def build_cache_command(args, config, logger):
    """
    构建缓存
    """
    logger.info(f"为版本 {args.target_version} 构建缓存...")
    
    try:
        # 获取仓库配置
        repo_config = config.repositories.get(args.target_version, {})
        if not repo_config.get('path'):
            logger.error(f"配置中未找到版本 {args.target_version} 的仓库路径")
            print(f"错误: 未配置版本 {args.target_version}")
            return
        
        # 实例化GitRepoManager并构建缓存
        git_manager = GitRepoManager(
            {args.target_version: {
                'path': repo_config['path'],
                'branch': repo_config.get('branch')
            }},
            use_cache=True
        )
        
        max_commits = config.cache.max_cached_commits if hasattr(config.cache, 'max_cached_commits') else 10000
        git_manager.build_commit_cache(args.target_version, max_commits=max_commits)
        
        logger.info("缓存构建完成")
        print(f"✅ 缓存构建成功，已缓存最近 {max_commits} 个commits")
    
    except Exception as e:
        logger.error(f"构建缓存时出错: {e}", exc_info=True)
        print(f"❌ 缓存构建失败: {e}")


def search_commit_command(args, config, logger):
    """
    搜索commit
    """
    logger.info(f"在 {args.target_version} 中搜索commit: {args.commit_id}")
    
    try:
        # 获取仓库路径
        repo_config = config.repositories.get(args.target_version, {})
        if not repo_config.get('path'):
            logger.error(f"配置中未找到版本 {args.target_version} 的仓库路径")
            print(f"错误: 未配置版本 {args.target_version}")
            return
        
        # 实例化GitRepoManager
        git_manager = GitRepoManager(
            {args.target_version: {
                'path': repo_config['path'],
                'branch': repo_config.get('branch')
            }},
            use_cache=config.cache.enabled
        )
        
        # 搜索commit
        result = git_manager.find_commit_by_id(args.commit_id, args.target_version)
        
        print("\n搜索结果:")
        if result:
            print(json.dumps(result, indent=4, ensure_ascii=False))
            print(f"\n✅ 找到commit: {result['commit_id'][:12]}")
            print(f"   Subject: {result.get('subject', 'N/A')}")
            print(f"   Author: {result.get('author', 'N/A')}")
        else:
            print(f"❌ 未找到commit: {args.commit_id}")
    
    except Exception as e:
        logger.error(f"搜索commit时出错: {e}", exc_info=True)
        print(f"❌ 搜索失败: {e}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="CVE补丁回合分析工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 分析单个CVE
  python cli.py analyze --cve CVE-2024-12345 --target 5.10-hulk
  
  # 批量分析
  python cli.py analyze --batch cve_list.txt --target 5.10-hulk
  
  # 构建缓存
  python cli.py build-cache --target 5.10-hulk
  
  # 搜索commit
  python cli.py search --commit abc123def456 --target 5.10-hulk
        """
    )
    
    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='配置文件路径 (默认: config.yaml)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='子命令')
    
    # analyze子命令
    analyze_parser = subparsers.add_parser('analyze', help='分析CVE')
    analyze_parser.add_argument(
        '--cve',
        dest='cve_id',
        help='CVE ID (例如: CVE-2024-12345)'
    )
    analyze_parser.add_argument(
        '--batch',
        dest='batch_file',
        help='批量分析，指定包含CVE列表的文件'
    )
    analyze_parser.add_argument(
        '--target',
        dest='target_version',
        required=True,
        help='目标内核版本 (例如: 5.10-hulk)'
    )
    analyze_parser.add_argument(
        '--no-ai',
        action='store_true',
        help='禁用AI分析（加快速度）'
    )
    
    # build-cache子命令
    cache_parser = subparsers.add_parser('build-cache', help='构建commit缓存')
    cache_parser.add_argument(
        '--target',
        dest='target_version',
        required=True,
        help='目标内核版本'
    )
    
    # search子命令
    search_parser = subparsers.add_parser('search', help='搜索commit')
    search_parser.add_argument(
        '--commit',
        dest='commit_id',
        required=True,
        help='Commit ID或关键词'
    )
    search_parser.add_argument(
        '--target',
        dest='target_version',
        required=True,
        help='目标内核版本'
    )
    
    # 解析参数
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # 加载配置
    config = ConfigLoader.load(args.config)
    
    # 验证配置
    if not ConfigLoader.validate_config(config):
        print("错误: 配置验证失败")
        sys.exit(1)
    
    # 设置日志
    logger = setup_logging(config)
    
    # 执行命令
    try:
        if args.command == 'analyze':
            if args.batch_file:
                analyze_batch_cves(args, config, logger)
            elif args.cve_id:
                analyze_single_cve(args, config, logger)
            else:
                print("错误: 请指定 --cve 或 --batch")
                analyze_parser.print_help()
                sys.exit(1)
        
        elif args.command == 'build-cache':
            build_cache_command(args, config, logger)
        
        elif args.command == 'search':
            search_commit_command(args, config, logger)
    
    except KeyboardInterrupt:
        logger.info("用户中断")
        sys.exit(130)
    
    except Exception as e:
        logger.error(f"执行出错: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
