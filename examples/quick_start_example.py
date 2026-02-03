#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速开始示例 - 完整的CVE分析流程
展示如何使用新实现的 Crawl_Cve_Patch 类
"""

import json
from crawl_cve_patch import Crawl_Cve_Patch
from enhanced_patch_matcher import CommitMatcher, CommitInfo, DependencyAnalyzer


def example_1_basic_cve_info():
    """
    示例1: 基础CVE信息获取
    """
    print("\n" + "="*80)
    print("示例1: 获取CVE的基础信息")
    print("="*80)
    
    crawler = Crawl_Cve_Patch()
    
    # 获取CVE信息
    cve_id = "CVE-2024-26633"
    result = crawler.get_introduced_fixed_commit(cve_id)
    
    if result:
        print(f"\n✅ 成功获取 {cve_id}")
        print(f"   修复commit: {result['fix_commit_id']}")
        print(f"   引入commit: {result.get('introduced_commit_id', '未知')}")
        print(f"   严重程度: {result['severity']}")
    else:
        print(f"\n❌ 获取失败")


def example_2_patch_content():
    """
    示例2: 获取补丁详细内容
    """
    print("\n" + "="*80)
    print("示例2: 获取补丁的详细内容")
    print("="*80)
    
    crawler = Crawl_Cve_Patch()
    
    # 先获取CVE信息
    cve_id = "CVE-2024-26633"
    cve_info = crawler.get_introduced_fixed_commit(cve_id)
    
    if cve_info and cve_info['fix_commit_id']:
        fix_commit = cve_info['fix_commit_id']
        
        # 获取patch内容
        patch = crawler.get_patch_content(fix_commit[:12], "Mainline")
        
        if patch:
            print(f"\n✅ 成功获取patch")
            print(f"   Subject: {patch['subject']}")
            print(f"   Author: {patch['author']}")
            print(f"   修改文件: {patch['modified_files']}")
            
            # 保存patch
            import os
            output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'output')
            os.makedirs(output_dir, exist_ok=True)
            with open(os.path.join(output_dir, f"example_patch_{fix_commit[:12]}.txt"), 'w', encoding='utf-8') as f:
                f.write(patch['patch'])
            print(f"   已保存到: example_patch_{fix_commit[:12]}.txt")


def example_3_commit_matching():
    """
    示例3: 使用增强匹配功能
    """
    print("\n" + "="*80)
    print("示例3: commit匹配功能演示")
    print("="*80)
    
    crawler = Crawl_Cve_Patch()
    matcher = CommitMatcher()
    
    # 获取社区的修复补丁
    cve_id = "CVE-2024-26633"
    cve_info = crawler.get_introduced_fixed_commit(cve_id)
    
    if cve_info and cve_info['fix_commit_id']:
        fix_commit = cve_info['fix_commit_id']
        patch = crawler.get_patch_content(fix_commit[:12], "Mainline")
        
        if patch:
            # 构建CommitInfo对象
            source_commit = CommitInfo(
                commit_id=fix_commit,
                subject=patch['subject'],
                commit_msg=patch['commit_msg'],
                diff_code=patch['diff_code'],
                modified_files=patch['modified_files']
            )
            
            print(f"\n社区commit信息:")
            print(f"   ID: {source_commit.commit_id[:12]}")
            print(f"   Subject: {source_commit.subject}")
            print(f"   修改文件: {len(source_commit.modified_files)}")
            
            # 演示相似度计算
            print(f"\n演示Subject相似度计算:")
            
            test_subjects = [
                patch['subject'],  # 100% 相同
                f"[backport] {patch['subject']}",  # 应该有很高相似度
                f"net: fix some other bug",  # 低相似度
            ]
            
            for test_subject in test_subjects:
                similarity = matcher.calculate_text_similarity(
                    source_commit.subject,
                    test_subject
                )
                print(f"   '{test_subject[:60]}...'")
                print(f"   相似度: {similarity:.2%}")
                print()


def example_4_handle_multiple_commits():
    """
    示例4: 处理有多个commits的情况
    """
    print("\n" + "="*80)
    print("示例4: 处理多个commits的CVE")
    print("="*80)
    
    crawler = Crawl_Cve_Patch()
    
    # 某些CVE可能有多个相关commits
    cve_id = "CVE-2024-26633"
    result = crawler.get_introduced_fixed_commit(cve_id)
    
    if result:
        all_commits = result.get('all_fix_commits', [])
        
        print(f"\n找到 {len(all_commits)} 个修复commits:")
        
        for i, commit in enumerate(all_commits, 1):
            print(f"\n   Commit {i}:")
            print(f"      ID: {commit['commit_id'][:12]}")
            print(f"      来源: {commit['source']}")
            print(f"      URL: {commit['url']}")
            print(f"      Tags: {commit.get('tags', [])}")
        
        print(f"\n最终选择的mainline commit: {result['mainline_commit'][:12]}")
        
        # 解释选择原因
        selected_commit = next(
            (c for c in all_commits if c['commit_id'] == result['mainline_commit']),
            None
        )
        if selected_commit:
            print(f"   选择原因: 来源为 '{selected_commit['source']}'")


def example_5_complete_workflow():
    """
    示例5: 完整的分析工作流
    """
    print("\n" + "="*80)
    print("示例5: 完整的CVE分析工作流")
    print("="*80)
    
    crawler = Crawl_Cve_Patch()
    
    cve_id = "CVE-2024-26633"
    
    print(f"\n步骤1: 获取CVE信息")
    cve_info = crawler.get_introduced_fixed_commit(cve_id)
    
    if not cve_info:
        print("❌ 获取CVE信息失败")
        return
    
    print(f"✅ CVE: {cve_id}")
    print(f"   严重程度: {cve_info['severity']}")
    print(f"   修复commit: {cve_info['fix_commit_id'][:12]}")
    
    print(f"\n步骤2: 获取修复补丁内容")
    fix_patch = crawler.get_patch_content(cve_info['fix_commit_id'][:12], "Mainline")
    
    if not fix_patch:
        print("❌ 获取补丁内容失败")
        return
    
    print(f"✅ Subject: {fix_patch['subject']}")
    print(f"   Author: {fix_patch['author']}")
    print(f"   修改文件数: {len(fix_patch['modified_files'])}")
    
    print(f"\n步骤3: 分析修改的文件")
    for file in fix_patch['modified_files'][:5]:
        print(f"   - {file}")
    
    if len(fix_patch['modified_files']) > 5:
        print(f"   ... 还有 {len(fix_patch['modified_files']) - 5} 个文件")
    
    print(f"\n步骤4: 提取修改的函数")
    matcher = CommitMatcher()
    functions = matcher.extract_modified_functions(fix_patch['diff_code'])
    
    if functions:
        print(f"   修改了 {len(functions)} 个函数:")
        for func in functions[:5]:
            print(f"   - {func}")
    else:
        print(f"   未检测到函数修改（可能是配置文件或宏定义）")
    
    print(f"\n步骤5: 生成分析报告")
    report = {
        "cve_id": cve_id,
        "severity": cve_info['severity'],
        "description": cve_info['cve_description'][:200] + "...",
        "fix_commit": {
            "id": cve_info['fix_commit_id'],
            "subject": fix_patch['subject'],
            "author": fix_patch['author'],
            "modified_files": fix_patch['modified_files'],
            "modified_functions": functions
        },
        "analysis_time": "now"
    }
    
    import os
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'output')
    os.makedirs(output_dir, exist_ok=True)
    report_file = os.path.join(output_dir, f"example_report_{cve_id.replace('-', '_')}.json")
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    
    print(f"✅ 报告已保存: {report_file}")


def example_6_error_handling():
    """
    示例6: 错误处理
    """
    print("\n" + "="*80)
    print("示例6: 错误处理演示")
    print("="*80)
    
    crawler = Crawl_Cve_Patch()
    
    # 测试不存在的CVE
    print("\n测试1: 不存在的CVE")
    result = crawler.get_introduced_fixed_commit("CVE-9999-99999")
    if result:
        print("   意外: 应该返回None")
    else:
        print("   ✅ 正确处理: 返回None")
    
    # 测试无效的commit ID
    print("\n测试2: 无效的commit ID")
    patch = crawler.get_patch_content("invalid_commit_id", "Mainline")
    if patch:
        print("   意外: 应该返回空字典")
    else:
        print("   ✅ 正确处理: 返回空字典")


def run_all_examples():
    """运行所有示例"""
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                  CVE补丁分析系统 - 使用示例                                   ║
║                                                                            ║
║  本脚本演示如何使用新实现的 Crawl_Cve_Patch 类                               ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    examples = [
        ("基础CVE信息获取", example_1_basic_cve_info),
        ("获取补丁详细内容", example_2_patch_content),
        ("commit匹配功能", example_3_commit_matching),
        ("处理多个commits", example_4_handle_multiple_commits),
        ("完整分析工作流", example_5_complete_workflow),
        ("错误处理", example_6_error_handling),
    ]
    
    for i, (name, func) in enumerate(examples, 1):
        try:
            func()
        except Exception as e:
            print(f"\n❌ 示例 {i} 执行出错: {e}")
            import traceback
            traceback.print_exc()
        
        print("\n" + "-"*80)
        
        # 每个示例之间暂停一下，避免API请求过快
        if i < len(examples):
            import time
            time.sleep(2)
    
    print("\n" + "="*80)
    print("所有示例执行完成")
    print("="*80)
    print("\n生成的文件:")
    print("   - example_patch_*.txt : 补丁文本")
    print("   - example_report_*.json : 分析报告")
    print("\n下一步:")
    print("   1. 查看生成的文件")
    print("   2. 根据需要调整代码")
    print("   3. 集成到你的完整系统中")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # 运行指定的示例
        example_num = sys.argv[1]
        
        examples_map = {
            "1": example_1_basic_cve_info,
            "2": example_2_patch_content,
            "3": example_3_commit_matching,
            "4": example_4_handle_multiple_commits,
            "5": example_5_complete_workflow,
            "6": example_6_error_handling,
        }
        
        if example_num in examples_map:
            examples_map[example_num]()
        else:
            print(f"未知示例: {example_num}")
            print("可用示例: 1-6")
    else:
        # 运行所有示例
        run_all_examples()
