#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整的CVE分析工作流示例
演示从CVE获取到依赖分析的完整流程
"""

import json
from crawl_cve_patch import Crawl_Cve_Patch


def demo_basic_workflow():
    """基础工作流：获取CVE信息和版本映射"""
    print("="*80)
    print("示例1: 基础工作流 - CVE信息获取和版本映射")
    print("="*80)
    print()
    
    cve_id = "CVE-2025-40198"
    
    # 步骤1: 创建爬虫实例
    print("[步骤1] 创建CVE爬虫实例...")
    crawler = Crawl_Cve_Patch()
    print("✅ 完成")
    print()
    
    # 步骤2: 获取CVE信息
    print(f"[步骤2] 从MITRE CVE API获取 {cve_id} 的信息...")
    result = crawler.get_introduced_fixed_commit(cve_id)
    
    if not result:
        print("❌ 获取失败")
        return
    
    print("✅ 成功获取CVE信息")
    print()
    
    # 步骤3: 显示关键信息
    print("[步骤3] CVE关键信息")
    print("-" * 80)
    
    print(f"📝 CVE描述:")
    print(f"   {result['cve_description'][:150]}...")
    print()
    
    mainline_commit = result.get('mainline_commit', '')
    mainline_version = result.get('mainline_version', '')
    introduced_commit = result.get('introduced_commit_id', '')
    
    print(f"⭐ Mainline修复信息:")
    print(f"   Commit ID: {mainline_commit}")
    print(f"   内核版本: {mainline_version}")
    print()
    
    if introduced_commit:
        print(f"🐛 问题引入:")
        print(f"   Commit ID: {introduced_commit}")
        print()
    
    # 步骤4: 版本映射关系
    print("[步骤4] 完整的版本到commit映射")
    print("-" * 80)
    
    version_mapping = result.get('version_commit_mapping', {})
    
    if version_mapping:
        print(f"\n{'版本':<20} {'Commit ID':<15} {'类型'}")
        print("-" * 60)
        
        for version in sorted(version_mapping.keys()):
            commit = version_mapping[version]
            is_mainline = (version == mainline_version)
            commit_type = "⭐ Mainline" if is_mainline else "🔄 Backport"
            print(f"{version:<20} {commit[:12]:<15} {commit_type}")
    
    print()
    print("="*80)
    print()
    
    return result


def demo_search_strategy(cve_info):
    """演示在自维护仓库中的搜索策略"""
    print("="*80)
    print("示例2: 自维护仓库搜索策略")
    print("="*80)
    print()
    
    mainline_commit = cve_info.get('mainline_commit', '')
    introduced_commit = cve_info.get('introduced_commit_id', '')
    
    # 获取commit详细信息
    crawler = Crawl_Cve_Patch()
    
    print("[步骤1] 获取社区commit的详细信息...")
    
    if introduced_commit:
        intro_patch = crawler.get_patch_content(introduced_commit[:12], "Mainline")
        if intro_patch:
            print(f"  引入问题的commit:")
            print(f"    Subject: {intro_patch.get('subject', '')}")
            print(f"    修改文件: {', '.join(intro_patch.get('modified_files', [])[:2])}")
    
    fix_patch = crawler.get_patch_content(mainline_commit[:12], "Mainline")
    if fix_patch:
        print(f"\n  修复补丁:")
        print(f"    Subject: {fix_patch.get('subject', '')}")
        print(f"    修改文件: {', '.join(fix_patch.get('modified_files', [])[:2])}")
    
    print()
    
    # 展示搜索策略
    print("[步骤2] 在自维护仓库中的搜索策略")
    print("-" * 80)
    print()
    
    if introduced_commit:
        print("🔍 搜索引入commit:")
        print(f"  1. 精确匹配: git log --all --grep='{introduced_commit[:12]}'")
        if intro_patch:
            subject = intro_patch.get('subject', '')
            print(f"  2. Subject匹配: git log --all --grep='{subject[:40]}'")
            print(f"  3. Backport格式: git log --all --grep='\\[backport\\].*{subject[:20]}'")
        print()
    
    print("🔍 搜索修复commit:")
    print(f"  1. 精确匹配: git log --all --grep='{mainline_commit[:12]}'")
    if fix_patch:
        subject = fix_patch.get('subject', '')
        files = fix_patch.get('modified_files', [])
        print(f"  2. Subject匹配: git log --all --grep='{subject[:40]}'")
        print(f"  3. Backport格式: git log --all --grep='\\[backport\\].*{subject[:20]}'")
        if files:
            print(f"  4. 文件匹配: git log --all -- {' '.join(files[:2])}")
    
    print()
    print("="*80)
    print()


def demo_analysis_logic():
    """演示完整的分析逻辑"""
    print("="*80)
    print("示例3: 完整分析逻辑流程")
    print("="*80)
    print()
    
    print("假设场景: 您有一个基于5.10内核的自维护版本")
    print()
    
    # 模拟数据
    target_version = "5.10.xxx-hulk"
    cve_id = "CVE-2025-40198"
    
    print(f"[场景设置]")
    print(f"  目标内核版本: {target_version}")
    print(f"  分析CVE: {cve_id}")
    print()
    
    # 步骤1: 获取CVE信息
    print("[步骤1] 获取CVE信息")
    print("  社区mainline修复: 8ecb790ea8c3 (6.18)")
    print("  社区5.10 backport: b2bac84fde28 (5.10.246)")
    print("  问题引入: 8b67f04ab9de")
    print()
    
    # 步骤2: 检查引入commit
    print("[步骤2] 在目标仓库中查找引入commit")
    print("  🔍 搜索 '8b67f04ab9de'...")
    print()
    print("  结果A: 找到精确匹配")
    print("    ✅ Commit: 8b67f04ab9de")
    print("    ✅ 确认: 目标仓库存在此漏洞")
    print("    ⚠️  需要: 合入修复补丁")
    print()
    print("  结果B: 未找到，但找到相似commit")
    print("    🔍 发现: abc123def456 - [backport] ext4: get rid of super block...")
    print("    📊 相似度: 95%")
    print("    ✅ 确认: 目标仓库存在此漏洞（已backport）")
    print("    ⚠️  需要: 合入修复补丁")
    print()
    print("  结果C: 完全未找到")
    print("    ✅ 确认: 目标仓库不存在此漏洞")
    print("    ✅ 结论: 无需修复")
    print()
    
    # 步骤3: 检查修复commit
    print("[步骤3] 检查修复补丁是否已合入")
    print("  🔍 优先搜索 'b2bac84fde28' (5.10 backport)...")
    print()
    print("  结果A: 找到修复补丁")
    print("    ✅ Commit: b2bac84fde28 或类似的backport")
    print("    ✅ 结论: CVE已修复，无需action")
    print()
    print("  结果B: 未找到修复补丁")
    print("    ⚠️  结论: 需要合入修复补丁")
    print("    ⏭️  继续: 分析前置依赖")
    print()
    
    # 步骤4: 依赖分析
    print("[步骤4] 分析修复补丁的前置依赖")
    print("  📦 假设修复补丁 b2bac84fde28 依赖:")
    print("    - dep1: commit_aaa111 (已合入 ✅)")
    print("    - dep2: commit_bbb222 (已合入 ✅)")
    print("    - dep3: commit_ccc333 (未合入 ❌)")
    print()
    print("  📋 合入计划:")
    print("    1. 先合入: commit_ccc333 (前置依赖)")
    print("    2. 再合入: b2bac84fde28 (修复补丁)")
    print()
    
    print("="*80)
    print()


def demo_test_commands():
    """演示测试命令的使用"""
    print("="*80)
    print("示例4: 测试命令使用指南")
    print("="*80)
    print()
    
    print("1️⃣  查看CVE基本信息和版本映射:")
    print("   python3 test_crawl_cve.py CVE-2025-40198")
    print()
    
    print("2️⃣  查找自维护仓库中的引入commit:")
    print("   # 显示搜索策略（不需要配置仓库）")
    print("   python3 test_crawl_cve.py search_introduced 8b67f04ab9de")
    print()
    print("   # 实际搜索（需要配置config.yaml）")
    print("   python3 test_crawl_cve.py search_introduced 8b67f04ab9de 5.10-hulk")
    print()
    
    print("3️⃣  检查修复补丁是否已合入:")
    print("   # 提供CVE ID（自动获取修复信息）")
    print("   python3 test_crawl_cve.py check_fix abc123def 5.10-hulk CVE-2025-40198")
    print()
    print("   # 不提供CVE ID（手动输入修复commit）")
    print("   python3 test_crawl_cve.py check_fix abc123def")
    print()
    
    print("4️⃣  测试mainline识别功能:")
    print("   python3 test_crawl_cve.py mainline")
    print()
    
    print("5️⃣  测试完整项目逻辑:")
    print("   python3 test_crawl_cve.py full")
    print()
    
    print("="*80)
    print()


def main():
    """主函数"""
    print("\n")
    print("╔" + "="*78 + "╗")
    print("║" + " "*20 + "CVE Backporting 完整工作流示例" + " "*27 + "║")
    print("╚" + "="*78 + "╝")
    print()
    
    # 示例1: 基础工作流
    cve_info = demo_basic_workflow()
    
    if not cve_info:
        print("❌ 无法继续后续示例（网络问题）")
        print()
        print("💡 但您仍然可以查看其他示例的逻辑说明...")
        print()
    
    # 示例2: 搜索策略（即使网络失败也能展示）
    if cve_info:
        demo_search_strategy(cve_info)
    
    # 示例3: 分析逻辑（模拟数据）
    demo_analysis_logic()
    
    # 示例4: 测试命令
    demo_test_commands()
    
    # 总结
    print("="*80)
    print("📚 更多信息")
    print("="*80)
    print()
    print("详细文档:")
    print("  - TESTING_GUIDE.md: 完整测试指南")
    print("  - CVE_MAINLINE_ANALYSIS.md: Mainline识别原理")
    print("  - README.md: 项目说明")
    print()
    print("核心模块:")
    print("  - crawl_cve_patch.py: CVE信息获取和commit识别")
    print("  - git_repo_manager.py: Git仓库管理和搜索")
    print("  - enhanced_cve_analyzer.py: 完整的CVE分析")
    print("  - enhanced_patch_matcher.py: Commit匹配算法")
    print()
    print("="*80)
    print()


if __name__ == "__main__":
    main()
