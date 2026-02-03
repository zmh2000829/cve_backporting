#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 Crawl_Cve_Patch 类的功能
"""

import json
from crawl_cve_patch import Crawl_Cve_Patch


def test_single_cve(cve_id: str):
    """测试单个CVE的获取"""
    print("\n" + "="*80)
    print(f"测试CVE: {cve_id}")
    print("="*80)
    
    crawler = Crawl_Cve_Patch()
    
    # 获取CVE信息
    result = crawler.get_introduced_fixed_commit(cve_id)
    
    if not result:
        print(f"❌ 获取 {cve_id} 失败")
        return False
    
    # 打印结果
    print("\n✅ 成功获取CVE信息:")
    print(f"   CVE描述: {result.get('cve_description', 'N/A')[:150]}...")
    print(f"   严重程度: {result.get('severity', 'N/A')}")
    print(f"   引入commit: {result.get('introduced_commit_id', 'N/A')}")
    print(f"   修复commit (mainline): {result.get('fix_commit_id', 'N/A')}")
    
    # 显示所有找到的commits
    all_commits = result.get('all_fix_commits', [])
    if all_commits:
        print(f"\n   找到 {len(all_commits)} 个修复commits:")
        for i, commit in enumerate(all_commits, 1):
            print(f"      {i}. {commit['commit_id'][:12]} (来源: {commit['source']})")
            print(f"         URL: {commit['url']}")
    
    # 测试获取patch内容
    fix_commit = result.get('fix_commit_id')
    if fix_commit:
        print(f"\n" + "-"*80)
        print(f"获取修复补丁的详细内容...")
        print("-"*80)
        
        patch = crawler.get_patch_content(fix_commit[:12], "Mainline")
        
        if patch:
            print(f"✅ 成功获取Patch:")
            print(f"   Commit ID: {patch.get('commit_id', 'N/A')}")
            print(f"   Subject: {patch.get('subject', 'N/A')}")
            print(f"   Author: {patch.get('author', 'N/A')}")
            print(f"   Date: {patch.get('date', 'N/A')}")
            print(f"   修改文件数: {len(patch.get('modified_files', []))}")
            
            if patch.get('modified_files'):
                print(f"   修改的文件:")
                for file in patch['modified_files'][:5]:  # 只显示前5个
                    print(f"      - {file}")
                if len(patch['modified_files']) > 5:
                    print(f"      ... 还有 {len(patch['modified_files']) - 5} 个文件")
            
            # 保存完整patch到文件
            patch_filename = f"patch_{fix_commit[:12]}.txt"
            with open(patch_filename, 'w', encoding='utf-8') as f:
                f.write(patch.get('patch', ''))
            print(f"\n   完整patch已保存到: {patch_filename}")
        else:
            print(f"❌ 获取patch内容失败")
    
    # 保存完整结果到JSON
    result_filename = f"cve_{cve_id.replace('-', '_')}_result.json"
    with open(result_filename, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    print(f"\n   完整结果已保存到: {result_filename}")
    
    return True


def test_multiple_cves():
    """测试多个CVE"""
    # 这些是真实的Linux kernel CVE
    test_cves = [
        "CVE-2024-26633",  # Linux kernel: ip6_tunnel UAF
        "CVE-2024-26642",  # Linux kernel: netfilter NULL pointer
        "CVE-2024-26643",  # Linux kernel: netfilter nf_tables
    ]
    
    print("\n" + "="*80)
    print("批量测试多个CVE")
    print("="*80)
    
    results = []
    
    for cve_id in test_cves:
        success = test_single_cve(cve_id)
        results.append({
            "cve_id": cve_id,
            "success": success
        })
        print("\n" + "-"*80 + "\n")
    
    # 汇总结果
    print("\n" + "="*80)
    print("测试汇总")
    print("="*80)
    
    success_count = sum(1 for r in results if r["success"])
    total_count = len(results)
    
    print(f"总测试数: {total_count}")
    print(f"成功: {success_count}")
    print(f"失败: {total_count - success_count}")
    print(f"成功率: {success_count/total_count*100:.1f}%")
    
    print("\n详细结果:")
    for r in results:
        status = "✅" if r["success"] else "❌"
        print(f"  {status} {r['cve_id']}")


def test_commit_selection():
    """测试多个commits的选择逻辑"""
    print("\n" + "="*80)
    print("测试Mainline Commit选择逻辑")
    print("="*80)
    
    crawler = Crawl_Cve_Patch()
    
    # 模拟多个commits
    test_commits = [
        {
            "commit_id": "abc123def456",
            "url": "https://git.kernel.org/stable/linux.git/commit/?id=abc123",
            "tags": ["patch"],
            "source": "stable"
        },
        {
            "commit_id": "def456ghi789",
            "url": "https://git.kernel.org/torvalds/linux.git/commit/?id=def456",
            "tags": ["patch", "mainline"],
            "source": "mainline"
        },
        {
            "commit_id": "ghi789jkl012",
            "url": "https://github.com/torvalds/linux/commit/ghi789",
            "tags": [],
            "source": "mainline"
        }
    ]
    
    selected = crawler._select_mainline_commit(test_commits, {})
    
    print(f"\n选择的commit: {selected}")
    print(f"预期: def456ghi789 (torvalds仓库且有mainline标签)")
    
    if selected == "def456ghi789":
        print("✅ 选择逻辑正确")
    else:
        print("❌ 选择逻辑可能需要调整")


if __name__ == "__main__":
    import sys
    
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                      CVE补丁获取功能测试                                      ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # 如果命令行提供了CVE ID，只测试该CVE
    if len(sys.argv) > 1:
        cve_id = sys.argv[1]
        test_single_cve(cve_id)
    else:
        # 运行所有测试
        print("运行完整测试套件...\n")
        
        # 测试1: 单个CVE
        test_single_cve("CVE-2024-26633")
        
        # 测试2: commit选择逻辑
        test_commit_selection()
        
        # 测试3: 批量测试（可选，因为会比较慢）
        response = input("\n是否运行批量测试? (y/n): ")
        if response.lower() == 'y':
            test_multiple_cves()
    
    print("\n" + "="*80)
    print("测试完成")
    print("="*80)
