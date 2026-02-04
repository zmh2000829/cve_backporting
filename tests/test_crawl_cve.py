#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试 Crawl_Cve_Patch 类的功能
"""

import sys
import os
# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import sqlite3
from crawl_cve_patch import Crawl_Cve_Patch
from config_loader import ConfigLoader


# 全局变量：存储加载的配置
_config = None


def load_config():
    """加载配置文件"""
    global _config
    if _config is None:
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")
        _config = ConfigLoader.load(config_path)
    return _config


def get_repository_list():
    """获取配置的仓库列表"""
    config = load_config()
    if not config.repositories:
        return []
    return list(config.repositories.keys())


def get_repository_info(repo_name: str):
    """
    获取指定仓库的配置信息
    
    Args:
        repo_name: 仓库名称
        
    Returns:
        包含path, branch, description的字典，如果不存在返回None
    """
    config = load_config()
    return config.repositories.get(repo_name)


def check_cache_exists(repo_version: str = None) -> tuple:
    """
    检查缓存数据库是否存在以及是否有数据
    
    Returns:
        (cache_exists, has_data, commit_count)
    """
    cache_db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "commit_cache.db")
    
    if not os.path.exists(cache_db_path):
        return (False, False, 0)
    
    try:
        conn = sqlite3.connect(cache_db_path)
        cursor = conn.cursor()
        
        if repo_version:
            cursor.execute('SELECT COUNT(*) FROM commits WHERE repo_version = ?', (repo_version,))
        else:
            cursor.execute('SELECT COUNT(*) FROM commits')
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return (True, count > 0, count)
    except Exception as e:
        return (False, False, 0)


def build_cache_for_repo(repo_version: str, max_commits: int = None):
    """
    为指定仓库构建缓存
    
    Args:
        repo_version: 仓库版本名称
        max_commits: 最大缓存的commit数量，None或0表示缓存所有commits
    """
    try:
        from git_repo_manager import GitRepoManager
        
        config = load_config()
        # 传递完整的配置信息（包括path和branch）
        repo_configs = {k: {'path': v['path'], 'branch': v.get('branch')} 
                       for k, v in config.repositories.items()}
        
        manager = GitRepoManager(repo_configs, use_cache=True)
        manager.build_commit_cache(repo_version, max_commits=max_commits)
        
        return True
    except Exception as e:
        print(f"构建缓存失败: {e}")
        import traceback
        traceback.print_exc()
        return False


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
            import os
            output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'output')
            os.makedirs(output_dir, exist_ok=True)
            patch_filename = os.path.join(output_dir, f"patch_{fix_commit[:12]}.txt")
            with open(patch_filename, 'w', encoding='utf-8') as f:
                f.write(patch.get('patch', ''))
            print(f"\n   完整patch已保存到: {patch_filename}")
        else:
            print(f"❌ 获取patch内容失败")
    
    # 保存完整结果到JSON
    import os
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'output')
    os.makedirs(output_dir, exist_ok=True)
    result_filename = os.path.join(output_dir, f"cve_{cve_id.replace('-', '_')}_result.json")
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


def test_mainline_commit_identification():
    """
    测试Mainline Commit识别功能
    
    使用真实的CVE案例验证是否能正确识别mainline commit
    """
    print("\n" + "="*80)
    print("测试Mainline Commit识别功能")
    print("="*80)
    
    crawler = Crawl_Cve_Patch()
    
    # 测试用例1: CVE-2025-40198
    # 这个CVE有7个修复commits，对应不同的内核版本
    # 预期: 8ecb790 应该被识别为mainline commit
    test_cases = [
        {
            "cve_id": "CVE-2025-40198",
            "expected_mainline": "8ecb790ea8c3fc69e77bace57f14cf0d7c177bd8",
            "expected_mainline_version": "6.18",
            "expected_version_mapping": {
                "5.4.301": "7bf46ff83a0ef11836e38ebd72cdc5107209342d",
                "5.10.246": "b2bac84fde28fb6a88817b8b761abda17a1d300b",
                "6.1.158": "e651294218d2684302ee5ed95ccf381646f3e5b4",
                "6.6.114": "01829af7656b56d83682b3491265d583d502e502",
                "6.12.54": "2a0cf438320cdb783e0378570744c0ef0d83e934",
                "6.17.4": "a6e94557cd05adc82fae0400f6e17745563e5412",
                "6.18": "8ecb790ea8c3fc69e77bace57f14cf0d7c177bd8"
            },
            "expected_backports": [
                "7bf46ff83a0ef11836e38ebd72cdc5107209342d",  # 5.4
                "b2bac84fde28fb6a88817b8b761abda17a1d300b",  # 5.10
                "e651294218d2684302ee5ed95ccf381646f3e5b4",  # 6.1
                "01829af7656b56d83682b3491265d583d502e502",  # 6.6
                "2a0cf438320cdb783e0378570744c0ef0d83e934",  # 6.12
                "a6e94557cd05adc82fae0400f6e17745563e5412",  # 6.17
            ]
        }
    ]
    
    for test_case in test_cases:
        cve_id = test_case["cve_id"]
        expected_mainline = test_case["expected_mainline"]
        
        print(f"\n测试CVE: {cve_id}")
        print(f"预期mainline commit: {expected_mainline[:12]}")
        print("-" * 80)
        
        # 获取CVE信息
        result = crawler.get_introduced_fixed_commit(cve_id)
        
        if not result:
            print(f"❌ 获取CVE信息失败")
            continue
        
        # 检查结果
        fix_commit = result.get('fix_commit_id', '')
        mainline_commit = result.get('mainline_commit', '')
        mainline_version = result.get('mainline_version', '')
        version_mapping = result.get('version_commit_mapping', {})
        all_commits = result.get('all_fix_commits', [])
        
        print(f"\n实际结果:")
        print(f"  - 识别的fix_commit_id: {fix_commit[:12] if fix_commit else 'N/A'}")
        print(f"  - 识别的mainline_commit: {mainline_commit[:12] if mainline_commit else 'N/A'}")
        print(f"  - 识别的mainline_version: {mainline_version or 'N/A'}")
        print(f"  - 找到的所有commits数量: {len(all_commits)}")
        
        # 显示版本到commit的映射
        if version_mapping:
            print(f"\n  版本到commit的映射关系:")
            for version in sorted(version_mapping.keys()):
                commit = version_mapping[version]
                is_mainline_marker = " ⭐ [MAINLINE]" if version == mainline_version else ""
                print(f"    {version:15s} → {commit[:12]}{is_mainline_marker}")
        
        # 显示所有commits
        if all_commits:
            print(f"\n  所有修复commits:")
            for i, commit in enumerate(all_commits, 1):
                commit_id = commit.get('commit_id', '')
                source = commit.get('source', 'unknown')
                is_mainline = commit.get('is_mainline', False)
                kernel_version = commit.get('kernel_version', 'unknown')
                is_backport = commit.get('is_backport', False)
                marker = " ⭐ [MAINLINE]" if is_mainline else (" 🔄 [BACKPORT]" if is_backport else "")
                print(f"    {i}. {commit_id[:12]} (版本: {kernel_version}, source: {source}){marker}")
        
        # 验证mainline commit
        print(f"\n验证结果:")
        
        expected_mainline_version = test_case["expected_mainline_version"]
        expected_version_mapping = test_case["expected_version_mapping"]
        
        # 检查1: mainline_commit是否正确
        if mainline_commit.startswith(expected_mainline[:12]):
            print(f"  ✅ mainline_commit正确识别: {mainline_commit[:12]}")
        else:
            print(f"  ❌ mainline_commit错误")
            print(f"     预期: {expected_mainline[:12]}")
            print(f"     实际: {mainline_commit[:12] if mainline_commit else 'N/A'}")
        
        # 检查2: mainline_version是否正确
        if mainline_version == expected_mainline_version:
            print(f"  ✅ mainline_version正确识别: {mainline_version}")
        else:
            print(f"  ❌ mainline_version错误")
            print(f"     预期: {expected_mainline_version}")
            print(f"     实际: {mainline_version or 'N/A'}")
        
        # 检查3: fix_commit_id是否等于mainline_commit
        if fix_commit.startswith(expected_mainline[:12]):
            print(f"  ✅ fix_commit_id正确等于mainline_commit")
        else:
            print(f"  ⚠️  fix_commit_id与mainline_commit不一致")
            print(f"     fix_commit_id: {fix_commit[:12] if fix_commit else 'N/A'}")
            print(f"     mainline_commit: {mainline_commit[:12] if mainline_commit else 'N/A'}")
        
        # 检查4: 版本到commit的映射是否正确
        mapping_correct = 0
        mapping_total = len(expected_version_mapping)
        for version, expected_commit in expected_version_mapping.items():
            actual_commit = version_mapping.get(version, '')
            if actual_commit.startswith(expected_commit[:12]):
                mapping_correct += 1
            else:
                print(f"  ⚠️  版本映射错误: {version}")
                print(f"     预期: {expected_commit[:12]}")
                print(f"     实际: {actual_commit[:12] if actual_commit else 'N/A'}")
        
        if mapping_correct == mapping_total:
            print(f"  ✅ 版本到commit的映射完全正确 ({mapping_correct}/{mapping_total})")
        else:
            print(f"  ⚠️  版本到commit的映射部分正确 ({mapping_correct}/{mapping_total})")
        
        # 检查5: 是否在all_fix_commits中标记了mainline
        mainline_marked = False
        for commit in all_commits:
            if commit.get('commit_id', '').startswith(expected_mainline[:12]):
                if commit.get('is_mainline', False):
                    mainline_marked = True
                    print(f"  ✅ mainline commit在列表中正确标记")
                break
        
        if not mainline_marked:
            print(f"  ⚠️  mainline commit未在列表中标记")
        
        # 检查3: 是否找到了所有backport commits
        found_commits = set(c.get('commit_id', '')[:12] for c in all_commits)
        expected_backports = test_case["expected_backports"]
        
        found_backports = 0
        for expected in expected_backports:
            if expected[:12] in found_commits:
                found_backports += 1
        
        print(f"  📊 找到 {found_backports}/{len(expected_backports)} 个backport commits")
        
        if found_backports == len(expected_backports):
            print(f"  ✅ 所有backport commits都已找到")
        else:
            print(f"  ⚠️  部分backport commits未找到")
            missing = [exp[:12] for exp in expected_backports if exp[:12] not in found_commits]
            if missing:
                print(f"     缺失: {', '.join(missing)}")
        
        # 总体评分
        print(f"\n总体评估:")
        score = 0
        # mainline_commit识别正确 (30分)
        if mainline_commit.startswith(expected_mainline[:12]):
            score += 30
        # mainline_version识别正确 (20分)
        if mainline_version == expected_mainline_version:
            score += 20
        # 版本映射正确 (20分)
        score += int((mapping_correct / mapping_total) * 20)
        # fix_commit_id等于mainline_commit (10分)
        if fix_commit.startswith(expected_mainline[:12]):
            score += 10
        # 标记正确 (10分)
        if mainline_marked:
            score += 10
        # 找到backport commits (10分)
        score += int((found_backports / len(expected_backports)) * 10)
        
        print(f"  得分: {score}/100")
        if score >= 90:
            print(f"  ✅ 优秀")
        elif score >= 70:
            print(f"  ✅ 良好")
        elif score >= 50:
            print(f"  ⚠️  需要改进")
        else:
            print(f"  ❌ 失败")
        
        # 保存详细结果
        import os
        output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'output')
        os.makedirs(output_dir, exist_ok=True)
        result_file = os.path.join(output_dir, f"test_mainline_{cve_id.replace('-', '_')}.json")
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump({
                "cve_id": cve_id,
                "test_case": test_case,
                "result": result,
                "score": score
            }, f, indent=4, ensure_ascii=False)
        print(f"\n  详细结果已保存到: {result_file}")


def test_commit_selection():
    """测试多个commits的选择逻辑"""
    print("\n" + "="*80)
    print("测试Commit选择算法")
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


def test_search_introduced_commit(community_commit_id: str, target_repo_version: str = None):
    """
    测试功能1: 根据社区CVE引入的commit id，查找自维护仓库中的对应commit
    
    Args:
        community_commit_id: 社区引入问题的commit ID
        target_repo_version: 目标仓库版本（如果为None，从配置文件读取第一个仓库）
    """
    print("\n" + "="*80)
    print("测试功能1: 查找自维护仓库中的漏洞引入commit")
    print("="*80)
    
    # 如果未指定仓库，尝试从配置文件读取
    if not target_repo_version:
        repos = get_repository_list()
        if repos:
            target_repo_version = repos[0]
            print(f"使用配置文件中的仓库: {target_repo_version}")
        else:
            print(f"警告: 配置文件中未找到仓库配置，将使用模拟模式")
    
    print(f"\n社区引入commit: {community_commit_id}")
    if target_repo_version:
        repo_info = get_repository_info(target_repo_version)
        if repo_info:
            print(f"目标仓库: {target_repo_version}")
            print(f"  - 路径: {repo_info.get('path', 'N/A')}")
            print(f"  - 分支: {repo_info.get('branch', 'N/A')}")
    print("-" * 80)
    
    crawler = Crawl_Cve_Patch()
    
    # 步骤1: 获取社区commit的详细信息
    print(f"\n[步骤1] 获取社区commit的详细信息...")
    
    # 尝试从CVE API获取完整信息
    patch_info = crawler.get_patch_content(community_commit_id[:12], "Mainline")
    
    if not patch_info or not patch_info.get('subject'):
        print(f"  ⚠️  无法从kernel.org获取，使用基本信息")
        subject = f"commit {community_commit_id[:12]}"
        modified_files = []
        diff_code = ""
    else:
        subject = patch_info.get('subject', '')
        modified_files = patch_info.get('modified_files', [])
        diff_code = patch_info.get('diff_code', '')
    
    print(f"  ✅ Subject: {subject}")
    print(f"  ✅ 修改的文件数: {len(modified_files)}")
    if modified_files:
        print(f"     文件列表:")
        for f in modified_files[:3]:
            print(f"       - {f}")
        if len(modified_files) > 3:
            print(f"       ... 还有 {len(modified_files) - 3} 个文件")
    
    # 步骤2: 在自维护仓库中搜索
    print(f"\n[步骤2] 在自维护仓库中搜索匹配的commit...")
    print("-" * 80)
    
    if not target_repo_version:
        print(f"  ❌ 错误: 未配置目标仓库")
        print(f"  请执行以下步骤:")
        print(f"    1. 复制 config.example.yaml 为 config.yaml")
        print(f"    2. 在 config.yaml 中配置仓库路径和分支")
        print(f"    3. 运行测试时指定仓库版本，或在配置文件中添加仓库")
        print()
        print(f"  可用的Git搜索策略:")
        print(f"    策略1 - 精确匹配commit ID:")
        print(f"      git log --all --format='%H|%s' | grep '{community_commit_id[:12]}'")
        print()
        print(f"    策略2 - 匹配commit subject:")
        print(f"      git log --all --grep='{subject}' --format='%H|%s'")
        print()
        print(f"    策略3 - 匹配backport格式:")
        keywords = [w for w in subject.split() if len(w) > 4 and w.isalnum()]
        if keywords:
            keyword_pattern = '.*'.join(keywords[:3])
            print(f"      git log --all --grep='\\[backport\\].*{keyword_pattern}' --format='%H|%s'")
        print()
        print(f"    策略4 - 基于修改文件:")
        if modified_files:
            print(f"      git log --all --format='%H|%s' -- {' '.join(modified_files[:2])}")
        
    else:
        # 检查缓存是否存在
        cache_exists, has_data, commit_count = check_cache_exists(target_repo_version)
        
        if not cache_exists or not has_data:
            print(f"  ⚠️  警告: 缓存数据库不存在或无数据")
            print(f"  建议先构建缓存以提高搜索效率")
            print()
            
            response = input(f"  是否现在为 {target_repo_version} 构建缓存? (y/n): ").strip().lower()
            if response == 'y':
                max_commits = input(f"  缓存多少个commits? (默认10000): ").strip()
                max_commits = int(max_commits) if max_commits.isdigit() else 10000
                
                print(f"\n  正在构建缓存...")
                if build_cache_for_repo(target_repo_version, max_commits):
                    print(f"  ✅ 缓存构建成功")
                else:
                    print(f"  ❌ 缓存构建失败，将直接查询Git仓库（较慢）")
            else:
                print(f"  跳过缓存构建，将直接查询Git仓库（较慢）")
            print()
        # 实际搜索
        try:
            from git_repo_manager import GitRepoManager
            
            # 加载配置
            config = load_config()
            # 传递完整的配置信息（包括path和branch）
            repo_configs = {k: {'path': v['path'], 'branch': v.get('branch')} 
                           for k, v in config.repositories.items()}
            
            # 检查仓库路径是否存在
            repo_config = config.repositories.get(target_repo_version)
            if not repo_config or not os.path.exists(repo_config.get('path', '')):
                print(f"  ❌ 错误: 仓库路径不存在: {repo_config.get('path', '') if repo_config else 'N/A'}")
                print(f"  请检查 config.yaml 中的配置")
                return {"found": False}
            
            manager = GitRepoManager(repo_configs, use_cache=True)
            
            # 策略1: 精确ID匹配
            print(f"  🔍 策略1: 精确commit ID匹配...")
            exact_match = manager.find_commit_by_id(community_commit_id[:12], target_repo_version)
            
            if exact_match:
                print(f"  ✅ 找到精确匹配:")
                print(f"     Commit: {exact_match['commit_id'][:12]}")
                print(f"     Subject: {exact_match['subject']}")
                print(f"     置信度: 100% (完全匹配)")
                return {
                    "found": True,
                    "strategy": "exact_id",
                    "commit_id": exact_match['commit_id'],
                    "subject": exact_match['subject'],
                    "confidence": 1.0
                }
            else:
                print(f"  未找到精确匹配的commit ID")
            
            # 策略2: Subject模糊匹配
            print(f"\n  🔍 策略2: Subject模糊匹配...")
            keywords = [w for w in subject.split() if len(w) > 4][:5]
            if keywords:
                print(f"     搜索关键词: {', '.join(keywords)}")
                candidates = manager.search_commits_by_keywords(
                    keywords, target_repo_version, limit=20
                )
                
                if candidates:
                    print(f"  找到 {len(candidates)} 个候选:")
                    best_match = None
                    best_similarity = 0.0
                    
                    for i, c in enumerate(candidates[:5], 1):
                        # 计算相似度
                        similarity = calculate_subject_similarity(subject, c.subject)
                        print(f"     {i}. {c.commit_id[:12]} - {c.subject[:60]}...")
                        print(f"        相似度: {similarity:.1%}")
                        
                        if similarity > best_similarity:
                            best_similarity = similarity
                            best_match = c
                    
                    if best_match and best_similarity > 0.8:
                        print(f"\n  ✅ 找到高相似度匹配 (相似度: {best_similarity:.1%})")
                        return {
                            "found": True,
                            "strategy": "subject_match",
                            "commit_id": best_match.commit_id,
                            "subject": best_match.subject,
                            "confidence": best_similarity
                        }
                    else:
                        print(f"  未找到高相似度匹配 (最高相似度: {best_similarity:.1%})")
                else:
                    print(f"  未找到包含关键词的commits")
            
            # 策略3: 文件匹配
            if modified_files:
                print(f"\n  🔍 策略3: 基于修改文件匹配...")
                print(f"     搜索文件: {', '.join(modified_files[:3])}")
                file_commits = manager.search_commits_by_files(
                    modified_files[:3], target_repo_version, limit=50
                )
                
                if file_commits:
                    print(f"  找到 {len(file_commits)} 个修改相同文件的commits")
                    print(f"  提示: 需要进一步通过diff相似度分析确认")
                else:
                    print(f"  未找到修改相同文件的commits")
            
            print(f"\n  ❌ 未找到匹配的commit")
            print(f"  建议:")
            print(f"    1. 检查该commit是否真的存在于目标仓库")
            print(f"    2. 尝试手动使用git命令搜索")
            print(f"    3. 检查是否使用了不同的commit message格式")
            
        except ImportError:
            print(f"  ❌ 错误: 无法导入 git_repo_manager 模块")
            print(f"  请确保 git_repo_manager.py 文件存在")
        except Exception as e:
            print(f"  ⚠️  搜索时出错: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n" + "="*80)
    print(f"测试完成")
    print("="*80)
    
    return {"found": False}


def calculate_subject_similarity(s1: str, s2: str) -> float:
    """计算两个subject的相似度（简单实现）"""
    # 规范化
    s1 = s1.lower().strip()
    s2 = s2.lower().strip()
    
    # 移除backport前缀
    s2 = s2.replace('[backport]', '').strip()
    
    # 简单的词袋模型
    words1 = set(w for w in s1.split() if len(w) > 3)
    words2 = set(w for w in s2.split() if len(w) > 3)
    
    if not words1 or not words2:
        return 0.0
    
    intersection = words1 & words2
    union = words1 | words2
    
    return len(intersection) / len(union)


def test_check_fix_merged(introduced_commit_id: str, 
                          target_repo_version: str = None,
                          cve_id: str = None):
    """
    测试功能2: 根据自维护仓库的漏洞引入commit，分析修复补丁是否已合入
    
    Args:
        introduced_commit_id: 自维护仓库中的漏洞引入commit ID
        target_repo_version: 目标仓库版本（如果为None，从配置文件读取第一个仓库）
        cve_id: CVE ID（如果提供，会自动获取修复补丁信息）
    """
    print("\n" + "="*80)
    print("测试功能2: 检查修复补丁是否已合入")
    print("="*80)
    
    # 如果未指定仓库，尝试从配置文件读取
    if not target_repo_version:
        repos = get_repository_list()
        if repos:
            target_repo_version = repos[0]
            print(f"使用配置文件中的仓库: {target_repo_version}")
        else:
            print(f"警告: 配置文件中未找到仓库配置，将使用模拟模式")
    
    print(f"\n自维护仓库漏洞引入commit: {introduced_commit_id}")
    if cve_id:
        print(f"CVE ID: {cve_id}")
    if target_repo_version:
        repo_info = get_repository_info(target_repo_version)
        if repo_info:
            print(f"目标仓库: {target_repo_version}")
            print(f"  - 路径: {repo_info.get('path', 'N/A')}")
            print(f"  - 分支: {repo_info.get('branch', 'N/A')}")
    print("-" * 80)
    
    crawler = Crawl_Cve_Patch()
    
    # 步骤1: 获取CVE修复补丁信息
    if cve_id:
        print(f"\n[步骤1] 从CVE API获取社区修复补丁信息...")
        
        cve_info = crawler.get_introduced_fixed_commit(cve_id)
        
        if not cve_info:
            print(f"  ❌ 获取CVE信息失败")
            return
        
        mainline_fix_commit = cve_info.get('mainline_commit', '')
        fix_subject = ""
        fix_files = []
        
        if mainline_fix_commit:
            print(f"  ✅ 社区修复commit: {mainline_fix_commit[:12]}")
            print(f"     版本: {cve_info.get('mainline_version', 'N/A')}")
            
            # 获取修复补丁的详细信息
            print(f"\n[步骤2] 获取修复补丁的详细信息...")
            fix_patch = crawler.get_patch_content(mainline_fix_commit[:12], "Mainline")
            
            if fix_patch:
                fix_subject = fix_patch.get('subject', '')
                fix_files = fix_patch.get('modified_files', [])
                print(f"  ✅ Subject: {fix_subject}")
                print(f"  ✅ 修改文件: {len(fix_files)} 个")
                if fix_files:
                    for f in fix_files[:3]:
                        print(f"     - {f}")
    else:
        print(f"\n  ⚠️  未提供CVE ID，需要手动指定修复补丁信息")
        mainline_fix_commit = input("  请输入社区修复commit ID: ").strip()
        
        if not mainline_fix_commit:
            print("  ❌ 未提供修复commit")
            return
        
        fix_patch = crawler.get_patch_content(mainline_fix_commit[:12], "Mainline")
        fix_subject = fix_patch.get('subject', '') if fix_patch else ''
        fix_files = fix_patch.get('modified_files', []) if fix_patch else []
    
    # 步骤3: 在自维护仓库中搜索修复补丁
    print(f"\n[步骤3] 在自维护仓库中搜索修复补丁...")
    print("-" * 80)
    
    if not target_repo_version:
        print(f"  ❌ 错误: 未配置目标仓库")
        print(f"  请执行以下步骤:")
        print(f"    1. 复制 config.example.yaml 为 config.yaml")
        print(f"    2. 在 config.yaml 中配置仓库路径和分支")
        print(f"    3. 运行测试时指定仓库版本")
        print()
        print(f"  可用的Git搜索策略:")
        print(f"    策略1 - 精确匹配修复commit ID:")
        print(f"      git log --all --format='%H|%s' | grep '{mainline_fix_commit[:12]}'")
        print()
        print(f"    策略2 - 匹配修复commit subject:")
        if fix_subject:
            print(f"      git log --all --grep='{fix_subject}' --format='%H|%s'")
        print()
        print(f"    策略3 - 时间范围搜索:")
        print(f"      git log --all --since='{introduced_commit_id}' --format='%H|%s' -- {' '.join(fix_files[:2]) if fix_files else ''}")
        print()
        print(f"    策略4 - 基于Fixes标签:")
        print(f"      git log --all --grep='Fixes:.*{introduced_commit_id[:12]}' --format='%H|%s'")
        
    else:
        # 检查缓存是否存在
        cache_exists, has_data, commit_count = check_cache_exists(target_repo_version)
        
        if not cache_exists or not has_data:
            print(f"  ⚠️  警告: 缓存数据库不存在或无数据")
            print(f"  建议先构建缓存以提高搜索效率")
            print()
            
            response = input(f"  是否现在为 {target_repo_version} 构建缓存? (y/n): ").strip().lower()
            if response == 'y':
                max_commits = input(f"  缓存多少个commits? (默认10000): ").strip()
                max_commits = int(max_commits) if max_commits.isdigit() else 10000
                
                print(f"\n  正在构建缓存...")
                if build_cache_for_repo(target_repo_version, max_commits):
                    print(f"  ✅ 缓存构建成功")
                else:
                    print(f"  ❌ 缓存构建失败，将直接查询Git仓库（较慢）")
            else:
                print(f"  跳过缓存构建，将直接查询Git仓库（较慢）")
            print()
        # 实际搜索
        try:
            from git_repo_manager import GitRepoManager
            
            config = load_config()
            # 传递完整的配置信息（包括path和branch）
            repo_configs = {k: {'path': v['path'], 'branch': v.get('branch')} 
                           for k, v in config.repositories.items()}
            
            # 检查仓库路径是否存在
            repo_config = config.repositories.get(target_repo_version)
            if not repo_config or not os.path.exists(repo_config.get('path', '')):
                print(f"  ❌ 错误: 仓库路径不存在: {repo_config.get('path', '') if repo_config else 'N/A'}")
                print(f"  请检查 config.yaml 中的配置")
                return {"merged": False}
            
            manager = GitRepoManager(repo_configs, use_cache=True)
            
            # 策略1: 精确ID匹配
            print(f"  🔍 策略1: 精确修复commit ID匹配...")
            exact_match = manager.find_commit_by_id(mainline_fix_commit[:12], target_repo_version)
            
            if exact_match:
                print(f"  ✅ 修复补丁已合入!")
                print(f"     Commit: {exact_match['commit_id'][:12]}")
                print(f"     Subject: {exact_match['subject']}")
                print(f"\n  结论: 该CVE已修复，无需进一步action")
                return {
                    "merged": True,
                    "fix_commit": exact_match['commit_id'],
                    "strategy": "exact_id"
                }
            else:
                print(f"  未找到精确匹配的commit ID")
            
            # 策略2: Subject匹配
            print(f"\n  🔍 策略2: Subject模糊匹配...")
            if fix_subject:
                keywords = [w for w in fix_subject.split() if len(w) > 4][:5]
                print(f"     搜索关键词: {', '.join(keywords)}")
                candidates = manager.search_commits_by_keywords(
                    keywords, target_repo_version, limit=20
                )
                
                if candidates:
                    print(f"  找到 {len(candidates)} 个候选修复commits:")
                    best_match = None
                    best_similarity = 0.0
                    
                    for i, c in enumerate(candidates[:5], 1):
                        similarity = calculate_subject_similarity(fix_subject, c.subject)
                        print(f"     {i}. {c.commit_id[:12]} - {c.subject[:60]}...")
                        print(f"        相似度: {similarity:.1%}")
                        
                        if similarity > best_similarity:
                            best_similarity = similarity
                            best_match = c
                    
                    if best_match and best_similarity > 0.85:
                        print(f"\n  ✅ 可能已合入 (高相似度匹配: {best_similarity:.1%})")
                        return {
                            "merged": True,
                            "fix_commit": best_match.commit_id,
                            "confidence": best_similarity,
                            "strategy": "subject_match"
                        }
                    else:
                        print(f"  未找到高相似度匹配 (最高相似度: {best_similarity:.1%})")
                else:
                    print(f"  未找到包含关键词的commits")
            
            # 策略3: Fixes标签
            print(f"\n  🔍 策略3: 搜索Fixes标签...")
            print(f"     搜索模式: Fixes:.*{introduced_commit_id[:12]}")
            fixes_pattern = f"Fixes:.*{introduced_commit_id[:12]}"
            fixes_commits = manager.search_commits_by_keywords(
                [fixes_pattern], target_repo_version, limit=10
            )
            
            if fixes_commits:
                print(f"  ✅ 找到 {len(fixes_commits)} 个包含Fixes标签的commits:")
                for c in fixes_commits[:3]:
                    print(f"     {c.commit_id[:12]} - {c.subject}")
                
                return {
                    "merged": True,
                    "fix_commit": fixes_commits[0].commit_id,
                    "strategy": "fixes_tag"
                }
            else:
                print(f"  未找到包含Fixes标签的commits")
            
            print(f"\n  ❌ 未找到修复补丁")
            print(f"\n  结论: 修复补丁未合入，需要进行依赖分析和合入计划")
            print(f"  建议:")
            print(f"    1. 检查修复补丁是否真的需要合入")
            print(f"    2. 使用 enhanced_cve_analyzer.py 分析依赖")
            print(f"    3. 手动使用git命令验证")
            
        except ImportError:
            print(f"  ❌ 错误: 无法导入 git_repo_manager 模块")
            print(f"  请确保 git_repo_manager.py 文件存在")
        except Exception as e:
            print(f"  ⚠️  搜索时出错: {e}")
            import traceback
            traceback.print_exc()
    
    # 步骤4: 如果未合入，分析依赖
    print(f"\n[步骤4] 分析修复补丁的依赖...")
    print("-" * 80)
    print(f"  ℹ️  依赖分析需要使用 enhanced_cve_analyzer.py")
    print(f"  ℹ️  或手动使用以下命令:")
    print()
    print(f"  # 查看修复commit之前的相关commits")
    print(f"  git log {mainline_fix_commit}~20..{mainline_fix_commit} --oneline -- {' '.join(fix_files[:2]) if fix_files else ''}")
    print()
    
    print(f"\n" + "="*80)
    print(f"测试完成")
    print("="*80)
    
    return {"merged": False}


def test_full_project_logic():
    """
    测试完整的项目逻辑
    
    验证项目能否实现用户描述的完整流程：
    1. 从CVE API获取mainline修复commit
    2. 在自维护仓库查找相同commit id
    3. 如果没找到，查找相似的commit msg（[backport] + 社区msg）
    4. 找到漏洞引入commit
    5. 查找修复补丁是否已合入
    6. 分析前置依赖补丁
    """
    print("\n" + "="*80)
    print("测试完整项目逻辑 - CVE-2025-40198")
    print("="*80)
    
    crawler = Crawl_Cve_Patch()
    cve_id = "CVE-2025-40198"
    
    # ===== 步骤1: 获取CVE信息和mainline commit =====
    print("\n[步骤1] 从CVE API获取信息...")
    print("-" * 80)
    
    result = crawler.get_introduced_fixed_commit(cve_id)
    
    if not result:
        print("❌ 获取CVE信息失败")
        return False
    
    mainline_commit = result.get('mainline_commit', '')
    mainline_version = result.get('mainline_version', '')
    version_mapping = result.get('version_commit_mapping', {})
    introduced_commit = result.get('introduced_commit_id', '')
    
    print(f"✅ 成功获取CVE信息:")
    print(f"   - Mainline修复commit: {mainline_commit[:12]} (版本: {mainline_version})")
    print(f"   - 问题引入commit: {introduced_commit or '未知'}")
    print(f"   - 版本映射数量: {len(version_mapping)}")
    
    # ===== 步骤2: 模拟在自维护仓库查找commit =====
    print(f"\n[步骤2] 在自维护仓库查找commit...")
    print("-" * 80)
    print(f"🔍 查找策略:")
    print(f"   1. 精确匹配commit ID: {mainline_commit[:12]}")
    print(f"   2. 模糊匹配commit subject")
    print(f"   3. 匹配 [backport] + 社区commit msg")
    
    # 获取mainline commit的详细信息
    patch_info = crawler.get_patch_content(mainline_commit[:12], "Mainline")
    
    if patch_info:
        subject = patch_info.get('subject', '')
        print(f"\n   原始subject: {subject}")
        print(f"   可能的backport subject: [backport] {subject}")
        print(f"   修改的文件: {patch_info.get('modified_files', [])}")
    
    print(f"\n   ℹ️  注意: 实际的仓库查找需要GitRepoManager实现")
    print(f"   ℹ️  查找逻辑已在 enhanced_cve_analyzer.py 中实现")
    
    # ===== 步骤3: 验证版本映射关系 =====
    print(f"\n[步骤3] 验证版本到commit的映射关系...")
    print("-" * 80)
    
    if version_mapping:
        print(f"✅ 成功建立版本映射关系:")
        for version in sorted(version_mapping.keys()):
            commit = version_mapping[version]
            is_mainline = (version == mainline_version)
            marker = " ⭐ [MAINLINE]" if is_mainline else " 🔄 [BACKPORT]"
            print(f"   {version:15s} → {commit[:12]}{marker}")
    else:
        print(f"❌ 未找到版本映射")
        return False
    
    # ===== 步骤4: 分析依赖补丁（模拟）=====
    print(f"\n[步骤4] 分析前置依赖补丁...")
    print("-" * 80)
    print(f"   ℹ️  依赖分析功能在 enhanced_cve_analyzer.py 中实现")
    print(f"   ℹ️  需要调用 analyze_cve_patch_enhanced() 方法")
    print(f"   ℹ️  该方法会:")
    print(f"      - 获取修复补丁的依赖列表")
    print(f"      - 在目标仓库中搜索每个依赖补丁")
    print(f"      - 标识哪些已合入、哪些还需合入")
    
    # ===== 总结 =====
    print(f"\n" + "="*80)
    print(f"项目逻辑验证总结")
    print("="*80)
    
    checks = [
        ("✅ 从CVE API获取信息", True),
        ("✅ 识别mainline commit", bool(mainline_commit)),
        ("✅ 建立版本到commit的映射", len(version_mapping) > 0),
        ("✅ 获取commit详细信息（subject, diff等）", bool(patch_info)),
        ("⚠️  在自维护仓库查找commit（需要GitRepoManager）", None),
        ("⚠️  查找相似commit msg（[backport] + 社区msg）", None),
        ("⚠️  分析前置依赖补丁（需要完整环境）", None),
    ]
    
    print(f"\n功能检查清单:")
    for check, status in checks:
        if status is True:
            print(f"  {check}")
        elif status is False:
            print(f"  ❌ {check} - 失败")
        else:
            print(f"  {check}")
    
    print(f"\n结论:")
    print(f"  ✅ 核心逻辑已实现: CVE信息获取、mainline识别、版本映射")
    print(f"  ✅ 高级功能已设计: commit搜索、依赖分析（enhanced_cve_analyzer.py）")
    print(f"  ⚠️  完整测试需要: GitRepoManager + 实际的kernel仓库")
    
    # 保存测试结果
    test_result = {
        "cve_id": cve_id,
        "mainline_commit": mainline_commit,
        "mainline_version": mainline_version,
        "version_mapping": version_mapping,
        "introduced_commit": introduced_commit,
        "patch_info": {
            "subject": patch_info.get('subject', '') if patch_info else '',
            "modified_files": patch_info.get('modified_files', []) if patch_info else []
        }
    }
    
    import os
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'output')
    os.makedirs(output_dir, exist_ok=True)
    result_file = os.path.join(output_dir, f"test_full_logic_{cve_id.replace('-', '_')}.json")
    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump(test_result, f, indent=4, ensure_ascii=False)
    print(f"\n  测试结果已保存到: {result_file}")
    
    return True


if __name__ == "__main__":
    import sys
    
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                      CVE补丁获取功能测试                                      ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # 显示配置的仓库信息和缓存状态
    repos = get_repository_list()
    if repos:
        print("配置的仓库:")
        has_uncached = False
        for repo_name in repos:
            repo_info = get_repository_info(repo_name)
            print(f"  - {repo_name}")
            if repo_info:
                print(f"      路径: {repo_info.get('path', 'N/A')}")
                print(f"      分支: {repo_info.get('branch', 'N/A')}")
                if 'description' in repo_info:
                    print(f"      说明: {repo_info['description']}")
                
                # 检查缓存状态
                cache_exists, has_data, commit_count = check_cache_exists(repo_name)
                if has_data:
                    print(f"      缓存: ✅ 已缓存 {commit_count} 个commits")
                else:
                    print(f"      缓存: ⚠️  未构建 (建议执行: python test_crawl_cve.py build-cache {repo_name})")
                    has_uncached = True
        print()
        
        if has_uncached:
            print("💡 提示: 首次使用建议先构建缓存，可大幅提高搜索效率")
            print("   命令: python test_crawl_cve.py build-cache <repo_name> [max_commits|all]")
            print("   示例: python test_crawl_cve.py build-cache 5.10-hulk all  # 缓存所有commits")
            print()
    else:
        print("⚠️  未找到配置的仓库")
        print("   请复制 config.example.yaml 为 config.yaml 并配置仓库信息\n")
    
    # 如果命令行提供了参数，执行对应的测试
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        
        if cmd == "mainline":
            # 特殊命令：只测试mainline识别
            test_mainline_commit_identification()
            
        elif cmd == "full":
            # 特殊命令：测试完整项目逻辑
            test_full_project_logic()
            
        elif cmd == "search_introduced":
            # 新功能1：查找自维护仓库中的漏洞引入commit
            if len(sys.argv) < 3:
                print("用法: python test_crawl_cve.py search_introduced <community_commit_id> [target_repo_version]")
                print("示例: python test_crawl_cve.py search_introduced 8b67f04ab9de 5.10-hulk")
                print()
                repos = get_repository_list()
                if repos:
                    print("可用的仓库版本:")
                    for r in repos:
                        print(f"  - {r}")
                else:
                    print("提示: 请先配置 config.yaml 中的仓库信息")
            else:
                community_commit = sys.argv[2]
                target_repo = sys.argv[3] if len(sys.argv) > 3 else None
                test_search_introduced_commit(community_commit, target_repo)
                
        elif cmd == "check_fix":
            # 新功能2：检查修复补丁是否已合入
            if len(sys.argv) < 3:
                print("用法: python test_crawl_cve.py check_fix <introduced_commit_id> [target_repo_version] [cve_id]")
                print("示例1: python test_crawl_cve.py check_fix abc123def456 5.10-hulk CVE-2025-40198")
                print("示例2: python test_crawl_cve.py check_fix abc123def456")
                print()
                repos = get_repository_list()
                if repos:
                    print("可用的仓库版本:")
                    for r in repos:
                        print(f"  - {r}")
                else:
                    print("提示: 请先配置 config.yaml 中的仓库信息")
            else:
                introduced_commit = sys.argv[2]
                target_repo = sys.argv[3] if len(sys.argv) > 3 else None
                cve_id = sys.argv[4] if len(sys.argv) > 4 else None
                test_check_fix_merged(introduced_commit, target_repo, cve_id)
                
        elif cmd == "repos" or cmd == "list-repos":
            # 列出配置的仓库
            repos = get_repository_list()
            if repos:
                print("\n配置的仓库列表:")
                print("=" * 80)
                for repo_name in repos:
                    repo_info = get_repository_info(repo_name)
                    print(f"\n仓库: {repo_name}")
                    if repo_info:
                        print(f"  路径: {repo_info.get('path', 'N/A')}")
                        print(f"  分支: {repo_info.get('branch', 'N/A')}")
                        if 'description' in repo_info:
                            print(f"  说明: {repo_info['description']}")
                        # 检查路径是否存在
                        repo_path = repo_info.get('path', '')
                        if os.path.exists(repo_path):
                            print(f"  状态: ✅ 路径存在")
                            # 检查缓存状态
                            cache_exists, has_data, commit_count = check_cache_exists(repo_name)
                            if has_data:
                                print(f"  缓存: ✅ 已缓存 {commit_count} 个commits")
                            else:
                                print(f"  缓存: ⚠️  未构建缓存")
                        else:
                            print(f"  状态: ❌ 路径不存在")
            else:
                print("\n⚠️  未找到配置的仓库")
                print("提示: 请复制 config.example.yaml 为 config.yaml 并填写仓库配置")
            
        elif cmd == "build-cache":
            # 构建缓存
            if len(sys.argv) < 3:
                print("用法: python test_crawl_cve.py build-cache <repo_version> [max_commits|all]")
                print("示例: python test_crawl_cve.py build-cache 5.10-hulk 10000")
                print("示例: python test_crawl_cve.py build-cache 5.10-hulk all  # 缓存所有commits")
                print()
                repos = get_repository_list()
                if repos:
                    print("可用的仓库版本:")
                    for r in repos:
                        print(f"  - {r}")
                else:
                    print("提示: 请先配置 config.yaml 中的仓库信息")
            else:
                repo_version = sys.argv[2]
                
                # 解析 max_commits 参数：支持数字或 "all"
                max_commits_arg = sys.argv[3] if len(sys.argv) > 3 else "all"
                if max_commits_arg.lower() == "all" or max_commits_arg == "0":
                    max_commits = None  # None 表示获取所有commits
                    commits_desc = "全部"
                else:
                    max_commits = int(max_commits_arg)
                    commits_desc = str(max_commits)
                
                print(f"\n为 {repo_version} 构建缓存...")
                print(f"缓存commits数: {commits_desc}")
                print("-" * 80)
                
                if build_cache_for_repo(repo_version, max_commits):
                    print("\n✅ 缓存构建成功")
                    cache_exists, has_data, commit_count = check_cache_exists(repo_version)
                    print(f"已缓存 {commit_count} 个commits")
                else:
                    print("\n❌ 缓存构建失败")
            
        elif cmd == "CVE-2025-40198":
            # 特殊CVE：运行完整的mainline测试和项目逻辑测试
            print("\n🎯 针对 CVE-2025-40198 运行完整测试套件\n")
            test_mainline_commit_identification()
            print("\n" + "="*80 + "\n")
            test_full_project_logic()
            
        elif cmd.startswith("CVE-"):
            # 普通CVE测试
            test_single_cve(cmd)
            
        else:
            print(f"未知命令: {cmd}")
            print("\n可用命令:")
            print("  python test_crawl_cve.py repos                            # 列出配置的仓库")
            print("  python test_crawl_cve.py build-cache <repo> [max|all]     # 构建commit缓存")
            print("  python test_crawl_cve.py mainline                         # 测试mainline识别")
            print("  python test_crawl_cve.py full                             # 测试完整项目逻辑")
            print("  python test_crawl_cve.py CVE-XXXX-XXXXX                   # 测试单个CVE")
            print("  python test_crawl_cve.py search_introduced <commit> [repo]")
            print("  python test_crawl_cve.py check_fix <commit> [repo] [cve_id]")
            print("\n重要提示:")
            print("  首次使用前，请先执行 build-cache 命令构建缓存，以提高搜索效率。")
            print("  示例: python test_crawl_cve.py build-cache 5.10-hulk all    # 缓存所有commits")
            print("  示例: python test_crawl_cve.py build-cache 5.10-hulk 10000  # 缓存最近10000个")
    else:
        # 运行所有测试
        print("运行完整测试套件...\n")
        
        # 测试1: Mainline Commit识别（最重要的新功能）
        print("\n" + "🔑 " + "="*76)
        print("🔑  核心功能测试：Mainline Commit智能识别")
        print("🔑 " + "="*76)
        test_mainline_commit_identification()
        
        # 测试2: 单个CVE基础功能
        print("\n" + "="*80)
        print("基础功能测试")
        print("="*80)
        test_single_cve("CVE-2024-26633")
        
        # 测试3: 完整项目逻辑
        print("\n" + "="*80)
        print("完整项目逻辑测试")
        print("="*80)
        test_full_project_logic()
        
        # 测试4: commit选择算法
        test_commit_selection()
        
        # 测试5: 批量测试（可选，因为会比较慢）
        response = input("\n是否运行批量测试? (y/n): ")
        if response.lower() == 'y':
            test_multiple_cves()
    
    print("\n" + "="*80)
    print("测试完成")
    print("="*80)
