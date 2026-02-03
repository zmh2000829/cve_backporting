#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证分支配置是否正确

检查：
1. config.yaml中是否配置了branch
2. 分支是否存在于仓库
3. GitRepoManager是否正确使用新格式
"""

import os
import sys
import subprocess
from config_loader import ConfigLoader


def check_config_has_branch(config):
    """检查配置中是否有branch字段"""
    print("\n" + "="*80)
    print("检查1: 配置文件中的分支配置")
    print("="*80)
    
    all_have_branch = True
    
    for repo_name, repo_config in config.repositories.items():
        branch = repo_config.get('branch')
        path = repo_config.get('path')
        
        print(f"\n仓库: {repo_name}")
        print(f"  路径: {path}")
        
        if branch:
            print(f"  分支: {branch} ✅")
        else:
            print(f"  分支: 未配置 ❌")
            all_have_branch = False
    
    return all_have_branch


def check_branch_exists_in_repo(config):
    """检查配置的分支是否存在于仓库"""
    print("\n" + "="*80)
    print("检查2: 分支是否存在于仓库")
    print("="*80)
    
    all_branches_exist = True
    
    for repo_name, repo_config in config.repositories.items():
        branch = repo_config.get('branch')
        path = repo_config.get('path')
        
        print(f"\n仓库: {repo_name}")
        
        if not path or not os.path.exists(path):
            print(f"  ⚠️  仓库路径不存在: {path}")
            all_branches_exist = False
            continue
        
        if not branch:
            print(f"  ⚠️  未配置分支")
            all_branches_exist = False
            continue
        
        try:
            # 检查分支是否存在
            result = subprocess.run(
                ["git", "branch", "-a"],
                cwd=path,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                branches = result.stdout
                # 检查分支名是否在输出中
                if branch in branches:
                    print(f"  分支 '{branch}' 存在 ✅")
                else:
                    print(f"  分支 '{branch}' 不存在 ❌")
                    print(f"  可用分支:")
                    for line in branches.split('\n')[:10]:
                        if line.strip():
                            print(f"    {line.strip()}")
                    all_branches_exist = False
            else:
                print(f"  ❌ 无法列出分支: {result.stderr}")
                all_branches_exist = False
                
        except Exception as e:
            print(f"  ❌ 检查分支时出错: {e}")
            all_branches_exist = False
    
    return all_branches_exist


def check_cache_db():
    """检查缓存数据库是否存在"""
    print("\n" + "="*80)
    print("检查3: 缓存数据库状态")
    print("="*80)
    
    cache_db = "commit_cache.db"
    
    if os.path.exists(cache_db):
        print(f"\n缓存数据库存在: {cache_db}")
        
        # 检查缓存数据
        try:
            import sqlite3
            conn = sqlite3.connect(cache_db)
            cursor = conn.cursor()
            
            cursor.execute("SELECT repo_version, COUNT(*) FROM commits GROUP BY repo_version")
            rows = cursor.fetchall()
            
            if rows:
                print(f"\n缓存统计:")
                for repo_version, count in rows:
                    print(f"  {repo_version}: {count} commits")
                
                print(f"\n⚠️  建议: 删除旧缓存并重新构建（使用新的分支限定）")
                print(f"  命令: rm {cache_db}")
                print(f"  然后: python tests/test_crawl_cve.py build-cache <repo_version> 10000")
            else:
                print(f"\n缓存数据库为空")
            
            conn.close()
        except Exception as e:
            print(f"\n❌ 读取缓存数据库失败: {e}")
    else:
        print(f"\n缓存数据库不存在: {cache_db}")
        print(f"✅ 这是好的，因为需要用新格式重新构建缓存")


def test_git_log_command(config):
    """测试git log命令（带分支限定）"""
    print("\n" + "="*80)
    print("检查4: 测试Git命令（带分支限定）")
    print("="*80)
    
    for repo_name, repo_config in config.repositories.items():
        branch = repo_config.get('branch')
        path = repo_config.get('path')
        
        print(f"\n仓库: {repo_name}")
        
        if not path or not os.path.exists(path):
            print(f"  ⚠️  仓库路径不存在")
            continue
        
        if not branch:
            print(f"  ⚠️  未配置分支")
            continue
        
        try:
            # 测试命令：git log <branch> --max-count=1
            cmd = ["git", "log", branch, "--max-count=1", "--format=%H|%s"]
            
            print(f"  测试命令: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                cwd=path,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                if lines:
                    parts = lines[0].split('|', 1)
                    commit_id = parts[0][:12] if parts else "unknown"
                    subject = parts[1] if len(parts) > 1 else "unknown"
                    
                    print(f"  ✅ 成功获取分支上的commit:")
                    print(f"     Commit: {commit_id}")
                    print(f"     Subject: {subject[:60]}...")
            else:
                print(f"  ❌ 命令执行失败: {result.stderr}")
                
        except Exception as e:
            print(f"  ❌ 测试命令时出错: {e}")


def main():
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                    分支配置验证工具                                           ║
║                                                                            ║
║  验证基于分支的搜索和缓存配置是否正确                                          ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # 加载配置
    try:
        config = ConfigLoader.load("config.yaml")
    except Exception as e:
        print(f"❌ 加载配置文件失败: {e}")
        print(f"请确保 config.yaml 文件存在")
        return 1
    
    if not config.repositories:
        print("❌ 配置文件中没有仓库配置")
        return 1
    
    # 执行检查
    check1 = check_config_has_branch(config)
    check2 = check_branch_exists_in_repo(config)
    check_cache_db()
    test_git_log_command(config)
    
    # 总结
    print("\n" + "="*80)
    print("验证总结")
    print("="*80)
    
    issues = []
    
    if not check1:
        issues.append("⚠️  部分仓库未配置branch字段")
    
    if not check2:
        issues.append("⚠️  部分配置的分支不存在于仓库")
    
    if issues:
        print("\n发现以下问题:")
        for issue in issues:
            print(f"  {issue}")
        
        print("\n建议:")
        print("  1. 在 config.yaml 中为每个仓库添加 'branch' 字段")
        print("  2. 确保分支名称正确且存在于仓库中")
        print("  3. 删除旧的缓存数据库: rm commit_cache.db")
        print("  4. 重新构建缓存: python tests/test_crawl_cve.py build-cache <repo_version> 10000")
        print()
        print("详细文档: docs/BRANCH_BASED_SEARCH.md")
        
        return 1
    else:
        print("\n✅ 所有检查通过!")
        print("\n下一步:")
        print("  1. 删除旧缓存（如果存在）: rm commit_cache.db")
        print("  2. 重新构建缓存: python tests/test_crawl_cve.py build-cache <repo_version> 10000")
        print("  3. 测试搜索: python tests/test_crawl_cve.py search_introduced <commit_id> <repo_version>")
        print()
        print("详细文档: docs/BRANCH_BASED_SEARCH.md")
        
        return 0


if __name__ == "__main__":
    sys.exit(main())
