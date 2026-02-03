#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强的CVE补丁分析器 - 主函数
整合所有增强功能
"""

import json
import time
from typing import Dict, List, Optional
from enhanced_patch_matcher import (
    CommitInfo, CommitMatcher, DependencyAnalyzer,
    PatchBackportAnalyzer, generate_analysis_report
)


class EnhancedCVEAnalyzer:
    """
    增强的CVE分析器
    """
    
    def __init__(self, crawl_cve_patch, ai_analyze, git_repo_manager):
        self.crawl_cve_patch = crawl_cve_patch
        self.ai_analyze = ai_analyze
        self.git_repo_manager = git_repo_manager  # 用于操作目标git仓库
        self.patch_analyzer = PatchBackportAnalyzer(crawl_cve_patch, ai_analyze)
        self.commit_matcher = CommitMatcher()
    
    def get_target_repo_commits(self, 
                               target_version: str,
                               time_window: Optional[tuple] = None,
                               file_paths: Optional[List[str]] = None,
                               limit: int = 1000) -> List[CommitInfo]:
        """
        从目标仓库获取候选commits
        
        Args:
            target_version: 目标内核版本
            time_window: (start_ts, end_ts) 时间窗口
            file_paths: 要关注的文件路径列表
            limit: 最大返回数量
        """
        commits = []
        
        # 方法1: 通过git log获取
        # 构建git log命令
        cmd_parts = ["git", "log", f"--max-count={limit}", "--format=%H|%s|%at|%an"]
        
        if time_window:
            start_ts, end_ts = time_window
            cmd_parts.append(f"--since={start_ts}")
            cmd_parts.append(f"--until={end_ts}")
        
        if file_paths:
            cmd_parts.append("--")
            cmd_parts.extend(file_paths)
        
        # 执行git命令（需要实现具体的执行逻辑）
        # git_output = self.git_repo_manager.execute_git_command(cmd_parts, target_version)
        
        # 方法2: 如果你有数据库，直接查询
        # commits = self.git_repo_manager.query_commits_from_db(
        #     version=target_version,
        #     time_window=time_window,
        #     file_paths=file_paths,
        #     limit=limit
        # )
        
        # 暂时返回空列表，你需要实现具体的获取逻辑
        return commits
    
    def search_commit_with_multiple_strategies(self,
                                               source_commit_id: str,
                                               source_subject: str,
                                               source_diff: str,
                                               target_version: str) -> Dict:
        """
        使用多种策略搜索commit
        """
        # 构建源commit信息
        source_commit = CommitInfo(
            commit_id=source_commit_id,
            subject=source_subject,
            commit_msg="",
            diff_code=source_diff,
            modified_files=self.commit_matcher.extract_modified_files(source_diff),
            modified_functions=self.commit_matcher.extract_modified_functions(source_diff)
        )
        
        # 策略1: 精确commit ID查找（最快）
        print(f"[策略1] 精确查找commit ID: {source_commit_id[:12]}")
        exact_match = self.git_repo_manager.find_commit_by_id(source_commit_id[:12], target_version)
        if exact_match:
            return {
                "found": True,
                "strategy": "exact_commit_id",
                "confidence": 1.0,
                "target_commit": exact_match["commit_id"],
                "target_subject": exact_match.get("subject", "")
            }
        
        # 策略2: 基于subject的模糊搜索（快速）
        print(f"[策略2] 基于subject模糊搜索")
        # 先搜索包含关键词的commits
        keywords = self.extract_keywords_from_subject(source_subject)
        candidate_commits = self.git_repo_manager.search_commits_by_keywords(
            keywords, target_version, limit=100
        )
        
        if candidate_commits:
            matches = self.commit_matcher.match_by_subject(
                source_commit, candidate_commits, threshold=0.80
            )
            if matches and matches[0].confidence > 0.85:
                return {
                    "found": True,
                    "strategy": "subject_match",
                    "confidence": matches[0].confidence,
                    "target_commit": matches[0].target_commit,
                    "all_candidates": [
                        {
                            "commit": m.target_commit,
                            "confidence": m.confidence,
                            "details": m.details
                        }
                        for m in matches[:5]
                    ]
                }
        
        # 策略3: 基于修改文件的搜索（中速）
        print(f"[策略3] 基于修改文件搜索")
        if source_commit.modified_files:
            # 搜索修改了相同文件的commits
            file_based_commits = self.git_repo_manager.search_commits_by_files(
                source_commit.modified_files, target_version, limit=200
            )
            
            if file_based_commits:
                # 同时用subject和diff匹配
                subject_matches = self.commit_matcher.match_by_subject(
                    source_commit, file_based_commits, threshold=0.75
                )
                diff_matches = self.commit_matcher.match_by_diff(
                    source_commit, file_based_commits, threshold=0.65
                )
                
                # 合并结果
                all_matches = {}
                for match in subject_matches + diff_matches:
                    if match.target_commit not in all_matches or \
                       match.confidence > all_matches[match.target_commit].confidence:
                        all_matches[match.target_commit] = match
                
                sorted_matches = sorted(all_matches.values(), 
                                       key=lambda x: x.confidence, reverse=True)
                
                if sorted_matches and sorted_matches[0].confidence > 0.70:
                    return {
                        "found": True,
                        "strategy": "file_and_code_match",
                        "confidence": sorted_matches[0].confidence,
                        "target_commit": sorted_matches[0].target_commit,
                        "all_candidates": [
                            {
                                "commit": m.target_commit,
                                "confidence": m.confidence,
                                "match_type": m.match_type,
                                "details": m.details
                            }
                            for m in sorted_matches[:5]
                        ]
                    }
        
        # 策略4: 时间窗口 + 作者搜索（慢速，最后手段）
        print(f"[策略4] 时间窗口 + 全局搜索")
        # 假设回合时间不会超过±6个月
        # 这一步比较慢，只在前面策略都失败时使用
        
        return {
            "found": False,
            "strategy": "none",
            "confidence": 0.0,
            "message": "未找到匹配的commit"
        }
    
    def extract_keywords_from_subject(self, subject: str) -> List[str]:
        """
        从subject中提取关键词用于搜索
        """
        import re
        
        # 标准化
        normalized = self.commit_matcher.normalize_subject(subject)
        
        # 移除常见的停用词
        stopwords = {'a', 'an', 'the', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        
        # 分词并过滤
        words = re.findall(r'\w+', normalized)
        keywords = [w for w in words if len(w) > 3 and w not in stopwords]
        
        # 取前5个最重要的关键词
        return keywords[:5]
    
    def analyze_cve_patch_enhanced(self, cve_id: str, target_kernel_version: str) -> Dict:
        """
        增强版CVE补丁分析主函数
        """
        start_time = time.time()
        
        analysis_result = {
            "vuln_id": cve_id,
            "kernel_version": target_kernel_version,
            "introduced_commit_analysis": {},
            "fix_commit_analysis": {},
            "dependency_analysis": {},
            "recommendations": []
        }
        
        print(f"\n{'='*80}")
        print(f"开始分析 CVE: {cve_id}, 目标版本: {target_kernel_version}")
        print(f"{'='*80}\n")
        
        # ===== 步骤0: 获取CVE信息 =====
        print(f"[步骤0] 从CVE API获取补丁信息...")
        cve_patch_info = self.crawl_cve_patch.get_introduced_fixed_commit(cve_id)
        
        if not cve_patch_info or not cve_patch_info.get("fix_commit_id"):
            return {
                "code": 1,
                "msg": f"CVE {cve_id} 未找到修复补丁信息",
                "data": analysis_result
            }
        
        introduced_commit = cve_patch_info.get("introduced_commit_id")
        fix_commit = cve_patch_info["fix_commit_id"]
        
        print(f"  - 引入问题的commit: {introduced_commit or '未知'}")
        print(f"  - 修复补丁commit: {fix_commit}")
        
        # ===== 步骤1: 分析引入问题的commit（如果存在）=====
        if introduced_commit:
            print(f"\n[步骤1] 分析问题引入commit: {introduced_commit}")
            
            # 获取社区引入commit的详细信息
            intro_patch_content = self.crawl_cve_patch.get_patch_content(
                introduced_commit, kernel_version="Stable"
            )
            
            # 在目标仓库中搜索
            intro_search_result = self.search_commit_with_multiple_strategies(
                source_commit_id=introduced_commit,
                source_subject=intro_patch_content.get("subject", ""),
                source_diff=intro_patch_content.get("diff_code", ""),
                target_version=target_kernel_version
            )
            
            analysis_result["introduced_commit_analysis"] = {
                "community_commit": introduced_commit,
                "community_subject": intro_patch_content.get("subject", ""),
                "search_result": intro_search_result
            }
            
            if intro_search_result["found"]:
                print(f"  ✓ 找到匹配: {intro_search_result['target_commit']}")
                print(f"    置信度: {intro_search_result['confidence']:.2%}")
                print(f"    匹配策略: {intro_search_result['strategy']}")
                analysis_result["recommendations"].append(
                    f"目标仓库包含问题引入commit {intro_search_result['target_commit']}, "
                    f"需要合入修复补丁"
                )
            else:
                print(f"  ✗ 未找到匹配的commit")
                analysis_result["recommendations"].append(
                    f"目标仓库中未找到问题引入commit的匹配, 可能不受此CVE影响, "
                    f"或需要人工确认"
                )
        
        # ===== 步骤2: 分析修复补丁 =====
        print(f"\n[步骤2] 分析修复补丁: {fix_commit}")
        
        fix_patch_content = self.crawl_cve_patch.get_patch_content(
            fix_commit, kernel_version="Stable"
        )
        
        if not fix_patch_content.get("patch"):
            return {
                "code": 1,
                "msg": f"无法获取修复补丁 {fix_commit} 的内容",
                "data": analysis_result
            }
        
        # AI分析补丁内容
        print(f"  - 使用AI分析补丁内容...")
        fix_ai_analysis = self.ai_analyze.analyze_patch(
            fix_patch_content["patch"], cve_id
        )
        
        # 在目标仓库中搜索修复补丁
        print(f"  - 在目标仓库中搜索修复补丁...")
        fix_search_result = self.search_commit_with_multiple_strategies(
            source_commit_id=fix_commit,
            source_subject=fix_patch_content.get("subject", ""),
            source_diff=fix_patch_content.get("diff_code", ""),
            target_version=target_kernel_version
        )
        
        analysis_result["fix_commit_analysis"] = {
            "community_commit": fix_commit,
            "community_subject": fix_patch_content.get("subject", ""),
            "patch_content": fix_patch_content.get("patch", ""),
            "ai_analysis": fix_ai_analysis.get("choices", [{}])[0].get("message", {}).get("content", ""),
            "search_result": fix_search_result,
            "modified_files": self.commit_matcher.extract_modified_files(
                fix_patch_content.get("diff_code", "")
            )
        }
        
        if fix_search_result["found"]:
            print(f"  ✓ 修复补丁已合入: {fix_search_result['target_commit']}")
            print(f"    置信度: {fix_search_result['confidence']:.2%}")
            analysis_result["recommendations"].append(
                f"修复补丁可能已合入目标仓库 (commit: {fix_search_result['target_commit']}), "
                f"建议人工确认"
            )
            
            # 如果已合入，任务基本完成
            end_time = time.time()
            analysis_result["duration"] = end_time - start_time
            analysis_result["code"] = 0
            return analysis_result
        else:
            print(f"  ✗ 修复补丁未合入目标仓库")
            analysis_result["recommendations"].append(
                f"修复补丁未合入，需要分析依赖并准备回合"
            )
        
        # ===== 步骤3: 分析依赖补丁 =====
        print(f"\n[步骤3] 分析修复补丁的依赖...")
        
        # 获取社区依赖补丁列表
        dep_params = {"fix_commit": fix_commit}
        if introduced_commit:
            dep_params["issue_commit"] = introduced_commit
        
        print(f"  - 从社区获取相关补丁...")
        associated_patch_info = self.crawl_cve_patch.analyze_fix_deps_commit(dep_params)
        
        # 解析依赖补丁列表
        dep_commits = []
        for line in associated_patch_info.get("dep_post_patch", "").split("\n"):
            if line.strip():
                commit_id = line.strip().split()[0]
                dep_commits.append(commit_id)
        
        for line in associated_patch_info.get("fix_post_patch", "").split("\n"):
            if line.strip():
                commit_id = line.strip().split()[0]
                if commit_id not in dep_commits:
                    dep_commits.append(commit_id)
        
        print(f"  - 找到 {len(dep_commits)} 个相关补丁")
        
        # 分析每个依赖补丁
        dependency_details = {}
        for idx, dep_commit in enumerate(dep_commits, 1):
            print(f"\n  [{idx}/{len(dep_commits)}] 分析依赖补丁: {dep_commit}")
            
            # 获取依赖补丁内容
            dep_patch_content = self.crawl_cve_patch.get_patch_content(
                dep_commit, kernel_version="Stable"
            )
            
            if not dep_patch_content.get("patch"):
                print(f"    ⚠ 无法获取补丁内容，跳过")
                continue
            
            # AI分析依赖关系
            print(f"    - AI分析依赖关系...")
            dep_ai_analysis = self.ai_analyze.analyze_patch_dependencies(
                fix_commit[:12],
                fix_patch_content,
                dep_commit[:12],
                dep_patch_content["patch"],
                cve_id
            )
            
            # 在目标仓库中搜索
            print(f"    - 在目标仓库中搜索...")
            dep_search_result = self.search_commit_with_multiple_strategies(
                source_commit_id=dep_commit,
                source_subject=dep_patch_content.get("subject", ""),
                source_diff=dep_patch_content.get("diff_code", ""),
                target_version=target_kernel_version
            )
            
            dependency_details[dep_commit] = {
                "community_subject": dep_patch_content.get("subject", ""),
                "patch_content": dep_patch_content.get("patch", ""),
                "ai_dependency_analysis": dep_ai_analysis.get("choices", [{}])[0].get("message", {}).get("content", ""),
                "search_result": dep_search_result,
                "is_merged": dep_search_result["found"] and dep_search_result["confidence"] > 0.80
            }
            
            if dep_search_result["found"]:
                print(f"    ✓ 已合入: {dep_search_result['target_commit']} "
                      f"(置信度: {dep_search_result['confidence']:.2%})")
            else:
                print(f"    ✗ 未合入，需要回合")
        
        analysis_result["dependency_analysis"]["dependencies"] = dependency_details
        
        # ===== 步骤4: 生成回合建议 =====
        print(f"\n[步骤4] 生成回合建议...")
        
        # 统计需要合入的补丁
        not_merged = [
            commit for commit, info in dependency_details.items()
            if not info["is_merged"]
        ]
        
        already_merged = [
            commit for commit, info in dependency_details.items()
            if info["is_merged"]
        ]
        
        analysis_result["dependency_analysis"]["summary"] = {
            "total_dependencies": len(dep_commits),
            "already_merged": len(already_merged),
            "need_to_merge": len(not_merged),
            "not_merged_list": not_merged,
            "already_merged_list": already_merged
        }
        
        print(f"\n{'='*80}")
        print(f"分析完成!")
        print(f"  - 总依赖补丁: {len(dep_commits)}")
        print(f"  - 已合入: {len(already_merged)}")
        print(f"  - 需要合入: {len(not_merged) + 1}")  # +1 for fix commit
        print(f"{'='*80}")
        
        # 生成建议
        if not_merged:
            analysis_result["recommendations"].append(
                f"需要先合入 {len(not_merged)} 个依赖补丁: {', '.join(not_merged)}"
            )
        analysis_result["recommendations"].append(
            f"最后合入修复补丁: {fix_commit}"
        )
        
        end_time = time.time()
        analysis_result["duration"] = end_time - start_time
        analysis_result["code"] = 0
        
        return analysis_result


def main():
    """
    使用示例
    """
    # 导入实际的模块
    from crawl_cve_patch import Crawl_Cve_Patch
    from git_repo_manager import GitRepoManager
    from ai_analyze import Ai_Analyze
    from config_loader import ConfigLoader
    
    # 加载配置
    config = ConfigLoader.load("config.yaml")
    
    # 初始化组件
    crawl_cve_patch = Crawl_Cve_Patch()
    ai_analyze = Ai_Analyze()
    
    # 初始化GitRepoManager（传递完整的配置信息，包括path和branch）
    repo_configs = {k: {'path': v['path'], 'branch': v.get('branch')} 
                   for k, v in config.repositories.items()}
    git_repo_manager = GitRepoManager(repo_configs, use_cache=config.cache.enabled)
    
    analyzer = EnhancedCVEAnalyzer(crawl_cve_patch, ai_analyze, git_repo_manager)
    
    # 分析CVE
    result = analyzer.analyze_cve_patch_enhanced(
        cve_id="CVE-2024-12345",
        target_kernel_version="5.10-hulk"
    )
    
    # 打印结果
    print(json.dumps(result, indent=4, ensure_ascii=False))
    
    # 生成报告
    report = generate_analysis_report(result)
    print("\n" + report)
    
    # 保存结果
    with open(f"cve_analysis_{result['vuln_id']}.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    main()
