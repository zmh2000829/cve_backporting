#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强的补丁匹配器 - 用于CVE补丁回合分析
核心功能：
1. 多维度commit匹配（ID、msg、diff、文件路径）
2. 语义相似度计算
3. 依赖图构建与拓扑排序
4. 增量搜索策略
"""

import re
import difflib
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict, deque
import json


@dataclass
class CommitInfo:
    """commit信息数据结构"""
    commit_id: str
    subject: str
    commit_msg: str
    diff_code: str
    modified_files: List[str] = field(default_factory=list)
    modified_functions: List[str] = field(default_factory=list)
    author: str = ""
    timestamp: int = 0
    
    def __hash__(self):
        return hash(self.commit_id)


@dataclass
class MatchResult:
    """匹配结果"""
    target_commit: str  # 目标仓库的commit
    source_commit: str  # 社区commit
    confidence: float   # 置信度 0-1
    match_type: str     # 匹配类型
    details: Dict = field(default_factory=dict)


class CommitMatcher:
    """
    多维度commit匹配器
    支持：精确匹配、语义匹配、代码diff匹配
    """
    
    def __init__(self):
        self.backport_prefixes = [
            "[backport]", "[stable]", "backport:", "stable:",
            "[patch]", "cherry-pick", "cherry pick"
        ]
        
    def extract_modified_files(self, diff_code: str) -> List[str]:
        """从diff中提取修改的文件列表"""
        files = []
        for line in diff_code.split('\n'):
            if line.startswith('---') or line.startswith('+++'):
                # 匹配 --- a/path/to/file 或 +++ b/path/to/file
                match = re.search(r'[+-]{3}\s+[ab]/(.*?)(?:\s|$)', line)
                if match:
                    filepath = match.group(1)
                    if filepath != '/dev/null':
                        files.append(filepath)
        return list(set(files))
    
    def extract_modified_functions(self, diff_code: str) -> List[str]:
        """从diff中提取修改的函数名"""
        functions = []
        # 匹配 @@ -x,y +a,b @@ function_name 格式
        pattern = r'@@\s+-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s+@@\s*(.+?)(?:\s*\{|$)'
        for match in re.finditer(pattern, diff_code):
            func_name = match.group(1).strip()
            if func_name:
                functions.append(func_name)
        
        # 也匹配函数定义行
        func_patterns = [
            r'^\+\s*(?:static\s+)?(?:inline\s+)?(?:\w+\s+)+(\w+)\s*\(',  # C函数
            r'^\+\s*def\s+(\w+)\s*\(',  # Python函数
        ]
        for pattern in func_patterns:
            for match in re.finditer(pattern, diff_code, re.MULTILINE):
                functions.append(match.group(1))
        
        return list(set(functions))
    
    def normalize_subject(self, subject: str) -> str:
        """
        标准化subject，去除backport前缀等
        """
        normalized = subject.lower().strip()
        
        # 移除backport前缀
        for prefix in self.backport_prefixes:
            if normalized.startswith(prefix.lower()):
                normalized = normalized[len(prefix):].strip()
                break
        
        # 移除前导的特殊字符
        normalized = re.sub(r'^[\s\-:]+', '', normalized)
        
        return normalized
    
    def calculate_text_similarity(self, text1: str, text2: str) -> float:
        """
        计算两个文本的相似度（使用序列匹配）
        返回：0-1之间的相似度分数
        """
        # 标准化文本
        t1 = self.normalize_subject(text1)
        t2 = self.normalize_subject(text2)
        
        # 使用difflib计算相似度
        ratio = difflib.SequenceMatcher(None, t1, t2).ratio()
        return ratio
    
    def calculate_commit_msg_similarity(self, msg1: str, msg2: str) -> float:
        """
        计算完整commit msg的相似度
        考虑多行、关键信息等
        """
        # 分别计算subject和body的相似度
        lines1 = msg1.strip().split('\n')
        lines2 = msg2.strip().split('\n')
        
        subject1 = lines1[0] if lines1 else ""
        subject2 = lines2[0] if lines2 else ""
        
        # subject权重更高
        subject_sim = self.calculate_text_similarity(subject1, subject2)
        
        # 如果都有body，也计算body相似度
        if len(lines1) > 1 and len(lines2) > 1:
            body1 = '\n'.join(lines1[1:])
            body2 = '\n'.join(lines2[1:])
            body_sim = difflib.SequenceMatcher(None, body1, body2).ratio()
            # subject占70%，body占30%
            return subject_sim * 0.7 + body_sim * 0.3
        
        return subject_sim
    
    def calculate_diff_similarity(self, diff1: str, diff2: str) -> float:
        """
        计算两个diff的相似度
        忽略行号变化，关注实际代码修改
        """
        # 提取实际的修改行（+ 和 - 开头的）
        def extract_changes(diff: str) -> List[str]:
            changes = []
            for line in diff.split('\n'):
                if line.startswith('+') or line.startswith('-'):
                    # 去除+/-符号和空白
                    clean_line = line[1:].strip()
                    if clean_line:  # 忽略空行
                        changes.append(clean_line)
            return changes
        
        changes1 = extract_changes(diff1)
        changes2 = extract_changes(diff2)
        
        if not changes1 or not changes2:
            return 0.0
        
        # 计算修改行的相似度
        matcher = difflib.SequenceMatcher(None, changes1, changes2)
        return matcher.ratio()
    
    def calculate_file_similarity(self, files1: List[str], files2: List[str]) -> float:
        """
        计算修改文件列表的相似度
        考虑文件路径可能有变化（重构等）
        """
        if not files1 or not files2:
            return 0.0
        
        # 提取文件名（不含路径）
        def get_filename(path: str) -> str:
            return path.split('/')[-1]
        
        names1 = set(get_filename(f) for f in files1)
        names2 = set(get_filename(f) for f in files2)
        
        # Jaccard相似度
        intersection = len(names1 & names2)
        union = len(names1 | names2)
        
        return intersection / union if union > 0 else 0.0
    
    def match_exact_commit_id(self, 
                              source_commit: CommitInfo,
                              target_commits: List[CommitInfo]) -> Optional[MatchResult]:
        """
        精确匹配commit ID
        """
        for target in target_commits:
            if source_commit.commit_id.startswith(target.commit_id[:12]) or \
               target.commit_id.startswith(source_commit.commit_id[:12]):
                return MatchResult(
                    target_commit=target.commit_id,
                    source_commit=source_commit.commit_id,
                    confidence=1.0,
                    match_type="exact_commit_id",
                    details={"target_subject": target.subject}
                )
        return None
    
    def match_by_subject(self,
                        source_commit: CommitInfo,
                        target_commits: List[CommitInfo],
                        threshold: float = 0.85) -> List[MatchResult]:
        """
        基于subject的相似度匹配
        返回所有超过阈值的匹配结果
        """
        results = []
        
        for target in target_commits:
            similarity = self.calculate_text_similarity(
                source_commit.subject,
                target.subject
            )
            
            if similarity >= threshold:
                results.append(MatchResult(
                    target_commit=target.commit_id,
                    source_commit=source_commit.commit_id,
                    confidence=similarity,
                    match_type="subject_similarity",
                    details={
                        "source_subject": source_commit.subject,
                        "target_subject": target.subject,
                        "similarity": similarity
                    }
                ))
        
        # 按置信度降序排序
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results
    
    def match_by_diff(self,
                     source_commit: CommitInfo,
                     target_commits: List[CommitInfo],
                     threshold: float = 0.70) -> List[MatchResult]:
        """
        基于代码diff的相似度匹配
        """
        results = []
        
        source_files = source_commit.modified_files or \
                      self.extract_modified_files(source_commit.diff_code)
        
        for target in target_commits:
            target_files = target.modified_files or \
                          self.extract_modified_files(target.diff_code)
            
            # 先检查文件相似度（快速过滤）
            file_sim = self.calculate_file_similarity(source_files, target_files)
            if file_sim < 0.3:  # 文件完全不匹配，跳过
                continue
            
            # 计算diff相似度
            diff_sim = self.calculate_diff_similarity(
                source_commit.diff_code,
                target.diff_code
            )
            
            # 综合评分：文件相似度40%，diff相似度60%
            combined_score = file_sim * 0.4 + diff_sim * 0.6
            
            if combined_score >= threshold:
                results.append(MatchResult(
                    target_commit=target.commit_id,
                    source_commit=source_commit.commit_id,
                    confidence=combined_score,
                    match_type="diff_similarity",
                    details={
                        "file_similarity": file_sim,
                        "diff_similarity": diff_sim,
                        "source_files": source_files,
                        "target_files": target_files
                    }
                ))
        
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results
    
    def match_comprehensive(self,
                           source_commit: CommitInfo,
                           target_commits: List[CommitInfo]) -> List[MatchResult]:
        """
        综合多种匹配策略
        按优先级返回匹配结果
        """
        all_results = []
        
        # 1. 优先精确匹配commit ID
        exact_match = self.match_exact_commit_id(source_commit, target_commits)
        if exact_match:
            return [exact_match]
        
        # 2. 高相似度subject匹配
        subject_matches = self.match_by_subject(source_commit, target_commits, threshold=0.85)
        all_results.extend(subject_matches)
        
        # 3. diff匹配（如果subject没找到好的匹配）
        if not subject_matches or subject_matches[0].confidence < 0.95:
            diff_matches = self.match_by_diff(source_commit, target_commits, threshold=0.70)
            all_results.extend(diff_matches)
        
        # 去重（同一个target_commit只保留置信度最高的）
        seen = {}
        for result in all_results:
            if result.target_commit not in seen or \
               result.confidence > seen[result.target_commit].confidence:
                seen[result.target_commit] = result
        
        final_results = list(seen.values())
        final_results.sort(key=lambda x: x.confidence, reverse=True)
        
        return final_results


class DependencyAnalyzer:
    """
    补丁依赖关系分析器
    构建依赖图并进行拓扑排序
    """
    
    def __init__(self):
        self.dependency_graph: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_graph: Dict[str, Set[str]] = defaultdict(set)
        
    def add_dependency(self, patch: str, depends_on: str):
        """
        添加依赖关系：patch依赖于depends_on
        """
        self.dependency_graph[patch].add(depends_on)
        self.reverse_graph[depends_on].add(patch)
    
    def find_dependencies_from_commits(self,
                                      fix_commit: CommitInfo,
                                      candidate_commits: List[CommitInfo]) -> Dict[str, float]:
        """
        从候选commits中找出与fix_commit有依赖关系的补丁
        返回：{commit_id: 依赖强度}
        """
        dependencies = {}
        
        fix_files = set(fix_commit.modified_files or 
                       self.extract_modified_files(fix_commit.diff_code))
        fix_functions = set(fix_commit.modified_functions or 
                           self.extract_modified_functions(fix_commit.diff_code))
        
        for candidate in candidate_commits:
            if candidate.commit_id == fix_commit.commit_id:
                continue
            
            # 如果时间戳可用，只考虑更早的commit
            if fix_commit.timestamp > 0 and candidate.timestamp > 0:
                if candidate.timestamp >= fix_commit.timestamp:
                    continue
            
            candidate_files = set(candidate.modified_files or 
                                 self.extract_modified_files(candidate.diff_code))
            candidate_functions = set(candidate.modified_functions or 
                                     self.extract_modified_functions(candidate.diff_code))
            
            # 计算依赖强度
            file_overlap = len(fix_files & candidate_files) / len(fix_files) if fix_files else 0
            func_overlap = len(fix_functions & candidate_functions) / len(fix_functions) if fix_functions else 0
            
            # 综合评分
            dependency_score = file_overlap * 0.6 + func_overlap * 0.4
            
            if dependency_score > 0.3:  # 超过阈值才认为有依赖
                dependencies[candidate.commit_id] = dependency_score
        
        return dependencies
    
    def extract_modified_files(self, diff_code: str) -> List[str]:
        """从diff中提取修改的文件"""
        matcher = CommitMatcher()
        return matcher.extract_modified_files(diff_code)
    
    def extract_modified_functions(self, diff_code: str) -> List[str]:
        """从diff中提取修改的函数"""
        matcher = CommitMatcher()
        return matcher.extract_modified_functions(diff_code)
    
    def topological_sort(self, patches: List[str]) -> List[str]:
        """
        对补丁进行拓扑排序
        返回：应该按照此顺序合入的补丁列表
        """
        # 计算入度
        in_degree = {patch: 0 for patch in patches}
        for patch in patches:
            for dep in self.dependency_graph[patch]:
                if dep in in_degree:
                    in_degree[patch] += 1
        
        # BFS拓扑排序
        queue = deque([p for p in patches if in_degree[p] == 0])
        result = []
        
        while queue:
            current = queue.popleft()
            result.append(current)
            
            # 更新依赖于current的节点
            for dependent in self.reverse_graph[current]:
                if dependent in in_degree:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        queue.append(dependent)
        
        # 检查是否有环
        if len(result) != len(patches):
            # 有环，返回部分排序结果并警告
            print(f"警告：依赖图中存在环，无法完全排序")
        
        return result
    
    def get_all_dependencies(self, patch: str, visited: Set[str] = None) -> Set[str]:
        """
        递归获取某个补丁的所有依赖（包括传递依赖）
        """
        if visited is None:
            visited = set()
        
        if patch in visited:
            return set()
        
        visited.add(patch)
        all_deps = set(self.dependency_graph[patch])
        
        for dep in self.dependency_graph[patch]:
            all_deps.update(self.get_all_dependencies(dep, visited))
        
        return all_deps


class PatchBackportAnalyzer:
    """
    补丁回合分析器主类
    整合所有功能模块
    """
    
    def __init__(self, crawl_cve_patch, ai_analyze):
        self.crawl_cve_patch = crawl_cve_patch
        self.ai_analyze = ai_analyze
        self.commit_matcher = CommitMatcher()
        self.dep_analyzer = DependencyAnalyzer()
    
    def search_commit_in_target_repo(self,
                                    source_commit: CommitInfo,
                                    target_version: str,
                                    max_candidates: int = 50) -> List[MatchResult]:
        """
        在目标仓库中搜索匹配的commit
        使用增量搜索策略
        """
        # 这里需要实现从目标仓库获取候选commits的逻辑
        # 你可以通过git log、数据库查询等方式获取
        
        # 伪代码示例：
        # target_commits = self.crawl_cve_patch.get_commits_from_repo(
        #     kernel_version=target_version,
        #     time_range=(source_commit.timestamp - 30*24*3600, source_commit.timestamp + 30*24*3600),
        #     file_filter=source_commit.modified_files
        # )
        
        # 暂时返回空列表，需要你实现具体的搜索逻辑
        target_commits = []
        
        # 使用综合匹配
        matches = self.commit_matcher.match_comprehensive(source_commit, target_commits)
        
        return matches[:5]  # 返回前5个最佳匹配
    
    def analyze_patch_dependencies_enhanced(self,
                                           fix_commit_info: Dict,
                                           related_commits: List[Dict],
                                           target_version: str) -> Dict:
        """
        增强的依赖分析
        """
        # 构建CommitInfo对象
        fix_commit = CommitInfo(
            commit_id=fix_commit_info["commit_id"],
            subject=fix_commit_info["subject"],
            commit_msg=fix_commit_info["commit_msg"],
            diff_code=fix_commit_info["diff_code"],
            modified_files=self.commit_matcher.extract_modified_files(fix_commit_info["diff_code"]),
            modified_functions=self.commit_matcher.extract_modified_functions(fix_commit_info["diff_code"])
        )
        
        candidate_commits = []
        for commit_dict in related_commits:
            candidate = CommitInfo(
                commit_id=commit_dict["commit_id"],
                subject=commit_dict.get("subject", ""),
                commit_msg=commit_dict.get("commit_msg", ""),
                diff_code=commit_dict.get("diff_code", ""),
                modified_files=self.commit_matcher.extract_modified_files(commit_dict.get("diff_code", "")),
                modified_functions=self.commit_matcher.extract_modified_functions(commit_dict.get("diff_code", ""))
            )
            candidate_commits.append(candidate)
        
        # 分析依赖关系
        dependencies = self.dep_analyzer.find_dependencies_from_commits(
            fix_commit, candidate_commits
        )
        
        # 构建依赖图
        for dep_commit, strength in dependencies.items():
            if strength > 0.5:  # 强依赖
                self.dep_analyzer.add_dependency(fix_commit.commit_id, dep_commit)
        
        # 拓扑排序
        all_patches = [fix_commit.commit_id] + list(dependencies.keys())
        sorted_patches = self.dep_analyzer.topological_sort(all_patches)
        
        # 为每个依赖补丁查找目标仓库中的匹配
        dependency_analysis = {}
        for dep_commit_id in dependencies.keys():
            dep_commit = next((c for c in candidate_commits if c.commit_id == dep_commit_id), None)
            if dep_commit:
                matches = self.search_commit_in_target_repo(dep_commit, target_version)
                dependency_analysis[dep_commit_id] = {
                    "dependency_strength": dependencies[dep_commit_id],
                    "matches_in_target": [
                        {
                            "target_commit": m.target_commit,
                            "confidence": m.confidence,
                            "match_type": m.match_type,
                            "details": m.details
                        }
                        for m in matches
                    ],
                    "is_merged": len(matches) > 0 and matches[0].confidence > 0.85
                }
        
        return {
            "dependencies": dependency_analysis,
            "merge_order": sorted_patches,
            "dependency_graph": dict(self.dep_analyzer.dependency_graph)
        }


def generate_analysis_report(analysis_result: Dict) -> str:
    """
    生成人类可读的分析报告
    """
    report = []
    report.append(f"# CVE补丁回合分析报告")
    report.append(f"\n## CVE信息")
    report.append(f"- CVE ID: {analysis_result.get('vuln_id', 'N/A')}")
    report.append(f"- 目标内核版本: {analysis_result.get('kernel_version', 'N/A')}")
    
    if "fix_analysis" in analysis_result:
        report.append(f"\n## 修复补丁分析")
        for commit_id, info in analysis_result["fix_analysis"].items():
            report.append(f"\n### 社区修复补丁: {commit_id}")
            report.append(f"- Subject: {info.get('subject', 'N/A')}")
            report.append(f"- 是否已合入目标版本: {'是' if info.get('subject_exists') else '否'}")
            
            if "matches_in_target" in info:
                report.append(f"\n#### 目标仓库中的匹配结果:")
                for match in info["matches_in_target"][:3]:  # 只显示前3个
                    report.append(f"  - Commit: {match['target_commit']}")
                    report.append(f"    置信度: {match['confidence']:.2%}")
                    report.append(f"    匹配类型: {match['match_type']}")
    
    if "dependency_analysis" in analysis_result:
        report.append(f"\n## 依赖补丁分析")
        dep_analysis = analysis_result["dependency_analysis"]
        
        if "merge_order" in dep_analysis:
            report.append(f"\n### 建议的合入顺序:")
            for idx, patch in enumerate(dep_analysis["merge_order"], 1):
                report.append(f"{idx}. {patch}")
        
        if "dependencies" in dep_analysis:
            report.append(f"\n### 依赖补丁详情:")
            for dep_commit, dep_info in dep_analysis["dependencies"].items():
                report.append(f"\n#### {dep_commit}")
                report.append(f"- 依赖强度: {dep_info['dependency_strength']:.2%}")
                report.append(f"- 是否已合入: {'是' if dep_info.get('is_merged') else '否'}")
                
                if dep_info.get("matches_in_target"):
                    report.append(f"- 最佳匹配: {dep_info['matches_in_target'][0]['target_commit']} "
                                f"(置信度: {dep_info['matches_in_target'][0]['confidence']:.2%})")
    
    return '\n'.join(report)


# 使用示例
if __name__ == "__main__":
    # 测试commit匹配
    matcher = CommitMatcher()
    
    # 示例：计算相似度
    subject1 = "[backport] net: fix memory leak in tcp_connect"
    subject2 = "net: fix memory leak in tcp_connect"
    similarity = matcher.calculate_text_similarity(subject1, subject2)
    print(f"Subject相似度: {similarity:.2%}")
