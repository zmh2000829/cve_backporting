#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE补丁信息获取模块
从MITRE CVE API和kernel.org获取CVE相关的commit信息
"""

import requests
import re
import json
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import time


class Crawl_Cve_Patch:
    """
    CVE补丁信息爬取类
    负责从各种数据源获取CVE相关的commit信息
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        初始化
        
        Args:
            config: 配置字典，包含API地址、超时时间等
        """
        self.config = config or {}
        
        # MITRE CVE API配置
        self.mitre_api_base = self.config.get(
            'mitre_api_base', 
            'https://cveawg.mitre.org/api/cve/'
        )
        self.api_timeout = self.config.get('api_timeout', 30)
        
        # kernel.org git配置
        self.kernel_git_web = "https://git.kernel.org/pub/scm/linux/kernel/git"
        self.mainline_repo = f"{self.kernel_git_web}/torvalds/linux.git"
        self.stable_repo = f"{self.kernel_git_web}/stable/linux.git"
        
        # 请求headers
        self.headers = {
            'User-Agent': 'CVE-Backporting-Tool/1.0',
            'Accept': 'application/json'
        }
        
        # mainline关键词（用于识别mainline commit）
        self.mainline_keywords = [
            'mainline', 'upstream', 'torvalds', 'linus', 
            'master', 'main branch'
        ]
    
    def get_introduced_fixed_commit(self, cve_id: str) -> Optional[Dict]:
        """
        从MITRE CVE API获取CVE的引入和修复commit
        
        Args:
            cve_id: CVE编号，例如 "CVE-2024-12345"
            
        Returns:
            {
                "introduced_commit_id": "abc123..." or None,
                "fix_commit_id": "def456..." or None,
                "all_fix_commits": ["commit1", "commit2", ...],
                "mainline_commit": "最可能的mainline commit",
                "cve_description": "CVE描述",
                "severity": "严重程度"
            }
        """
        print(f"[CVE获取] 开始获取 {cve_id} 的信息...")
        
        try:
            # 1. 从MITRE API获取CVE数据
            cve_data = self._fetch_cve_from_mitre(cve_id)
            if not cve_data:
                print(f"[CVE获取] 无法从MITRE API获取 {cve_id}")
                return None
            
            # 2. 解析CVE数据，提取commit信息
            result = self._parse_cve_data(cve_data, cve_id)
            
            # 3. 如果找到多个fix commits，选择mainline的
            if result and result.get("all_fix_commits"):
                mainline_commit = self._select_mainline_commit(
                    result["all_fix_commits"],
                    cve_data
                )
                result["fix_commit_id"] = mainline_commit
                result["mainline_commit"] = mainline_commit
                
                print(f"[CVE获取] 找到 {len(result['all_fix_commits'])} 个修复commits")
                print(f"[CVE获取] 选择mainline commit: {mainline_commit}")
            
            return result
        
        except Exception as e:
            print(f"[CVE获取] 获取 {cve_id} 时出错: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _fetch_cve_from_mitre(self, cve_id: str) -> Optional[Dict]:
        """
        从MITRE API获取CVE原始数据
        """
        url = f"{self.mitre_api_base}{cve_id}"
        print(f"[API请求] {url}")
        
        try:
            response = requests.get(
                url, 
                headers=self.headers, 
                timeout=self.api_timeout
            )
            
            # 检查HTTP状态
            if response.status_code == 404:
                print(f"[API请求] CVE不存在: {cve_id}")
                return None
            
            response.raise_for_status()
            
            data = response.json()
            print(f"[API请求] 成功获取CVE数据")
            return data
        
        except requests.exceptions.Timeout:
            print(f"[API请求] 请求超时 (>{self.api_timeout}秒)")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[API请求] 网络错误: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"[API请求] JSON解析失败: {e}")
            return None
    
    def _parse_cve_data(self, cve_data: Dict, cve_id: str) -> Dict:
        """
        解析CVE数据，提取commit信息
        
        MITRE CVE数据结构（简化版）:
        {
            "containers": {
                "cna": {
                    "descriptions": [...],
                    "metrics": [...],
                    "references": [
                        {
                            "url": "https://git.kernel.org/.../commit/abc123",
                            "tags": ["patch", "vendor-advisory"]
                        }
                    ],
                    "problemTypes": [...]
                }
            }
        }
        """
        result = {
            "introduced_commit_id": None,
            "fix_commit_id": None,
            "all_fix_commits": [],
            "all_introduced_commits": [],
            "cve_description": "",
            "severity": "unknown",
            "references": []
        }
        
        try:
            # 获取CNA容器（CVE Numbering Authority）
            containers = cve_data.get("containers", {})
            cna = containers.get("cna", {})
            
            # 1. 获取CVE描述
            descriptions = cna.get("descriptions", [])
            if descriptions:
                # 通常第一个是英文描述
                result["cve_description"] = descriptions[0].get("value", "")
            
            # 2. 获取严重程度
            metrics = cna.get("metrics", [])
            if metrics:
                for metric in metrics:
                    if "cvssV3_1" in metric:
                        result["severity"] = metric["cvssV3_1"].get("baseSeverity", "unknown")
                        break
            
            # 3. 解析references，提取commit信息
            references = cna.get("references", [])
            print(f"[CVE解析] 找到 {len(references)} 个参考链接")
            
            for ref in references:
                url = ref.get("url", "")
                tags = ref.get("tags", [])
                
                result["references"].append({
                    "url": url,
                    "tags": tags
                })
                
                # 提取commit ID
                commit_id = self._extract_commit_from_url(url)
                if commit_id:
                    print(f"[CVE解析] 从URL提取到commit: {commit_id}")
                    print(f"[CVE解析]   URL: {url}")
                    print(f"[CVE解析]   Tags: {tags}")
                    
                    # 根据tags判断是引入还是修复
                    if any(tag in ["patch", "fix", "vendor-advisory"] for tag in tags):
                        result["all_fix_commits"].append({
                            "commit_id": commit_id,
                            "url": url,
                            "tags": tags,
                            "source": self._identify_source(url)
                        })
                    
                    if any(tag in ["introduced", "regression"] for tag in tags):
                        result["all_introduced_commits"].append({
                            "commit_id": commit_id,
                            "url": url,
                            "tags": tags
                        })
            
            # 4. 如果没有明确标记，尝试从URL模式识别
            if not result["all_fix_commits"]:
                print("[CVE解析] 未找到明确标记的fix commits，尝试智能识别...")
                result["all_fix_commits"] = self._smart_identify_commits(references)
            
            # 5. 去重
            result["all_fix_commits"] = self._deduplicate_commits(result["all_fix_commits"])
            result["all_introduced_commits"] = self._deduplicate_commits(result["all_introduced_commits"])
            
            print(f"[CVE解析] 最终找到:")
            print(f"[CVE解析]   - 修复commits: {len(result['all_fix_commits'])}")
            print(f"[CVE解析]   - 引入commits: {len(result['all_introduced_commits'])}")
            
            # 6. 设置单个commit字段（向后兼容）
            if result["all_introduced_commits"]:
                result["introduced_commit_id"] = result["all_introduced_commits"][0]["commit_id"]
            
            if result["all_fix_commits"]:
                result["fix_commit_id"] = result["all_fix_commits"][0]["commit_id"]
            
        except Exception as e:
            print(f"[CVE解析] 解析CVE数据时出错: {e}")
            import traceback
            traceback.print_exc()
        
        return result
    
    def _extract_commit_from_url(self, url: str) -> Optional[str]:
        """
        从URL中提取commit ID
        
        支持的URL格式:
        - https://git.kernel.org/.../commit/?id=abc123
        - https://git.kernel.org/.../commit/abc123
        - https://github.com/torvalds/linux/commit/abc123
        - https://lore.kernel.org/...@.../ (从邮件线索提取)
        """
        if not url:
            return None
        
        # 模式1: /commit/?id=<commit_id>
        match = re.search(r'/commit/\?id=([0-9a-f]{7,40})', url)
        if match:
            return match.group(1)
        
        # 模式2: /commit/<commit_id>
        match = re.search(r'/commit/([0-9a-f]{7,40})', url)
        if match:
            return match.group(1)
        
        # 模式3: cgit URL
        match = re.search(r'[?&]id=([0-9a-f]{7,40})', url)
        if match:
            return match.group(1)
        
        # 模式4: 从URL路径提取
        match = re.search(r'([0-9a-f]{12,40})', url)
        if match:
            potential_commit = match.group(1)
            # 验证长度（git commit SHA通常至少12个字符）
            if len(potential_commit) >= 12:
                return potential_commit
        
        return None
    
    def _identify_source(self, url: str) -> str:
        """
        识别commit来源（mainline, stable, 等）
        """
        if "torvalds/linux" in url or "/torvalds/" in url:
            return "mainline"
        elif "stable/linux" in url or "/stable/" in url:
            return "stable"
        elif "github.com" in url:
            return "github"
        else:
            return "unknown"
    
    def _smart_identify_commits(self, references: List[Dict]) -> List[Dict]:
        """
        智能识别commits（当没有明确tags时）
        """
        commits = []
        
        for ref in references:
            url = ref.get("url", "")
            
            # 包含git.kernel.org或github.com/torvalds/linux的链接
            if "git.kernel.org" in url or "github.com/torvalds/linux" in url:
                commit_id = self._extract_commit_from_url(url)
                if commit_id:
                    commits.append({
                        "commit_id": commit_id,
                        "url": url,
                        "tags": ref.get("tags", []),
                        "source": self._identify_source(url)
                    })
        
        return commits
    
    def _deduplicate_commits(self, commits: List[Dict]) -> List[Dict]:
        """
        去重commits（同一个commit可能出现多次）
        """
        seen = set()
        unique_commits = []
        
        for commit in commits:
            commit_id = commit["commit_id"]
            # 使用短ID（前12位）去重
            short_id = commit_id[:12]
            
            if short_id not in seen:
                seen.add(short_id)
                unique_commits.append(commit)
        
        return unique_commits
    
    def _select_mainline_commit(self, commits: List[Dict], cve_data: Dict) -> str:
        """
        从多个commits中选择mainline的commit
        
        优先级:
        1. source == "mainline" (来自torvalds仓库)
        2. URL包含mainline关键词
        3. 描述中提到mainline
        4. 最早的commit（通常是最初的修复）
        """
        if not commits:
            return None
        
        if len(commits) == 1:
            return commits[0]["commit_id"]
        
        print(f"[Mainline选择] 从 {len(commits)} 个commits中选择mainline:")
        
        # 打分系统
        scored_commits = []
        
        for commit in commits:
            score = 0
            commit_id = commit["commit_id"]
            url = commit.get("url", "")
            source = commit.get("source", "")
            tags = commit.get("tags", [])
            
            # 1. 来自mainline仓库 (+10分)
            if source == "mainline":
                score += 10
                print(f"[Mainline选择]   {commit_id[:12]}: +10 (mainline仓库)")
            
            # 2. URL包含torvalds (+8分)
            if "torvalds" in url.lower():
                score += 8
                print(f"[Mainline选择]   {commit_id[:12]}: +8 (torvalds)")
            
            # 3. 来自stable仓库 (-5分，我们倾向于mainline)
            if source == "stable":
                score -= 5
                print(f"[Mainline选择]   {commit_id[:12]}: -5 (stable仓库)")
            
            # 4. tags包含patch (+5分)
            if "patch" in tags:
                score += 5
                print(f"[Mainline选择]   {commit_id[:12]}: +5 (patch tag)")
            
            # 5. URL包含mainline关键词 (+3分)
            for keyword in self.mainline_keywords:
                if keyword in url.lower():
                    score += 3
                    print(f"[Mainline选择]   {commit_id[:12]}: +3 (关键词: {keyword})")
                    break
            
            scored_commits.append({
                "commit": commit,
                "score": score
            })
        
        # 按分数排序
        scored_commits.sort(key=lambda x: x["score"], reverse=True)
        
        # 返回最高分的commit
        best_commit = scored_commits[0]["commit"]["commit_id"]
        best_score = scored_commits[0]["score"]
        
        print(f"[Mainline选择] 最终选择: {best_commit[:12]} (得分: {best_score})")
        
        # 如果最高分是负数或0，可能都不是mainline，给出警告
        if best_score <= 0:
            print(f"[Mainline选择] 警告: 所有commits得分都较低，可能没有mainline commit")
        
        return best_commit
    
    def get_patch_content(self, commit_id: str, kernel_version: str = "Stable") -> Dict:
        """
        获取补丁的完整内容
        
        Args:
            commit_id: commit ID（支持短ID或完整ID）
            kernel_version: 内核版本（"Mainline"或"Stable"）
            
        Returns:
            {
                "commit_id": "完整commit ID",
                "subject": "commit标题",
                "commit_msg": "完整commit消息",
                "author": "作者",
                "date": "提交日期",
                "diff_code": "diff内容",
                "patch": "完整patch文本",
                "modified_files": ["file1", "file2", ...]
            }
        """
        print(f"[Patch获取] 获取commit {commit_id} 的补丁内容...")
        
        try:
            # 1. 确定仓库URL
            if kernel_version.lower() == "mainline":
                repo_url = self.mainline_repo
            else:
                repo_url = self.stable_repo
            
            # 2. 从kernel.org web界面获取patch
            patch_data = self._fetch_patch_from_kernel_org(commit_id, repo_url)
            
            if not patch_data:
                print(f"[Patch获取] 从kernel.org获取失败，尝试其他方式...")
                # 可以添加其他获取方式，比如从本地git仓库
                return {}
            
            return patch_data
        
        except Exception as e:
            print(f"[Patch获取] 获取patch时出错: {e}")
            import traceback
            traceback.print_exc()
            return {}
    
    def _fetch_patch_from_kernel_org(self, commit_id: str, repo_url: str) -> Dict:
        """
        从kernel.org获取patch内容
        """
        # kernel.org cgit URL格式
        # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=<commit>
        patch_url = f"{repo_url}/patch/?id={commit_id}"
        
        print(f"[Patch获取] URL: {patch_url}")
        
        try:
            response = requests.get(patch_url, timeout=self.api_timeout)
            response.raise_for_status()
            
            patch_text = response.text
            
            # 解析patch
            result = self._parse_patch_text(patch_text, commit_id)
            result["patch"] = patch_text
            
            print(f"[Patch获取] 成功获取patch")
            print(f"[Patch获取]   Subject: {result.get('subject', 'N/A')}")
            print(f"[Patch获取]   修改文件数: {len(result.get('modified_files', []))}")
            
            return result
        
        except Exception as e:
            print(f"[Patch获取] 请求失败: {e}")
            return {}
    
    def _parse_patch_text(self, patch_text: str, commit_id: str) -> Dict:
        """
        解析patch文本，提取关键信息
        """
        lines = patch_text.split('\n')
        
        result = {
            "commit_id": commit_id,
            "subject": "",
            "commit_msg": "",
            "author": "",
            "date": "",
            "diff_code": "",
            "modified_files": []
        }
        
        # 查找关键信息
        commit_msg_lines = []
        diff_start = -1
        
        for i, line in enumerate(lines):
            # Subject（通常在From: 之后的第一行非空行）
            if line.startswith('Subject:'):
                result["subject"] = line.replace('Subject:', '').strip()
                # 移除可能的[PATCH]前缀
                result["subject"] = re.sub(r'^\[PATCH[^\]]*\]\s*', '', result["subject"])
            
            # Author
            if line.startswith('From:'):
                result["author"] = line.replace('From:', '').strip()
            
            # Date
            if line.startswith('Date:'):
                result["date"] = line.replace('Date:', '').strip()
            
            # Diff开始位置
            if line.startswith('diff --git'):
                diff_start = i
                break
            
            # Commit message（在---之前的内容）
            if line.startswith('---') and diff_start == -1:
                break
            
            # 收集commit message
            if i > 10 and not line.startswith(('From:', 'Date:', 'Subject:')):
                commit_msg_lines.append(line)
        
        # 提取commit message
        result["commit_msg"] = '\n'.join(commit_msg_lines).strip()
        
        # 提取diff部分
        if diff_start >= 0:
            result["diff_code"] = '\n'.join(lines[diff_start:])
            
            # 提取修改的文件
            result["modified_files"] = self._extract_modified_files_from_diff(
                result["diff_code"]
            )
        
        return result
    
    def _extract_modified_files_from_diff(self, diff_code: str) -> List[str]:
        """
        从diff中提取修改的文件列表
        """
        files = []
        
        for line in diff_code.split('\n'):
            # 匹配 diff --git a/path/file b/path/file
            if line.startswith('diff --git'):
                match = re.search(r'a/(.*?)\s+b/', line)
                if match:
                    files.append(match.group(1))
            # 也可以从 +++ 行提取
            elif line.startswith('+++'):
                match = re.search(r'\+\+\+\s+b/(.+)', line)
                if match:
                    filepath = match.group(1)
                    if filepath not in files and filepath != '/dev/null':
                        files.append(filepath)
        
        return list(set(files))  # 去重
    
    def analyze_fix_deps_commit(self, params: Dict) -> Dict:
        """
        分析修复补丁的依赖commits
        
        Args:
            params: {
                "fix_commit": "修复补丁的commit ID",
                "issue_commit": "引入问题的commit ID（可选）"
            }
            
        Returns:
            {
                "dep_post_patch": "依赖的前置补丁列表（字符串，每行一个）",
                "fix_post_patch": "修复后的后续补丁列表",
                "dependencies": [详细的依赖信息]
            }
        """
        fix_commit = params.get("fix_commit")
        issue_commit = params.get("issue_commit")
        
        print(f"[依赖分析] 分析 {fix_commit} 的依赖...")
        
        # 这里实现依赖分析逻辑
        # 可以通过以下方式:
        # 1. git log 查找相关commits
        # 2. 分析Fixes: 标签
        # 3. 分析修改的文件
        
        result = {
            "dep_post_patch": "",
            "fix_post_patch": "",
            "dependencies": []
        }
        
        try:
            # 使用git log查找相关commits
            # 这里提供一个简单实现，你可以根据实际情况扩展
            
            # 注意: 这需要本地有kernel仓库
            # 更完善的实现应该从kernel.org web API获取
            
            print(f"[依赖分析] 注意: 依赖分析功能需要根据实际环境实现")
            print(f"[依赖分析] 建议: 使用git log --follow或其他工具分析依赖关系")
            
        except Exception as e:
            print(f"[依赖分析] 分析失败: {e}")
        
        return result
    
    def search_subject(self, subject: str, kernel_version: str) -> Dict:
        """
        在目标内核版本中搜索匹配的commit subject
        
        Args:
            subject: 要搜索的commit subject
            kernel_version: 目标内核版本
            
        Returns:
            {
                "subject_res": "找到的匹配commit" or None,
                "matches": [匹配的commit列表]
            }
        """
        print(f"[Subject搜索] 搜索: {subject}")
        print(f"[Subject搜索] 目标版本: {kernel_version}")
        
        # 这个方法应该在GitRepoManager中实现
        # 这里提供一个简单的存根
        
        result = {
            "subject_res": None,
            "matches": []
        }
        
        print(f"[Subject搜索] 注意: 此方法应该由GitRepoManager实现")
        
        return result


# 使用示例
if __name__ == "__main__":
    # 创建实例
    crawler = Crawl_Cve_Patch()
    
    # 测试CVE获取
    print("="*80)
    print("测试CVE信息获取")
    print("="*80)
    
    # 使用一个真实的CVE进行测试
    test_cve = "CVE-2024-26633"  # 这是一个真实的Linux kernel CVE
    
    result = crawler.get_introduced_fixed_commit(test_cve)
    
    if result:
        print("\n" + "="*80)
        print("获取结果:")
        print("="*80)
        print(f"CVE ID: {test_cve}")
        print(f"描述: {result.get('cve_description', 'N/A')[:100]}...")
        print(f"严重程度: {result.get('severity', 'N/A')}")
        print(f"引入commit: {result.get('introduced_commit_id', 'N/A')}")
        print(f"修复commit: {result.get('fix_commit_id', 'N/A')}")
        print(f"所有修复commits: {len(result.get('all_fix_commits', []))}")
        
        for i, commit in enumerate(result.get('all_fix_commits', []), 1):
            print(f"  {i}. {commit['commit_id'][:12]} (source: {commit['source']})")
        
        # 测试获取patch内容
        if result.get('fix_commit_id'):
            print("\n" + "="*80)
            print("测试获取Patch内容")
            print("="*80)
            
            patch = crawler.get_patch_content(result['fix_commit_id'][:12], "Mainline")
            if patch:
                print(f"Subject: {patch.get('subject', 'N/A')}")
                print(f"Author: {patch.get('author', 'N/A')}")
                print(f"修改文件: {patch.get('modified_files', [])}")
    else:
        print("获取CVE信息失败")
