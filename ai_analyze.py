#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI分析模块
用于分析补丁内容和依赖关系
"""

import os
from typing import Dict, Optional


class Ai_Analyze:
    """
    AI分析类
    支持多种AI服务提供商（OpenAI, Azure, 本地模型等）
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        初始化AI分析器
        
        Args:
            config: 配置字典，包含AI服务的配置信息
        """
        self.config = config or {}
        
        # 从配置或环境变量获取API密钥
        self.provider = self.config.get('provider', 'openai')
        self.api_key = self.config.get('api_key') or os.getenv('OPENAI_API_KEY')
        self.model = self.config.get('model', 'gpt-4')
        self.max_tokens = self.config.get('max_tokens', 2000)
        self.temperature = self.config.get('temperature', 0.3)
        
        # 如果没有API密钥，使用模拟模式
        self.mock_mode = not self.api_key
        
        if self.mock_mode:
            print("[AI分析] 警告: 未配置API密钥，使用模拟模式")
        else:
            print(f"[AI分析] 使用 {self.provider} - {self.model}")
    
    def analyze_patch(self, patch_content: str, cve_id: str) -> Dict:
        """
        分析补丁内容
        
        Args:
            patch_content: 补丁的完整内容（包括commit msg和diff）
            cve_id: CVE编号
            
        Returns:
            {
                "choices": [
                    {
                        "message": {
                            "content": "AI的分析结果"
                        }
                    }
                ]
            }
        """
        if self.mock_mode:
            return self._mock_analyze_patch(patch_content, cve_id)
        
        try:
            if self.provider == 'openai':
                return self._analyze_with_openai(patch_content, cve_id)
            else:
                print(f"[AI分析] 不支持的提供商: {self.provider}")
                return self._mock_analyze_patch(patch_content, cve_id)
        
        except Exception as e:
            print(f"[AI分析] 调用失败: {e}")
            return self._mock_analyze_patch(patch_content, cve_id)
    
    def analyze_patch_dependencies(self, 
                                   fix_commit: str, 
                                   fix_content: Dict,
                                   dep_commit: str, 
                                   dep_content: str, 
                                   cve_id: str) -> Dict:
        """
        分析两个补丁之间的依赖关系
        
        Args:
            fix_commit: 修复补丁的commit ID
            fix_content: 修复补丁的内容
            dep_commit: 依赖补丁的commit ID
            dep_content: 依赖补丁的内容
            cve_id: CVE编号
            
        Returns:
            {
                "choices": [
                    {
                        "message": {
                            "content": "依赖关系分析结果"
                        }
                    }
                ]
            }
        """
        if self.mock_mode:
            return self._mock_analyze_dependencies(
                fix_commit, fix_content, dep_commit, dep_content, cve_id
            )
        
        try:
            if self.provider == 'openai':
                return self._analyze_dependencies_with_openai(
                    fix_commit, fix_content, dep_commit, dep_content, cve_id
                )
            else:
                return self._mock_analyze_dependencies(
                    fix_commit, fix_content, dep_commit, dep_content, cve_id
                )
        
        except Exception as e:
            print(f"[AI分析] 依赖分析失败: {e}")
            return self._mock_analyze_dependencies(
                fix_commit, fix_content, dep_commit, dep_content, cve_id
            )
    
    def _analyze_with_openai(self, patch_content: str, cve_id: str) -> Dict:
        """
        使用OpenAI API分析补丁
        """
        try:
            import openai
            
            # 设置API密钥
            openai.api_key = self.api_key
            
            # 构建prompt
            prompt = f"""
请分析以下Linux Kernel补丁，这是针对 {cve_id} 的修复补丁。

补丁内容:
{patch_content[:3000]}  # 限制长度避免超出token限制

请提供以下分析:
1. 修复的主要问题是什么？
2. 修改了哪些关键代码？
3. 可能的影响范围？
4. 回合到旧版本时需要注意什么？

请用中文简洁回答。
"""
            
            # 调用OpenAI API
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一个Linux Kernel安全专家，擅长分析补丁和CVE。"},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            return response
        
        except ImportError:
            print("[AI分析] 错误: 未安装openai包，请运行: pip install openai")
            return self._mock_analyze_patch(patch_content, cve_id)
        
        except Exception as e:
            print(f"[AI分析] OpenAI调用失败: {e}")
            return self._mock_analyze_patch(patch_content, cve_id)
    
    def _analyze_dependencies_with_openai(self,
                                         fix_commit: str,
                                         fix_content: Dict,
                                         dep_commit: str,
                                         dep_content: str,
                                         cve_id: str) -> Dict:
        """
        使用OpenAI分析依赖关系
        """
        try:
            import openai
            
            openai.api_key = self.api_key
            
            # 提取关键信息
            fix_subject = fix_content.get('subject', '')
            fix_files = fix_content.get('modified_files', [])
            
            prompt = f"""
分析两个Linux Kernel补丁之间的依赖关系:

修复补丁 ({fix_commit}):
- Subject: {fix_subject}
- 修改文件: {', '.join(fix_files[:5])}

依赖补丁 ({dep_commit}):
{dep_content[:2000]}

问题:
1. 依赖补丁是否是修复补丁的前置依赖？
2. 依赖强度如何（强/中/弱）？
3. 为什么存在依赖关系？
4. 如果缺少依赖补丁会有什么影响？

请用中文简洁回答。
"""
            
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是Linux Kernel补丁依赖分析专家。"},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            return response
        
        except Exception as e:
            print(f"[AI分析] OpenAI依赖分析失败: {e}")
            return self._mock_analyze_dependencies(
                fix_commit, fix_content, dep_commit, dep_content, cve_id
            )
    
    def _mock_analyze_patch(self, patch_content: str, cve_id: str) -> Dict:
        """
        模拟模式：基于规则的简单分析
        """
        # 提取一些基本信息
        lines = patch_content.split('\n')
        
        # 统计修改
        additions = sum(1 for line in lines if line.startswith('+') and not line.startswith('+++'))
        deletions = sum(1 for line in lines if line.startswith('-') and not line.startswith('---'))
        
        # 识别修改的子系统
        subsystem = "未知"
        for line in lines:
            if line.startswith('diff --git'):
                if '/net/' in line:
                    subsystem = "网络子系统"
                    break
                elif '/fs/' in line:
                    subsystem = "文件系统"
                    break
                elif '/drivers/' in line:
                    subsystem = "驱动"
                    break
                elif '/mm/' in line:
                    subsystem = "内存管理"
                    break
        
        analysis = f"""
[模拟分析模式 - 基于规则的简单分析]

补丁分析 ({cve_id}):

1. 修改统计:
   - 新增代码: {additions} 行
   - 删除代码: {deletions} 行
   - 涉及子系统: {subsystem}

2. 初步评估:
   - 这是一个针对 {cve_id} 的安全修复补丁
   - 修改了 {subsystem} 相关代码

3. 回合建议:
   - 建议先在测试环境验证
   - 注意检查相关依赖补丁
   - 确认修改的函数在目标版本中存在

注意: 这是模拟分析结果，建议配置真实的AI服务获得更准确的分析。
配置方法: 在config.yaml中设置OpenAI API密钥，或设置环境变量 OPENAI_API_KEY。
"""
        
        return {
            "choices": [{
                "message": {
                    "content": analysis
                }
            }]
        }
    
    def _mock_analyze_dependencies(self,
                                   fix_commit: str,
                                   fix_content: Dict,
                                   dep_commit: str,
                                   dep_content: str,
                                   cve_id: str) -> Dict:
        """
        模拟模式：简单的依赖关系分析
        """
        # 提取修改的文件
        fix_files = set(fix_content.get('modified_files', []))
        
        # 从依赖补丁中提取文件
        dep_files = set()
        for line in dep_content.split('\n'):
            if line.startswith('diff --git'):
                import re
                match = re.search(r'a/(.*?)\s+b/', line)
                if match:
                    dep_files.add(match.group(1))
        
        # 计算文件重叠
        common_files = fix_files & dep_files
        
        if common_files:
            dependency_strength = "强"
            reason = f"两个补丁都修改了相同的文件: {', '.join(list(common_files)[:3])}"
        elif fix_files and dep_files:
            # 检查是否在相同目录
            fix_dirs = {f.split('/')[0] for f in fix_files}
            dep_dirs = {f.split('/')[0] for f in dep_files}
            
            if fix_dirs & dep_dirs:
                dependency_strength = "中"
                reason = f"补丁涉及相同的子系统目录"
            else:
                dependency_strength = "弱"
                reason = "补丁涉及不同的子系统"
        else:
            dependency_strength = "未知"
            reason = "无法确定依赖关系"
        
        analysis = f"""
[模拟分析模式 - 依赖关系分析]

补丁依赖分析:
- 修复补丁: {fix_commit[:12]}
- 依赖补丁: {dep_commit[:12]}

1. 依赖强度: {dependency_strength}

2. 分析原因:
   {reason}

3. 建议:
   - 依赖强度为"强"时，建议先合入依赖补丁
   - 依赖强度为"中"时，建议检查代码兼容性
   - 依赖强度为"弱"时，可能无直接依赖关系

注意: 这是基于文件路径的简单分析，建议使用AI服务获得更准确的结果。
"""
        
        return {
            "choices": [{
                "message": {
                    "content": analysis
                }
            }]
        }


# 使用示例
if __name__ == "__main__":
    # 示例1: 不使用AI（模拟模式）
    print("="*80)
    print("示例1: 模拟模式（无需API密钥）")
    print("="*80)
    
    ai = Ai_Analyze()
    
    sample_patch = """
diff --git a/net/ipv6/ip6_tunnel.c b/net/ipv6/ip6_tunnel.c
index abc123..def456 100644
--- a/net/ipv6/ip6_tunnel.c
+++ b/net/ipv6/ip6_tunnel.c
@@ -100,7 +100,10 @@ static int ip6_tnl_create(struct net *net)
+       if (!tunnel)
+               return -ENOMEM;
"""
    
    result = ai.analyze_patch(sample_patch, "CVE-2024-12345")
    print("\n分析结果:")
    print(result["choices"][0]["message"]["content"])
    
    # 示例2: 使用OpenAI API（需要API密钥）
    print("\n" + "="*80)
    print("示例2: 使用OpenAI API（需要配置）")
    print("="*80)
    
    # 从环境变量读取API密钥
    api_key = os.getenv('OPENAI_API_KEY')
    
    if api_key:
        ai_with_openai = Ai_Analyze({
            'provider': 'openai',
            'api_key': api_key,
            'model': 'gpt-4',
            'max_tokens': 1000
        })
        
        result2 = ai_with_openai.analyze_patch(sample_patch, "CVE-2024-12345")
        print("\nOpenAI分析结果:")
        print(result2["choices"][0]["message"]["content"])
    else:
        print("\n未配置OPENAI_API_KEY，跳过OpenAI示例")
        print("配置方法:")
        print("  Windows: set OPENAI_API_KEY=your-api-key")
        print("  Linux/Mac: export OPENAI_API_KEY=your-api-key")
