#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置加载器
从YAML文件加载配置
"""

import yaml
import os
from typing import Dict, Any
from dataclasses import dataclass, field


@dataclass
class MatchingConfig:
    """匹配策略配置"""
    subject_similarity_threshold: float = 0.85
    diff_similarity_threshold: float = 0.70
    file_similarity_threshold: float = 0.30
    max_candidates: int = 5
    auto_accept_threshold: float = 0.95


@dataclass
class DependencyConfig:
    """依赖分析配置"""
    dependency_threshold: float = 0.30
    strong_dependency_threshold: float = 0.60
    max_time_window_days: int = 180
    max_dependency_depth: int = 10


@dataclass
class CacheConfig:
    """缓存配置"""
    enabled: bool = True
    database_path: str = "./commit_cache.db"
    max_cached_commits: int = 10000
    cache_expiry_days: int = 30


@dataclass
class PerformanceConfig:
    """性能配置"""
    max_workers: int = 4
    search_timeout: int = 300
    git_timeout: int = 60
    use_bloom_filter: bool = True


@dataclass
class OutputConfig:
    """输出配置"""
    output_dir: str = "./analysis_results"
    report_formats: list = field(default_factory=lambda: ["json", "markdown"])
    log_level: str = "INFO"
    log_file: str = "./cve_analysis.log"


@dataclass
class Config:
    """总配置类"""
    repositories: Dict[str, Dict[str, str]] = field(default_factory=dict)
    cache: CacheConfig = field(default_factory=CacheConfig)
    matching: MatchingConfig = field(default_factory=MatchingConfig)
    dependency: DependencyConfig = field(default_factory=DependencyConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    ai_analysis: Dict[str, Any] = field(default_factory=dict)
    advanced: Dict[str, Any] = field(default_factory=dict)


class ConfigLoader:
    """配置加载器"""
    
    @staticmethod
    def load(config_path: str = "config.yaml") -> Config:
        """
        从YAML文件加载配置
        
        Args:
            config_path: 配置文件路径
            
        Returns:
            Config对象
        """
        if not os.path.exists(config_path):
            print(f"警告: 配置文件 {config_path} 不存在，使用默认配置")
            return Config()
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data:
                print("警告: 配置文件为空，使用默认配置")
                return Config()
            
            # 解析各部分配置
            config = Config()
            
            # 仓库配置
            if 'repositories' in data:
                config.repositories = data['repositories']
            
            # 缓存配置
            if 'cache' in data:
                config.cache = CacheConfig(**data['cache'])
            
            # 匹配配置
            if 'matching' in data:
                config.matching = MatchingConfig(**data['matching'])
            
            # 依赖配置
            if 'dependency' in data:
                config.dependency = DependencyConfig(**data['dependency'])
            
            # 性能配置
            if 'performance' in data:
                config.performance = PerformanceConfig(**data['performance'])
            
            # 输出配置
            if 'output' in data:
                config.output = OutputConfig(**data['output'])
            
            # AI分析配置
            if 'ai_analysis' in data:
                config.ai_analysis = data['ai_analysis']
            
            # 高级选项
            if 'advanced' in data:
                config.advanced = data['advanced']
            
            return config
        
        except yaml.YAMLError as e:
            print(f"错误: 解析配置文件失败: {e}")
            print("使用默认配置")
            return Config()
        except Exception as e:
            print(f"错误: 加载配置文件时出错: {e}")
            print("使用默认配置")
            return Config()
    
    @staticmethod
    def validate_config(config: Config) -> bool:
        """
        验证配置有效性
        
        Args:
            config: 要验证的配置
            
        Returns:
            是否有效
        """
        errors = []
        
        # 验证仓库配置
        if not config.repositories:
            errors.append("未配置任何Git仓库")
        else:
            for name, repo_config in config.repositories.items():
                if 'path' not in repo_config:
                    errors.append(f"仓库 {name} 缺少 path 配置")
                elif not os.path.exists(repo_config['path']):
                    errors.append(f"仓库路径不存在: {repo_config['path']}")
        
        # 验证阈值范围
        if not 0 <= config.matching.subject_similarity_threshold <= 1:
            errors.append("subject_similarity_threshold 必须在 0-1 之间")
        
        if not 0 <= config.matching.diff_similarity_threshold <= 1:
            errors.append("diff_similarity_threshold 必须在 0-1 之间")
        
        # 验证输出目录
        output_dir = config.output.output_dir
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
                print(f"创建输出目录: {output_dir}")
            except Exception as e:
                errors.append(f"无法创建输出目录 {output_dir}: {e}")
        
        # 打印错误
        if errors:
            print("配置验证失败:")
            for error in errors:
                print(f"  - {error}")
            return False
        
        print("配置验证通过")
        return True


# 使用示例
if __name__ == "__main__":
    # 加载配置
    config = ConfigLoader.load("config.yaml")
    
    # 验证配置
    if ConfigLoader.validate_config(config):
        print("\n配置信息:")
        print(f"  - 配置的仓库数: {len(config.repositories)}")
        print(f"  - 缓存启用: {config.cache.enabled}")
        print(f"  - Subject相似度阈值: {config.matching.subject_similarity_threshold}")
        print(f"  - 并行线程数: {config.performance.max_workers}")
        print(f"  - 输出目录: {config.output.output_dir}")
