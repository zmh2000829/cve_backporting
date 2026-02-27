"""配置加载"""

import os
import yaml
from typing import Dict, Any
from dataclasses import dataclass, field


@dataclass
class MatchingConfig:
    subject_similarity_threshold: float = 0.85
    diff_similarity_threshold: float = 0.70
    file_similarity_threshold: float = 0.30
    max_candidates: int = 5
    auto_accept_threshold: float = 0.95


@dataclass
class DependencyConfig:
    dependency_threshold: float = 0.30
    strong_dependency_threshold: float = 0.60
    max_time_window_days: int = 180
    max_dependency_depth: int = 10


@dataclass
class CacheConfig:
    enabled: bool = True
    database_path: str = "./commit_cache.db"
    max_cached_commits: int = 10000
    cache_expiry_days: int = 30


@dataclass
class PerformanceConfig:
    max_workers: int = 4
    search_timeout: int = 300
    git_timeout: int = 60
    use_bloom_filter: bool = True


@dataclass
class OutputConfig:
    output_dir: str = "./analysis_results"
    report_formats: list = field(default_factory=lambda: ["json", "markdown"])
    log_level: str = "INFO"
    log_file: str = "./cve_analysis.log"


@dataclass
class Config:
    repositories: Dict[str, Dict[str, str]] = field(default_factory=dict)
    cache: CacheConfig = field(default_factory=CacheConfig)
    matching: MatchingConfig = field(default_factory=MatchingConfig)
    dependency: DependencyConfig = field(default_factory=DependencyConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    ai_analysis: Dict[str, Any] = field(default_factory=dict)
    advanced: Dict[str, Any] = field(default_factory=dict)


class ConfigLoader:
    @staticmethod
    def load(config_path: str = "config.yaml") -> Config:
        if not os.path.exists(config_path):
            return Config()
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not data:
                return Config()
            cfg = Config()
            if "repositories" in data:
                cfg.repositories = data["repositories"]
            if "cache" in data:
                cfg.cache = CacheConfig(**data["cache"])
            if "matching" in data:
                cfg.matching = MatchingConfig(**data["matching"])
            if "dependency" in data:
                cfg.dependency = DependencyConfig(**data["dependency"])
            if "performance" in data:
                cfg.performance = PerformanceConfig(**data["performance"])
            if "output" in data:
                cfg.output = OutputConfig(**data["output"])
            if "ai_analysis" in data:
                cfg.ai_analysis = data["ai_analysis"]
            if "advanced" in data:
                cfg.advanced = data["advanced"]
            return cfg
        except Exception:
            return Config()
