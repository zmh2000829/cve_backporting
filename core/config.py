"""配置加载"""

import os
import yaml
from typing import Dict
from dataclasses import dataclass, field


@dataclass
class CacheConfig:
    enabled: bool = True
    database_path: str = "./commit_cache.db"
    max_cached_commits: int = 10000000


@dataclass
class OutputConfig:
    output_dir: str = "./analysis_results"
    log_level: str = "INFO"
    log_file: str = "./cve_analysis.log"


# 内核版本演进中的已知路径迁移 (upstream=高版本路径, local=低版本路径)
DEFAULT_PATH_MAPPINGS = [
    {"upstream": "fs/smb/client/", "local": "fs/cifs/", "since": "6.2"},
    {"upstream": "fs/smb/server/", "local": "fs/ksmbd/", "since": "6.2"},
    {"upstream": "fs/smb/common/", "local": "fs/smbfs_common/", "since": "6.2"},
    {"upstream": "drivers/gpu/drm/amd/display/dc/link/", "local": "drivers/gpu/drm/amd/display/dc/core/", "since": "6.2"},
    {"upstream": "drivers/gpu/drm/i915/display/", "local": "drivers/gpu/drm/i915/", "since": "5.18"},
    {"upstream": "drivers/net/wireless/realtek/rtw89/", "local": "drivers/staging/rtw89/", "since": "5.16"},
    {"upstream": "drivers/net/wireless/ath/ath12k/", "local": "drivers/staging/ath12k/", "since": "6.5"},
    {"upstream": "fs/netfs/", "local": "fs/fscache/", "since": "6.1"},
]


@dataclass
class LLMConfig:
    enabled: bool = False
    provider: str = "openai"
    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o"
    max_tokens: int = 2000
    temperature: float = 0.3
    timeout: int = 60


@dataclass
class PolicyConfig:
    """L0-L5 分级与规则引擎配置"""
    enabled: bool = True
    profile: str = "default"
    large_change_line_threshold: int = 80
    large_hunk_threshold: int = 8
    call_chain_fanout_threshold: int = 6
    critical_structure_keywords: list = field(default_factory=lambda: [
        "spin_lock", "mutex", "rcu", "refcount", "kref", "atomic", "struct"
    ])
    extra_rule_modules: list = field(default_factory=list)


@dataclass
class Config:
    repositories: Dict[str, Dict[str, str]] = field(default_factory=dict)
    cache: CacheConfig = field(default_factory=CacheConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    path_mappings: list = field(default_factory=lambda: list(DEFAULT_PATH_MAPPINGS))


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
                cfg.cache = CacheConfig(**{
                    k: v for k, v in data["cache"].items()
                    if k in ("enabled", "database_path", "max_cached_commits")
                })
            if "output" in data:
                cfg.output = OutputConfig(**{
                    k: v for k, v in data["output"].items()
                    if k in ("output_dir", "log_level", "log_file")
                })
            if "llm" in data and isinstance(data["llm"], dict):
                cfg.llm = LLMConfig(**{
                    k: v for k, v in data["llm"].items()
                    if k in ("enabled", "provider", "api_key", "base_url",
                             "model", "max_tokens", "temperature", "timeout")
                })
            if "policy" in data and isinstance(data["policy"], dict):
                cfg.policy = PolicyConfig(**{
                    k: v for k, v in data["policy"].items()
                    if k in ("enabled", "profile",
                             "large_change_line_threshold",
                             "large_hunk_threshold",
                             "call_chain_fanout_threshold",
                             "critical_structure_keywords",
                             "extra_rule_modules")
                })
            if "path_mappings" in data and isinstance(data["path_mappings"], list):
                cfg.path_mappings = data["path_mappings"]
            return cfg
        except Exception:
            return Config()
