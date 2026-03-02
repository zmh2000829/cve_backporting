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
class Config:
    repositories: Dict[str, Dict[str, str]] = field(default_factory=dict)
    cache: CacheConfig = field(default_factory=CacheConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
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
            if "path_mappings" in data and isinstance(data["path_mappings"], list):
                cfg.path_mappings = data["path_mappings"]
            return cfg
        except Exception:
            return Config()
