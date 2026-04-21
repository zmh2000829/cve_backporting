"""配置加载"""

import os
import yaml
from typing import Dict, Any
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
class AnalysisConfig:
    """基础分析策略配置"""
    # 上游 CVE 没有 introduced commit 时的处理策略:
    # assume_vulnerable: 保持旧行为，默认目标受影响并继续补丁回溯
    # patch_probe:      用 fix patch 的 removed/added 行探测目标代码形态
    # strict_unknown:   不做受影响假设，仅输出未知/不适用判断
    missing_intro_policy: str = "patch_probe"
    # patch_probe 无法稳定判断时是否仍按受影响继续后续回溯/DryRun
    missing_intro_assume_on_uncertain: bool = True
    # 判断目标仍保留修复前代码所需的 removed 行命中率
    missing_intro_min_removed_line_match: float = 0.30
    # 判断有效探测所需的目标文件覆盖率
    missing_intro_min_file_coverage: float = 0.50
    # added 行高度命中且 removed 行不命中时，认为目标可能已有等价修复
    missing_intro_fixed_line_threshold: float = 0.70
    # 过滤过短的噪声变更行，如单独的 "}" / "};"
    missing_intro_min_changed_line_length: int = 4


SEARCH_PROFILE_PRESETS: Dict[str, Dict[str, Any]] = {
    "conservative": {
        "subject_threshold": 0.90,
        "diff_threshold": 0.78,
        "subject_candidate_limit": 10,
        "keyword_candidate_limit": 30,
        "diff_candidate_limit": 40,
        "file_search_limit": 6,
        "near_miss_limit": 5,
    },
    "balanced": {
        "subject_threshold": 0.85,
        "diff_threshold": 0.70,
        "subject_candidate_limit": 10,
        "keyword_candidate_limit": 30,
        "diff_candidate_limit": 50,
        "file_search_limit": 6,
        "near_miss_limit": 5,
    },
    "aggressive": {
        "subject_threshold": 0.80,
        "diff_threshold": 0.62,
        "subject_candidate_limit": 20,
        "keyword_candidate_limit": 50,
        "diff_candidate_limit": 100,
        "file_search_limit": 8,
        "near_miss_limit": 8,
    },
    "default": {},
}


@dataclass
class SearchConfig:
    """commit 搜索 profile 与候选保留策略。"""
    profile: str = "balanced"
    subject_threshold: float = 0.85
    diff_threshold: float = 0.70
    subject_candidate_limit: int = 10
    keyword_candidate_limit: int = 30
    diff_candidate_limit: int = 50
    file_search_limit: int = 6
    near_miss_limit: int = 5


# policy.profile 预设：显式写在 YAML 中的阈值始终覆盖此处
POLICY_PROFILE_PRESETS: Dict[str, Dict[str, int]] = {
    "conservative": {
        "large_change_line_threshold": 40,
        "large_hunk_threshold": 4,
        "call_chain_fanout_threshold": 4,
    },
    "balanced": {
        "large_change_line_threshold": 80,
        "large_hunk_threshold": 8,
        "call_chain_fanout_threshold": 6,
    },
    "aggressive": {
        "large_change_line_threshold": 200,
        "large_hunk_threshold": 16,
        "call_chain_fanout_threshold": 12,
    },
    "default": {},
}


@dataclass
class PolicyConfig:
    """L0-L5 分级与规则引擎配置"""
    enabled: bool = True
    profile: str = "balanced"
    special_risk_rules_enabled: bool = True
    prerequisite_rules_enabled: bool = True
    direct_backport_rules_enabled: bool = True
    direct_backport_line_threshold: int = 24
    direct_backport_hunk_threshold: int = 2
    large_change_rules_enabled: bool = True
    large_change_line_threshold: int = 80
    large_hunk_threshold: int = 8
    call_chain_rules_enabled: bool = True
    call_chain_fanout_threshold: int = 6
    call_chain_promotion_min_fanout: int = 2
    critical_structure_rules_enabled: bool = True
    critical_structure_keywords: list = field(default_factory=lambda: [
        "spin_lock", "mutex", "rcu", "refcount", "kref", "atomic"
    ])
    extra_rule_modules: list = field(default_factory=list)
    # L1 细粒度：签名/返回值启发式（可关）
    l1_api_surface_rules_enabled: bool = True
    l1_return_line_delta_threshold: int = 2
    high_impact_single_line_rules_enabled: bool = True
    single_line_impact_max_changed_lines: int = 4


@dataclass
class Config:
    repositories: Dict[str, Dict[str, str]] = field(default_factory=dict)
    cache: CacheConfig = field(default_factory=CacheConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    search: SearchConfig = field(default_factory=SearchConfig)
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
            if "analysis" in data and isinstance(data["analysis"], dict):
                cfg.analysis = AnalysisConfig(**{
                    k: v for k, v in data["analysis"].items()
                    if k in (
                        "missing_intro_policy",
                        "missing_intro_assume_on_uncertain",
                        "missing_intro_min_removed_line_match",
                        "missing_intro_min_file_coverage",
                        "missing_intro_fixed_line_threshold",
                        "missing_intro_min_changed_line_length",
                    )
                })
            if "search" in data and isinstance(data["search"], dict):
                raw_search: Dict[str, Any] = dict(data["search"])
                prof = str(raw_search.get("profile") or "balanced")
                preset = dict(SEARCH_PROFILE_PRESETS.get(prof) or SEARCH_PROFILE_PRESETS.get("default") or {})
                merged_search = {**preset, **raw_search}
                merged_search["profile"] = prof
                allowed_search_keys = (
                    "profile",
                    "subject_threshold",
                    "diff_threshold",
                    "subject_candidate_limit",
                    "keyword_candidate_limit",
                    "diff_candidate_limit",
                    "file_search_limit",
                    "near_miss_limit",
                )
                cfg.search = SearchConfig(**{
                    k: v for k, v in merged_search.items()
                    if k in allowed_search_keys
                })
            if "policy" in data and isinstance(data["policy"], dict):
                raw_policy: Dict[str, Any] = dict(data["policy"])
                prof = str(raw_policy.get("profile") or "balanced")
                preset = dict(POLICY_PROFILE_PRESETS.get(prof) or POLICY_PROFILE_PRESETS.get("default") or {})
                merged_policy = {**preset, **raw_policy}
                merged_policy["profile"] = prof
                allowed_policy_keys = (
                    "enabled", "profile",
                    "special_risk_rules_enabled",
                    "prerequisite_rules_enabled",
                    "direct_backport_rules_enabled",
                    "direct_backport_line_threshold",
                    "direct_backport_hunk_threshold",
                    "large_change_rules_enabled",
                    "large_change_line_threshold",
                    "large_hunk_threshold",
                    "call_chain_rules_enabled",
                    "call_chain_fanout_threshold",
                    "call_chain_promotion_min_fanout",
                    "critical_structure_rules_enabled",
                    "critical_structure_keywords",
                    "extra_rule_modules",
                    "l1_api_surface_rules_enabled",
                    "l1_return_line_delta_threshold",
                    "high_impact_single_line_rules_enabled",
                    "single_line_impact_max_changed_lines",
                )
                cfg.policy = PolicyConfig(**{
                    k: v for k, v in merged_policy.items()
                    if k in allowed_policy_keys
                })
            if "path_mappings" in data and isinstance(data["path_mappings"], list):
                cfg.path_mappings = data["path_mappings"]
            return cfg
        except Exception:
            return Config()
