"""CLI 层的策略 profile / P2 开关覆盖。"""

import copy

from core.config import POLICY_PROFILE_PRESETS, SEARCH_PROFILE_PRESETS


CLI_POLICY_PROFILES = ("conservative", "balanced")
CLI_SEARCH_PROFILES = ("conservative", "balanced", "aggressive")


def add_policy_profile_arg(parser):
    parser.add_argument(
        "--policy-profile",
        choices=CLI_POLICY_PROFILES,
        default=None,
        help="策略风格预设：conservative=更保守，balanced=默认平衡；命令行参数优先于 YAML policy.profile",
    )


def add_search_profile_arg(parser):
    parser.add_argument(
        "--search-profile",
        choices=CLI_SEARCH_PROFILES,
        default=None,
        help="搜索召回/精度预设：conservative=更高阈值，balanced=默认，aggressive=更高召回；命令行参数优先于 YAML search.profile",
    )


def add_p2_toggle(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--enable-p2",
        dest="p2_enabled",
        action="store_true",
        default=None,
        help="启用 P2 关键结构/关键语义/高风险场景专项分析",
    )
    group.add_argument(
        "--disable-p2",
        dest="p2_enabled",
        action="store_false",
        help="关闭 P2 关键结构/关键语义/高风险场景专项分析",
    )


def apply_policy_cli_overrides(config, args):
    cfg = copy.deepcopy(config)
    policy = getattr(cfg, "policy", None)
    search = getattr(cfg, "search", None)
    search_profile = getattr(args, "search_profile", None)
    if search and search_profile:
        search.profile = str(search_profile)
        for key, value in (SEARCH_PROFILE_PRESETS.get(search.profile) or {}).items():
            setattr(search, key, value)

    if not policy:
        return cfg

    profile = getattr(args, "policy_profile", None)
    if profile:
        policy.profile = str(profile)
        for key, value in (POLICY_PROFILE_PRESETS.get(policy.profile) or {}).items():
            setattr(policy, key, value)

    override = getattr(args, "p2_enabled", None)
    if override is not None:
        policy.special_risk_rules_enabled = bool(override)

    return cfg
