# -*- coding: utf-8 -*-
"""Integration — 与 QwenPaw ToolGuardEngine 集成的入口函数。

提供 URLNetGuard（HTTP Monkey-Patch 层）的安装和卸载函数，
适配 QwenPaw 的配置体系（UrlGuardConfig Pydantic 模型）。

URLToolGuardian 和 URLNetGuard 共享同一个 URLRuleEngine 实例，
确保两层拦截使用同一套规则。

设计原则：
- setup_url_net_guard() 从 UrlGuardConfig 或现有 engine 的 URLToolGuardian 获取规则引擎
- teardown_url_net_guard() 卸载 monkey-patch 并恢复原始 HTTP 方法
- 配置优先级：QWENPAW_URL_GUARD_ENABLED 环境变量 > config.json > 默认启用
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .url_net_guard import URLNetGuard
from .url_rule_engine import URLRuleEngine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# URLNetGuard 安装/卸载函数
# ---------------------------------------------------------------------------


def setup_url_net_guard(
    rule_engine: Optional[URLRuleEngine] = None,
    *,
    enable_proxy: bool = True,
) -> URLNetGuard:
    """创建并安装 URLNetGuard（HTTP Monkey-Patch 层 + 子进程代理）。

    优先使用传入的 rule_engine（通常从 URLToolGuardian._rule_engine 获取），
    确保 ToolGuard 和 HTTP Monkey-Patch 两层拦截共享同一套规则。
    如果未传入 rule_engine，则从 QwenPaw 配置创建默认引擎。

    :param rule_engine: URL 规则引擎实例（推荐从 URLToolGuardian 传递）。
    :param enable_proxy: 是否启用子进程 HTTP 过滤代理。
    :returns: 已安装的 URLNetGuard 实例。
    """
    if rule_engine is None:
        # 尝试从 QwenPaw 配置创建规则引擎
        rule_engine = _create_rule_engine_from_config()

    net_guard = URLNetGuard(rule_engine=rule_engine, enable_proxy=enable_proxy)
    net_guard.install()

    proxy_info = f"（代理: {net_guard.proxy_url}）" if net_guard.proxy_url else ""
    logger.info("URLNetGuard 已安装（规则引擎: %d 条规则）%s", rule_engine.rule_count, proxy_info)
    return net_guard


def setup_url_net_guard_from_engine(
    engine: Any, *, enable_proxy: bool = True,
) -> Optional[URLNetGuard]:
    """从 ToolGuardEngine 中提取 URLToolGuardian 的 rule_engine 并安装 URLNetGuard。

    此函数用于 QwenPaw 启动流程中，在 ToolGuardEngine 初始化后自动安装
    HTTP Monkey-Patch 层，确保两层拦截使用同一套规则。
    同时启动子进程 HTTP 过滤代理（URLFilterProxy）。

    :param engine: ToolGuardEngine 实例。
    :param enable_proxy: 是否启用子进程 HTTP 过滤代理。
    :returns: 已安装的 URLNetGuard 实例，如果 URL Guard 未启用则返回 None。
    """
    # 从 engine 中获取 URLToolGuardian 的 rule_engine
    url_guardian = next(
        (g for g in engine._guardians if g.name == "url_tool_guardian"), None
    )
    if url_guardian is None or not hasattr(url_guardian, "_rule_engine"):
        logger.info("URLToolGuardian 未注册或无 rule_engine，跳过 URLNetGuard 安装")
        return None

    rule_engine = url_guardian._rule_engine
    net_guard = URLNetGuard(rule_engine=rule_engine, enable_proxy=enable_proxy)
    net_guard.install()

    proxy_info = f"（代理: {net_guard.proxy_url}）" if net_guard.proxy_url else ""
    logger.info(
        "URLNetGuard 已从 ToolGuardEngine 安装（共享规则引擎: %d 条规则）%s",
        rule_engine.rule_count, proxy_info,
    )
    return net_guard


def teardown_url_net_guard(net_guard: Optional[URLNetGuard] = None) -> None:
    """清理 URL Guard（卸载 monkey-patch）。

    :param net_guard: URLNetGuard 实例（可选）。
        如果未提供，不做任何操作。
    """
    if net_guard is not None and net_guard.is_installed:
        net_guard.uninstall()
        logger.info("URL Guard monkey-patch 已卸载")
    else:
        logger.debug("URL Guard 未安装或 net_guard 未提供，无需卸载")


# ---------------------------------------------------------------------------
# 内部辅助：从 QwenPaw 配置创建规则引擎
# ---------------------------------------------------------------------------


def _create_rule_engine_from_config() -> URLRuleEngine:
    """从 QwenPaw 配置创建 URLRuleEngine。

    读取 config.json 的 security.url_guard 配置，
    构建规则引擎并加载自定义规则。

    :returns: URLRuleEngine 实例。
    """
    try:
        from qwenpaw.config import load_config

        url_cfg = load_config().security.url_guard
    except Exception:
        # 配置加载失败时用默认配置
        logger.warning("无法加载 QwenPaw URL Guard 配置，使用默认规则引擎")
        return URLRuleEngine()

    rule_engine = URLRuleEngine(
        blocked_domains=url_cfg.blocked_domains,
        blocked_patterns=url_cfg.blocked_patterns,
        allowed_domains=url_cfg.allowed_domains,
    )

    # 加载自定义规则
    from .url_rule_engine import URLRule
    for cr in url_cfg.custom_rules:
        rule = URLRule(
            id=cr.get("id", f"URL_CUSTOM_{len(url_cfg.custom_rules)}"),
            category=cr.get("category", "network_abuse"),
            severity=cr.get("severity", "HIGH"),
            blocked_domains=cr.get("blocked_domains", []),
            blocked_patterns=cr.get("blocked_patterns", []),
            description=cr.get("description", ""),
            remediation=cr.get("remediation", ""),
            allowed_domains=cr.get("allowed_domains", []),
        )
        rule_engine.add_rule(rule)

    logger.info(
        "URL 规则引擎已从配置创建（blocked_domains=%d, blocked_patterns=%d, "
        "allowed_domains=%d, custom_rules=%d）",
        len(url_cfg.blocked_domains),
        len(url_cfg.blocked_patterns),
        len(url_cfg.allowed_domains),
        len(url_cfg.custom_rules),
    )

    return rule_engine
