# -*- coding: utf-8 -*-
"""URL Rule Engine — URL 规则引擎核心类。

负责加载 YAML 规则文件、执行 URL 匹配检查、运行时动态更新规则。
支持精确域名匹配、正则模式匹配、白名单优先级、内网 IP 检测和通配符域名匹配。

规则格式::

    - id: BLOCK_MALICIOUS_DOMAINS
      category: network_abuse
      severity: CRITICAL
      blocked_domains:
        - "malware-site.com"
        - "phishing-domain.org"
      blocked_patterns:
        - ".*\\.evil\\..*"
      description: "阻止已知恶意域名"
      remediation: "使用安全的替代域名"
"""
from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------


@dataclass
class URLCheckResult:
    """URL 检查结果。

    :param is_blocked: 是否被拦截。
    :param reason: 拦截原因描述（放行时为空字符串）。
    :param rule_id: 匹配的规则 ID（放行时为空字符串）。
    :param severity: 严重等级（放行时为空字符串）。
    :param matched_domain: 匹配的域名（放行时为 None）。
    :param matched_pattern: 匹配的正则模式（放行时为 None）。
    """

    is_blocked: bool = False
    reason: str = ""
    rule_id: str = ""
    severity: str = ""
    matched_domain: Optional[str] = None
    matched_pattern: Optional[str] = None


@dataclass
class URLRule:
    """单条 URL 规则。

    :param id: 规则唯一标识。
    :param category: 威胁类别。
    :param severity: 严重等级。
    :param blocked_domains: 精确域名黑名单。
    :param blocked_patterns: 正则模式黑名单。
    :param description: 规则描述。
    :param remediation: 修复建议。
    :param allowed_domains: 白名单域名（仅在规则级别）。
    """

    id: str
    category: str = "network_abuse"
    severity: str = "HIGH"
    blocked_domains: list[str] = field(default_factory=list)
    blocked_patterns: list[str] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    allowed_domains: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """预编译正则模式以提升匹配性能。"""
        self._compiled_patterns: list[re.Pattern[str]] = [
            re.compile(p) for p in self.blocked_patterns
        ]
        # 构建域名集合用于 O(1) 查找
        self._blocked_domain_set: set[str] = set(self.blocked_domains)
        self._allowed_domain_set: set[str] = set(self.allowed_domains)


# ---------------------------------------------------------------------------
# 内网 IP 检测
# ---------------------------------------------------------------------------

_PRIVATE_IP_PREFIXES: tuple[str, ...] = (
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "192.168.",
    "127.",
)

_LOOPBACK_IPS: tuple[str, ...] = ("127.0.0.1", "0.0.0.0", "::1")


def _is_private_ip(hostname: str) -> bool:
    """检查 hostname 是否为内网/本地 IP 地址。

    支持 RFC 1918 私有地址范围、回环地址、IPv6 本地地址和链路本地地址。

    :param hostname: 待检查的 IP 地址字符串。
    :returns: 如果是内网 IP 则返回 True。
    """
    if hostname in _LOOPBACK_IPS:
        return True
    for prefix in _PRIVATE_IP_PREFIXES:
        if hostname.startswith(prefix):
            return True
    # 使用 ipaddress 模块覆盖 IPv6 及其他地址类型
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        # hostname 不是合法 IP 地址（可能是域名），不做内网检测
        return False


# ---------------------------------------------------------------------------
# URL 规范化
# ---------------------------------------------------------------------------

# IPv4 正则
_IPV4_RE = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)


def _extract_hostname(url: str) -> str:
    """从 URL 中提取 hostname，去掉端口。

    :param url: 待解析的 URL。
    :returns: 提取的 hostname（不含端口）。
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    # hostname 已由 urlparse 去掉端口
    return hostname.lower()


def _is_valid_ipv4(hostname: str) -> bool:
    """检查 hostname 是否为有效的 IPv4 地址。

    :param hostname: 待检查的字符串。
    :returns: 如果是有效 IPv4 地址返回 True。
    """
    match = _IPV4_RE.match(hostname)
    if not match:
        return False
    # 检查每个 octet 是否在 0-255 范围内
    for i in range(1, 5):
        octet = int(match.group(i))
        if octet > 255:
            return False
    return True


def _wildcard_match(pattern: str, hostname: str) -> bool:
    """通配符域名匹配。

    支持 ``*.evil.com`` 匹配 ``sub.evil.com`` 以及 ``evil.com`` 本身，
    也支持纯 ``*`` 通配符匹配所有域名。

    :param pattern: 通配符模式（例如 ``*.evil.com`` 或 ``*``）。
    :param hostname: 待匹配的域名。
    :returns: 是否匹配。
    """
    if pattern == "*":
        return True
    if not pattern.startswith("*."):
        return pattern == hostname

    base_domain = pattern[2:]  # 去掉 "*." 前缀
    # *.evil.com 匹配 sub.evil.com 和 evil.com
    if hostname == base_domain:
        return True
    if hostname.endswith("." + base_domain):
        return True
    return False


# ---------------------------------------------------------------------------
# URLRuleEngine 核心类
# ---------------------------------------------------------------------------


class URLRuleEngine:
    """URL 规则引擎。

    加载 YAML 规则文件和配置级别的规则，执行 URL 匹配检查，
    支持白名单优先、精确域名匹配、正则模式匹配、内网 IP 检测和通配符匹配。

    :param rules_file: YAML 规则文件路径。
    :param blocked_domains: 配置级别的精确域名黑名单。
    :param blocked_patterns: 配置级别的正则模式黑名单。
    :param allowed_domains: 配置级别的白名单域名。
    """

    def __init__(
        self,
        rules_file: Optional[str | Path] = None,
        blocked_domains: Optional[list[str]] = None,
        blocked_patterns: Optional[list[str]] = None,
        allowed_domains: Optional[list[str]] = None,
    ) -> None:
        self._rules: list[URLRule] = []
        self._global_blocked_domains: set[str] = set(blocked_domains or [])
        self._global_blocked_patterns: list[re.Pattern[str]] = [
            re.compile(p) for p in (blocked_patterns or [])
        ]
        self._global_allowed_domains: set[str] = set(allowed_domains or [])

        if rules_file is not None:
            self.load_rules_from_yaml(rules_file)
        elif "*" not in self._global_allowed_domains:
            # 仅在未设置全局白名单通配符时加载默认规则
            # allowed_domains=["*"] 表示禁用模式，不应加载任何默认拦截规则
            default_rules = Path(__file__).parent / "rules" / "url_access_rules.yaml"
            if default_rules.exists():
                self.load_rules_from_yaml(default_rules)
                logger.info("已加载默认 URL 规则文件: %s", default_rules)

    # ------------------------------------------------------------------
    # 规则加载
    # ------------------------------------------------------------------

    def load_rules_from_yaml(self, filepath: str | Path) -> None:
        """从 YAML 文件加载规则。

        :param filepath: YAML 规则文件路径。
        :raises FileNotFoundError: 当规则文件不存在时。
        :raises ValueError: 当规则文件格式不正确时。
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"URL 规则文件不存在: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            raw_rules: Any = yaml.safe_load(f)

        if raw_rules is None:
            logger.warning("URL 规则文件为空: %s", filepath)
            return

        if not isinstance(raw_rules, list):
            raise ValueError(
                f"URL 规则文件格式错误: 期望列表，得到 {type(raw_rules).__name__}"
            )

        for raw in raw_rules:
            if not isinstance(raw, dict):
                raise ValueError(
                    f"URL 规则格式错误: 每条规则应为字典，得到 {type(raw).__name__}"
                )
            rule = URLRule(
                id=raw.get("id", ""),
                category=raw.get("category", "network_abuse"),
                severity=raw.get("severity", "HIGH"),
                blocked_domains=raw.get("blocked_domains", []),
                blocked_patterns=raw.get("blocked_patterns", []),
                description=raw.get("description", ""),
                remediation=raw.get("remediation", ""),
                allowed_domains=raw.get("allowed_domains", []),
            )
            if not rule.id:
                raise ValueError("URL 规则缺少必需的 id 字段")
            self._rules.append(rule)

        logger.info("已从 %s 加载 %d 条 URL 规则", filepath, len(self._rules))

    def add_rule(self, rule: URLRule) -> None:
        """动态添加一条规则。

        :param rule: 要添加的 URLRule 对象。
        """
        self._rules.append(rule)
        logger.debug("已添加 URL 规则: %s", rule.id)

    # ------------------------------------------------------------------
    # URL 检查
    # ------------------------------------------------------------------

    def check_url(self, url: str) -> URLCheckResult:
        """检查 URL 是否应该被拦截。

        执行顺序：
        1. 白名单检查（全局 allowed_domains 优先级最高）
        2. 规则级白名单检查
        3. 内网 IP 检测
        4. 全局精确域名匹配
        5. 规则级精确域名匹配
        6. 全局正则模式匹配
        7. 规则级正则模式匹配

        :param url: 待检查的 URL。
        :returns: URLCheckResult 包含检查结果和详情。
        """
        hostname = _extract_hostname(url)
        if not hostname:
            # 无法解析 hostname 的 URL，放行但不做特殊处理
            return URLCheckResult(is_blocked=False)

        # 1. 全局白名单（最高优先级）
        if self._is_allowed_by_global(hostname):
            return URLCheckResult(is_blocked=False)

        # 2. 规则级白名单
        for rule in self._rules:
            if self._is_allowed_by_rule(hostname, rule):
                return URLCheckResult(is_blocked=False)

        # 3. 内网 IP 检测（IPv4 + IPv6）
        if _is_private_ip(hostname):
            # 检查是否有专门的内网拦截规则
            for rule in self._rules:
                if rule.id == "URL_BLOCK_PRIVATE_NETWORK":
                    return URLCheckResult(
                        is_blocked=True,
                        reason=rule.description,
                        rule_id=rule.id,
                        severity=rule.severity,
                        matched_domain=hostname,
                    )
            # 无专门规则时用默认信息
            return URLCheckResult(
                is_blocked=True,
                reason="访问内网/本地地址（SSRF 防护）",
                rule_id="SSRF_PROTECTION",
                severity="HIGH",
                matched_domain=hostname,
            )

        # 4. 全局精确域名匹配
        if hostname in self._global_blocked_domains:
            return URLCheckResult(
                is_blocked=True,
                reason="域名在全局黑名单中",
                rule_id="GLOBAL_BLOCKED_DOMAIN",
                severity="CRITICAL",
                matched_domain=hostname,
            )

        # 5. 规则级精确域名匹配
        for rule in self._rules:
            if hostname in rule._blocked_domain_set:
                return URLCheckResult(
                    is_blocked=True,
                    reason=rule.description,
                    rule_id=rule.id,
                    severity=rule.severity,
                    matched_domain=hostname,
                )

        # 6. 全局正则模式匹配
        for pattern in self._global_blocked_patterns:
            if pattern.search(url):
                return URLCheckResult(
                    is_blocked=True,
                    reason="URL 匹配全局黑名单模式",
                    rule_id="GLOBAL_BLOCKED_PATTERN",
                    severity="CRITICAL",
                    matched_pattern=pattern.pattern,
                )

        # 7. 规则级正则模式匹配
        for rule in self._rules:
            for compiled_pattern in rule._compiled_patterns:
                if compiled_pattern.search(url):
                    return URLCheckResult(
                        is_blocked=True,
                        reason=rule.description,
                        rule_id=rule.id,
                        severity=rule.severity,
                        matched_pattern=compiled_pattern.pattern,
                    )

        # 所有检查通过，放行
        return URLCheckResult(is_blocked=False)

    def _is_allowed_by_global(self, hostname: str) -> bool:
        """检查 hostname 是否在全局白名单中。

        支持通配符匹配，例如 ``*.safe.com``。

        :param hostname: 待检查的域名。
        :returns: 是否在白名单中。
        """
        for allowed in self._global_allowed_domains:
            if _wildcard_match(allowed, hostname):
                return True
        return False

    def _is_allowed_by_rule(self, hostname: str, rule: URLRule) -> bool:
        """检查 hostname 是否在某条规则的白名单中。

        :param hostname: 待检查的域名。
        :param rule: 规则对象。
        :returns: 是否在规则白名单中。
        """
        for allowed in rule._allowed_domain_set:
            if _wildcard_match(allowed, hostname):
                return True
        return False

    # ------------------------------------------------------------------
    # 动态更新
    # ------------------------------------------------------------------

    def reload(
        self,
        rules_file: Optional[str | Path] = None,
        blocked_domains: Optional[list[str]] = None,
        blocked_patterns: Optional[list[str]] = None,
        allowed_domains: Optional[list[str]] = None,
    ) -> None:
        """运行时动态更新规则。

        清空现有规则并重新加载。可用于热更新配置。

        :param rules_file: 新的 YAML 规则文件路径（None 则不重新加载文件）。
        :param blocked_domains: 新的全局黑名单域名列表。
        :param blocked_patterns: 新的全局黑名单正则列表。
        :param allowed_domains: 新的全局白名单域名列表。
        """
        self._rules.clear()
        self._global_blocked_domains = set(blocked_domains or [])
        self._global_blocked_patterns = [
            re.compile(p) for p in (blocked_patterns or [])
        ]
        self._global_allowed_domains = set(allowed_domains or [])

        if rules_file is not None:
            self.load_rules_from_yaml(rules_file)
        elif "*" not in self._global_allowed_domains:
            default_rules = Path(__file__).parent / "rules" / "url_access_rules.yaml"
            if default_rules.exists():
                self.load_rules_from_yaml(default_rules)

        logger.info("URL 规则引擎已重新加载")

    # ------------------------------------------------------------------
    # 属性访问
    # ------------------------------------------------------------------

    @property
    def rules(self) -> list[URLRule]:
        """返回当前加载的规则列表。"""
        return list(self._rules)

    @property
    def rule_count(self) -> int:
        """返回当前加载的规则数量。"""
        return len(self._rules)
