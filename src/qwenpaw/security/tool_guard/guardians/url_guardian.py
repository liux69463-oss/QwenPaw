# -*- coding: utf-8 -*-
"""URL Tool Guardian — 框架层面的 URL 拦截 Guardian。

继承 BaseToolGuardian（或在独立模式下使用内置 fallback 基类），
从工具参数中提取 URL 并通过 URLRuleEngine 执行安全检查。

URL 提取策略：
1. 已知工具的 URL 参数名映射（类似 FilePathToolGuardian 的 _TOOL_FILE_PARAMS）
2. Shell 命令 URL 提取（正则匹配 curl、wget 等命令的 URL 参数）
3. 通用参数扫描（检查所有字符串参数是否看起来像 URL）
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

from ..url_guard.url_rule_engine import URLRuleEngine, URLCheckResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 独立模式下的 Fallback 基类和数据模型
# ---------------------------------------------------------------------------

try:
    # 嵌入 QwenPaw 时，从真实路径导入基类和数据模型
    from qwenpaw.security.tool_guard.guardians import BaseToolGuardian
    from qwenpaw.security.tool_guard.models import (
        GuardFinding,
        GuardSeverity,
        GuardThreatCategory,
    )
except ImportError:
    # 独立模式：提供 fallback 实现（QwenPaw 未安装时仍可独立运行）
    from abc import ABC, abstractmethod
    from dataclasses import dataclass, field
    from enum import Enum

    class GuardSeverity(str, Enum):
        """安全等级枚举。"""
        CRITICAL = "CRITICAL"
        HIGH = "HIGH"
        MEDIUM = "MEDIUM"
        LOW = "LOW"
        INFO = "INFO"
        SAFE = "SAFE"

    class GuardThreatCategory(str, Enum):
        """威胁类别枚举。"""
        NETWORK_ABUSE = "network_abuse"
        FILE_ACCESS = "file_access"
        COMMAND_INJECTION = "command_injection"
        DATA_LEAK = "data_leak"

    @dataclass
    class GuardFinding:
        """安全检查发现。"""
        id: str
        rule_id: str
        category: GuardThreatCategory
        severity: GuardSeverity
        title: str
        description: str
        tool_name: str
        param_name: Optional[str] = None
        matched_value: Optional[str] = None
        matched_pattern: Optional[str] = None
        snippet: Optional[str] = None
        remediation: Optional[str] = None
        guardian: Optional[str] = None
        metadata: dict[str, Any] = field(default_factory=dict)

    class BaseToolGuardian(ABC):
        """Fallback 基类（独立模式使用）。"""
        def __init__(self, name: str, *, always_run: bool = False) -> None:
            self.name = name
            self.always_run = always_run

        @abstractmethod
        def guard(
            self, tool_name: str, params: dict[str, Any]
        ) -> list[GuardFinding]:
            """检查工具调用的安全性。"""
            ...

        def __repr__(self) -> str:
            return f"<{self.__class__.__name__} name={self.name!r}>"


# ---------------------------------------------------------------------------
# Shell 命令 URL 提取正则
# ---------------------------------------------------------------------------

_SHELL_URL_PATTERNS: list[re.Pattern[str]] = [
    # curl 命令（支持 -X POST、--header 等选项参数在 URL 之前的情况）
    re.compile(r"curl\s+.*?(https?://[^\s'\"<>|;&]+)", re.IGNORECASE),
    # wget 命令（支持 -O、--header 等选项参数在 URL 之前的情况）
    re.compile(r"wget\s+.*?(https?://[^\s'\"<>|;&]+)", re.IGNORECASE),
    # nc 命令（不太常见但覆盖）
    re.compile(r"nc\s+.*?\s(https?://[^\s'\"<>|;&]+)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# URL 外观正则（通用参数扫描用）
# ---------------------------------------------------------------------------

_URL_APPEARANCE_RE = re.compile(r"https?://\S+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# 已知工具的 URL 参数名映射
# ---------------------------------------------------------------------------

_TOOL_URL_PARAMS: dict[str, list[str]] = {
    "web_fetch": ["url"],
    "execute_shell_command": ["command"],
    "browser_use": ["url", "cdp_url"],
}


class URLToolGuardian(BaseToolGuardian):
    """URL 拦截 Guardian。

    检查工具调用参数中的 URL 是否违反安全策略。
    使用 URLRuleEngine 执行实际的 URL 匹配检查。

    :param rule_engine: URL 规则引擎实例。
    :param name: Guardian 名称。
    :param always_run: 是否对所有工具调用都运行此 Guardian。
    """

    def __init__(
        self,
        rule_engine: URLRuleEngine,
        name: str = "url_tool_guardian",
        always_run: bool = True,
    ) -> None:
        super().__init__(name=name, always_run=always_run)
        self._rule_engine = rule_engine

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------

    def guard(
        self, tool_name: str, params: dict[str, Any]
    ) -> list[GuardFinding]:
        """检查工具调用参数中的 URL 安全性。

        :param tool_name: 工具名称。
        :param params: 工具调用参数字典。
        :returns: GuardFinding 列表（空列表表示放行）。
        """
        urls = self._extract_urls(tool_name, params)
        findings: list[GuardFinding] = []

        for url_info in urls:
            url = url_info["url"]
            param_name = url_info["param_name"]
            extraction_method = url_info["method"]

            result: URLCheckResult = self._rule_engine.check_url(url)

            if result.is_blocked:
                finding = self._create_finding(
                    url=url,
                    result=result,
                    tool_name=tool_name,
                    param_name=param_name,
                    extraction_method=extraction_method,
                )
                findings.append(finding)
                logger.warning(
                    "URL 拦截: %s（工具: %s, 参数: %s, 规则: %s, 原因: %s）",
                    url,
                    tool_name,
                    param_name,
                    result.rule_id,
                    result.reason,
                )

        return findings

    # ------------------------------------------------------------------
    # URL 提取
    # ------------------------------------------------------------------

    def _extract_urls(
        self, tool_name: str, params: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """从工具参数中提取所有 URL。

        策略：
        1. 已知工具的参数名映射
        2. Shell 命令 URL 提取
        3. 通用参数扫描

        :param tool_name: 工具名称。
        :param params: 工具参数。
        :returns: URL 信息列表，每个元素包含 url、param_name 和 method。
        """
        urls: list[dict[str, Any]] = []

        # 策略 1: 已知工具的参数名映射
        if tool_name in _TOOL_URL_PARAMS:
            for param_name in _TOOL_URL_PARAMS[tool_name]:
                value = params.get(param_name)
                if value is None:
                    continue
                if isinstance(value, str):
                    extracted = self._extract_urls_from_value(
                        value, param_name, "known_tool_mapping"
                    )
                    urls.extend(extracted)

        # 策略 2: Shell 命令 URL 提取（即使已知工具也会做此检查）
        command = params.get("command")
        if command and isinstance(command, str):
            shell_urls = self._extract_urls_from_shell_command(command)
            # 避免重复（已知工具映射可能已提取过）
            existing_urls = {u["url"] for u in urls}
            for su in shell_urls:
                if su["url"] not in existing_urls:
                    urls.append(su)

        # 策略 3: 通用参数扫描（对所有字符串参数检查）
        for param_name, value in params.items():
            if not isinstance(value, str):
                continue
            # 跳过已经检查过的参数
            if tool_name in _TOOL_URL_PARAMS and param_name in _TOOL_URL_PARAMS[tool_name]:
                continue
            if param_name == "command":
                continue
            extracted = self._extract_urls_from_value(
                value, param_name, "generic_scan"
            )
            # 避免重复
            existing_urls = {u["url"] for u in urls}
            for e in extracted:
                if e["url"] not in existing_urls:
                    urls.append(e)

        return urls

    def _extract_urls_from_value(
        self, value: str, param_name: str, method: str
    ) -> list[dict[str, Any]]:
        """从字符串值中提取 URL。

        :param value: 待检查的字符串值。
        :param param_name: 参数名。
        :param method: 提取方法标识。
        :returns: URL 信息列表。
        """
        urls: list[dict[str, Any]] = []
        matches = _URL_APPEARANCE_RE.findall(value)
        for match in matches:
            # 清理 URL（去掉末尾可能附带的标点）
            url = match.rstrip(",.;:!?)]}'\"")
            urls.append({
                "url": url,
                "param_name": param_name,
                "method": method,
            })
        return urls

    def _extract_urls_from_shell_command(
        self, command: str
    ) -> list[dict[str, Any]]:
        """从 Shell 命令中提取 URL。

        匹配 curl、wget、nc 等命令的 URL 参数。

        :param command: Shell 命令字符串。
        :returns: URL 信息列表。
        """
        urls: list[dict[str, Any]] = []
        for pattern in _SHELL_URL_PATTERNS:
            matches = pattern.findall(command)
            for match in matches:
                urls.append({
                    "url": match,
                    "param_name": "command",
                    "method": "shell_command_extraction",
                })
        return urls

    # ------------------------------------------------------------------
    # GuardFinding 创建
    # ------------------------------------------------------------------

    def _create_finding(
        self,
        url: str,
        result: URLCheckResult,
        tool_name: str,
        param_name: str,
        extraction_method: str,
    ) -> GuardFinding:
        """根据 URL 检查结果创建 GuardFinding。

        :param url: 被拦截的 URL。
        :param result: URL 检查结果。
        :param tool_name: 工具名称。
        :param param_name: 参数名。
        :param extraction_method: URL 提取方法。
        :returns: GuardFinding 对象。
        """
        # 安全转换 severity
        severity_str = result.severity or "HIGH"
        try:
            severity = GuardSeverity(severity_str)
        except ValueError:
            severity = GuardSeverity.HIGH

        # 从匹配到的规则中获取 category，找不到时使用默认值
        category_str = "network_abuse"
        for rule in self._rule_engine.rules:
            if rule.id == result.rule_id:
                category_str = rule.category
                break
        try:
            category = GuardThreatCategory(category_str)
        except ValueError:
            category = GuardThreatCategory.NETWORK_ABUSE if hasattr(GuardThreatCategory, "NETWORK_ABUSE") else "network_abuse"

        return GuardFinding(
            id=f"url_guard_{result.rule_id}_{hash(url) % 10000}",
            rule_id=result.rule_id,
            category=category,
            severity=severity,
            title=f"URL 安全拦截: {url}",
            description=result.reason,
            tool_name=tool_name,
            param_name=param_name,
            matched_value=url,
            matched_pattern=result.matched_pattern,
            remediation=self._get_remediation(result),
            guardian=self.name,
            metadata={
                "url": url,
                "matched_domain": result.matched_domain,
                "extraction_method": extraction_method,
            },
        )

    def _get_remediation(self, result: URLCheckResult) -> str:
        """获取修复建议。

        :param result: URL 检查结果。
        :returns: 修复建议字符串。
        """
        # 从规则中查找 remediation
        for rule in self._rule_engine.rules:
            if rule.id == result.rule_id and rule.remediation:
                return rule.remediation
        # 默认修复建议
        return "请确认 URL 安全后将其添加到白名单"
