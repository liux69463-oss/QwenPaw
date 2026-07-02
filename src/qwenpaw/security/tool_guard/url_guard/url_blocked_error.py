# -*- coding: utf-8 -*-
"""URL Blocked Error — 自定义异常类。

当 URLGuard 拦截一个 URL 访问时抛出此异常，包含被拦截的 URL、
拦截原因以及匹配的规则 ID。

:Example:

>>> error = URLBlockedError(
...     url="http://malware-site.com/payload",
...     reason="匹配恶意域名规则",
...     rule_id="BLOCK_MALICIOUS_DOMAINS"
... )
>>> str(error)
'URLBlockedError: 访问 http://malware-site.com/payload 被拦截（原因：匹配恶意域名规则，规则ID：BLOCK_MALICIOUS_DOMAINS）'
"""
from __future__ import annotations


class URLBlockedError(Exception):
    """URL 拦截异常。

    当 URLGuard 检测到 URL 访问违反安全策略时抛出此异常。

    :param url: 被拦截的 URL 地址。
    :param reason: 拦截原因的描述。
    :param rule_id: 匹配的规则 ID，用于追溯具体规则。
    """

    def __init__(
        self,
        url: str,
        reason: str,
        rule_id: str,
    ) -> None:
        self.url = url
        self.reason = reason
        self.rule_id = rule_id
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        """构建异常消息字符串。"""
        return (
            f"访问 {self.url} 被拦截"
            f"（原因：{self.reason}，规则ID：{self.rule_id}）"
        )

    def __str__(self) -> str:
        """返回清晰的拦截信息。"""
        return f"URLBlockedError: {self._build_message()}"

    def __repr__(self) -> str:
        """返回异常的详细表示。"""
        return (
            f"URLBlockedError(url={self.url!r}, "
            f"reason={self.reason!r}, rule_id={self.rule_id!r})"
        )
