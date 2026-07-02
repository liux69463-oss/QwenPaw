# -*- coding: utf-8 -*-
"""URL Net Guard — HTTP Library Monkey-Patch 层 + 子进程代理。

对 Python HTTP 库（requests、httpx、urllib、aiohttp）进行 monkey-patch，
在每个请求发出前通过 URLRuleEngine 检查 URL 安全性。
支持线程安全的安装和完全可撤销的卸载。

同时管理一个本地 HTTP/HTTPS 过滤代理（URLFilterProxy），
通过环境变量注入到 Bash 子进程中，拦截其 HTTP 请求。

设计原则：
- 线程安全：使用 threading.Lock 保护 patch 安装/卸载
- 零侵入：uninstall() 恢复所有原始方法
- 日志记录：所有拦截事件通过 logging 记录
- 双通道防御：monkey-patch（同进程）+ 代理（子进程）
"""
from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Optional

from .url_blocked_error import URLBlockedError
from .url_proxy import URLFilterProxy
from .url_rule_engine import URLRuleEngine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# localhost / infrastructure bypass
# ---------------------------------------------------------------------------

_LOCALHOST_HOSTNAMES: frozenset[str] = frozenset({
    "127.0.0.1",
    "localhost",
    "::1",
    "0.0.0.0",
})


def _is_localhost_url(url: str) -> bool:
    """Check whether a URL targets localhost or the loopback interface.

    Infrastructure calls (Playwright CDP, health checks, internal RPC)
    must never be intercepted by the monkey-patch.  Phase 1.6 parameter
    scanning in :class:`GovernancePolicy` still applies its own SSRF
    protection independently — this bypass only affects the library-level
    monkey-patch layer.
    """
    try:
        # Quick string-based check (avoids urlparse overhead for
        # the overwhelming majority of external URLs).
        if "://" not in url:
            return False

        # Avoid importing urllib.parse at module level; the import cost
        # is negligible and the function is rarely called (most URLs
        # are external → early-return above).
        from urllib.parse import urlparse

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        return hostname in _LOCALHOST_HOSTNAMES
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 类型辅助
# ---------------------------------------------------------------------------

# 原始方法保存类型
_OriginalMethod = Optional[Callable[..., Any]]


class URLNetGuard:
    """HTTP Library Monkey-Patch 管理器 + 子进程代理。

    对 HTTP 库进行 monkey-patch，在请求发出前拦截不安全的 URL。
    同时管理本地 URLFilterProxy，拦截子进程中的 HTTP 请求。

    :param rule_engine: URL 规则引擎实例。
    :param enable_proxy: 是否启用子进程代理（默认 True）。
    """

    def __init__(self, rule_engine: URLRuleEngine, *, enable_proxy: bool = True) -> None:
        self._rule_engine = rule_engine
        self._lock = threading.Lock()
        self._installed = False

        # 保存原始方法引用（用于卸载恢复）
        self._originals: dict[str, _OriginalMethod] = {}

        # 子进程代理（拦截 Bash 子进程中的 HTTP 请求）
        self._proxy: Optional[URLFilterProxy] = (
            URLFilterProxy(rule_engine) if enable_proxy else None
        )

    # ------------------------------------------------------------------
    # 安装 Monkey-Patch
    # ------------------------------------------------------------------

    def install(self) -> None:
        """安装所有 HTTP 库的 monkey-patch 并启动子进程代理。

        线程安全：使用 Lock 保护安装过程。
        只能安装一次，重复调用会跳过。

        :raises RuntimeError: 当 patch 安装过程中出现不可恢复的错误时。
        """
        with self._lock:
            if self._installed:
                logger.warning("URLNetGuard 已安装，跳过重复安装")
                return

            try:
                self._patch_requests()
                self._patch_urllib()
                self._patch_httpx()
                self._patch_aiohttp()

                # 启动子进程代理
                if self._proxy is not None:
                    self._proxy.start()

                self._installed = True
                logger.info(
                    "URLNetGuard monkey-patch 已安装%s",
                    f"（代理: {self._proxy.proxy_url}）" if self._proxy else "",
                )
            except Exception as e:
                logger.error("URLNetGuard 安装失败: %s", e)
                # 尝试回滚
                self._rollback()
                raise RuntimeError(f"URLNetGuard 安装失败: {e}") from e

    # ------------------------------------------------------------------
    # 卸载 Monkey-Patch
    # ------------------------------------------------------------------

    def uninstall(self) -> None:
        """卸载所有 monkey-patch，停止子进程代理，恢复原始方法。

        线程安全：使用 Lock 保护卸载过程。
        只能卸载一次，重复调用会跳过。
        """
        with self._lock:
            if not self._installed:
                logger.warning("URLNetGuard 未安装，跳过卸载")
                return

            try:
                self._rollback()

                # 停止子进程代理
                if self._proxy is not None:
                    self._proxy.stop()

                self._installed = False
                logger.info("URLNetGuard monkey-patch 已卸载，恢复原始方法")
            except Exception as e:
                logger.error("URLNetGuard 卸载失败: %s", e)
                raise RuntimeError(f"URLNetGuard 卸载失败: {e}") from e

    def _rollback(self) -> None:
        """回滚所有已安装的 patch。"""
        # requests.Session.request
        if "requests.Session.request" in self._originals:
            self._restore_requests_method("request", self._originals["requests.Session.request"])
            del self._originals["requests.Session.request"]

        # requests.Session.send
        if "requests.Session.send" in self._originals:
            self._restore_requests_method("send", self._originals["requests.Session.send"])
            del self._originals["requests.Session.send"]

        # urllib.request.urlopen
        if "urllib.request.urlopen" in self._originals:
            import urllib.request
            urllib.request.urlopen = self._originals["urllib.request.urlopen"]
            del self._originals["urllib.request.urlopen"]

        # httpx.Client.request
        if "httpx.Client.request" in self._originals:
            self._restore_httpx_method("request", self._originals["httpx.Client.request"])
            del self._originals["httpx.Client.request"]

        # aiohttp.ClientSession._request
        if "aiohttp.ClientSession._request" in self._originals:
            self._restore_aiohttp_method("_request", self._originals["aiohttp.ClientSession._request"])
            del self._originals["aiohttp.ClientSession._request"]

    # ------------------------------------------------------------------
    # requests patch
    # ------------------------------------------------------------------

    def _patch_requests(self) -> None:
        """对 requests 库进行 monkey-patch。

        Patch ``requests.Session.request`` 和 ``requests.Session.send``。
        """
        try:
            import requests

            # Patch Session.request（最核心）
            original_request = requests.Session.request
            self._originals["requests.Session.request"] = original_request

            def patched_request(
                self_session: Any,
                method: str,
                url: str,
                **kwargs: Any,
            ) -> Any:
                """requests.Session.request 的 patch 版本。"""
                if _is_localhost_url(url):
                    return original_request(self_session, method, url, **kwargs)
                result = self._rule_engine.check_url(url)
                if result.is_blocked:
                    logger.warning(
                        "requests 拦截 URL: %s（规则: %s, 原因: %s）",
                        url, result.rule_id, result.reason,
                    )
                    raise URLBlockedError(
                        url=url,
                        reason=result.reason,
                        rule_id=result.rule_id,
                    )
                return original_request(self_session, method, url, **kwargs)

            requests.Session.request = patched_request
            logger.debug("已 patch requests.Session.request")

            # Patch Session.send（兜底）
            original_send = requests.Session.send
            self._originals["requests.Session.send"] = original_send

            def patched_send(
                self_session: Any,
                request_obj: Any,
                **kwargs: Any,
            ) -> Any:
                """requests.Session.send 的 patch 版本。"""
                url = str(request_obj.url) if hasattr(request_obj, "url") else ""
                if url and not _is_localhost_url(url):
                    result = self._rule_engine.check_url(url)
                    if result.is_blocked:
                        logger.warning(
                            "requests send 拦截 URL: %s（规则: %s, 原因: %s）",
                            url, result.rule_id, result.reason,
                        )
                        raise URLBlockedError(
                            url=url,
                            reason=result.reason,
                            rule_id=result.rule_id,
                        )
                return original_send(self_session, request_obj, **kwargs)

            requests.Session.send = patched_send
            logger.debug("已 patch requests.Session.send")

        except ImportError:
            logger.debug("requests 库未安装，跳过 patch")

    def _restore_requests_method(
        self, method_name: str, original: Callable[..., Any]
    ) -> None:
        """恢复 requests.Session 的原始方法。

        :param method_name: 方法名（request 或 send）。
        :param original: 原始方法引用。
        """
        try:
            import requests
            setattr(requests.Session, method_name, original)
        except ImportError:
            pass  # 库未安装，无需恢复

    # ------------------------------------------------------------------
    # urllib patch
    # ------------------------------------------------------------------

    def _patch_urllib(self) -> None:
        """对 urllib 标准库进行 monkey-patch。

        Patch ``urllib.request.urlopen``。
        """
        import urllib.request

        original_urlopen = urllib.request.urlopen
        self._originals["urllib.request.urlopen"] = original_urlopen

        def patched_urlopen(url: Any, *args: Any, **kwargs: Any) -> Any:
            """urllib.request.urlopen 的 patch 版本。"""
            url_str = str(url) if not isinstance(url, str) else url
            if _is_localhost_url(url_str):
                return original_urlopen(url, *args, **kwargs)
            result = self._rule_engine.check_url(url_str)
            if result.is_blocked:
                logger.warning(
                    "urllib 拦截 URL: %s（规则: %s, 原因: %s）",
                    url_str, result.rule_id, result.reason,
                )
                raise URLBlockedError(
                    url=url_str,
                    reason=result.reason,
                    rule_id=result.rule_id,
                )
            return original_urlopen(url, *args, **kwargs)

        urllib.request.urlopen = patched_urlopen
        logger.debug("已 patch urllib.request.urlopen")

    # ------------------------------------------------------------------
    # httpx patch
    # ------------------------------------------------------------------

    def _patch_httpx(self) -> None:
        """对 httpx 库进行 monkey-patch。

        Patch ``httpx.Client.request``。
        """
        try:
            import httpx

            original_request = httpx.Client.request
            self._originals["httpx.Client.request"] = original_request

            def patched_request(
                self_client: Any,
                method: str,
                url: Any,
                **kwargs: Any,
            ) -> Any:
                """httpx.Client.request 的 patch 版本。"""
                url_str = str(url)
                if _is_localhost_url(url_str):
                    return original_request(self_client, method, url, **kwargs)
                result = self._rule_engine.check_url(url_str)
                if result.is_blocked:
                    logger.warning(
                        "httpx 拦截 URL: %s（规则: %s, 原因: %s）",
                        url_str, result.rule_id, result.reason,
                    )
                    raise URLBlockedError(
                        url=url_str,
                        reason=result.reason,
                        rule_id=result.rule_id,
                    )
                return original_request(self_client, method, url, **kwargs)

            httpx.Client.request = patched_request
            logger.debug("已 patch httpx.Client.request")

        except ImportError:
            logger.debug("httpx 库未安装，跳过 patch")

    def _restore_httpx_method(
        self, method_name: str, original: Callable[..., Any]
    ) -> None:
        """恢复 httpx.Client 的原始方法。

        :param method_name: 方法名。
        :param original: 原始方法引用。
        """
        try:
            import httpx
            setattr(httpx.Client, method_name, original)
        except ImportError:
            pass  # 库未安装，无需恢复

    # ------------------------------------------------------------------
    # aiohttp patch
    # ------------------------------------------------------------------

    def _patch_aiohttp(self) -> None:
        """对 aiohttp 库进行 monkey-patch。

        Patch ``aiohttp.ClientSession._request``（可选，异步库）。
        """
        try:
            import aiohttp

            original_request = aiohttp.ClientSession._request
            self._originals["aiohttp.ClientSession._request"] = original_request

            async def patched_request(
                self_session: Any,
                method: str,
                url: Any,
                **kwargs: Any,
            ) -> Any:
                """aiohttp.ClientSession._request 的 patch 版本。"""
                url_str = str(url)
                if _is_localhost_url(url_str):
                    return await original_request(self_session, method, url, **kwargs)
                result = self._rule_engine.check_url(url_str)
                if result.is_blocked:
                    logger.warning(
                        "aiohttp 拦截 URL: %s（规则: %s, 原因: %s）",
                        url_str, result.rule_id, result.reason,
                    )
                    raise URLBlockedError(
                        url=url_str,
                        reason=result.reason,
                        rule_id=result.rule_id,
                    )
                return await original_request(self_session, method, url, **kwargs)

            aiohttp.ClientSession._request = patched_request
            logger.debug("已 patch aiohttp.ClientSession._request")

        except ImportError:
            logger.debug("aiohttp 库未安装，跳过 patch")

    def _restore_aiohttp_method(
        self, method_name: str, original: Callable[..., Any]
    ) -> None:
        """恢复 aiohttp.ClientSession 的原始方法。

        :param method_name: 方法名。
        :param original: 原始方法引用。
        """
        try:
            import aiohttp
            setattr(aiohttp.ClientSession, method_name, original)
        except ImportError:
            pass  # 库未安装，无需恢复

    # ------------------------------------------------------------------
    # 属性
    # ------------------------------------------------------------------

    @property
    def is_installed(self) -> bool:
        """返回 monkey-patch 是否已安装。"""
        return self._installed

    @property
    def proxy_url(self) -> Optional[str]:
        """返回子进程代理的 URL 地址，未启用代理时返回 None。

        shell.py 通过此属性获取代理 URL，注入 HTTP_PROXY 环境变量。
        """
        if self._proxy is not None:
            return self._proxy.proxy_url
        return None

    @property
    def is_proxy_running(self) -> bool:
        """返回子进程代理是否正在运行。"""
        return self._proxy is not None and self._proxy.is_running
