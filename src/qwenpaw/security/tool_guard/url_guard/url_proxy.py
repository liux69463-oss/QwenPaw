# -*- coding: utf-8 -*-
"""URL Filter Proxy — 本地 HTTP/HTTPS 过滤代理。

在父进程中启动一个 localhost 代理，通过环境变量注入到 Bash 子进程中，
让子进程的 HTTP 请求经过 URLRuleEngine 审查。

支持：
- HTTP 正向代理：解析请求 URL → check_url() → 403 拦截 / 透传转发
- HTTPS CONNECT 隧道：检查 hostname → 403 拦截 / 建立隧道

设计原则：
- 线程安全：基于 socketserver.ThreadingTCPServer，每个连接独立线程
- 无外部依赖：仅使用 Python 标准库（socket、socketserver、select）
- 零侵入卸载：stop() 后不留痕迹
- 全局入口：get_active_proxy_url() 供 shell.py 注入子进程环境变量
"""
from __future__ import annotations

import logging
import select
import socket
import socketserver
import threading
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from .url_rule_engine import URLRuleEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 模块级全局：活跃代理 URL（供跨模块注入子进程环境变量）
# ---------------------------------------------------------------------------
_active_proxy_url: str | None = None
_active_proxy_lock = threading.Lock()


def get_active_proxy_url() -> str | None:
    """返回当前活跃的 URL 过滤代理地址。

    shell.py 通过此函数获取代理 URL，注入子进程的 HTTP_PROXY 环境变量。
    无活跃代理时返回 None。
    """
    with _active_proxy_lock:
        return _active_proxy_url


def _set_active_proxy_url(url: str | None) -> None:
    global _active_proxy_url
    with _active_proxy_lock:
        _active_proxy_url = url


# ---------------------------------------------------------------------------
# 代理连接处理
# ---------------------------------------------------------------------------

_BUFSIZE = 65536
_RELAY_TIMEOUT = 30  # 秒
_CONNECT_TIMEOUT = 10  # 秒
_MAX_HEADER_SIZE = 65536  # 请求头最大字节数


def _read_until(client: socket.socket, delimiter: bytes, max_size: int) -> bytearray:
    """从 socket 读取数据直到遇到 delimiter 或达到 max_size。"""
    buf = bytearray()
    while len(buf) < max_size:
        chunk = client.recv(min(4096, max_size - len(buf)))
        if not chunk:
            break
        buf.extend(chunk)
        if delimiter in buf:
            idx = buf.index(delimiter)
            # 返回 delimiter 之前的数据 + delimiter
            return buf[: idx + len(delimiter)]
    return buf


def _check_url(rule_engine: URLRuleEngine, url: str) -> str | None:
    """检查 URL，返回拦截原因（None = 放行）。"""
    if not url:
        return None
    result = rule_engine.check_url(url)
    if result.is_blocked:
        logger.warning(
            "代理拦截 URL: %s（规则: %s, 原因: %s）",
            url, result.rule_id, result.reason,
        )
        return result.reason
    return None


def _send_blocked(client: socket.socket, reason: str) -> None:
    """向客户端发送 403 响应。"""
    body = f"URL blocked by QwenPaw URL Filter Proxy: {reason}".encode()
    client.sendall(
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/plain\r\n"
        b"Connection: close\r\n"
        b"Content-Length: %d\r\n\r\n" % len(body)
        + body,
    )


def _relay_response(remote: socket.socket, client: socket.socket) -> None:
    """单向中继：从 remote 读取响应数据，转发给 client。

    用于 HTTP 代理场景（请求已发送完毕，只需等待响应）。
    读取直到 remote 关闭或超时。
    """
    try:
        while True:
            try:
                readable, _, _ = select.select([remote], [], [], _RELAY_TIMEOUT)
            except (ValueError, OSError):
                break

            if not readable:
                break

            try:
                data = remote.recv(_BUFSIZE)
            except (ConnectionResetError, BrokenPipeError, OSError):
                break

            if not data:
                break

            try:
                client.sendall(data)
            except (ConnectionResetError, BrokenPipeError, OSError):
                break
    finally:
        for s in (client, remote):
            try:
                s.close()
            except OSError:
                pass


def _relay(client: socket.socket, remote: socket.socket) -> None:
    """双向数据中继（用于 HTTPS CONNECT 隧道 和 HTTP 透传）。

    使用 select 进行非阻塞双向转发，30 秒无活动超时。
    """
    sockets = [client, remote]
    try:
        while sockets:
            try:
                readable, _, _ = select.select(sockets, [], [], _RELAY_TIMEOUT)
            except (ValueError, OSError):
                # socket 已关闭
                break

            if not readable:
                # 超时无活动
                break

            for sock in readable:
                try:
                    data = sock.recv(_BUFSIZE)
                except (ConnectionResetError, BrokenPipeError, OSError):
                    data = b""

                if not data:
                    sockets.remove(sock)
                    continue

                # 找到对应的另一端
                peer = remote if sock is client else client
                try:
                    peer.sendall(data)
                except (ConnectionResetError, BrokenPipeError, OSError):
                    sockets.remove(sock)
    finally:
        for s in (client, remote):
            try:
                s.close()
            except OSError:
                pass


def _handle_connect(client: socket.socket, target: str, rule_engine: URLRuleEngine) -> None:
    """处理 HTTPS CONNECT 隧道。

    按 RFC 2817：检查 hostname → 403 拦截 / 建立隧道。
    """
    # 解析 hostname:port
    hostname, _, port_str = target.partition(":")
    port = int(port_str) if port_str else 443

    # 构造完整 URL 进行规则检查
    fake_url = f"https://{hostname}/"
    reason = _check_url(rule_engine, fake_url)
    if reason:
        _send_blocked(client, reason)
        return

    # 连接目标服务器
    try:
        remote = socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT)
    except OSError as e:
        logger.debug("代理 CONNECT 连接失败: %s:%d — %s", hostname, port, e)
        body = f"Connection to {hostname}:{port} failed: {e}".encode()
        client.sendall(
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            b"Content-Length: %d\r\n\r\n" % len(body)
            + body,
        )
        return

    # 发送 200 Connection Established
    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    # 双向中继
    _relay(client, remote)


def _handle_http(
    client: socket.socket,
    method: str,
    url_str: str,
    rule_engine: URLRuleEngine,
    header_data: bytes = b"",
    body_extra: bytes = b"",
) -> None:
    """处理 HTTP 正向代理请求。

    检查 URL → 403 拦截 / 连接目标服务器并透传。

    :param header_data: 请求行之后已从客户端读取到的头部数据（含 \\r\\n\\r\\n 终止）。
    :param body_extra: 头部 \\r\\n\\r\\n 之后可能已读取到的请求体数据。
    """
    reason = _check_url(rule_engine, url_str)
    if reason:
        _send_blocked(client, reason)
        return

    # 解析目标
    try:
        parsed = urlparse(url_str)
    except Exception:
        _send_blocked(client, "Invalid URL")
        return

    hostname = parsed.hostname or ""
    port = parsed.port or 80

    if not hostname:
        _send_blocked(client, "Missing hostname")
        return

    # 连接目标服务器
    try:
        remote = socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT)
    except OSError as e:
        logger.debug("代理 HTTP 连接失败: %s:%d — %s", hostname, port, e)
        body = f"Connection failed: {e}".encode()
        client.sendall(
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            b"Content-Length: %d\r\n\r\n" % len(body)
            + body,
        )
        return

    # 构造代理请求行（相对路径）
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    request_line = f"{method} {path} HTTP/1.1\r\n".encode()
    remote.sendall(request_line)

    # 转发已读取的头部（过滤 hop-by-hop 头部，确保 Host 正确）
    if header_data:
        # 提取头部块（截至 \r\n\r\n）
        header_end = header_data.find(b"\r\n\r\n")
        if header_end >= 0:
            header_block = bytearray(header_data[:header_end])
        else:
            header_block = bytearray(header_data)

        filtered = _filter_proxy_headers(header_block, hostname)
        remote.sendall(filtered)

    # 转发已读取的请求体数据
    if body_extra:
        remote.sendall(body_extra)

    # 单向转发响应（remote → client），不等待客户端再发数据
    _relay_response(remote, client)


_HOP_BY_HOP = {
    b"proxy-connection",
    b"proxy-authorization",
    b"proxy-authenticate",
    b"te",
    b"trailers",
    b"transfer-encoding",
    b"upgrade",
}


def _filter_proxy_headers(header_block: bytearray, target_host: str) -> bytes:
    """过滤代理头部：移除 hop-by-hop 头部，确保 Host 指向目标。

    返回过滤后可直接转发的字节。
    """
    lines = header_block.split(b"\r\n")
    filtered: list[bytes] = []
    has_host = False

    for line in lines:
        if line == b"":
            continue
        if b":" in line:
            name = bytes(line.split(b":", 1)[0].strip()).lower()
            if name in _HOP_BY_HOP:
                continue
            if name == b"host":
                has_host = True
        filtered.append(bytes(line))

    if not has_host:
        filtered.append(f"Host: {target_host}".encode())

    return b"\r\n".join(filtered) + b"\r\n\r\n"


def _proxy_handle(client_socket: socket.socket, rule_engine: URLRuleEngine) -> None:
    """代理请求处理入口（每个连接一个线程）。"""
    try:
        # 读取完整请求头（到 \\r\\n\\r\\n）
        header_data = _read_until(client_socket, b"\r\n\r\n", _MAX_HEADER_SIZE)
        if not header_data or b"\r\n\r\n" not in header_data:
            return

        # 解析请求行
        header_str = header_data.decode("utf-8", errors="replace")
        first_line = header_str.split("\r\n")[0]
        parts = first_line.split()
        if len(parts) < 2:
            return

        method, target = parts[0].upper(), parts[1]
        # 提取请求头部分：请求行之后、\r\n\r\n 之前的数据
        first_line_raw = header_data.split(b"\r\n")[0]
        header_rest = header_data[len(first_line_raw) + 2:]  # 跳过第一行 +\r\n
        # 如果读到了请求体数据（\r\n\r\n 之后的部分），先缓存起来
        body_extra = header_rest[header_rest.find(b"\r\n\r\n") + 4:] if b"\r\n\r\n" in header_rest else b""

        if method == "CONNECT":
            _handle_connect(client_socket, target, rule_engine)
        else:
            _handle_http(client_socket, method, target, rule_engine, header_rest, body_extra)

    except Exception:
        logger.debug("代理处理异常", exc_info=True)
    finally:
        try:
            client_socket.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# URLFilterProxy 主类
# ---------------------------------------------------------------------------


class URLFilterProxy:
    """本地 HTTP/HTTPS 过滤代理。

    在后台线程运行，使用 URLRuleEngine 对经过的 HTTP/HTTPS 请求进行安全检查。
    每个连接在独立线程中处理，支持并发。

    :param rule_engine: URL 规则引擎实例。
    :param host: 监听地址（默认 127.0.0.1）。
    :param port: 监听端口（0 = 自动分配）。
    """

    def __init__(
        self,
        rule_engine: URLRuleEngine,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self._rule_engine = rule_engine
        self._host = host
        self._port = port
        self._server: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    @property
    def proxy_url(self) -> str:
        """代理 URL（http://host:port）。"""
        return f"http://{self._host}:{self._port}"

    @property
    def is_running(self) -> bool:
        """代理是否在运行。"""
        return self._server is not None and self._thread is not None and self._thread.is_alive()

    def start(self) -> int:
        """启动代理，返回监听端口号。

        如果已启动则直接返回当前端口（幂等操作）。
        """
        if self.is_running:
            logger.warning("URLFilterProxy 已在运行（端口 %d），跳过重复启动", self._port)
            return self._port

        # 创建 handler 工厂（闭包捕获 rule_engine）
        rule_engine = self._rule_engine

        class _ProxyHandler(socketserver.BaseRequestHandler):
            def handle(self):
                _proxy_handle(self.request, rule_engine)

        try:
            self._server = socketserver.ThreadingTCPServer(
                (self._host, self._port), _ProxyHandler,
            )
            self._port = self._server.server_address[1]
        except OSError as e:
            logger.error("代理启动失败: %s", e)
            raise RuntimeError(f"URLFilterProxy 无法绑定 {self._host}:{self._port}: {e}") from e

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="url-filter-proxy",
            daemon=True,
        )
        self._thread.start()

        # 等待代理线程就绪（serve_forever 已绑定 socket 并开始 accept）
        import time
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if self._thread.is_alive():
                break
            time.sleep(0.01)

        # 注册到全局
        _set_active_proxy_url(self.proxy_url)

        logger.info(
            "URLFilterProxy 已启动: %s（规则引擎: %d 条规则）",
            self.proxy_url, rule_engine.rule_count,
        )
        return self._port

    def stop(self) -> None:
        """停止代理并清理资源。"""
        # 清除全局注册
        _set_active_proxy_url(None)

        server = self._server
        self._server = None

        if server is not None:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                logger.debug("代理 shutdown 异常", exc_info=True)

        thread = self._thread
        self._thread = None

        if thread is not None and thread.is_alive():
            thread.join(timeout=3.0)
            if thread.is_alive():
                logger.warning("URLFilterProxy 线程未能及时退出")

        logger.info("URLFilterProxy 已停止")
