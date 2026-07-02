# -*- coding: utf-8 -*-
"""URL-based tool-call guardian.

Scans tool call parameters for URLs and checks them against configurable
blocklists and allowlists.  Supports shell commands (curl, wget) as well
as plain URL params in any tool.

Integration with the guard framework::

    from qwenpaw.security.tool_guard.url_guard import UrlGuardian
    guardian = UrlGuardian()
    findings = guardian.guard("execute_shell_command", {"command": "curl http://evil.com"})
"""
from __future__ import annotations

import ipaddress
import logging
import re
import uuid
from fnmatch import fnmatch
from typing import Any, Iterable
from urllib.parse import urlparse

from ..models import GuardFinding, GuardSeverity, GuardThreatCategory
from ..guardians import BaseToolGuardian

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default block/allow patterns
# ---------------------------------------------------------------------------

# Private / reserved IP ranges we explicitly warn about.
_PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("0.0.0.0/8"),
]

# URL extraction regex.
# Matches http:// and https:// URLs in text, including IPv6 bracket notation.
_URL_RE = re.compile(
    r"https?://"
    r"(?:"
    r"\[[0-9a-fA-F:]+]"        # IPv6 bracket notation: [2001:db8::1]
    r"|"
    r"[^\s<>\"'`{}|\\^\[\]]+"  # regular hostname or IPv4
    r")"
    r"(?::\d{1,5})?"
    r"(?:/[^\s<>\"'`{}|\\^\[\]]*)?",
    re.IGNORECASE,
)

# Tool names whose "command" / "url" params we always inspect.
_URL_AWARE_TOOLS: dict[str, tuple[str, ...]] = {
    "execute_shell_command": ("command",),
    # Future: browser-like tools.
}

# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def extract_urls(text: str) -> list[str]:
    """Extract all http/https URLs from *text*.

    Returns de-duplicated list of URLs in order of first appearance.
    """
    if not text:
        return []
    seen: set[str] = set()
    result: list[str] = []
    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?)")
        low = url.lower()
        if low not in seen:
            seen.add(low)
            result.append(url)
    return result


def _hostname(url: str) -> str:
    """Return the hostname portion of *url*, lowercased."""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _is_loopback(url: str) -> bool:
    """Check if *url* targets localhost / loopback."""
    try:
        host = _hostname(url)
        if host in ("localhost", "127.0.0.1", "::1"):
            return True
        ipaddress.ip_address(host)
        # If it's an IP, check private ranges
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in _PRIVATE_IP_RANGES)
    except ValueError:
        # Not an IP – not loopback unless "localhost"
        return _hostname(url) == "localhost"
    except Exception:
        return False


# ---------------------------------------------------------------------------
# UrlGuardian
# ---------------------------------------------------------------------------


class UrlGuardian(BaseToolGuardian):
    """Guardian that blocks tool calls containing unsafe URLs.

    Parameters
    ----------
    blocked_urls:
        Exact URLs or glob-like patterns to block (e.g. ``"http://evil.com/*"``).
    allowed_urls:
        Whitelist entries that override the blocklist.
    blocked_ip_ranges:
        Additional IP networks in CIDR notation to treat as blocked
        (e.g. ``"10.0.0.0/8"``).
    enabled:
        Override the config-driven enabled flag.
    """

    # Common suspicious TLDs often seen in phishing / C2 domains.
    _SUSPICIOUS_TLDS: frozenset[str] = frozenset({
        "tk", "ml", "ga", "cf", "gq",   # free ccTLDs, often abused
        "xyz", "top", "club", "online", "site", "website",
        "work", "buzz", "live", "icu", "cyou", "rest",
    })

    def __init__(
        self,
        *,
        blocked_urls: Iterable[str] | None = None,
        allowed_urls: Iterable[str] | None = None,
        blocked_ip_ranges: Iterable[str] | None = None,
        enabled: bool | None = None,
    ) -> None:
        super().__init__(name="url_guardian")
        self._enabled = (
            enabled if enabled is not None else _is_url_guard_enabled()
        )
        self._blocked_urls: list[str] = []
        self._allowed_urls: list[str] = []
        self._blocked_ip_ranges: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

        # Load from config first, then overlay constructor args.
        cfg_blocked, cfg_allowed, cfg_ip_ranges = _load_url_guard_config()
        self._blocked_urls.extend(cfg_blocked)
        self._allowed_urls.extend(cfg_allowed)
        self._blocked_ip_ranges.extend(cfg_ip_ranges)

        if blocked_urls is not None:
            self._blocked_urls.extend(blocked_urls)
        if allowed_urls is not None:
            self._allowed_urls.extend(allowed_urls)
        if blocked_ip_ranges is not None:
            for cidr in blocked_ip_ranges:
                self._blocked_ip_ranges.append(ipaddress.ip_network(cidr))

    # ------------------------------------------------------------------
    # Core interface
    # ------------------------------------------------------------------

    def guard(
        self,
        tool_name: str,
        params: dict[str, Any],
    ) -> list[GuardFinding]:
        """Scan tool parameters for URLs that match the blocklist."""
        if not self._enabled:
            return []

        findings: list[GuardFinding] = []

        # Determine which params to scan.
        known_params = _URL_AWARE_TOOLS.get(tool_name)
        if known_params:
            for param_name in known_params:
                raw = params.get(param_name)
                if isinstance(raw, str) and raw.strip():
                    findings.extend(
                        self._scan_value(tool_name, param_name, raw),
                    )
        else:
            # For non-shell tools, scan every string param for URLs.
            for param_name, param_value in params.items():
                if not isinstance(param_value, str) or not param_value.strip():
                    continue
                urls = extract_urls(param_value)
                if urls:
                    for url in urls:
                        findings.extend(
                            self._check_url(tool_name, param_name, url, param_value),
                        )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _scan_value(
        self,
        tool_name: str,
        param_name: str,
        value: str,
    ) -> list[GuardFinding]:
        """Extract URLs from a parameter value and check each one."""
        urls = extract_urls(value)
        if not urls:
            return []

        findings: list[GuardFinding] = []
        for url in urls:
            findings.extend(
                self._check_url(tool_name, param_name, url, value),
            )
        return findings

    def _check_url(
        self,
        tool_name: str,
        param_name: str,
        url: str,
        snippet: str | None = None,
    ) -> list[GuardFinding]:
        """Run all URL safety checks and return findings."""
        findings: list[GuardFinding] = []

        # 1. Check against allowlist first.
        if self._is_allowed(url):
            return findings

        # 2. Check IP-based restrictions.
        is_private = _is_loopback(url)
        host = _hostname(url)

        # Build a list of (rule_id, severity, desc, remediation) tuples.
        blocks: list[tuple[str, GuardSeverity, str, str]] = []

        # 2a. Explicit blocklist match.
        matched_block = self._match_blocklist(url)
        if matched_block:
            blocks.append((
                "URL_BLOCKLIST",
                GuardSeverity.HIGH,
                f"URL '{url}' is on the URL blocklist (matched pattern: {matched_block})",
                "Use an alternative resource or contact admin to whitelist this URL.",
            ))

        # 2b. Loopback / private IP access.
        if is_private:
            blocks.append((
                "URL_LOOPBACK",
                GuardSeverity.HIGH,
                f"URL '{url}' targets a localhost or private network address",
                "Agents should not access internal network services.",
            ))

        # 2c. Suspicious TLD.
        if self._has_suspicious_tld(host):
            blocks.append((
                "URL_SUSPICIOUS_TLD",
                GuardSeverity.MEDIUM,
                f"Domain '{host}' uses a TLD commonly associated with malicious activity",
                "Verify domain legitimacy before proceeding.",
            ))

        # 2d. IP address as hostname (often used to hide intent).
        if self._is_ip_host(host):
            blocks.append((
                "URL_IP_HOST",
                GuardSeverity.LOW,
                f"URL '{url}' uses a raw IP address instead of a domain name",
                "IP-based URLs are harder to identify. Verify intent.",
            ))

        for rule_id, severity, desc, remediation in blocks:
            findings.append(
                GuardFinding(
                    id=f"GUARD-{uuid.uuid4().hex}",
                    rule_id=rule_id,
                    category=GuardThreatCategory.NETWORK_ABUSE,
                    severity=severity,
                    title=f"[{severity.value}] {desc}",
                    description=desc,
                    tool_name=tool_name,
                    param_name=param_name,
                    matched_value=url,
                    matched_pattern=url,
                    snippet=snippet,
                    remediation=remediation,
                    guardian=self.name,
                ),
            )

        return findings

    # --------------------------------------------------------------
    # Matching
    # --------------------------------------------------------------

    def _is_allowed(self, url: str) -> bool:
        """Check against the allowlist (exact or glob)."""
        low = url.lower()
        for pattern in self._allowed_urls:
            if fnmatch(low, pattern.lower()) or fnmatch(
                _hostname(url),
                pattern.lower(),
            ):
                logger.debug("URL '%s' allowed by pattern '%s'", url, pattern)
                return True
        return False

    def _match_blocklist(self, url: str) -> str | None:
        """Return the first blocklist pattern that matches *url*, or None."""
        low = url.lower()
        hl = _hostname(url)
        for pattern in self._blocked_urls:
            pl = pattern.lower()
            if fnmatch(low, pl) or fnmatch(hl, pl):
                return pattern
        return None

    @classmethod
    def _has_suspicious_tld(cls, host: str) -> bool:
        """Return True when *host* uses a known-abused TLD."""
        if not host:
            return False
        parts = host.rsplit(".", 1)
        if len(parts) == 2 and parts[1].lower() in cls._SUSPICIOUS_TLDS:
            return True
        return False

    @staticmethod
    def _is_ip_host(host: str) -> bool:
        """Return True when *host* is an IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Reload
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Refresh enabled state and URL lists from config."""
        self._enabled = _is_url_guard_enabled()
        cfg_blocked, cfg_allowed, cfg_ip_ranges = _load_url_guard_config()
        self._blocked_urls = list(cfg_blocked)
        self._allowed_urls = list(cfg_allowed)
        self._blocked_ip_ranges = list(cfg_ip_ranges)
        logger.info(
            "UrlGuardian reloaded: enabled=%s, blocked=%d, allowed=%d",
            self._enabled,
            len(self._blocked_urls),
            len(self._allowed_urls),
        )


# =========================================================================
# Config helpers
# =========================================================================


def _is_url_guard_enabled() -> bool:
    """Check ``security.url_guard.enabled`` from config."""
    try:
        from qwenpaw.config import load_config

        return bool(load_config().security.url_guard.enabled)
    except Exception:
        return True


def _load_url_guard_config() -> tuple[
    list[str],
    list[str],
    list[ipaddress.IPv4Network | ipaddress.IPv6Network],
]:
    """Load URL guard settings from config.json.

    Returns ``(blocked_urls, allowed_urls, ip_ranges)``.
    """
    try:
        from qwenpaw.config import load_config

        cfg = load_config().security.url_guard
        blocked = list(cfg.blocked_urls or [])
        allowed = list(cfg.allowed_urls or [])
        ip_ranges: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in cfg.blocked_ip_ranges or []:
            try:
                ip_ranges.append(ipaddress.ip_network(cidr))
            except ValueError as exc:
                logger.warning(
                    "Invalid IP range in url_guard.blocked_ip_ranges: %s (%s)",
                    cidr,
                    exc,
                )
        return blocked, allowed, ip_ranges
    except Exception:
        return [], [], []
