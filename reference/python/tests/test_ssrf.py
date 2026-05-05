"""SSRF gating tests for assert_public_url.

Spec source of truth: SPEC.md section 10. Every CIDR range listed there
gets at least one test using a stub resolver.
"""

from __future__ import annotations

from typing import Callable, List

import pytest

from yawlabs_awsp import SsrfBlockedError, assert_public_url


def _stub(addrs: List[str]) -> Callable[[str], List[str]]:
    """Build a deterministic resolver stub returning a fixed address list."""
    return lambda host: list(addrs)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_public_ipv4_passes_and_url_rewritten() -> None:
    out = assert_public_url(
        "https://example.com/webhook",
        resolve=_stub(["93.184.216.34"]),
    )
    assert out == "https://93.184.216.34/webhook"


def test_public_ipv6_passes_and_bracketed_in_url() -> None:
    out = assert_public_url(
        "https://example.com/webhook",
        resolve=_stub(["2606:2800:220:1:248:1893:25c8:1946"]),
    )
    assert out == "https://[2606:2800:220:1:248:1893:25c8:1946]/webhook"


def test_url_with_port_preserved() -> None:
    out = assert_public_url(
        "https://example.com:8443/webhook",
        resolve=_stub(["93.184.216.34"]),
    )
    assert out == "https://93.184.216.34:8443/webhook"


def test_url_with_query_and_fragment_preserved() -> None:
    out = assert_public_url(
        "https://example.com/path?a=1&b=2#frag",
        resolve=_stub(["93.184.216.34"]),
    )
    assert out == "https://93.184.216.34/path?a=1&b=2#frag"


def test_url_with_userinfo_preserved() -> None:
    out = assert_public_url(
        "https://user:pass@example.com/webhook",
        resolve=_stub(["93.184.216.34"]),
    )
    assert out == "https://user:pass@93.184.216.34/webhook"


# ---------------------------------------------------------------------------
# IPv4 blocklist coverage -- one per range
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip,description",
    [
        ("0.0.0.0", "this-network 0.0.0.0/8"),
        ("0.255.255.255", "this-network 0.0.0.0/8 high"),
        ("10.0.0.1", "rfc1918 10.0.0.0/8"),
        ("10.255.255.255", "rfc1918 10.0.0.0/8 high"),
        ("100.64.0.1", "rfc6598 cgnat 100.64.0.0/10"),
        ("100.127.255.255", "rfc6598 cgnat 100.64.0.0/10 high"),
        ("127.0.0.1", "loopback 127.0.0.0/8"),
        ("127.255.255.254", "loopback 127.0.0.0/8 high"),
        ("169.254.169.254", "link-local 169.254.0.0/16 -- aws metadata"),
        ("169.254.0.1", "link-local 169.254.0.0/16 low"),
        ("172.16.0.1", "rfc1918 172.16.0.0/12"),
        ("172.31.255.255", "rfc1918 172.16.0.0/12 high"),
        ("192.0.0.1", "ietf-protocol 192.0.0.0/24"),
        ("192.0.2.1", "test-net-1 192.0.2.0/24"),
        ("192.168.0.1", "rfc1918 192.168.0.0/16"),
        ("192.168.255.255", "rfc1918 192.168.0.0/16 high"),
        ("198.18.0.1", "benchmark 198.18.0.0/15"),
        ("198.19.255.255", "benchmark 198.18.0.0/15 high"),
        ("198.51.100.1", "test-net-2 198.51.100.0/24"),
        ("203.0.113.1", "test-net-3 203.0.113.0/24"),
        ("224.0.0.1", "multicast 224.0.0.0/4"),
        ("239.255.255.255", "multicast 224.0.0.0/4 high"),
        ("240.0.0.1", "reserved 240.0.0.0/4"),
        ("254.255.255.255", "reserved 240.0.0.0/4 high"),
        ("255.255.255.255", "broadcast"),
    ],
)
def test_ipv4_blocklist(ip: str, description: str) -> None:
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url(
            "https://internal.example/webhook",
            resolve=_stub([ip]),
        )
    assert exc_info.value.reason == "private_ip"
    assert exc_info.value.resolved_ip == ip


# ---------------------------------------------------------------------------
# IPv6 blocklist coverage -- one per range
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip,description",
    [
        ("::", "unspecified ::/128"),
        ("::1", "loopback ::1/128"),
        ("64:ff9b::1", "nat64 64:ff9b::/96"),
        ("100::1", "discard-only 100::/64"),
        ("2001::1", "ietf-protocol-assignments 2001::/23"),
        ("2001:db8::1", "documentation 2001:db8::/32"),
        ("fc00::1", "unique-local fc00::/7"),
        ("fd00::1", "unique-local fc00::/7 (fd is in fc00::/7)"),
        ("fe80::1", "link-local fe80::/10"),
        ("ff00::1", "multicast ff00::/8"),
        ("ff02::1", "multicast all-nodes"),
    ],
)
def test_ipv6_blocklist(ip: str, description: str) -> None:
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url(
            "https://internal.example/webhook",
            resolve=_stub([ip]),
        )
    assert exc_info.value.reason == "private_ip"
    assert exc_info.value.resolved_ip == ip


# ---------------------------------------------------------------------------
# IPv4-mapped IPv6 -- the v4 rules apply
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mapped",
    [
        "::ffff:10.0.0.1",          # rfc1918 v4 via mapped
        "::ffff:127.0.0.1",         # loopback via mapped
        "::ffff:169.254.169.254",   # link-local / metadata via mapped
        "::ffff:192.168.1.1",       # rfc1918 via mapped
    ],
)
def test_ipv4_mapped_ipv6_uses_v4_rules(mapped: str) -> None:
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url(
            "https://internal.example/webhook",
            resolve=_stub([mapped]),
        )
    assert exc_info.value.reason == "private_ip"


# ---------------------------------------------------------------------------
# Multi-resolver: any blocked IP poisons the URL
# ---------------------------------------------------------------------------


def test_multi_resolve_any_private_ip_blocks() -> None:
    """Resolver returns one public + one private; we must reject."""
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url(
            "https://example.com/webhook",
            resolve=_stub(["93.184.216.34", "10.0.0.1"]),
        )
    assert exc_info.value.reason == "private_ip"
    assert exc_info.value.resolved_ip == "10.0.0.1"


def test_multi_resolve_all_public_uses_first() -> None:
    out = assert_public_url(
        "https://example.com/webhook",
        resolve=_stub(["93.184.216.34", "8.8.8.8"]),
    )
    assert out == "https://93.184.216.34/webhook"


# ---------------------------------------------------------------------------
# Scheme handling
# ---------------------------------------------------------------------------


def test_http_rejected_by_default() -> None:
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url(
            "http://example.com/webhook",
            resolve=_stub(["93.184.216.34"]),
        )
    assert exc_info.value.reason == "scheme_not_allowed"


def test_http_allowed_with_opt_in() -> None:
    out = assert_public_url(
        "http://example.com/webhook",
        allow_http=True,
        resolve=_stub(["93.184.216.34"]),
    )
    assert out == "http://93.184.216.34/webhook"


def test_ftp_scheme_rejected_even_with_allow_http() -> None:
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url(
            "ftp://example.com/file",
            allow_http=True,
            resolve=_stub(["93.184.216.34"]),
        )
    assert exc_info.value.reason == "scheme_not_allowed"


def test_file_scheme_rejected() -> None:
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url("file:///etc/passwd", resolve=_stub([]))
    assert exc_info.value.reason == "scheme_not_allowed"


def test_data_scheme_rejected() -> None:
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url(
            "data:text/plain,hello",
            resolve=_stub(["93.184.216.34"]),
        )
    assert exc_info.value.reason == "scheme_not_allowed"


# ---------------------------------------------------------------------------
# Invalid URL surface
# ---------------------------------------------------------------------------


def test_empty_url_invalid() -> None:
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url("", resolve=_stub([]))
    assert exc_info.value.reason == "invalid_url"


def test_no_hostname_invalid() -> None:
    # https:// with no host
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url("https:///webhook", resolve=_stub([]))
    # Either invalid_url (no hostname) or scheme rejection -- both safe
    assert exc_info.value.reason in ("invalid_url", "scheme_not_allowed")


def test_non_string_url_invalid() -> None:
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url(None, resolve=_stub([]))  # type: ignore[arg-type]
    assert exc_info.value.reason == "invalid_url"


# ---------------------------------------------------------------------------
# DNS failure
# ---------------------------------------------------------------------------


def test_dns_failure_resolver_raises() -> None:
    def boom(host: str) -> List[str]:
        raise OSError("name or service not known")

    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url("https://example.com/", resolve=boom)
    assert exc_info.value.reason == "dns_failure"


def test_dns_failure_empty_resolver_result() -> None:
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url("https://example.com/", resolve=_stub([]))
    assert exc_info.value.reason == "dns_failure"


# ---------------------------------------------------------------------------
# Unparseable IP from resolver -- conservative block
# ---------------------------------------------------------------------------


def test_resolver_returns_garbage_blocked() -> None:
    with pytest.raises(SsrfBlockedError) as exc_info:
        assert_public_url(
            "https://example.com/",
            resolve=_stub(["not-an-ip"]),
        )
    # Conservative default: garbage IP gets treated as private_ip
    # (label "unparseable-ip"). The contract is "doesn't pass through".
    assert exc_info.value.reason == "private_ip"


# ---------------------------------------------------------------------------
# Error attributes are populated
# ---------------------------------------------------------------------------


def test_error_attributes_populated_for_private_ip() -> None:
    try:
        assert_public_url(
            "https://internal.example/x",
            resolve=_stub(["10.1.2.3"]),
        )
    except SsrfBlockedError as exc:
        assert exc.reason == "private_ip"
        assert exc.url == "https://internal.example/x"
        assert exc.resolved_ip == "10.1.2.3"
    else:
        pytest.fail("expected SsrfBlockedError")


def test_error_attributes_populated_for_scheme() -> None:
    try:
        assert_public_url("http://example.com/", resolve=_stub([]))
    except SsrfBlockedError as exc:
        assert exc.reason == "scheme_not_allowed"
        assert exc.url == "http://example.com/"
        assert exc.resolved_ip is None
    else:
        pytest.fail("expected SsrfBlockedError")
