"""Sender-side SSRF defense for Receiver-supplied webhook URLs.

SPEC.md section 10 mandates this. A Receiver supplies its webhook URL
during configuration; without active defense, an attacker controlling
that configuration can point the URL at internal hosts (cloud-metadata
service, RFC 1918 ranges, loopback) and trick the Sender into making
requests on its behalf.

`assert_public_url` resolves the hostname to one or more IP addresses,
rejects the URL if any resolved address falls in a private, reserved,
link-local, multicast, or loopback range, and returns a URL whose
hostname has been rewritten to the resolved public IP. Connecting to
the IP (not the hostname) defeats DNS-rebinding -- the IP we resolved
and gated is the IP we actually connect to.

Stdlib only: `ipaddress`, `socket`, `urllib.parse`. The default
resolver is `socket.getaddrinfo`; pass `resolve=` to inject a stub
for testing.

Caller pattern (requests / httpx):

    from yawlabs_awsp import assert_public_url, SsrfBlockedError

    try:
        safe_url = assert_public_url(receiver_url)
    except SsrfBlockedError as err:
        # log err.reason / err.url / err.resolved_ip; refuse to send
        raise

    # Connect by IP, send the original Host header so TLS / vhosting works.
    parsed = urllib.parse.urlparse(receiver_url)
    requests.post(safe_url, data=body, headers={"Host": parsed.netloc, ...})
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Callable, List, Literal, Optional
from urllib.parse import urlparse, urlunparse

__all__ = ["SsrfBlockedError", "SsrfBlockReason", "assert_public_url"]


SsrfBlockReason = Literal[
    "private_ip",
    "invalid_url",
    "dns_failure",
    "scheme_not_allowed",
]


class SsrfBlockedError(Exception):
    """Raised when a URL fails SSRF gating.

    Attributes:
        reason: One of "private_ip", "invalid_url", "dns_failure",
            "scheme_not_allowed". Stable string suitable for logging /
            metrics.
        url: The URL that was rejected (the original input).
        resolved_ip: The offending IP, if applicable. Populated for
            "private_ip"; None for "invalid_url", "dns_failure",
            "scheme_not_allowed".
    """

    def __init__(
        self,
        reason: SsrfBlockReason,
        url: str,
        message: str,
        *,
        resolved_ip: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.reason: SsrfBlockReason = reason
        self.url: str = url
        self.resolved_ip: Optional[str] = resolved_ip


# IPv4 ranges from SPEC.md section 10. Each entry is (network, label).
# Labels are descriptive, used only in error messages -- the SPEC list
# is authoritative.
_IPV4_BLOCKLIST: tuple[tuple[ipaddress.IPv4Network, str], ...] = (
    (ipaddress.IPv4Network("0.0.0.0/8"), "this-network"),
    (ipaddress.IPv4Network("10.0.0.0/8"), "rfc1918"),
    (ipaddress.IPv4Network("100.64.0.0/10"), "rfc6598-cgnat"),
    (ipaddress.IPv4Network("127.0.0.0/8"), "loopback"),
    (ipaddress.IPv4Network("169.254.0.0/16"), "link-local"),
    (ipaddress.IPv4Network("172.16.0.0/12"), "rfc1918"),
    (ipaddress.IPv4Network("192.0.0.0/24"), "ietf-protocol"),
    (ipaddress.IPv4Network("192.0.2.0/24"), "test-net-1"),
    (ipaddress.IPv4Network("192.168.0.0/16"), "rfc1918"),
    (ipaddress.IPv4Network("198.18.0.0/15"), "benchmark"),
    (ipaddress.IPv4Network("198.51.100.0/24"), "test-net-2"),
    (ipaddress.IPv4Network("203.0.113.0/24"), "test-net-3"),
    (ipaddress.IPv4Network("224.0.0.0/4"), "multicast"),
    (ipaddress.IPv4Network("240.0.0.0/4"), "reserved"),
    (ipaddress.IPv4Network("255.255.255.255/32"), "broadcast"),
)


# IPv6 ranges from SPEC.md section 10. ::ffff:0:0/96 (IPv4-mapped) is
# handled separately below: the embedded IPv4 is extracted and re-checked
# against _IPV4_BLOCKLIST so that, e.g., ::ffff:10.0.0.1 is rejected as
# rfc1918 rather than passing because IPv4-mapped is "just" reserved.
_IPV6_BLOCKLIST: tuple[tuple[ipaddress.IPv6Network, str], ...] = (
    (ipaddress.IPv6Network("::/128"), "unspecified"),
    (ipaddress.IPv6Network("::1/128"), "loopback"),
    (ipaddress.IPv6Network("64:ff9b::/96"), "nat64"),
    (ipaddress.IPv6Network("100::/64"), "discard-only"),
    (ipaddress.IPv6Network("2001::/23"), "ietf-protocol-assignments"),
    (ipaddress.IPv6Network("2001:db8::/32"), "documentation"),
    (ipaddress.IPv6Network("fc00::/7"), "unique-local"),
    (ipaddress.IPv6Network("fe80::/10"), "link-local"),
    (ipaddress.IPv6Network("ff00::/8"), "multicast"),
)


def _default_resolve(host: str) -> List[str]:
    """Default resolver: socket.getaddrinfo, returning all unique IPs."""
    seen: list[str] = []
    for info in socket.getaddrinfo(host, None):
        # info is (family, type, proto, canonname, sockaddr); sockaddr[0]
        # is the IP for both AF_INET and AF_INET6 (IPv6 sockaddr is a
        # 4-tuple but [0] is still the address).
        ip = info[4][0]
        # Strip IPv6 zone identifier if any (e.g. "fe80::1%eth0").
        if "%" in ip:
            ip = ip.split("%", 1)[0]
        if ip not in seen:
            seen.append(ip)
    return seen


def _check_ip(ip_str: str) -> Optional[str]:
    """Return a human label if `ip_str` is in any blocklist range, else None."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Not a parseable IP -- conservative default: block it. Can't
        # safely connect to something we can't even classify.
        return "unparseable-ip"

    if isinstance(ip, ipaddress.IPv4Address):
        for net, label in _IPV4_BLOCKLIST:
            if ip in net:
                return label
        return None

    # IPv6
    assert isinstance(ip, ipaddress.IPv6Address)

    # IPv4-mapped IPv6 (::ffff:0:0/96): check the embedded IPv4 against
    # the v4 blocklist. ipaddress.ip_address on the v4 form returns an
    # IPv4Address directly when we pass ip.ipv4_mapped.
    if ip.ipv4_mapped is not None:
        for net, label in _IPV4_BLOCKLIST:
            if ip.ipv4_mapped in net:
                return f"ipv4-mapped:{label}"
        return None

    for net, label in _IPV6_BLOCKLIST:
        if ip in net:
            return label
    return None


def assert_public_url(
    url: str,
    *,
    allow_http: bool = False,
    resolve: Optional[Callable[[str], List[str]]] = None,
) -> str:
    """Resolve a URL's hostname, reject private/reserved IPs, and return
    the URL with the hostname rewritten to the resolved public IP.

    The returned URL connects by IP (not hostname), defeating DNS-rebinding
    attacks. The original Host header SHOULD be preserved by the caller so
    TLS SNI and HTTP virtual hosting still work; see the module docstring
    for the requests/httpx pattern.

    Args:
        url: The URL to gate. MUST be https:// (or http:// if allow_http
            is True).
        allow_http: Permit http:// scheme. Default False -- spec section
            10 mandates HTTPS, with http:// reserved for sender-internal
            test fixtures or explicit operator opt-in.
        resolve: Optional hostname-to-IP-list resolver. Defaults to
            socket.getaddrinfo. Inject a stub for testing.

    Returns:
        A URL string with the hostname replaced by the first resolved
        public IP. IPv6 addresses are bracketed (e.g. https://[2606:...]/path).

    Raises:
        SsrfBlockedError: If the URL is malformed, the scheme is not
            permitted, DNS resolution fails, or any resolved IP is in
            the SPEC.md section 10 blocklist.
    """
    if not isinstance(url, str) or len(url) == 0:
        # Coerce non-string to string for the exception payload so
        # SsrfBlockedError.url stays well-typed.
        raise SsrfBlockedError(
            "invalid_url", url if isinstance(url, str) else "", "url must be a non-empty string"
        )

    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise SsrfBlockedError("invalid_url", url, f"url parse failed: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme == "https":
        pass
    elif scheme == "http":
        if not allow_http:
            raise SsrfBlockedError(
                "scheme_not_allowed",
                url,
                "http:// scheme not permitted; pass allow_http=True for test fixtures",
            )
    else:
        raise SsrfBlockedError(
            "scheme_not_allowed",
            url,
            f"scheme {scheme!r} not permitted; only https (or http with allow_http) allowed",
        )

    hostname = parsed.hostname
    if hostname is None or len(hostname) == 0:
        raise SsrfBlockedError("invalid_url", url, "url has no hostname")

    resolver = resolve if resolve is not None else _default_resolve

    try:
        ips = resolver(hostname)
    except Exception as exc:
        # socket.getaddrinfo raises socket.gaierror; stub resolvers may
        # raise anything. Treat all resolver failures uniformly.
        raise SsrfBlockedError(
            "dns_failure", url, f"dns resolution failed for {hostname!r}: {exc}"
        ) from exc

    if len(ips) == 0:
        raise SsrfBlockedError(
            "dns_failure", url, f"dns resolution returned no addresses for {hostname!r}"
        )

    for ip_str in ips:
        label = _check_ip(ip_str)
        if label is not None:
            raise SsrfBlockedError(
                "private_ip",
                url,
                f"resolved ip {ip_str} is in blocked range ({label})",
                resolved_ip=ip_str,
            )

    # Rewrite the URL's host to the first resolved public IP.
    target_ip = ips[0]
    try:
        target_obj = ipaddress.ip_address(target_ip)
    except ValueError:
        # Already filtered by _check_ip, so unreachable -- but be safe.
        raise SsrfBlockedError(
            "invalid_url", url, f"resolved ip {target_ip!r} is not parseable"
        )

    if isinstance(target_obj, ipaddress.IPv6Address):
        new_host = f"[{target_ip}]"
    else:
        new_host = target_ip

    new_netloc = new_host
    if parsed.port is not None:
        new_netloc = f"{new_host}:{parsed.port}"
    if parsed.username is not None:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo = f"{userinfo}:{parsed.password}"
        new_netloc = f"{userinfo}@{new_netloc}"

    return urlunparse(
        (
            parsed.scheme,
            new_netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )
