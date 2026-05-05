// AWSP -- A2A Webhook Security Profile reference implementation.
//
// Sender-side SSRF defense (SPEC.md section 10).
//
// A Receiver supplies its webhook URL during configuration. Without active defense, a hostile
// configuration call could point the URL at internal hosts (link-local metadata services, RFC
// 1918 networks, loopback) and trick the Sender into making requests on its behalf.
//
// This module implements the Sender-side checks the spec mandates:
//   1. Resolve the URL's hostname BEFORE connecting.
//   2. Reject the URL if any resolved address falls in a private, reserved, link-local,
//      multicast, or loopback range (full IPv4 + IPv6 list per SPEC.md section 10).
//   3. Return a URI with the host rewritten to the resolved IP literal so the caller can
//      open the connection by IP, defeating DNS-rebinding.
//   4. Refuse non-HTTPS schemes by default; opt-in for http:// via AllowHttp.
//
// Body-size caps, redirect-follow refusal, and total request time are caller responsibilities
// (configure them on HttpClient / HttpClientHandler).

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace YawLabs.Awsp;

/// <summary>
/// Thrown by <see cref="Ssrf.AssertPublicUrlAsync"/> when a URL fails the SSRF gate.
/// </summary>
public class SsrfBlockedException : Exception
{
    /// <summary>Reason taxonomy for blocked URLs.</summary>
    public enum SsrfReason
    {
        /// <summary>The URL resolved to a private, reserved, link-local, multicast, or loopback address.</summary>
        PrivateIp,

        /// <summary>The input could not be parsed as an absolute URL with a host component.</summary>
        InvalidUrl,

        /// <summary>DNS resolution returned no usable addresses or threw.</summary>
        DnsFailure,

        /// <summary>The URL scheme is not allowed (https required by default; http opt-in via options).</summary>
        SchemeNotAllowed,
    }

    /// <summary>Reason this URL was blocked.</summary>
    public SsrfReason Reason { get; }

    /// <summary>The original URL string the caller passed in.</summary>
    public string Url { get; }

    /// <summary>The resolved IP that triggered the block, or <c>null</c> if the failure was pre-DNS.</summary>
    public string? ResolvedIp { get; }

    /// <summary>Construct a new SSRF block.</summary>
    public SsrfBlockedException(SsrfReason reason, string url, string? resolvedIp, string message)
        : base(message)
    {
        Reason = reason;
        Url = url;
        ResolvedIp = resolvedIp;
    }
}

/// <summary>
/// Options for <see cref="Ssrf.AssertPublicUrlAsync"/>.
/// </summary>
public class AssertPublicUrlOptions
{
    /// <summary>
    /// When <c>true</c>, http:// URLs are accepted in addition to https://. Default <c>false</c>.
    /// Per SPEC.md section 10, http MAY be permitted only on Sender-internal test fixtures or
    /// explicit operator opt-in.
    /// </summary>
    public bool AllowHttp { get; init; }

    /// <summary>
    /// Optional DNS resolver override. Defaults to <see cref="Dns.GetHostAddressesAsync(string, CancellationToken)"/>.
    /// Useful in tests to inject deterministic addresses without touching the network.
    /// </summary>
    public Func<string, CancellationToken, Task<IPAddress[]>>? Resolve { get; init; }
}

/// <summary>
/// Sender-side SSRF gate. Resolves a Receiver-supplied URL, rejects private/reserved IPs, and
/// returns a URI rewritten to the resolved public IP literal so the caller can connect by IP
/// and defeat DNS-rebinding.
/// </summary>
public static class Ssrf
{
    /// <summary>
    /// Resolve <paramref name="rawUrl"/>'s hostname, reject private/reserved IPs per SPEC.md
    /// section 10, and return a <see cref="Uri"/> with the host rewritten to the resolved
    /// public IP literal. Throws <see cref="SsrfBlockedException"/> on any failure.
    /// </summary>
    /// <param name="rawUrl">The URL to validate. Must be absolute with a host component.</param>
    /// <param name="opts">Options. <c>null</c> means defaults (https only, system DNS).</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A URI identical to the input except the host is replaced with the resolved IP literal.</returns>
    /// <exception cref="SsrfBlockedException">The URL is invalid, uses a forbidden scheme, fails DNS, or resolves to a non-public address.</exception>
    public static async Task<Uri> AssertPublicUrlAsync(
        string rawUrl,
        AssertPublicUrlOptions? opts = null,
        CancellationToken ct = default)
    {
        opts ??= new AssertPublicUrlOptions();

        if (string.IsNullOrWhiteSpace(rawUrl))
        {
            throw new SsrfBlockedException(
                SsrfBlockedException.SsrfReason.InvalidUrl,
                rawUrl ?? string.Empty,
                null,
                "URL is null, empty, or whitespace.");
        }

        if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out Uri? uri) || string.IsNullOrEmpty(uri.Host))
        {
            throw new SsrfBlockedException(
                SsrfBlockedException.SsrfReason.InvalidUrl,
                rawUrl,
                null,
                "URL is not a valid absolute URI with a host component.");
        }

        // Scheme gate. Default: https only. With AllowHttp: http or https.
        bool isHttps = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        bool isHttp = string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
        if (!isHttps && !(isHttp && opts.AllowHttp))
        {
            throw new SsrfBlockedException(
                SsrfBlockedException.SsrfReason.SchemeNotAllowed,
                rawUrl,
                null,
                $"Scheme '{uri.Scheme}' is not allowed. Use https (or set AllowHttp = true for http).");
        }

        // Resolve. If the host is already an IP literal, IPAddress.TryParse handles it locally;
        // otherwise call out to DNS.
        IPAddress[] addresses;
        if (IPAddress.TryParse(uri.Host, out IPAddress? literal))
        {
            addresses = new[] { literal };
        }
        else
        {
            try
            {
                Func<string, CancellationToken, Task<IPAddress[]>> resolver =
                    opts.Resolve ?? ((host, token) => Dns.GetHostAddressesAsync(host, token));
                addresses = await resolver(uri.Host, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new SsrfBlockedException(
                    SsrfBlockedException.SsrfReason.DnsFailure,
                    rawUrl,
                    null,
                    $"DNS resolution failed for host '{uri.Host}': {ex.Message}");
            }

            if (addresses is null || addresses.Length == 0)
            {
                throw new SsrfBlockedException(
                    SsrfBlockedException.SsrfReason.DnsFailure,
                    rawUrl,
                    null,
                    $"DNS resolution returned no addresses for host '{uri.Host}'.");
            }
        }

        // Reject if ANY resolved address is non-public. The strictest interpretation: a single
        // private IP in the result set means we will not connect, even if a public one is also
        // present (a DNS-rebinding attacker can return a mix and steer the eventual connect
        // toward the private one).
        IPAddress? selected = null;
        foreach (IPAddress addr in addresses)
        {
            IPAddress canonical = NormalizeIpv4Mapped(addr);
            if (!IsPublicAddress(canonical))
            {
                throw new SsrfBlockedException(
                    SsrfBlockedException.SsrfReason.PrivateIp,
                    rawUrl,
                    canonical.ToString(),
                    $"Host '{uri.Host}' resolved to non-public address {canonical}.");
            }
            selected ??= canonical;
        }

        // Rewrite host to the resolved IP literal so the caller connects by IP.
        // IPv6 addresses must be wrapped in brackets in the URI.
        var builder = new UriBuilder(uri);
        if (selected!.AddressFamily == AddressFamily.InterNetworkV6)
        {
            builder.Host = "[" + selected + "]";
        }
        else
        {
            builder.Host = selected.ToString();
        }
        return builder.Uri;
    }

    // ----------------------------------------------------------------------
    // IP classification.
    // ----------------------------------------------------------------------

    /// <summary>
    /// True iff <paramref name="addr"/> is NOT in any of the private/reserved/link-local/
    /// multicast/loopback ranges enumerated in SPEC.md section 10.
    /// </summary>
    /// <remarks>
    /// Internal-visible for tests; the public surface intentionally exposes only the assert API.
    /// </remarks>
    internal static bool IsPublicAddress(IPAddress addr)
    {
        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            return !IsPrivateIPv4(addr);
        }
        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return !IsPrivateIPv6(addr);
        }
        // Anything other than IPv4/IPv6 (e.g. AppleTalk, IPX) is not connectable here -- treat
        // as non-public for safety.
        return false;
    }

    private static IPAddress NormalizeIpv4Mapped(IPAddress addr)
    {
        // ::ffff:a.b.c.d -- the IPv4 rules apply per SPEC.md.
        if (addr.AddressFamily == AddressFamily.InterNetworkV6 && addr.IsIPv4MappedToIPv6)
        {
            return addr.MapToIPv4();
        }
        return addr;
    }

    private static bool IsPrivateIPv4(IPAddress addr)
    {
        byte[] b = addr.GetAddressBytes();

        // 0.0.0.0/8
        if (b[0] == 0) return true;
        // 10.0.0.0/8
        if (b[0] == 10) return true;
        // 100.64.0.0/10 (RFC 6598 carrier-grade NAT)
        if (b[0] == 100 && (b[1] & 0xC0) == 64) return true;
        // 127.0.0.0/8 loopback
        if (b[0] == 127) return true;
        // 169.254.0.0/16 link-local (incl. 169.254.169.254 cloud metadata)
        if (b[0] == 169 && b[1] == 254) return true;
        // 172.16.0.0/12 -- 172.16.0.0 through 172.31.255.255
        if (b[0] == 172 && (b[1] & 0xF0) == 16) return true;
        // 192.0.0.0/24 IETF protocol assignments
        if (b[0] == 192 && b[1] == 0 && b[2] == 0) return true;
        // 192.0.2.0/24 TEST-NET-1
        if (b[0] == 192 && b[1] == 0 && b[2] == 2) return true;
        // 192.168.0.0/16 private
        if (b[0] == 192 && b[1] == 168) return true;
        // 198.18.0.0/15 -- 198.18.0.0 through 198.19.255.255 (benchmarking)
        if (b[0] == 198 && (b[1] & 0xFE) == 18) return true;
        // 198.51.100.0/24 TEST-NET-2
        if (b[0] == 198 && b[1] == 51 && b[2] == 100) return true;
        // 203.0.113.0/24 TEST-NET-3
        if (b[0] == 203 && b[1] == 0 && b[2] == 113) return true;
        // 224.0.0.0/4 multicast (224 .. 239)
        if (b[0] >= 224 && b[0] <= 239) return true;
        // 240.0.0.0/4 reserved (240 .. 255), which subsumes 255.255.255.255/32
        if (b[0] >= 240) return true;

        return false;
    }

    private static bool IsPrivateIPv6(IPAddress addr)
    {
        byte[] b = addr.GetAddressBytes();
        if (b.Length != 16)
        {
            // Defensive -- should not happen for AddressFamily.InterNetworkV6.
            return true;
        }

        // ::/128 unspecified
        bool allZero = true;
        for (int i = 0; i < 16; i++)
        {
            if (b[i] != 0) { allZero = false; break; }
        }
        if (allZero) return true;

        // ::1/128 loopback
        bool isLoopback = true;
        for (int i = 0; i < 15; i++)
        {
            if (b[i] != 0) { isLoopback = false; break; }
        }
        if (isLoopback && b[15] == 1) return true;

        // ::ffff:0:0/96 IPv4-mapped. Already handled by NormalizeIpv4Mapped before reaching
        // here, but keep the guard so a raw IPv4-mapped IPAddress is still flagged.
        if (IsPrefixMatch(b, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF }, 96))
        {
            return true;
        }

        // 64:ff9b::/96 well-known prefix for NAT64. Treat as non-public; if a Sender truly
        // wants NAT64 traversal it must explicitly target the embedded IPv4.
        if (IsPrefixMatch(b, new byte[] { 0x00, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0 }, 96))
        {
            return true;
        }

        // 100::/64 discard prefix
        if (IsPrefixMatch(b, new byte[] { 0x01, 0x00, 0, 0, 0, 0, 0, 0 }, 64))
        {
            return true;
        }

        // 2001::/23 IETF protocol assignments. Note: 2001:db8::/32 (documentation) is OUTSIDE
        // 2001::/23 (the /23 fixes bits 16-22 to zero; 2001:db8 has bit 20-21 set), so both
        // ranges are checked separately below.
        if (IsPrefixMatch(b, new byte[] { 0x20, 0x01, 0x00 }, 23))
        {
            return true;
        }

        // 2001:db8::/32 documentation prefix (disjoint from 2001::/23).
        if (IsPrefixMatch(b, new byte[] { 0x20, 0x01, 0x0D, 0xB8 }, 32))
        {
            return true;
        }

        // fc00::/7 unique local addresses (ULA)
        if ((b[0] & 0xFE) == 0xFC) return true;

        // fe80::/10 link-local
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;

        // ff00::/8 multicast
        if (b[0] == 0xFF) return true;

        return false;
    }

    /// <summary>
    /// Compare the high <paramref name="prefixBits"/> of <paramref name="addr"/> against
    /// <paramref name="prefix"/>. Bits past the prefix in <paramref name="prefix"/> are ignored.
    /// </summary>
    private static bool IsPrefixMatch(byte[] addr, byte[] prefix, int prefixBits)
    {
        int fullBytes = prefixBits / 8;
        int remainderBits = prefixBits % 8;
        int compareBytes = Math.Min(fullBytes, prefix.Length);

        for (int i = 0; i < compareBytes; i++)
        {
            if (addr[i] != prefix[i])
            {
                return false;
            }
        }

        if (remainderBits == 0)
        {
            return true;
        }
        if (fullBytes >= prefix.Length || fullBytes >= addr.Length)
        {
            // Prefix is shorter than the bit count claims -- treat as no match for safety.
            return false;
        }
        int mask = (0xFF << (8 - remainderBits)) & 0xFF;
        return (addr[fullBytes] & mask) == (prefix[fullBytes] & mask);
    }
}
