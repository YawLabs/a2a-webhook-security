// AWSP -- A2A Webhook Security Profile reference implementation.
//
// Tests for Sender-side SSRF defense (SPEC.md section 10).
//
// The DNS resolver is stubbed via AssertPublicUrlOptions.Resolve so the suite never touches the
// network. Every CIDR range from the spec is exercised with a representative IP.

using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace YawLabs.Awsp.Tests;

public sealed class SsrfTests
{
    // --------------------------------------------------------------------
    // IPv4 -- one test per CIDR range from SPEC.md section 10.
    // --------------------------------------------------------------------

    [Theory]
    [InlineData("0.0.0.0", "0.0.0.0/8 unspecified / 'this network'")]
    [InlineData("0.1.2.3", "0.0.0.0/8 unspecified / 'this network'")]
    [InlineData("10.0.0.1", "10.0.0.0/8 private")]
    [InlineData("10.255.255.254", "10.0.0.0/8 private")]
    [InlineData("100.64.0.1", "100.64.0.0/10 RFC 6598 CGN")]
    [InlineData("100.127.255.254", "100.64.0.0/10 RFC 6598 CGN")]
    [InlineData("127.0.0.1", "127.0.0.0/8 loopback")]
    [InlineData("127.255.255.254", "127.0.0.0/8 loopback")]
    [InlineData("169.254.169.254", "169.254.0.0/16 link-local incl. cloud metadata")]
    [InlineData("169.254.1.1", "169.254.0.0/16 link-local")]
    [InlineData("172.16.0.1", "172.16.0.0/12 private")]
    [InlineData("172.31.255.254", "172.16.0.0/12 private")]
    [InlineData("192.0.0.1", "192.0.0.0/24 IETF protocol assignments")]
    [InlineData("192.0.2.1", "192.0.2.0/24 TEST-NET-1")]
    [InlineData("192.168.0.1", "192.168.0.0/16 private")]
    [InlineData("192.168.255.254", "192.168.0.0/16 private")]
    [InlineData("198.18.0.1", "198.18.0.0/15 benchmarking")]
    [InlineData("198.19.255.254", "198.18.0.0/15 benchmarking")]
    [InlineData("198.51.100.1", "198.51.100.0/24 TEST-NET-2")]
    [InlineData("203.0.113.1", "203.0.113.0/24 TEST-NET-3")]
    [InlineData("224.0.0.1", "224.0.0.0/4 multicast")]
    [InlineData("239.255.255.254", "224.0.0.0/4 multicast")]
    [InlineData("240.0.0.1", "240.0.0.0/4 reserved")]
    [InlineData("255.255.255.255", "255.255.255.255/32 broadcast (covered by 240.0.0.0/4)")]
    public async Task BlocksIpv4Ranges(string ip, string description)
    {
        _ = description; // kept in [InlineData] for diagnostic readability on failure.
        var ex = await AssertBlocked("https://example.com/path", ip);
        Assert.Equal(SsrfBlockedException.SsrfReason.PrivateIp, ex.Reason);
        Assert.Equal(ip, ex.ResolvedIp);
    }

    // --------------------------------------------------------------------
    // IPv6 -- one test per CIDR range from SPEC.md section 10.
    // --------------------------------------------------------------------

    [Theory]
    [InlineData("::", "::/128 unspecified")]
    [InlineData("::1", "::1/128 loopback")]
    [InlineData("::ffff:10.0.0.1", "::ffff:0:0/96 IPv4-mapped, IPv4 rules apply -- 10/8 inside")]
    [InlineData("::ffff:127.0.0.1", "::ffff:0:0/96 IPv4-mapped -- 127/8 inside")]
    [InlineData("64:ff9b::1", "64:ff9b::/96 well-known NAT64 prefix")]
    [InlineData("100::1", "100::/64 discard prefix")]
    [InlineData("2001::1", "2001::/23 IETF protocol assignments")]
    [InlineData("2001:db8::1", "2001:db8::/32 documentation prefix")]
    [InlineData("fc00::1", "fc00::/7 ULA")]
    [InlineData("fdab:cdef::1", "fc00::/7 ULA -- fd... half")]
    [InlineData("fe80::1", "fe80::/10 link-local")]
    [InlineData("febf:ffff::1", "fe80::/10 link-local upper bound")]
    [InlineData("ff02::1", "ff00::/8 multicast")]
    public async Task BlocksIpv6Ranges(string ip, string description)
    {
        _ = description;
        var ex = await AssertBlocked("https://example.com/path", ip);
        Assert.Equal(SsrfBlockedException.SsrfReason.PrivateIp, ex.Reason);
        Assert.NotNull(ex.ResolvedIp);
    }

    // --------------------------------------------------------------------
    // Public addresses pass and produce a host-rewritten URI.
    // --------------------------------------------------------------------

    [Theory]
    [InlineData("8.8.8.8")]            // public IPv4
    [InlineData("1.1.1.1")]            // public IPv4
    [InlineData("203.0.114.1")]        // just outside 203.0.113.0/24
    [InlineData("198.20.0.1")]         // just outside 198.18.0.0/15
    [InlineData("100.128.0.1")]        // just outside 100.64.0.0/10
    [InlineData("172.32.0.1")]         // just outside 172.16.0.0/12
    public async Task PublicIpv4_PassesAndRewritesHost(string ip)
    {
        var opts = new AssertPublicUrlOptions { Resolve = StubResolver(ip) };
        Uri result = await Ssrf.AssertPublicUrlAsync("https://example.com/path", opts);
        Assert.Equal(ip, result.Host);
        Assert.Equal("https", result.Scheme);
        Assert.Equal("/path", result.AbsolutePath);
    }

    [Theory]
    [InlineData("2606:4700:4700::1111")] // Cloudflare DNS, public
    [InlineData("2001:4860:4860::8888")] // Google DNS, public
    public async Task PublicIpv6_PassesAndRewritesHost(string ip)
    {
        var opts = new AssertPublicUrlOptions { Resolve = StubResolver(ip) };
        Uri result = await Ssrf.AssertPublicUrlAsync("https://example.com/path", opts);
        // IPv6 hosts are bracketed in URIs; UriBuilder strips the brackets when round-tripping
        // through the Host property, but the resulting URI still parses back to the same address.
        Assert.True(IPAddress.TryParse(result.Host.Trim('[', ']'), out IPAddress? parsed));
        Assert.Equal(IPAddress.Parse(ip), parsed);
    }

    // --------------------------------------------------------------------
    // Mixed-result DNS: any private IP poisons the whole result set.
    // --------------------------------------------------------------------

    [Fact]
    public async Task MixedResolution_PrivateInSet_Blocks()
    {
        var opts = new AssertPublicUrlOptions
        {
            Resolve = (host, ct) => Task.FromResult(new[]
            {
                IPAddress.Parse("8.8.8.8"),     // public
                IPAddress.Parse("10.0.0.1"),    // private -- must poison the result
            }),
        };
        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            Ssrf.AssertPublicUrlAsync("https://example.com/", opts));
        Assert.Equal(SsrfBlockedException.SsrfReason.PrivateIp, ex.Reason);
        Assert.Equal("10.0.0.1", ex.ResolvedIp);
    }

    // --------------------------------------------------------------------
    // Invalid URL -- empty, garbage, missing host, missing scheme.
    // --------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("not a url")]
    [InlineData("/relative/path")]
    [InlineData("https://")]
    public async Task InvalidUrl_Throws(string url)
    {
        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            Ssrf.AssertPublicUrlAsync(url, new AssertPublicUrlOptions { Resolve = NeverResolver }));
        Assert.Equal(SsrfBlockedException.SsrfReason.InvalidUrl, ex.Reason);
    }

    // --------------------------------------------------------------------
    // DNS failure surfaces as DnsFailure, not InvalidUrl or PrivateIp.
    // --------------------------------------------------------------------

    [Fact]
    public async Task DnsFailure_ResolverThrows()
    {
        var opts = new AssertPublicUrlOptions
        {
            Resolve = (host, ct) => Task.FromException<IPAddress[]>(
                new System.Net.Sockets.SocketException(11001 /* host not found */)),
        };
        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            Ssrf.AssertPublicUrlAsync("https://nx.example.com/", opts));
        Assert.Equal(SsrfBlockedException.SsrfReason.DnsFailure, ex.Reason);
    }

    [Fact]
    public async Task DnsFailure_ResolverReturnsEmpty()
    {
        var opts = new AssertPublicUrlOptions
        {
            Resolve = (host, ct) => Task.FromResult(Array.Empty<IPAddress>()),
        };
        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            Ssrf.AssertPublicUrlAsync("https://nx.example.com/", opts));
        Assert.Equal(SsrfBlockedException.SsrfReason.DnsFailure, ex.Reason);
    }

    // --------------------------------------------------------------------
    // Scheme rejection -- ftp/file/etc. always rejected; http rejected by default; http allowed
    // with AllowHttp=true.
    // --------------------------------------------------------------------

    [Theory]
    [InlineData("ftp://example.com/")]
    [InlineData("file:///etc/passwd")]
    [InlineData("gopher://example.com/")]
    [InlineData("javascript:alert(1)")]
    public async Task ForbiddenScheme_Rejected(string url)
    {
        // We expect either SchemeNotAllowed or InvalidUrl (some pseudo-schemes don't parse as
        // proper absolute URIs with a host; either rejection is acceptable as defense-in-depth).
        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            Ssrf.AssertPublicUrlAsync(url, new AssertPublicUrlOptions { Resolve = NeverResolver }));
        Assert.True(
            ex.Reason == SsrfBlockedException.SsrfReason.SchemeNotAllowed ||
            ex.Reason == SsrfBlockedException.SsrfReason.InvalidUrl,
            $"expected SchemeNotAllowed or InvalidUrl, got {ex.Reason}");
    }

    [Fact]
    public async Task Http_Rejected_ByDefault()
    {
        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            Ssrf.AssertPublicUrlAsync("http://example.com/",
                new AssertPublicUrlOptions { Resolve = StubResolver("8.8.8.8") }));
        Assert.Equal(SsrfBlockedException.SsrfReason.SchemeNotAllowed, ex.Reason);
    }

    [Fact]
    public async Task Http_Allowed_WhenAllowHttp()
    {
        Uri result = await Ssrf.AssertPublicUrlAsync(
            "http://example.com/path?q=1",
            new AssertPublicUrlOptions { AllowHttp = true, Resolve = StubResolver("8.8.8.8") });
        Assert.Equal("http", result.Scheme);
        Assert.Equal("8.8.8.8", result.Host);
    }

    // --------------------------------------------------------------------
    // Direct IP literals in the URL still get classified -- no DNS bypass.
    // --------------------------------------------------------------------

    [Fact]
    public async Task IpLiteralInUrl_PrivateIsBlocked()
    {
        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            Ssrf.AssertPublicUrlAsync("https://10.0.0.1/path",
                new AssertPublicUrlOptions { Resolve = NeverResolver }));
        Assert.Equal(SsrfBlockedException.SsrfReason.PrivateIp, ex.Reason);
    }

    [Fact]
    public async Task IpLiteralInUrl_PublicIsAccepted()
    {
        Uri result = await Ssrf.AssertPublicUrlAsync(
            "https://8.8.8.8/path",
            new AssertPublicUrlOptions { Resolve = NeverResolver });
        Assert.Equal("8.8.8.8", result.Host);
    }

    [Fact]
    public async Task IpLiteralInUrl_LinkLocalIPv6Blocked()
    {
        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            Ssrf.AssertPublicUrlAsync("https://[fe80::1]/path",
                new AssertPublicUrlOptions { Resolve = NeverResolver }));
        Assert.Equal(SsrfBlockedException.SsrfReason.PrivateIp, ex.Reason);
    }

    // --------------------------------------------------------------------
    // Cancellation propagates from the resolver.
    // --------------------------------------------------------------------

    [Fact]
    public async Task Cancellation_PropagatesFromResolver()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var opts = new AssertPublicUrlOptions
        {
            Resolve = (host, ct) =>
            {
                ct.ThrowIfCancellationRequested();
                return Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") });
            },
        };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Ssrf.AssertPublicUrlAsync("https://example.com/", opts, cts.Token));
    }

    // --------------------------------------------------------------------
    // Helpers.
    // --------------------------------------------------------------------

    private static Func<string, CancellationToken, Task<IPAddress[]>> StubResolver(params string[] ips)
        => (host, ct) => Task.FromResult(ips.Select(IPAddress.Parse).ToArray());

    private static Task<IPAddress[]> NeverResolver(string host, CancellationToken ct)
        => throw new InvalidOperationException("DNS should not have been called for this test.");

    private static async Task<SsrfBlockedException> AssertBlocked(string url, string resolvedIp)
    {
        var opts = new AssertPublicUrlOptions { Resolve = StubResolver(resolvedIp) };
        return await Assert.ThrowsAsync<SsrfBlockedException>(() =>
            Ssrf.AssertPublicUrlAsync(url, opts));
    }
}
