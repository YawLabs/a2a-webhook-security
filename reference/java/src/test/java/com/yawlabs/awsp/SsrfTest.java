// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.

package com.yawlabs.awsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;

class SsrfTest {

    // -------------------------------------------------------------------------
    // Helpers: deterministic stub resolver so the test suite never touches DNS.
    // -------------------------------------------------------------------------

    /** Resolver that always returns the given address. */
    private static Ssrf.Resolver stubReturning(String literal) {
        return host -> new InetAddress[] { InetAddress.getByName(literal) };
    }

    /** Resolver that always throws {@link UnknownHostException}. */
    private static Ssrf.Resolver stubFailing() {
        return host -> {
            throw new UnknownHostException("unknown host: " + host);
        };
    }

    /** Resolver that returns multiple addresses (first arg shouldn't matter). */
    private static Ssrf.Resolver stubReturningAll(String... literals) {
        InetAddress[] addrs = new InetAddress[literals.length];
        for (int i = 0; i < literals.length; i++) {
            try {
                addrs[i] = InetAddress.getByName(literals[i]);
            } catch (UnknownHostException uhe) {
                throw new RuntimeException(uhe);
            }
        }
        return host -> addrs;
    }

    private static Ssrf.Options optsWith(Ssrf.Resolver r) {
        Ssrf.Options o = new Ssrf.Options();
        o.resolver = r;
        return o;
    }

    private static void assertBlocked(String url, Ssrf.Options opts, Ssrf.Reason reason) {
        Ssrf.SsrfBlockedException ex = assertThrows(
                Ssrf.SsrfBlockedException.class, () -> Ssrf.assertPublicUrl(url, opts));
        assertEquals(reason, ex.reason, () -> "expected " + reason + " for " + url + ", got " + ex.reason
                + " (" + ex.getMessage() + ")");
    }

    // -------------------------------------------------------------------------
    // Happy path.
    // -------------------------------------------------------------------------

    @Test
    void publicIpv4Accepted() {
        URI rewritten = Ssrf.assertPublicUrl(
                "https://example.com/hook", optsWith(stubReturning("93.184.216.34")));
        assertEquals("93.184.216.34", rewritten.getHost());
        assertEquals("/hook", rewritten.getPath());
        assertEquals("https", rewritten.getScheme());
    }

    @Test
    void publicIpv6Accepted() {
        URI rewritten = Ssrf.assertPublicUrl(
                "https://example.com/hook", optsWith(stubReturning("2606:2800:220:1:248:1893:25c8:1946")));
        // IPv6 hosts are wrapped in [..] in URIs.
        assertEquals("[2606:2800:220:1:248:1893:25c8:1946]", rewritten.getHost());
        assertEquals("/hook", rewritten.getPath());
    }

    @Test
    void preservesPortQueryAndPath() {
        URI rewritten = Ssrf.assertPublicUrl(
                "https://example.com:8443/a/b/c?q=1&r=2#frag",
                optsWith(stubReturning("93.184.216.34")));
        assertEquals(8443, rewritten.getPort());
        assertEquals("/a/b/c", rewritten.getPath());
        assertEquals("q=1&r=2", rewritten.getRawQuery());
        assertEquals("frag", rewritten.getRawFragment());
    }

    // -------------------------------------------------------------------------
    // Scheme rejection.
    // -------------------------------------------------------------------------

    @Test
    void httpRejectedByDefault() {
        assertBlocked("http://example.com/x", optsWith(stubReturning("93.184.216.34")), Ssrf.Reason.SCHEME_NOT_ALLOWED);
    }

    @Test
    void httpAllowedWithEscapeHatch() {
        Ssrf.Options o = optsWith(stubReturning("93.184.216.34"));
        o.allowHttp = true;
        URI rewritten = Ssrf.assertPublicUrl("http://example.com/x", o);
        assertEquals("http", rewritten.getScheme());
    }

    @Test
    void unknownSchemeRejected() {
        assertBlocked("file:///etc/passwd", new Ssrf.Options(), Ssrf.Reason.SCHEME_NOT_ALLOWED);
        assertBlocked("ftp://example.com/", new Ssrf.Options(), Ssrf.Reason.SCHEME_NOT_ALLOWED);
        assertBlocked("javascript:alert(1)", new Ssrf.Options(), Ssrf.Reason.SCHEME_NOT_ALLOWED);
        assertBlocked("gopher://example.com/", new Ssrf.Options(), Ssrf.Reason.SCHEME_NOT_ALLOWED);
    }

    // -------------------------------------------------------------------------
    // Invalid URL.
    // -------------------------------------------------------------------------

    @Test
    void nullUrlRejected() {
        assertBlocked(null, new Ssrf.Options(), Ssrf.Reason.INVALID_URL);
    }

    @Test
    void emptyUrlRejected() {
        assertBlocked("", new Ssrf.Options(), Ssrf.Reason.INVALID_URL);
    }

    @Test
    void garbageRejected() {
        assertBlocked("not a url", new Ssrf.Options(), Ssrf.Reason.INVALID_URL);
    }

    @Test
    void missingSchemeRejected() {
        assertBlocked("//example.com/", new Ssrf.Options(), Ssrf.Reason.INVALID_URL);
    }

    @Test
    void missingHostRejected() {
        assertBlocked("https:///path", new Ssrf.Options(), Ssrf.Reason.INVALID_URL);
    }

    // -------------------------------------------------------------------------
    // DNS failure.
    // -------------------------------------------------------------------------

    @Test
    void dnsFailureRejected() {
        Ssrf.SsrfBlockedException ex = assertThrows(
                Ssrf.SsrfBlockedException.class,
                () -> Ssrf.assertPublicUrl("https://no-such-host.example/", optsWith(stubFailing())));
        assertEquals(Ssrf.Reason.DNS_FAILURE, ex.reason);
    }

    @Test
    void dnsEmptyResultRejected() {
        Ssrf.Options o = optsWith(host -> new InetAddress[0]);
        assertBlocked("https://example.com/", o, Ssrf.Reason.DNS_FAILURE);
    }

    // -------------------------------------------------------------------------
    // IPv4 CIDR coverage -- one test per range from SPEC.md section 10.
    // -------------------------------------------------------------------------

    @Test
    void ipv4ZeroBlock() {
        assertBlocked("https://x.test/", optsWith(stubReturning("0.0.0.0")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("0.1.2.3")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4Rfc1918TenBlock() {
        assertBlocked("https://x.test/", optsWith(stubReturning("10.0.0.1")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("10.255.255.255")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4CarrierGradeNatBlock() {
        // 100.64.0.0/10
        assertBlocked("https://x.test/", optsWith(stubReturning("100.64.0.1")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("100.127.255.255")), Ssrf.Reason.PRIVATE_IP);
        // Just outside the range -- 100.128.x.x is public.
        URI ok = Ssrf.assertPublicUrl(
                "https://x.test/", optsWith(stubReturning("100.128.0.1")));
        assertNotNull(ok);
    }

    @Test
    void ipv4LoopbackBlock() {
        assertBlocked("https://x.test/", optsWith(stubReturning("127.0.0.1")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("127.255.255.254")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4LinkLocalAndImdsBlock() {
        // 169.254.0.0/16 includes 169.254.169.254 (cloud IMDS).
        assertBlocked("https://x.test/", optsWith(stubReturning("169.254.169.254")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("169.254.0.1")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4Rfc1918SeventyTwoBlock() {
        // 172.16.0.0/12 -- 172.16.0.0 to 172.31.255.255.
        assertBlocked("https://x.test/", optsWith(stubReturning("172.16.0.1")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("172.31.255.254")), Ssrf.Reason.PRIVATE_IP);
        // 172.32.x is public (just outside).
        URI ok = Ssrf.assertPublicUrl(
                "https://x.test/", optsWith(stubReturning("172.32.0.1")));
        assertNotNull(ok);
    }

    @Test
    void ipv4Rfc1918ProtocolAssignmentsBlock() {
        // 192.0.0.0/24 -- IETF protocol assignments
        assertBlocked("https://x.test/", optsWith(stubReturning("192.0.0.1")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4TestNet1Block() {
        // 192.0.2.0/24
        assertBlocked("https://x.test/", optsWith(stubReturning("192.0.2.5")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4Rfc1918OneNinetyTwoBlock() {
        // 192.168.0.0/16
        assertBlocked("https://x.test/", optsWith(stubReturning("192.168.0.1")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("192.168.255.255")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4BenchmarkingBlock() {
        // 198.18.0.0/15
        assertBlocked("https://x.test/", optsWith(stubReturning("198.18.0.1")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("198.19.255.254")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4TestNet2Block() {
        // 198.51.100.0/24
        assertBlocked("https://x.test/", optsWith(stubReturning("198.51.100.5")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4TestNet3Block() {
        // 203.0.113.0/24
        assertBlocked("https://x.test/", optsWith(stubReturning("203.0.113.5")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4MulticastBlock() {
        // 224.0.0.0/4
        assertBlocked("https://x.test/", optsWith(stubReturning("224.0.0.1")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("239.255.255.255")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4ReservedHighBlock() {
        // 240.0.0.0/4 (includes 255.255.255.255)
        assertBlocked("https://x.test/", optsWith(stubReturning("240.0.0.1")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("255.255.255.255")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv4BroadcastBlock() {
        // 255.255.255.255/32 -- already covered by 240.0.0.0/4 but the spec
        // calls it out separately.
        assertBlocked("https://x.test/", optsWith(stubReturning("255.255.255.255")), Ssrf.Reason.PRIVATE_IP);
    }

    // -------------------------------------------------------------------------
    // IPv6 CIDR coverage.
    // -------------------------------------------------------------------------

    @Test
    void ipv6UnspecifiedBlock() {
        // ::/128
        assertBlocked("https://x.test/", optsWith(stubReturning("::")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv6LoopbackBlock() {
        // ::1/128
        assertBlocked("https://x.test/", optsWith(stubReturning("::1")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv6Ipv4MappedBlock() {
        // ::ffff:0:0/96 -- IPv4-mapped, applies the IPv4 rules.
        // ::ffff:127.0.0.1 -> blocked because 127/8 is blocked.
        assertBlocked(
                "https://x.test/",
                optsWith(stubReturning("::ffff:127.0.0.1")),
                Ssrf.Reason.PRIVATE_IP);
        // ::ffff:10.0.0.1 -> blocked (10/8 private).
        assertBlocked(
                "https://x.test/",
                optsWith(stubReturning("::ffff:10.0.0.1")),
                Ssrf.Reason.PRIVATE_IP);
        // ::ffff:8.8.8.8 -> public (8.8.8.8 is public DNS).
        URI ok = Ssrf.assertPublicUrl(
                "https://x.test/", optsWith(stubReturning("::ffff:8.8.8.8")));
        assertNotNull(ok);
    }

    @Test
    void ipv6Nat64Block() {
        // 64:ff9b::/96
        assertBlocked("https://x.test/", optsWith(stubReturning("64:ff9b::1")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv6DiscardBlock() {
        // 100::/64
        assertBlocked("https://x.test/", optsWith(stubReturning("100::1")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv6IetfProtocolBlock() {
        // 2001::/23
        assertBlocked("https://x.test/", optsWith(stubReturning("2001::1")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff")),
                Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv6DocumentationBlock() {
        // 2001:db8::/32
        assertBlocked("https://x.test/", optsWith(stubReturning("2001:db8::1")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv6UlaBlock() {
        // fc00::/7
        assertBlocked("https://x.test/", optsWith(stubReturning("fc00::1")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("fd12:3456:789a::1")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv6LinkLocalBlock() {
        // fe80::/10
        assertBlocked("https://x.test/", optsWith(stubReturning("fe80::1")), Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void ipv6MulticastBlock() {
        // ff00::/8
        assertBlocked("https://x.test/", optsWith(stubReturning("ff00::1")), Ssrf.Reason.PRIVATE_IP);
        assertBlocked("https://x.test/", optsWith(stubReturning("ff02::1")), Ssrf.Reason.PRIVATE_IP);
    }

    // -------------------------------------------------------------------------
    // Multi-resolution defenses.
    // -------------------------------------------------------------------------

    @Test
    void anyPrivateAddressInResolutionRejects() {
        // If a hostname returns one public AND one private address, reject:
        // an attacker who can return both could rotate through them.
        assertBlocked(
                "https://example.com/",
                optsWith(stubReturningAll("93.184.216.34", "10.0.0.1")),
                Ssrf.Reason.PRIVATE_IP);
    }

    @Test
    void resolvedIpFieldIsSetOnPrivateRejection() {
        Ssrf.SsrfBlockedException ex = assertThrows(
                Ssrf.SsrfBlockedException.class,
                () -> Ssrf.assertPublicUrl("https://example.com/",
                        optsWith(stubReturning("169.254.169.254"))));
        assertEquals(Ssrf.Reason.PRIVATE_IP, ex.reason);
        assertEquals("169.254.169.254", ex.resolvedIp);
        assertEquals("https://example.com/", ex.url);
    }

    @Test
    void resolvedIpFieldNullOnPreResolutionRejection() {
        Ssrf.SsrfBlockedException ex = assertThrows(
                Ssrf.SsrfBlockedException.class,
                () -> Ssrf.assertPublicUrl("ftp://example.com/", new Ssrf.Options()));
        assertEquals(Ssrf.Reason.SCHEME_NOT_ALLOWED, ex.reason);
        assertTrue(ex.resolvedIp == null, "resolvedIp should be null");
    }

    @Test
    void rewrittenHostDiffersFromOriginalForDnsRebindDefense() {
        // The rewritten URI carries the literal IP, not the hostname,
        // so callers dialing it cannot be re-resolved to a private IP later.
        URI rewritten = Ssrf.assertPublicUrl(
                "https://example.com/x", optsWith(stubReturning("93.184.216.34")));
        assertNotEquals("example.com", rewritten.getHost());
        assertEquals("93.184.216.34", rewritten.getHost());
    }

    // -------------------------------------------------------------------------
    // Boundary checks: addresses just outside blocked ranges remain accepted.
    // -------------------------------------------------------------------------

    @Test
    void publicJustOutsideTen() {
        // 11.0.0.1 is public.
        URI ok = Ssrf.assertPublicUrl(
                "https://x.test/", optsWith(stubReturning("11.0.0.1")));
        assertNotNull(ok);
    }

    @Test
    void publicJustOutsideOneSixtyNineLink() {
        // 169.255.0.1 is just past the link-local /16.
        URI ok = Ssrf.assertPublicUrl(
                "https://x.test/", optsWith(stubReturning("169.255.0.1")));
        assertNotNull(ok);
    }

    @Test
    void googleDnsAccepted() {
        URI ok = Ssrf.assertPublicUrl(
                "https://dns.test/", optsWith(stubReturning("8.8.8.8")));
        assertEquals("8.8.8.8", ok.getHost());
    }

    @Test
    void cloudflareDnsAccepted() {
        URI ok = Ssrf.assertPublicUrl(
                "https://dns.test/", optsWith(stubReturning("1.1.1.1")));
        assertEquals("1.1.1.1", ok.getHost());
    }
}
