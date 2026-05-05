// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.

package com.yawlabs.awsp;

import java.math.BigInteger;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Sender-side SSRF defense per SPEC.md section 10.
 *
 * <p>A receiver supplies its webhook URL out-of-band (typically the A2A
 * {@code tasks/pushNotificationConfig/set} flow). Without active defense, an
 * attacker controlling that configuration call could point the URL at internal
 * hosts (cloud-metadata IMDS, RFC1918 ranges, loopback, etc.) and trick the
 * sender into making requests on its behalf.
 *
 * <p>{@link #assertPublicUrl(String, Options)} resolves the URL's hostname,
 * rejects any resolved address falling in a private / reserved / link-local /
 * multicast / loopback range, and returns the URI with its host rewritten to
 * the resolved public IP address (defeating DNS-rebinding -- the caller MUST
 * dial the returned URI literally rather than re-resolving the hostname).
 *
 * <p>Stdlib only -- no dependencies. CIDR matching is implemented via
 * {@link BigInteger} arithmetic on the address bytes so the same code path
 * works for IPv4 and IPv6 without an extra library.
 *
 * <p>Typical sender use:
 *
 * <pre>{@code
 * URI safe = Ssrf.assertPublicUrl(receiverWebhookUrl, new Ssrf.Options());
 * // Connect to 'safe' literally; do NOT re-resolve receiverWebhookUrl.
 * }</pre>
 */
public final class Ssrf {

    private Ssrf() {
        // not instantiable
    }

    /** Reasons {@link #assertPublicUrl(String, Options)} rejects a URL. */
    public enum Reason {
        /** The URL was syntactically invalid or missing a host. */
        INVALID_URL,
        /** The URL's scheme was not permitted (HTTPS required unless allowHttp). */
        SCHEME_NOT_ALLOWED,
        /** Hostname resolution failed (NXDOMAIN, network error, etc.). */
        DNS_FAILURE,
        /** At least one resolved address fell in a private / reserved range. */
        PRIVATE_IP,
    }

    /**
     * Thrown by {@link #assertPublicUrl(String, Options)} on any rejection.
     * The {@link #reason} field carries the structured cause; {@link #url}
     * the original input; {@link #resolvedIp} the offending address (if a
     * resolution succeeded before the rejection).
     */
    public static final class SsrfBlockedException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public final Reason reason;
        public final String url;
        /** Null when rejection happened before / during resolution. */
        public final String resolvedIp;

        public SsrfBlockedException(Reason reason, String url, String resolvedIp, String message) {
            super(message);
            this.reason = reason;
            this.url = url;
            this.resolvedIp = resolvedIp;
        }

        public SsrfBlockedException(Reason reason, String url, String resolvedIp, String message, Throwable cause) {
            super(message, cause);
            this.reason = reason;
            this.url = url;
            this.resolvedIp = resolvedIp;
        }
    }

    /** Pluggable hostname resolver. Defaults to {@link InetAddress#getAllByName(String)}. */
    @FunctionalInterface
    public interface Resolver {
        InetAddress[] resolve(String hostname) throws Exception;
    }

    /**
     * Options for {@link #assertPublicUrl(String, Options)}. All fields are
     * mutable; create one and tweak before calling. Defaults are the safe
     * choice for production -- HTTPS only, real DNS resolution.
     */
    public static final class Options {
        /**
         * If true, {@code http://} URLs are permitted. Defaults to false.
         * Senders MUST only enable this for internal test fixtures or with
         * explicit operator opt-in (per SPEC.md section 10).
         */
        public boolean allowHttp = false;

        /**
         * Custom resolver (useful for tests). When null, uses
         * {@link InetAddress#getAllByName(String)}.
         */
        public Resolver resolver = null;
    }

    /**
     * Resolve the URL's hostname, reject if any address falls in a private /
     * reserved range, and return the URI with the host rewritten to the
     * resolved public IP address.
     *
     * <p>The returned URI is the safe target -- callers MUST dial it
     * literally rather than re-resolving the hostname (DNS rebinding defense
     * per SPEC.md section 10 step 3).
     *
     * @throws SsrfBlockedException on any rejection (see {@link Reason}).
     */
    public static URI assertPublicUrl(String rawUrl, Options opts) {
        if (opts == null) {
            opts = new Options();
        }
        if (rawUrl == null || rawUrl.isEmpty()) {
            throw new SsrfBlockedException(Reason.INVALID_URL, rawUrl, null, "url is null or empty");
        }

        URI uri;
        try {
            uri = new URI(rawUrl);
        } catch (URISyntaxException use) {
            throw new SsrfBlockedException(Reason.INVALID_URL, rawUrl, null, "invalid URL: " + use.getMessage(), use);
        }

        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new SsrfBlockedException(Reason.INVALID_URL, rawUrl, null, "missing scheme");
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        if ("https".equals(scheme)) {
            // ok
        } else if ("http".equals(scheme)) {
            if (!opts.allowHttp) {
                throw new SsrfBlockedException(
                        Reason.SCHEME_NOT_ALLOWED,
                        rawUrl,
                        null,
                        "http:// not permitted; set Options.allowHttp=true to override");
            }
        } else {
            throw new SsrfBlockedException(
                    Reason.SCHEME_NOT_ALLOWED, rawUrl, null, "scheme not allowed: " + scheme);
        }

        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new SsrfBlockedException(Reason.INVALID_URL, rawUrl, null, "missing host");
        }
        // URI.getHost wraps literal IPv6 in [..]; strip for resolver and rewrite paths.
        String hostForResolve = host;
        if (hostForResolve.startsWith("[") && hostForResolve.endsWith("]")) {
            hostForResolve = hostForResolve.substring(1, hostForResolve.length() - 1);
        }

        InetAddress[] addresses;
        try {
            Resolver r = opts.resolver != null ? opts.resolver : InetAddress::getAllByName;
            addresses = r.resolve(hostForResolve);
        } catch (UnknownHostException uhe) {
            throw new SsrfBlockedException(
                    Reason.DNS_FAILURE, rawUrl, null, "DNS resolution failed: " + uhe.getMessage(), uhe);
        } catch (Exception e) {
            throw new SsrfBlockedException(
                    Reason.DNS_FAILURE, rawUrl, null, "DNS resolution failed: " + e.getMessage(), e);
        }

        if (addresses == null || addresses.length == 0) {
            throw new SsrfBlockedException(
                    Reason.DNS_FAILURE, rawUrl, null, "DNS resolution returned no addresses");
        }

        // Reject if ANY resolved address is in a blocked range. This is
        // strictly defensive: an attacker who can return both a public IP
        // and a private IP from a single hostname could otherwise rotate
        // through them.
        for (InetAddress addr : addresses) {
            if (isBlocked(addr)) {
                throw new SsrfBlockedException(
                        Reason.PRIVATE_IP,
                        rawUrl,
                        addr.getHostAddress(),
                        "resolved address in blocked range: " + addr.getHostAddress());
            }
        }

        // Rewrite the host to the first resolved (public) IP. This defeats
        // DNS rebinding -- the caller dials the literal IP, not the
        // hostname, so a flip after this resolution cannot redirect the
        // connection.
        InetAddress chosen = addresses[0];
        String literal = chosen.getHostAddress();
        // IPv6 literals must be wrapped in [] in URIs.
        String hostInUri = (chosen instanceof Inet6Address) ? "[" + literal + "]" : literal;

        // Build the rewritten URI by string concatenation so the already-
        // encoded path / query / fragment are preserved verbatim. The
        // 7-arg URI constructor would re-quote reserved characters and
        // could double-encode an already-percent-encoded path.
        StringBuilder sb = new StringBuilder(rawUrl.length() + 16);
        sb.append(scheme).append("://");
        String rawUserInfo = uri.getRawUserInfo();
        if (rawUserInfo != null) {
            sb.append(rawUserInfo).append('@');
        }
        sb.append(hostInUri);
        if (uri.getPort() >= 0) {
            sb.append(':').append(uri.getPort());
        }
        String rawPath = uri.getRawPath();
        if (rawPath != null) {
            sb.append(rawPath);
        }
        String rawQuery = uri.getRawQuery();
        if (rawQuery != null) {
            sb.append('?').append(rawQuery);
        }
        String rawFragment = uri.getRawFragment();
        if (rawFragment != null) {
            sb.append('#').append(rawFragment);
        }
        try {
            return new URI(sb.toString());
        } catch (URISyntaxException use) {
            // Should be impossible -- every component came out of a valid URI.
            throw new SsrfBlockedException(
                    Reason.INVALID_URL, rawUrl, literal, "could not rewrite host: " + use.getMessage(), use);
        }
    }

    // ------------------------------------------------------------------------
    // Block-range tables (SPEC.md section 10).
    // ------------------------------------------------------------------------

    /**
     * IPv4 ranges that MUST be rejected. Ordered as in SPEC.md section 10.
     * Each entry is {@code "<base>/<prefix>"} where base is dotted-quad.
     */
    private static final String[] V4_BLOCKED = {
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",       // RFC 6598 carrier-grade NAT
        "127.0.0.0/8",
        "169.254.0.0/16",      // link-local (includes IMDS 169.254.169.254)
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",        // TEST-NET-1
        "192.168.0.0/16",
        "198.18.0.0/15",       // benchmarking
        "198.51.100.0/24",     // TEST-NET-2
        "203.0.113.0/24",      // TEST-NET-3
        "224.0.0.0/4",         // multicast
        "240.0.0.0/4",         // reserved (includes 255.255.255.255/32)
        "255.255.255.255/32",
    };

    /**
     * IPv6 ranges that MUST be rejected. ::ffff:0:0/96 is handled by extracting
     * the embedded IPv4 and applying the IPv4 rules above.
     */
    private static final String[] V6_BLOCKED = {
        "::/128",
        "::1/128",
        "64:ff9b::/96",        // NAT64 well-known prefix
        "100::/64",            // discard-only address block
        "2001::/23",           // IETF protocol assignments
        "2001:db8::/32",       // documentation
        "fc00::/7",            // ULA
        "fe80::/10",           // link-local
        "ff00::/8",            // multicast
    };

    /** Pre-parsed (network, prefix) pairs for fast lookup. */
    private static final List<Cidr> V4_CIDRS = compile(V4_BLOCKED, true);
    private static final List<Cidr> V6_CIDRS = compile(V6_BLOCKED, false);

    /**
     * Returns true if the given address falls in any IPv4 or IPv6 blocked
     * range. IPv4-mapped IPv6 addresses (::ffff:0:0/96) are unwrapped to
     * their IPv4 form first per SPEC.md section 10.
     */
    static boolean isBlocked(InetAddress addr) {
        byte[] bytes = addr.getAddress();
        if (bytes.length == 4) {
            return matchesAny(bytes, V4_CIDRS);
        }
        if (bytes.length == 16) {
            // IPv4-mapped IPv6: ::ffff:a.b.c.d -- bytes 0..9 are zero,
            // bytes 10..11 are 0xff 0xff, bytes 12..15 are the IPv4 form.
            if (isIpv4Mapped(bytes)) {
                byte[] v4 = new byte[] { bytes[12], bytes[13], bytes[14], bytes[15] };
                return matchesAny(v4, V4_CIDRS);
            }
            return matchesAny(bytes, V6_CIDRS);
        }
        // Unknown address family -- conservative reject.
        return true;
    }

    private static boolean isIpv4Mapped(byte[] bytes) {
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) return false;
        }
        return bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff;
    }

    // ------------------------------------------------------------------------
    // CIDR plumbing.
    // ------------------------------------------------------------------------

    private static final class Cidr {
        final BigInteger network;
        final BigInteger mask;
        final int byteLength;

        Cidr(BigInteger network, BigInteger mask, int byteLength) {
            this.network = network;
            this.mask = mask;
            this.byteLength = byteLength;
        }
    }

    private static List<Cidr> compile(String[] entries, boolean v4) {
        List<Cidr> out = new ArrayList<>(entries.length);
        for (String entry : entries) {
            int slash = entry.indexOf('/');
            if (slash < 0) {
                throw new IllegalStateException("CIDR missing prefix: " + entry);
            }
            String addrPart = entry.substring(0, slash);
            int prefix = Integer.parseInt(entry.substring(slash + 1));
            byte[] bytes;
            try {
                bytes = InetAddress.getByName(addrPart).getAddress();
            } catch (UnknownHostException uhe) {
                throw new IllegalStateException("bad CIDR base: " + entry, uhe);
            }
            int expectedLen = v4 ? 4 : 16;
            if (bytes.length != expectedLen) {
                throw new IllegalStateException("address family mismatch in CIDR: " + entry);
            }
            int totalBits = expectedLen * 8;
            if (prefix < 0 || prefix > totalBits) {
                throw new IllegalStateException("bad prefix length in CIDR: " + entry);
            }
            BigInteger mask = prefix == 0
                    ? BigInteger.ZERO
                    : BigInteger.ONE.shiftLeft(totalBits).subtract(BigInteger.ONE)
                            .subtract(BigInteger.ONE.shiftLeft(totalBits - prefix).subtract(BigInteger.ONE));
            BigInteger network = toBigInt(bytes).and(mask);
            out.add(new Cidr(network, mask, expectedLen));
        }
        return out;
    }

    private static boolean matchesAny(byte[] bytes, List<Cidr> table) {
        BigInteger v = toBigInt(bytes);
        for (Cidr c : table) {
            if (c.byteLength != bytes.length) continue;
            if (v.and(c.mask).equals(c.network)) {
                return true;
            }
        }
        return false;
    }

    /** Treat the byte sequence as an unsigned big-endian integer. */
    private static BigInteger toBigInt(byte[] bytes) {
        // Prepend a zero byte so BigInteger interprets the high bit as
        // unsigned (otherwise an address starting with >=0x80 is negative).
        byte[] padded = new byte[bytes.length + 1];
        padded[0] = 0;
        System.arraycopy(bytes, 0, padded, 1, bytes.length);
        return new BigInteger(padded);
    }
}
