// AWSP Sender-side SSRF defense (SPEC.md section 10).
//
// AssertPublicURL resolves the URL's hostname, rejects any address that
// falls in a private, reserved, link-local, multicast, or loopback range,
// and returns a *url.URL with the host rewritten to the resolved public
// IP. Connecting to that returned URL by IP -- not by hostname -- is what
// defeats DNS-rebinding (the resolved IP becomes the connect target).
//
// Senders MUST gate every Receiver-supplied URL through this check before
// opening a connection. See SPEC.md section 10 and THREAT_MODEL.md.
//
// Zero new dependencies: stdlib net/netip only.

package awsp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// SsrfBlockedError is returned by AssertPublicURL when a URL is rejected.
//
// Reason is one of:
//
//   - "invalid_url"         -- the URL itself failed to parse, or carries
//     an empty host, or has an unparsable port.
//   - "scheme_not_allowed"  -- scheme is not https (and AllowHTTP is false
//     for an http URL, or any other scheme).
//   - "dns_failure"         -- hostname resolution returned no addresses
//     or errored.
//   - "private_ip"          -- at least one resolved address is in a
//     blocked range (see SPEC.md section 10).
//
// URL is the original input string (NOT a sanitized form) so callers can
// log it for triage. ResolvedIP is the address that triggered the
// rejection -- empty when the failure happened before resolution
// (invalid_url, scheme_not_allowed, dns_failure).
type SsrfBlockedError struct {
	Reason     string
	URL        string
	ResolvedIP string
}

// Error implements error.
func (e *SsrfBlockedError) Error() string {
	if e.ResolvedIP != "" {
		return fmt.Sprintf("awsp: SSRF blocked %q: %s (resolved %s)", e.URL, e.Reason, e.ResolvedIP)
	}
	return fmt.Sprintf("awsp: SSRF blocked %q: %s", e.URL, e.Reason)
}

// SSRF rejection-reason sentinels for callers that prefer errors.Is over
// inspecting SsrfBlockedError.Reason directly. AssertPublicURL always
// returns *SsrfBlockedError; these sentinels let callers branch on
// category without a string compare.
var (
	ErrSsrfInvalidURL       = errors.New("invalid_url")
	ErrSsrfSchemeNotAllowed = errors.New("scheme_not_allowed")
	ErrSsrfDNSFailure       = errors.New("dns_failure")
	ErrSsrfPrivateIP        = errors.New("private_ip")
)

// Is supports errors.Is matching against the category sentinels above.
func (e *SsrfBlockedError) Is(target error) bool {
	switch target {
	case ErrSsrfInvalidURL:
		return e.Reason == "invalid_url"
	case ErrSsrfSchemeNotAllowed:
		return e.Reason == "scheme_not_allowed"
	case ErrSsrfDNSFailure:
		return e.Reason == "dns_failure"
	case ErrSsrfPrivateIP:
		return e.Reason == "private_ip"
	}
	return false
}

// AssertPublicURLOptions tunes AssertPublicURL behavior.
//
// Zero-value is valid: AllowHTTP defaults false (https-only), and Resolve
// defaults to net.DefaultResolver.LookupHost.
type AssertPublicURLOptions struct {
	// AllowHTTP, if true, permits http:// in addition to https://.
	// Per SPEC.md section 10, http is allowed only on Sender-internal test
	// fixtures or explicit operator opt-in; default is false.
	AllowHTTP bool

	// Resolve overrides the hostname-resolution step. Useful for tests
	// (stub the resolver) and for callers that want a custom DNS path
	// (e.g. a hardened resolver, a local cache). Returns the list of IP
	// strings the hostname maps to.
	//
	// If nil, net.DefaultResolver.LookupHost is used.
	Resolve func(ctx context.Context, hostname string) ([]string, error)
}

// AssertPublicURL parses rawURL, validates the scheme, resolves the
// hostname, rejects every blocked range from SPEC.md section 10, and
// returns the URL with Host rewritten to the resolved public IP.
//
// The returned URL is intended to be the connect target -- using it
// rewrites the connection from "hostname" to a fixed IP, defeating
// DNS-rebinding attacks where a follow-up resolution would return a
// private address.
//
// Note: the returned URL has Host set to "ip:port" (or "[ip]:port" for
// IPv6). Callers that need to preserve the original Host header for the
// HTTP request itself MUST set Request.Host explicitly to the original
// hostname after substituting the IP into the URL -- otherwise virtual-
// hosted servers will see the wrong Host. The original hostname is
// available on the input rawURL.
//
// On failure returns (nil, *SsrfBlockedError).
func AssertPublicURL(ctx context.Context, rawURL string, opts *AssertPublicURLOptions) (*url.URL, error) {
	if opts == nil {
		opts = &AssertPublicURLOptions{}
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, &SsrfBlockedError{Reason: "invalid_url", URL: rawURL}
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, &SsrfBlockedError{Reason: "invalid_url", URL: rawURL}
	}

	// Scheme check. https is always allowed; http only if AllowHTTP.
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
		// allowed
	case "http":
		if !opts.AllowHTTP {
			return nil, &SsrfBlockedError{Reason: "scheme_not_allowed", URL: rawURL}
		}
	default:
		return nil, &SsrfBlockedError{Reason: "scheme_not_allowed", URL: rawURL}
	}

	hostname := u.Hostname()

	// If the hostname is already an IP literal, validate it directly --
	// no DNS lookup needed.
	if literal, err := netip.ParseAddr(strings.Trim(hostname, "[]")); err == nil {
		if isBlockedAddr(literal) {
			return nil, &SsrfBlockedError{
				Reason:     "private_ip",
				URL:        rawURL,
				ResolvedIP: literal.String(),
			}
		}
		return rewriteHost(u, literal), nil
	}

	resolve := opts.Resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupHost
	}

	addrs, err := resolve(ctx, hostname)
	if err != nil {
		return nil, &SsrfBlockedError{Reason: "dns_failure", URL: rawURL}
	}
	if len(addrs) == 0 {
		return nil, &SsrfBlockedError{Reason: "dns_failure", URL: rawURL}
	}

	// Reject if ANY resolved address falls in a blocked range. This is
	// stricter than "reject if all are blocked" -- one private answer
	// hidden behind a public one is still an SSRF vector if a future
	// connection picks that one.
	var firstPublic netip.Addr
	for _, a := range addrs {
		// LookupHost returns IP strings without zone or brackets.
		ip, err := netip.ParseAddr(a)
		if err != nil {
			// An unparseable address from the resolver is treated as
			// dns_failure -- we cannot reason about its blockedness.
			return nil, &SsrfBlockedError{Reason: "dns_failure", URL: rawURL, ResolvedIP: a}
		}
		if isBlockedAddr(ip) {
			return nil, &SsrfBlockedError{
				Reason:     "private_ip",
				URL:        rawURL,
				ResolvedIP: ip.String(),
			}
		}
		if !firstPublic.IsValid() {
			firstPublic = ip
		}
	}

	return rewriteHost(u, firstPublic), nil
}

// rewriteHost returns a copy of u with Host replaced by the resolved IP
// (preserving the original port). IPv6 addresses are bracketed regardless
// of whether a port is present, so the resulting URL parses unambiguously.
func rewriteHost(u *url.URL, ip netip.Addr) *url.URL {
	out := *u
	port := u.Port()
	hostStr := ip.String()
	if ip.Is6() && !ip.Is4In6() {
		hostStr = "[" + hostStr + "]"
	}
	if port != "" {
		out.Host = hostStr + ":" + port
	} else {
		out.Host = hostStr
	}
	return &out
}

// isBlockedAddr reports whether addr falls in any range SPEC.md section
// 10 mandates Senders reject. Covers IPv4 and IPv6, including
// IPv4-mapped IPv6 (::ffff:0:0/96 -- the inner IPv4 is checked under
// the IPv4 rules).
func isBlockedAddr(addr netip.Addr) bool {
	// Normalize IPv4-mapped IPv6 (::ffff:a.b.c.d) down to the underlying
	// IPv4 -- per spec, "apply the IPv4 rules". Unmap returns the same
	// addr unchanged for non-mapped values.
	addr = addr.Unmap()

	if addr.Is4() {
		return isBlockedV4(addr)
	}
	return isBlockedV6(addr)
}

// blockedV4 is every CIDR from SPEC.md section 10 IPv4 list.
var blockedV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),  // RFC 6598 (CGNAT)
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local (incl. cloud metadata)
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), // TEST-NET-1
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved (covers 255.255.255.255/32)
}

func isBlockedV4(addr netip.Addr) bool {
	for _, p := range blockedV4 {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// blockedV6 is every CIDR from SPEC.md section 10 IPv6 list, EXCLUDING
// ::ffff:0:0/96 (handled via Unmap before this function is called).
var blockedV6 = []netip.Prefix{
	netip.MustParsePrefix("::/128"),        // unspecified
	netip.MustParsePrefix("::1/128"),       // loopback
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64
	netip.MustParsePrefix("100::/64"),      // discard
	netip.MustParsePrefix("2001::/23"),     // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("fc00::/7"),      // unique-local
	netip.MustParsePrefix("fe80::/10"),     // link-local
	netip.MustParsePrefix("ff00::/8"),      // multicast
}

func isBlockedV6(addr netip.Addr) bool {
	for _, p := range blockedV6 {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
