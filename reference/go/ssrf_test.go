// AssertPublicURL coverage. One case per CIDR range from SPEC.md section
// 10, plus invalid URL / DNS failure / scheme rejection / AllowHTTP escape
// hatch.

package awsp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// stubResolver returns a fixed list of IPs for any hostname. Used to make
// the SSRF tests deterministic without hitting real DNS.
func stubResolver(addrs ...string) func(context.Context, string) ([]string, error) {
	return func(_ context.Context, _ string) ([]string, error) {
		return addrs, nil
	}
}

func TestAssertPublicURL_BlockedV4Ranges(t *testing.T) {
	// One representative IP per CIDR from SPEC.md section 10 IPv4 list.
	cases := []struct {
		name string
		ip   string
	}{
		{"0.0.0.0/8", "0.0.0.0"},
		{"0.0.0.0/8 mid", "0.255.1.2"},
		{"10.0.0.0/8", "10.0.0.1"},
		{"100.64.0.0/10 (CGNAT)", "100.64.0.1"},
		{"127.0.0.0/8 (loopback)", "127.0.0.1"},
		{"169.254.0.0/16 (link-local / cloud metadata)", "169.254.169.254"},
		{"172.16.0.0/12", "172.16.0.1"},
		{"192.0.0.0/24", "192.0.0.5"},
		{"192.0.2.0/24 (TEST-NET-1)", "192.0.2.10"},
		{"192.168.0.0/16", "192.168.1.1"},
		{"198.18.0.0/15 (benchmarking)", "198.18.0.1"},
		{"198.51.100.0/24 (TEST-NET-2)", "198.51.100.5"},
		{"203.0.113.0/24 (TEST-NET-3)", "203.0.113.5"},
		{"224.0.0.0/4 (multicast)", "224.0.0.1"},
		{"240.0.0.0/4 (reserved)", "240.0.0.1"},
		{"255.255.255.255/32 (broadcast)", "255.255.255.255"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := AssertPublicURL(context.Background(), "https://example.com/x",
				&AssertPublicURLOptions{Resolve: stubResolver(tc.ip)})
			var sse *SsrfBlockedError
			if !errors.As(err, &sse) {
				t.Fatalf("err = %v, want *SsrfBlockedError", err)
			}
			if sse.Reason != "private_ip" {
				t.Errorf("Reason = %q, want private_ip", sse.Reason)
			}
			if sse.ResolvedIP != tc.ip {
				t.Errorf("ResolvedIP = %q, want %q", sse.ResolvedIP, tc.ip)
			}
			if !errors.Is(err, ErrSsrfPrivateIP) {
				t.Errorf("errors.Is(err, ErrSsrfPrivateIP) = false")
			}
		})
	}
}

func TestAssertPublicURL_BlockedV6Ranges(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"::/128 (unspecified)", "::"},
		{"::1/128 (loopback)", "::1"},
		{"::ffff:0:0/96 IPv4-mapped (loopback inner)", "::ffff:127.0.0.1"},
		{"::ffff:0:0/96 IPv4-mapped (private inner)", "::ffff:10.0.0.1"},
		{"64:ff9b::/96 (NAT64)", "64:ff9b::1"},
		{"100::/64 (discard)", "100::1"},
		{"2001::/23 (IETF protocol)", "2001:0:0:1::1"},
		{"2001:db8::/32 (documentation)", "2001:db8::1"},
		{"fc00::/7 (unique-local)", "fc00::1"},
		{"fd00::/8 inside fc00::/7", "fd12::1"},
		{"fe80::/10 (link-local)", "fe80::1"},
		{"ff00::/8 (multicast)", "ff02::1"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := AssertPublicURL(context.Background(), "https://example.com/x",
				&AssertPublicURLOptions{Resolve: stubResolver(tc.ip)})
			var sse *SsrfBlockedError
			if !errors.As(err, &sse) {
				t.Fatalf("err = %v, want *SsrfBlockedError", err)
			}
			if sse.Reason != "private_ip" {
				t.Errorf("Reason = %q, want private_ip (got err %v)", sse.Reason, err)
			}
			if !errors.Is(err, ErrSsrfPrivateIP) {
				t.Errorf("errors.Is(err, ErrSsrfPrivateIP) = false")
			}
		})
	}
}

func TestAssertPublicURL_PublicAllowed(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		// expectedHost is what the rewritten URL.Host should contain
		// (with port, if any). The input URL has no explicit port, so
		// we don't append one -- url.Port() returns "" and net/http
		// applies the scheme default at dial time.
		expectedHost string
	}{
		{"public IPv4", "8.8.8.8", "8.8.8.8"},
		{"another public IPv4", "1.1.1.1", "1.1.1.1"},
		{"public IPv6 google DNS", "2001:4860:4860::8888", "[2001:4860:4860::8888]"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			out, err := AssertPublicURL(context.Background(), "https://example.com/x",
				&AssertPublicURLOptions{Resolve: stubResolver(tc.ip)})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if out == nil {
				t.Fatal("nil URL on success")
			}
			if out.Host != tc.expectedHost {
				t.Errorf("Host = %q, want %q", out.Host, tc.expectedHost)
			}
			if out.Path != "/x" {
				t.Errorf("Path = %q, want /x", out.Path)
			}
		})
	}
}

func TestAssertPublicURL_PreservesNonDefaultPort(t *testing.T) {
	out, err := AssertPublicURL(context.Background(), "https://example.com:8443/y",
		&AssertPublicURLOptions{Resolve: stubResolver("8.8.8.8")})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out.Host != "8.8.8.8:8443" {
		t.Errorf("Host = %q, want 8.8.8.8:8443", out.Host)
	}
}

func TestAssertPublicURL_AnyBlockedAmongMultipleRejects(t *testing.T) {
	// First answer is public, second is private. Spec mandates "if any
	// resolved address falls in a blocked range" -- reject.
	_, err := AssertPublicURL(context.Background(), "https://example.com/",
		&AssertPublicURLOptions{Resolve: stubResolver("8.8.8.8", "10.0.0.1")})
	var sse *SsrfBlockedError
	if !errors.As(err, &sse) {
		t.Fatalf("err = %v, want *SsrfBlockedError", err)
	}
	if sse.Reason != "private_ip" {
		t.Errorf("Reason = %q, want private_ip", sse.Reason)
	}
	if sse.ResolvedIP != "10.0.0.1" {
		t.Errorf("ResolvedIP = %q, want 10.0.0.1 (the offending one)", sse.ResolvedIP)
	}
}

func TestAssertPublicURL_IPLiteralHostBlocked(t *testing.T) {
	// IP literals don't go through the resolver; they're checked directly.
	_, err := AssertPublicURL(context.Background(), "https://127.0.0.1/x", nil)
	if !errors.Is(err, ErrSsrfPrivateIP) {
		t.Fatalf("err = %v, want ErrSsrfPrivateIP", err)
	}
}

func TestAssertPublicURL_IPLiteralHostV6Blocked(t *testing.T) {
	_, err := AssertPublicURL(context.Background(), "https://[::1]/x", nil)
	if !errors.Is(err, ErrSsrfPrivateIP) {
		t.Fatalf("err = %v, want ErrSsrfPrivateIP", err)
	}
}

func TestAssertPublicURL_IPLiteralHostPublic(t *testing.T) {
	out, err := AssertPublicURL(context.Background(), "https://8.8.8.8/x", nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out.Host != "8.8.8.8" {
		t.Errorf("Host = %q, want 8.8.8.8", out.Host)
	}
}

func TestAssertPublicURL_InvalidURL(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"control char in scheme", "ht\x00tps://example.com"},
		{"empty host", "https:///path"},
		{"empty string", ""},
		{"no scheme", "example.com/foo"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := AssertPublicURL(context.Background(), tc.raw,
				&AssertPublicURLOptions{Resolve: stubResolver("8.8.8.8")})
			if err == nil {
				t.Fatal("expected error")
			}
			var sse *SsrfBlockedError
			if !errors.As(err, &sse) {
				t.Fatalf("err = %v, want *SsrfBlockedError", err)
			}
			// "no scheme" routes through scheme_not_allowed, the others
			// through invalid_url; both are valid SSRF blocks.
			if sse.Reason != "invalid_url" && sse.Reason != "scheme_not_allowed" {
				t.Errorf("Reason = %q, want invalid_url or scheme_not_allowed", sse.Reason)
			}
		})
	}
}

func TestAssertPublicURL_DNSFailure(t *testing.T) {
	failingResolver := func(_ context.Context, _ string) ([]string, error) {
		return nil, errors.New("nxdomain")
	}
	_, err := AssertPublicURL(context.Background(), "https://example.com/x",
		&AssertPublicURLOptions{Resolve: failingResolver})
	if !errors.Is(err, ErrSsrfDNSFailure) {
		t.Fatalf("err = %v, want ErrSsrfDNSFailure", err)
	}
}

func TestAssertPublicURL_DNSEmptyResult(t *testing.T) {
	emptyResolver := func(_ context.Context, _ string) ([]string, error) {
		return []string{}, nil
	}
	_, err := AssertPublicURL(context.Background(), "https://example.com/x",
		&AssertPublicURLOptions{Resolve: emptyResolver})
	if !errors.Is(err, ErrSsrfDNSFailure) {
		t.Fatalf("err = %v, want ErrSsrfDNSFailure", err)
	}
}

func TestAssertPublicURL_DNSReturnsUnparseable(t *testing.T) {
	garbageResolver := func(_ context.Context, _ string) ([]string, error) {
		return []string{"not-an-ip"}, nil
	}
	_, err := AssertPublicURL(context.Background(), "https://example.com/x",
		&AssertPublicURLOptions{Resolve: garbageResolver})
	if !errors.Is(err, ErrSsrfDNSFailure) {
		t.Fatalf("err = %v, want ErrSsrfDNSFailure", err)
	}
}

func TestAssertPublicURL_SchemeRejection(t *testing.T) {
	cases := []string{
		"http://example.com/x", // http not allowed by default
		"file:///etc/passwd",
		"gopher://example.com/x",
		"ftp://example.com/x",
		"javascript:alert(1)", // no host, but scheme is the immediate signal
	}
	for _, raw := range cases {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			_, err := AssertPublicURL(context.Background(), raw,
				&AssertPublicURLOptions{Resolve: stubResolver("8.8.8.8")})
			if err == nil {
				t.Fatal("expected error")
			}
			var sse *SsrfBlockedError
			if !errors.As(err, &sse) {
				t.Fatalf("err = %v, want *SsrfBlockedError", err)
			}
			// javascript: and file: have no host -- they MAY route as
			// invalid_url depending on parse outcome. Both invalid_url
			// and scheme_not_allowed are correct SSRF blocks.
			if sse.Reason != "scheme_not_allowed" && sse.Reason != "invalid_url" {
				t.Errorf("Reason = %q, want scheme_not_allowed or invalid_url", sse.Reason)
			}
		})
	}
}

func TestAssertPublicURL_AllowHTTPEscapeHatch(t *testing.T) {
	out, err := AssertPublicURL(context.Background(), "http://example.com/x",
		&AssertPublicURLOptions{
			AllowHTTP: true,
			Resolve:   stubResolver("8.8.8.8"),
		})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out.Scheme != "http" {
		t.Errorf("Scheme = %q, want http", out.Scheme)
	}
	if out.Host != "8.8.8.8" {
		t.Errorf("Host = %q, want 8.8.8.8", out.Host)
	}
}

func TestAssertPublicURL_AllowHTTPDoesNotAllowOtherSchemes(t *testing.T) {
	// AllowHTTP is specifically for http; other schemes still rejected.
	_, err := AssertPublicURL(context.Background(), "ftp://example.com/x",
		&AssertPublicURLOptions{AllowHTTP: true, Resolve: stubResolver("8.8.8.8")})
	if !errors.Is(err, ErrSsrfSchemeNotAllowed) {
		t.Fatalf("err = %v, want ErrSsrfSchemeNotAllowed", err)
	}
}

func TestAssertPublicURL_NilOptionsUsesDefaults(t *testing.T) {
	// nil opts: AllowHTTP=false, Resolve=net.DefaultResolver.LookupHost.
	// Use an IP literal so we don't hit real DNS in CI.
	_, err := AssertPublicURL(context.Background(), "https://127.0.0.1/x", nil)
	if !errors.Is(err, ErrSsrfPrivateIP) {
		t.Fatalf("err = %v, want ErrSsrfPrivateIP", err)
	}
}

func TestSsrfBlockedError_Message(t *testing.T) {
	e := &SsrfBlockedError{Reason: "private_ip", URL: "https://x.test", ResolvedIP: "10.0.0.1"}
	msg := e.Error()
	if !strings.Contains(msg, "private_ip") {
		t.Errorf("Error() = %q, missing reason", msg)
	}
	if !strings.Contains(msg, "10.0.0.1") {
		t.Errorf("Error() = %q, missing resolved IP", msg)
	}

	// Without ResolvedIP, message still renders.
	e2 := &SsrfBlockedError{Reason: "invalid_url", URL: "garbage"}
	msg2 := e2.Error()
	if !strings.Contains(msg2, "invalid_url") {
		t.Errorf("Error() = %q, missing reason", msg2)
	}
}
