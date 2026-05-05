// Header parser unit tests, complementing the vector-driven coverage in
// awsp_test.go.

package awsp

import (
	"errors"
	"strings"
	"testing"
)

func TestParseSignatureHeaderHappyPath(t *testing.T) {
	raw := "t=1777248000,v1=" + sampleSig() + ",n=AAAAAAAAAAAAAAAAAAAAAAAA,kid=k_2026_05"
	p, err := parseSignatureHeader(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Timestamp != 1777248000 {
		t.Errorf("timestamp = %d", p.Timestamp)
	}
	if len(p.V1) != 1 || p.V1[0] != sampleSig() {
		t.Errorf("v1 = %v", p.V1)
	}
	if p.Nonce != "AAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Errorf("nonce = %q", p.Nonce)
	}
	if p.Kid != "k_2026_05" {
		t.Errorf("kid = %q", p.Kid)
	}
}

func TestParseSignatureHeaderMultipleV1(t *testing.T) {
	// Senders MAY include multiple v1= during algorithm rotation.
	raw := "t=1,v1=" + sampleSig() + ",v1=" + altSig() + ",n=A,kid=k"
	p, err := parseSignatureHeader(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(p.V1) != 2 {
		t.Fatalf("want 2 v1=, got %d", len(p.V1))
	}
}

func TestParseSignatureHeaderUnknownFieldIgnored(t *testing.T) {
	// Unknown non-version key is silently ignored for forward compatibility.
	raw := "t=1,v1=" + sampleSig() + ",n=A,kid=k,future=yes"
	if _, err := parseSignatureHeader(raw); err != nil {
		t.Fatalf("parse: %v", err)
	}
}

func TestParseSignatureHeaderUnknownAlgoOnly(t *testing.T) {
	raw := "t=1,v99=somefuture,n=A,kid=k"
	_, err := parseSignatureHeader(raw)
	if !errors.Is(err, errParseUnknownAlgo) {
		t.Fatalf("err = %v, want errParseUnknownAlgo", err)
	}
}

func TestParseSignatureHeaderTooLong(t *testing.T) {
	long := "t=1,v1=" + sampleSig() + ",n=" + strings.Repeat("A", 200) + ",kid=k_" + strings.Repeat("x", 4000)
	_, err := parseSignatureHeader(long)
	if !errors.Is(err, errParseMalformed) {
		t.Fatalf("err = %v, want errParseMalformed", err)
	}
}

func TestParseSignatureHeaderEmpty(t *testing.T) {
	_, err := parseSignatureHeader("")
	if !errors.Is(err, errParseMalformed) {
		t.Fatalf("err = %v, want errParseMalformed", err)
	}
}

func TestParseSignatureHeaderMissingFields(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"missing t", "v1=" + sampleSig() + ",n=A,kid=k", errParseMissingT},
		{"missing nonce", "t=1,v1=" + sampleSig() + ",kid=k", errParseMissingNonce},
		{"missing kid", "t=1,v1=" + sampleSig() + ",n=A", errParseMissingKid},
		{"missing sig", "t=1,n=A,kid=k", errParseMissingSig},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseSignatureHeader(c.raw)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestParseSignatureHeaderBadShapes(t *testing.T) {
	cases := []string{
		"this is not a signature header",                                 // garbage
		"t=,v1=" + sampleSig() + ",n=A,kid=k",                            // empty value
		"=value,v1=" + sampleSig() + ",n=A,kid=k",                        // empty key
		"t=-1,v1=" + sampleSig() + ",n=A,kid=k",                          // negative timestamp
		"t=abc,v1=" + sampleSig() + ",n=A,kid=k",                         // non-decimal timestamp
		"t=1,v1=" + strings.ToUpper(sampleSig()) + ",n=A,kid=k",          // uppercase hex
		"t=1,v1=" + sampleSig()[:63] + ",n=A,kid=k",                      // wrong-length sig
		"t=1,v1=" + sampleSig() + ",n=$$$,kid=k",                         // bad nonce char
		"t=1,v1=" + sampleSig() + ",n=A,kid=" + strings.Repeat("x", 200), // kid too long
	}
	for _, raw := range cases {
		raw := raw
		t.Run(truncate(raw, 40), func(t *testing.T) {
			if _, err := parseSignatureHeader(raw); err == nil {
				t.Fatalf("expected error for %q", raw)
			}
		})
	}
}

func TestParseSignatureHeaderDuplicates(t *testing.T) {
	cases := []string{
		"t=1,t=2,v1=" + sampleSig() + ",n=A,kid=k",       // dup t=
		"t=1,v1=" + sampleSig() + ",n=A,n=B,kid=k",       // dup n=
		"t=1,v1=" + sampleSig() + ",n=A,kid=k,kid=other", // dup kid=
	}
	for _, raw := range cases {
		raw := raw
		t.Run(truncate(raw, 40), func(t *testing.T) {
			if _, err := parseSignatureHeader(raw); err == nil {
				t.Fatalf("expected error for duplicate field")
			}
		})
	}
}

func TestSerializeRoundTrip(t *testing.T) {
	in := parsedHeader{
		Timestamp: 1777248000,
		V1:        []string{sampleSig(), altSig()},
		Nonce:     "AAAAAAAAAAAAAAAAAAAAAAAA",
		Kid:       "k_2026_05",
	}
	raw := serializeSignatureHeader(in)
	want := "t=1777248000,v1=" + sampleSig() + ",v1=" + altSig() +
		",n=AAAAAAAAAAAAAAAAAAAAAAAA,kid=k_2026_05"
	if raw != want {
		t.Fatalf("serialize mismatch:\n  got  %s\n  want %s", raw, want)
	}
	out, err := parseSignatureHeader(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Timestamp != in.Timestamp {
		t.Errorf("timestamp drift: got %d want %d", out.Timestamp, in.Timestamp)
	}
	if len(out.V1) != len(in.V1) {
		t.Errorf("v1 count drift: got %d want %d", len(out.V1), len(in.V1))
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func sampleSig() string {
	return "a8a83abd144feeb2f481bd997757faf5555354074ca05d2270fac24bd234ec96"
}

func altSig() string {
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
