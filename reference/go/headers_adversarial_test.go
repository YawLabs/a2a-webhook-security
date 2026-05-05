// Adversarial parser tests for parseSignatureHeader.
//
// Two layers:
//
//  1. FuzzParseSignatureHeader -- Go's native fuzz testing. Asserts that
//     for ANY input bytes, the parser EITHER returns a valid parsedHeader
//     (in which case its fields satisfy the invariants the spec mandates)
//     OR a typed error -- never panics, never returns wrong-shaped data.
//     A small seed corpus from the conformance vectors is checked in
//     under testdata/fuzz/FuzzParseSignatureHeader/.
//
//  2. Targeted Test* -- table-driven cases the fuzzer would take a long
//     time to discover by chance: truncation at every byte boundary,
//     oversize, duplicates, multi-v1 accumulation, mixed case keys, etc.

package awsp

import (
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Fuzz: parser must not panic, must not return wrong-shaped data
// ---------------------------------------------------------------------------

func FuzzParseSignatureHeader(f *testing.F) {
	// Seed with valid examples derived from the conformance vectors.
	seeds := []string{
		"t=1777248000,v1=" + sampleSig() + ",n=AAAAAAAAAAAAAAAAAAAAAAAA,kid=k_2026_05",
		"t=1,v1=" + sampleSig() + ",v1=" + altSig() + ",n=A,kid=k",
		"t=1,v99=somefuture,n=A,kid=k",
		"t=1,v1=" + sampleSig() + ",n=A,kid=k,future=ignored",
		"",
		"garbage",
		"t=,v1=,n=,kid=",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		// Constraint: parser must not panic. Anything else is a deferred
		// recover -- if we panic, the test framework reports the input.
		p, err := parseSignatureHeader(raw)
		if err != nil {
			// Every error path must be classifiable into a spec reason.
			// Enumerate the typed sentinels we expect; anything else means
			// the parser invented a new error class.
			switch {
			case errors.Is(err, errParseMalformed):
			case errors.Is(err, errParseUnknownAlgo):
			case errors.Is(err, errParseMissingT):
			case errors.Is(err, errParseMissingNonce):
			case errors.Is(err, errParseMissingKid):
			case errors.Is(err, errParseMissingSig):
			default:
				t.Fatalf("unclassified error %v for input %q", err, raw)
			}
			return
		}

		// On success the parsed struct must satisfy spec invariants.
		if p.Timestamp < 0 {
			t.Fatalf("negative timestamp %d for input %q", p.Timestamp, raw)
		}
		if len(p.V1) == 0 {
			t.Fatalf("V1 empty on success for input %q", raw)
		}
		for i, v := range p.V1 {
			if !isLowerHex64(v) {
				t.Fatalf("V1[%d] = %q is not 64 lowercase hex (input %q)", i, v, raw)
			}
		}
		if !isValidNonce(p.Nonce) {
			t.Fatalf("Nonce = %q invalid shape (input %q)", p.Nonce, raw)
		}
		if !isValidKid(p.Kid) {
			t.Fatalf("Kid = %q invalid shape (input %q)", p.Kid, raw)
		}
	})
}

// ---------------------------------------------------------------------------
// Targeted adversarial cases
// ---------------------------------------------------------------------------

func TestParseAdversarial_TruncationAtEveryByteBoundary(t *testing.T) {
	// A valid header truncated at every prefix length n MUST either parse
	// cleanly or return a typed error. Never panic, never garbage.
	full := "t=1777248000,v1=" + sampleSig() + ",n=AAAAAAAAAAAAAAAAAAAAAAAA,kid=k_2026_05"
	for n := 0; n <= len(full); n++ {
		n := n
		prefix := full[:n]
		t.Run(itoaTest(n), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on truncated input %q: %v", prefix, r)
				}
			}()
			_, _ = parseSignatureHeader(prefix)
		})
	}
}

// itoaTest stringifies an int for use in t.Run subtest names.
func itoaTest(n int) string {
	if n == 0 {
		return "len_0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return "len_" + string(buf[i:])
}

func TestParseAdversarial_Oversized(t *testing.T) {
	// Anything past maxHeaderLen MUST return errParseMalformed.
	huge := "t=1,v1=" + sampleSig() + ",n=A,kid=" + strings.Repeat("x", maxHeaderLen)
	_, err := parseSignatureHeader(huge)
	if !errors.Is(err, errParseMalformed) {
		t.Fatalf("err = %v, want errParseMalformed", err)
	}
}

func TestParseAdversarial_OversizedAtBoundary(t *testing.T) {
	// Length exactly maxHeaderLen+1 -- one byte over.
	n := maxHeaderLen + 1
	pad := strings.Repeat("x", n)
	if len(pad) != n {
		t.Fatalf("test setup: pad len %d != %d", len(pad), n)
	}
	_, err := parseSignatureHeader(pad)
	if !errors.Is(err, errParseMalformed) {
		t.Fatalf("err = %v, want errParseMalformed", err)
	}
}

func TestParseAdversarial_DuplicateKeys(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"dup t=", "t=1,t=2,v1=" + sampleSig() + ",n=A,kid=k"},
		{"dup n=", "t=1,v1=" + sampleSig() + ",n=A,n=B,kid=k"},
		{"dup kid=", "t=1,v1=" + sampleSig() + ",n=A,kid=k,kid=other"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSignatureHeader(tc.raw)
			if !errors.Is(err, errParseMalformed) {
				t.Fatalf("err = %v, want errParseMalformed", err)
			}
		})
	}
}

func TestParseAdversarial_MultipleV1Accumulation(t *testing.T) {
	// Multiple v1= MUST accumulate into V1[] (spec 5.1: "MAY appear
	// multiple times", "Receivers MUST treat the request as authentic
	// if any one valid v1= matches").
	raw := "t=1,v1=" + sampleSig() + ",v1=" + altSig() + ",v1=" + sampleSig() + ",n=A,kid=k"
	p, err := parseSignatureHeader(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(p.V1) != 3 {
		t.Fatalf("V1 count = %d, want 3", len(p.V1))
	}
}

func TestParseAdversarial_MixedCaseKeys(t *testing.T) {
	// Field keys are spec-defined as lowercase. Mixed case is an unknown
	// field per the parser's switch -- which silently ignores it for
	// forward compatibility -- but then the required field is missing.
	cases := []struct {
		name string
		raw  string
	}{
		{"T= uppercase (missing t)", "T=1,v1=" + sampleSig() + ",n=A,kid=k"},
		{"V1= uppercase (missing sig)", "t=1,V1=" + sampleSig() + ",n=A,kid=k"},
		{"N= uppercase (missing nonce)", "t=1,v1=" + sampleSig() + ",N=A,kid=k"},
		{"KID= uppercase (missing kid)", "t=1,v1=" + sampleSig() + ",n=A,KID=k"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSignatureHeader(tc.raw)
			if err == nil {
				t.Fatal("expected error for mixed-case key (treated as unknown field)")
			}
		})
	}
}

func TestParseAdversarial_WhitespaceInValues(t *testing.T) {
	// The parser TrimSpaces around each value. Internal whitespace in
	// values that don't allow it MUST produce errParseMalformed.
	cases := []string{
		"t=1,v1=" + sampleSig() + ",n=A B,kid=k",                             // space in nonce
		"t=1,v1=" + sampleSig() + ",n=A\tB,kid=k",                            // tab in nonce
		"t=1,v1=" + sampleSig() + ",n=A,kid=k\x00bad",                        // NUL in kid
		"t=1,v1=" + sampleSig() + ",n=A,kid=k\nx",                            // LF in kid
		"t=1 2,v1=" + sampleSig() + ",n=A,kid=k",                             // space in timestamp
		"t=1,v1=" + sampleSig()[:32] + " " + sampleSig()[32:] + ",n=A,kid=k", // space in v1 hex
	}
	for _, raw := range cases {
		raw := raw
		t.Run(truncate(raw, 50), func(t *testing.T) {
			_, err := parseSignatureHeader(raw)
			if err == nil {
				t.Fatalf("expected error for raw=%q", raw)
			}
		})
	}
}

func TestParseAdversarial_NonPrintableInValues(t *testing.T) {
	cases := []string{
		"t=1,v1=" + sampleSig() + ",n=A\x01,kid=k", // SOH in nonce
		"t=1,v1=" + sampleSig() + ",n=A,kid=\x7fk", // DEL in kid
		"t=\x00,v1=" + sampleSig() + ",n=A,kid=k",  // NUL in timestamp
	}
	for _, raw := range cases {
		raw := raw
		t.Run(truncate(raw, 50), func(t *testing.T) {
			_, err := parseSignatureHeader(raw)
			if err == nil {
				t.Fatalf("expected error for raw=%q", raw)
			}
		})
	}
}

func TestParseAdversarial_VeryHighTimestamp(t *testing.T) {
	// A timestamp at the int64 ceiling parses OK shape-wise. The parser
	// caps at 15 digits which keeps it inside int64 range. Year-3000ish
	// (16 digits) MUST be rejected.
	cases := []struct {
		name      string
		raw       string
		expectErr bool
	}{
		{"15 digits ok shape", "t=999999999999999,v1=" + sampleSig() + ",n=A,kid=k", false},
		{"16 digits rejected", "t=9999999999999999,v1=" + sampleSig() + ",n=A,kid=k", true},
		{"year 3000 ish (13 digits ok)", "t=1234567890123,v1=" + sampleSig() + ",n=A,kid=k", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSignatureHeader(tc.raw)
			if tc.expectErr {
				if !errors.Is(err, errParseMalformed) {
					t.Fatalf("err = %v, want errParseMalformed", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
			}
		})
	}
}

func TestParseAdversarial_NegativeTimestamp(t *testing.T) {
	cases := []string{
		"t=-1,v1=" + sampleSig() + ",n=A,kid=k",
		"t=-999999,v1=" + sampleSig() + ",n=A,kid=k",
	}
	for _, raw := range cases {
		raw := raw
		t.Run(truncate(raw, 30), func(t *testing.T) {
			_, err := parseSignatureHeader(raw)
			if !errors.Is(err, errParseMalformed) {
				t.Fatalf("err = %v, want errParseMalformed", err)
			}
		})
	}
}

func TestParseAdversarial_EmptyValuesAndBareKeys(t *testing.T) {
	cases := []string{
		"t=",                                    // bare equals (missing value)
		"=value",                                // bare equals (missing key)
		"t=,v1=" + sampleSig() + ",n=A,kid=k",   // empty t value
		"t=1,v1=,n=A,kid=k",                     // empty v1 value
		"t=1,v1=" + sampleSig() + ",n=,kid=k",   // empty nonce value
		"t=1,v1=" + sampleSig() + ",n=A,kid=",   // empty kid value
		"t",                                     // bare key, no =
		"t,v1=" + sampleSig() + ",n=A,kid=k",    // bare key amid valid pairs
		",,,",                                   // only commas
		",t=1,v1=" + sampleSig() + ",n=A,kid=k", // leading comma
	}
	for _, raw := range cases {
		raw := raw
		t.Run(truncate(raw, 40), func(t *testing.T) {
			_, err := parseSignatureHeader(raw)
			if err == nil {
				t.Fatalf("expected error for raw=%q", raw)
			}
			if !errors.Is(err, errParseMalformed) && !errors.Is(err, errParseMissingT) &&
				!errors.Is(err, errParseMissingNonce) && !errors.Is(err, errParseMissingKid) &&
				!errors.Is(err, errParseMissingSig) {
				t.Fatalf("err = %v, want a typed parse sentinel", err)
			}
		})
	}
}

// TestParseAdversarial_EveryReasonReachable confirms each spec-defined
// reason that the parser produces is reachable from at least one input.
// The Verify-side reasons (stale/future/replayed/unknown_kid/bad_hmac)
// are out of scope here -- they're covered in awsp_test.go.
func TestParseAdversarial_EveryReasonReachable(t *testing.T) {
	// (input, expected sentinel via errors.Is)
	cases := []struct {
		name     string
		raw      string
		sentinel error
	}{
		{"malformed: bad timestamp", "t=abc,v1=" + sampleSig() + ",n=A,kid=k", errParseMalformed},
		{"malformed: uppercase hex", "t=1,v1=" + strings.ToUpper(sampleSig()) + ",n=A,kid=k", errParseMalformed},
		{"unknown_algo: only v99", "t=1,v99=ff,n=A,kid=k", errParseUnknownAlgo},
		{"missing t", "v1=" + sampleSig() + ",n=A,kid=k", errParseMissingT},
		{"missing nonce", "t=1,v1=" + sampleSig() + ",kid=k", errParseMissingNonce},
		{"missing kid", "t=1,v1=" + sampleSig() + ",n=A", errParseMissingKid},
		{"missing sig", "t=1,n=A,kid=k", errParseMissingSig},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSignatureHeader(tc.raw)
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("err = %v, want errors.Is %v", err, tc.sentinel)
			}
		})
	}
}
