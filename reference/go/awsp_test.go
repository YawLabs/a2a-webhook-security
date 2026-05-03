// Conformance test: every vector in ../../test-vectors.json runs through
// Sign and Verify. All 50 vectors MUST pass for the implementation to be
// AWSP v1 conformant.

package awsp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type vectorFile struct {
	Spec        string   `json:"spec"`
	VectorCount int      `json:"vector_count"`
	Vectors     []vector `json:"vectors"`
}

type vector struct {
	Name                  string         `json:"name"`
	Description           string         `json:"description"`
	SecretHex             string         `json:"secret_hex"`
	Kid                   string         `json:"kid"`
	BodyHex               string         `json:"body_hex"`
	Timestamp             int64          `json:"timestamp"`
	NonceB64URL           string         `json:"nonce_b64url"`
	Now                   int64          `json:"now"`
	ExpectedSignatureHex  string         `json:"expected_signature_hex,omitempty"`
	PresentedSignatureHex string         `json:"presented_signature_hex,omitempty"`
	RawSignatureHeader    *string        `json:"raw_signature_header,omitempty"`
	ReplaySetup           *replaySetup   `json:"replay_setup,omitempty"`
	ReceiverKnownKid      string         `json:"receiver_known_kid,omitempty"`
	ExpectedVerify        expectedVerify `json:"expected_verify"`
}

type replaySetup struct {
	SeedNonces []string `json:"seed_nonces"`
}

// expectedVerify is either the literal string "ok" or { "error": "<reason>" }.
type expectedVerify struct {
	OK    bool
	Error string
}

func (e *expectedVerify) UnmarshalJSON(data []byte) error {
	// Try string ("ok") first.
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "ok" {
			e.OK = true
			return nil
		}
		e.OK = false
		e.Error = s
		return nil
	}
	// Otherwise expect { "error": "<reason>" }.
	var obj struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	e.OK = false
	e.Error = obj.Error
	return nil
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	// Test runtime dir is the package dir; vectors live two parents up.
	path := filepath.Join("..", "..", "test-vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read test-vectors.json at %s: %v", path, err)
	}
	var f vectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse test-vectors.json: %v", err)
	}
	return f
}

func TestVectorFileLoaded(t *testing.T) {
	f := loadVectors(t)
	if got := len(f.Vectors); got != 50 {
		t.Fatalf("expected 50 vectors, got %d", got)
	}
	if f.VectorCount != 50 {
		t.Fatalf("vector_count = %d, want 50", f.VectorCount)
	}
}

func TestAllVectors(t *testing.T) {
	f := loadVectors(t)
	for _, v := range f.Vectors {
		v := v // capture
		t.Run(v.Name, func(t *testing.T) {
			runVector(t, v)
		})
	}
}

func runVector(t *testing.T, v vector) {
	t.Helper()

	secret, err := hex.DecodeString(v.SecretHex)
	if err != nil {
		t.Fatalf("decode secret_hex: %v", err)
	}
	body, err := hex.DecodeString(v.BodyHex)
	if err != nil {
		t.Fatalf("decode body_hex: %v", err)
	}

	// Always exercise computeV1Hex so the canonical-string concatenation
	// is covered for every body, even invalid-verify vectors.
	computed := computeV1Hex(secret, v.Timestamp, body)
	if v.ExpectedSignatureHex != "" {
		if computed != v.ExpectedSignatureHex {
			t.Fatalf("ComputeV1 mismatch:\n  got  %s\n  want %s", computed, v.ExpectedSignatureHex)
		}
	}

	// Pick the signature hex to put in the header. Priority:
	//   1. raw_signature_header (vector supplies its own header verbatim)
	//   2. expected_signature_hex (valid case)
	//   3. presented_signature_hex (invalid case with explicit signature)
	//   4. recomputed (fallback)
	sigHex := v.ExpectedSignatureHex
	if sigHex == "" {
		sigHex = v.PresentedSignatureHex
	}
	if sigHex == "" {
		sigHex = computed
	}

	var headerValue string
	if v.RawSignatureHeader != nil {
		headerValue = *v.RawSignatureHeader
	} else {
		headerValue = "t=" + itoa(v.Timestamp) +
			",v1=" + sigHex +
			",n=" + v.NonceB64URL +
			",kid=" + v.Kid
	}

	headers := map[string]string{
		"X-A2A-Signature":  headerValue,
		"X-A2A-Webhook-Id": "00000000-0000-4000-8000-000000000000",
		"X-A2A-Event-Type": "test.event",
		"X-A2A-Timestamp":  itoa(v.Timestamp),
	}

	// Receiver's secret list. Most vectors use the kid in the vector itself;
	// the unknown_kid vector specifies which kid the receiver actually knows.
	receiverKid := v.ReceiverKnownKid
	if receiverKid == "" {
		receiverKid = v.Kid
	}
	secrets := map[string][]byte{
		receiverKid: secret,
	}

	// Replay setup: if the vector seeds nonces, allocate a store and
	// pre-seed it.
	var store ReplayStore
	if v.ReplaySetup != nil {
		nowFunc := func() time.Time { return time.Unix(v.Now, 0).UTC() }
		s := newInMemoryReplayStoreWithClock(nowFunc)
		for _, n := range v.ReplaySetup.SeedNonces {
			if _, err := s.CheckAndStore("", []byte(n), 360); err != nil {
				t.Fatalf("seed replay store: %v", err)
			}
		}
		store = s
	}

	result := Verify(VerifyParams{
		Headers:             headers,
		Body:                body,
		Secrets:             secrets,
		ReplayWindowSeconds: 300,
		ReplayStore:         store,
		Now:                 func() time.Time { return time.Unix(v.Now, 0).UTC() },
	})

	if v.ExpectedVerify.OK {
		if !result.OK {
			t.Fatalf("expected ok, got reason=%q err=%v", result.Reason, result.Err)
		}
		return
	}

	if result.OK {
		t.Fatalf("expected error %q, got ok", v.ExpectedVerify.Error)
	}
	if result.Reason != v.ExpectedVerify.Error {
		t.Fatalf("expected reason=%q, got reason=%q (err=%v)", v.ExpectedVerify.Error, result.Reason, result.Err)
	}
}

// itoa is a tiny helper so we don't drag strconv into every line.
func itoa(n int64) string {
	// Match the canonical-string formatting: decimal ASCII, no leading
	// zeros. Negative numbers won't appear in valid vectors -- the only
	// negative-timestamp vector uses raw_signature_header verbatim.
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	negative := false
	if n < 0 {
		negative = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// ---------------------------------------------------------------------------
// Sign-side checks (analogues of the TS reference's sign() unit tests)
// ---------------------------------------------------------------------------

func TestSignProducesAllFourHeaders(t *testing.T) {
	secret := make([]byte, 32)
	headers, err := Sign(SignParams{
		Secret:    secret,
		KeyID:     "k_test",
		Body:      []byte(`{"a":1}`),
		EventType: "test.created",
		Timestamp: time.Unix(1777248000, 0).UTC(),
		Nonce:     []byte("0123456789012345"),
		WebhookID: "00000000-0000-4000-8000-000000000000",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if headers.XA2ASignature == "" {
		t.Error("XA2ASignature empty")
	}
	if headers.XA2AWebhookID == "" {
		t.Error("XA2AWebhookID empty")
	}
	if headers.XA2AEventType == "" {
		t.Error("XA2AEventType empty")
	}
	if headers.XA2ATimestamp == "" {
		t.Error("XA2ATimestamp empty")
	}
	parsed, err := parseSignatureHeader(headers.XA2ASignature)
	if err != nil {
		t.Fatalf("parse own header: %v", err)
	}
	if parsed.Timestamp != 1777248000 {
		t.Errorf("timestamp = %d, want 1777248000", parsed.Timestamp)
	}
	if parsed.Kid != "k_test" {
		t.Errorf("kid = %q, want k_test", parsed.Kid)
	}
	if len(parsed.V1) != 1 {
		t.Errorf("v1 count = %d, want 1", len(parsed.V1))
	}
}

func TestSignDefaultsPopulated(t *testing.T) {
	headers, err := Sign(SignParams{
		Secret:    []byte{1, 2, 3, 4},
		KeyID:     "k",
		Body:      []byte{},
		EventType: "e",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := parseSignatureHeader(headers.XA2ASignature)
	if err != nil {
		t.Fatalf("parse own header: %v", err)
	}
	if parsed.Timestamp < 1700000000 {
		t.Errorf("timestamp not populated: %d", parsed.Timestamp)
	}
	if !isValidNonce(parsed.Nonce) {
		t.Errorf("default nonce shape invalid: %q", parsed.Nonce)
	}
	if len(headers.XA2AWebhookID) != 36 {
		t.Errorf("webhook id length = %d, want 36", len(headers.XA2AWebhookID))
	}
}

func TestSignRejectsZeroLengthSecret(t *testing.T) {
	_, err := Sign(SignParams{
		Secret:    []byte{},
		KeyID:     "k",
		Body:      []byte{},
		EventType: "e",
	})
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestSignRejectsBadKid(t *testing.T) {
	_, err := Sign(SignParams{
		Secret:    []byte{1},
		KeyID:     "spaces are not allowed",
		Body:      []byte{},
		EventType: "e",
	})
	if err == nil {
		t.Fatal("expected error for bad kid")
	}
}

// ---------------------------------------------------------------------------
// Verify-side edge cases
// ---------------------------------------------------------------------------

func TestVerifyMissingHeader(t *testing.T) {
	r := Verify(VerifyParams{
		Headers: map[string]string{},
		Body:    []byte{},
		Secrets: map[string][]byte{"k": make([]byte, 32)},
		Now:     func() time.Time { return time.Unix(1777248000, 0) },
	})
	if r.OK {
		t.Fatal("expected failure")
	}
	if r.Reason != "malformed_header" {
		t.Errorf("Reason = %q, want malformed_header", r.Reason)
	}
}

func TestVerifyOutOfRangeWindow(t *testing.T) {
	r := Verify(VerifyParams{
		Headers:             map[string]string{"x-a2a-signature": "t=1,v1=" + zeros64() + ",n=A,kid=k"},
		Body:                []byte{},
		Secrets:             map[string][]byte{},
		ReplayWindowSeconds: 30, // below MinReplayWindowSeconds
		Now:                 func() time.Time { return time.Unix(1777248000, 0) },
	})
	if r.OK {
		t.Fatal("expected failure")
	}
	if r.Reason != "malformed_header" {
		t.Errorf("Reason = %q, want malformed_header", r.Reason)
	}
}

// TestVerifyEndToEnd checks that a freshly Sign-ed Delivery verifies in a
// loop -- catches any drift between sign and verify in the same process.
func TestVerifyEndToEnd(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	body := []byte(`{"event":"task.completed"}`)
	ts := time.Unix(1777248000, 0).UTC()

	headers, err := Sign(SignParams{
		Secret:    secret,
		KeyID:     "k_e2e",
		Body:      body,
		EventType: "task.completed",
		Timestamp: ts,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	in := map[string]string{
		"X-A2A-Signature":  headers.XA2ASignature,
		"X-A2A-Webhook-Id": headers.XA2AWebhookID,
		"X-A2A-Event-Type": headers.XA2AEventType,
		"X-A2A-Timestamp":  headers.XA2ATimestamp,
	}
	store := NewInMemoryReplayStore()
	r := Verify(VerifyParams{
		Headers:     in,
		Body:        body,
		Secrets:     map[string][]byte{"k_e2e": secret},
		ReplayStore: store,
		Now:         func() time.Time { return ts },
	})
	if !r.OK {
		t.Fatalf("e2e verify failed: reason=%q err=%v", r.Reason, r.Err)
	}
	if r.MatchedKid != "k_e2e" {
		t.Errorf("MatchedKid = %q, want k_e2e", r.MatchedKid)
	}

	// Replay the same delivery -> should reject as replayed.
	r2 := Verify(VerifyParams{
		Headers:     in,
		Body:        body,
		Secrets:     map[string][]byte{"k_e2e": secret},
		ReplayStore: store,
		Now:         func() time.Time { return ts },
	})
	if r2.OK {
		t.Fatal("expected replay rejection")
	}
	if r2.Reason != "replayed" {
		t.Errorf("replay Reason = %q, want replayed", r2.Reason)
	}
}

func zeros64() string {
	const z = "0000000000000000000000000000000000000000000000000000000000000000"
	return z
}
