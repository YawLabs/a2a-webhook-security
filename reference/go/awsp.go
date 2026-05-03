// Package awsp is the Go reference implementation of the A2A Webhook
// Security Profile (AWSP) v1.
//
// AWSP defines a single, interoperable wire format for signing,
// verifying, and replay-protecting A2A push-notification webhook
// Deliveries. See SPEC.md at the package root for the full specification
// and test-vectors.json for the conformance test suite.
//
// This implementation is dependency-free (Go stdlib only). Replay
// storage is pluggable via the ReplayStore interface; an in-memory
// implementation is supplied for tests and single-replica receivers.
//
// # Quick start: signing
//
//	headers, err := awsp.Sign(awsp.SignParams{
//	    Secret:    secretBytes,
//	    Body:      []byte(`{"event":"task.completed"}`),
//	    KeyID:     "k_2026_05",
//	    EventType: "task.completed",
//	})
//	if err != nil { return err }
//	req, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
//	for k, v := range headers.ToHTTPHeader() { req.Header[k] = v }
//
// # Quick start: verifying
//
//	result := awsp.Verify(awsp.VerifyParams{
//	    Headers:     httpHeaderToMap(r.Header),
//	    Body:        rawBody,
//	    Secrets:     map[string][]byte{"k_2026_05": secretBytes},
//	    ReplayStore: store,
//	})
//	if !result.OK {
//	    http.Error(w, result.Reason, http.StatusUnauthorized)
//	    return
//	}
package awsp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// DefaultReplayWindowSeconds is the spec's default tolerance window
// for the t= timestamp (300 seconds, +/-).
const DefaultReplayWindowSeconds = 300

// MinReplayWindowSeconds is the lowest spec-conformant replay window.
const MinReplayWindowSeconds = 60

// MaxReplayWindowSeconds is the highest spec-conformant replay window.
const MaxReplayWindowSeconds = 600

// replayStoreTTLBufferSeconds is added on top of the configured replay
// window to bound nonce-storage TTL. Per spec section 7.2.
const replayStoreTTLBufferSeconds = 60

// nonceByteLen is the entropy size for auto-generated nonces. 16 bytes
// of entropy renders to 22 base64url chars -- comfortably above the
// spec's 16-byte recommendation (24-char "SHOULD") while fitting in a
// short header.
const nonceByteLen = 16

// ---------------------------------------------------------------------------
// Verify reason sentinels
// ---------------------------------------------------------------------------

// Verify failure-reason sentinels. The wire-facing string is exposed as
// VerifyResult.Reason; these errors let callers test with errors.Is.
var (
	ErrMalformedHeader   = errors.New("malformed_header")
	ErrUnknownAlgorithm  = errors.New("unknown_algorithm")
	ErrStaleTimestamp    = errors.New("stale")
	ErrFutureTimestamp   = errors.New("future")
	ErrReplayed          = errors.New("replayed")
	ErrUnknownKid        = errors.New("unknown_kid")
	ErrBadHMAC           = errors.New("bad_hmac")
	ErrReplayWindowRange = errors.New("replay window out of range [60, 600]")
)

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

// SignParams is the input to Sign.
type SignParams struct {
	// Secret is the raw secret bytes (the shared HMAC key). Required.
	Secret []byte

	// Body is the raw payload bytes. The HMAC is computed over
	// `<timestamp>.<body>` -- byte-exact, no transformation. Required.
	Body []byte

	// KeyID is the identifier for the secret, placed in the kid= field.
	// Required. Must match [A-Za-z0-9._-]{1,128}.
	KeyID string

	// EventType is placed in the X-A2A-Event-Type header. Required.
	EventType string

	// WebhookID is placed in X-A2A-Webhook-Id. Optional; if empty, a
	// random UUIDv4 is generated. On retry, Senders MUST reuse the same
	// WebhookID.
	WebhookID string

	// Timestamp is the t= value. Optional; if zero, time.Now() is used.
	Timestamp time.Time

	// Nonce is the per-Delivery random nonce bytes that get base64url
	// encoded into n=. Optional; if empty, 16 random bytes are generated.
	Nonce []byte
}

// Headers is the set of four AWSP headers Sign produces. All values are
// pre-formatted strings, ready for the wire.
type Headers struct {
	XA2ASignature string
	XA2AWebhookID string
	XA2AEventType string
	XA2ATimestamp string
}

// ToHTTPHeader returns the headers as an http.Header. The caller can
// merge the result into an outgoing http.Request.Header.
func (h Headers) ToHTTPHeader() http.Header {
	out := http.Header{}
	out.Set("X-A2A-Signature", h.XA2ASignature)
	out.Set("X-A2A-Webhook-Id", h.XA2AWebhookID)
	out.Set("X-A2A-Event-Type", h.XA2AEventType)
	out.Set("X-A2A-Timestamp", h.XA2ATimestamp)
	return out
}

// Sign produces the four AWSP headers for a payload.
//
// The HMAC is computed over the canonical string `<timestamp>.<body>`
// where <timestamp> is decimal ASCII unix-seconds with no leading zeros
// and <body> is the raw payload bytes. See SPEC.md section 6 for the
// algorithm.
func Sign(p SignParams) (Headers, error) {
	if len(p.Secret) == 0 {
		return Headers{}, errors.New("awsp: Sign: Secret must be non-empty")
	}
	if len(p.KeyID) == 0 {
		return Headers{}, errors.New("awsp: Sign: KeyID required")
	}
	if !isValidKid(p.KeyID) {
		return Headers{}, fmt.Errorf("awsp: Sign: KeyID %q must match [A-Za-z0-9._-]{1,128}", p.KeyID)
	}
	if len(p.EventType) == 0 {
		return Headers{}, errors.New("awsp: Sign: EventType required")
	}

	ts := p.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	tsUnix := ts.Unix()
	if tsUnix < 0 {
		return Headers{}, fmt.Errorf("awsp: Sign: Timestamp %s is before unix epoch", ts)
	}

	nonceBytes := p.Nonce
	if len(nonceBytes) == 0 {
		nonceBytes = make([]byte, nonceByteLen)
		if _, err := rand.Read(nonceBytes); err != nil {
			return Headers{}, fmt.Errorf("awsp: Sign: nonce generation: %w", err)
		}
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	if !isValidNonce(nonce) {
		return Headers{}, fmt.Errorf("awsp: Sign: encoded nonce %q does not match base64url shape", nonce)
	}

	webhookID := p.WebhookID
	if len(webhookID) == 0 {
		var err error
		webhookID, err = generateUUIDv4()
		if err != nil {
			return Headers{}, fmt.Errorf("awsp: Sign: webhook id generation: %w", err)
		}
	}

	v1Hex := computeV1Hex(p.Secret, tsUnix, p.Body)

	parsed := parsedHeader{
		Timestamp: tsUnix,
		V1:        []string{v1Hex},
		Nonce:     nonce,
		Kid:       p.KeyID,
	}
	return Headers{
		XA2ASignature: serializeSignatureHeader(parsed),
		XA2AWebhookID: webhookID,
		XA2AEventType: p.EventType,
		XA2ATimestamp: strconv.FormatInt(tsUnix, 10),
	}, nil
}

// ComputeV1 returns the lowercase-hex HMAC-SHA256 over the canonical
// string for a single (secret, timestamp, body). Exposed so test
// vectors and other-language ports can cross-check the canonical-string
// concatenation.
//
// Equivalent to lowercase_hex(HMAC-SHA256(secret, ts || "." || body))
// where ts is decimal-ASCII unix-seconds.
func ComputeV1(secret []byte, timestamp time.Time, body []byte) string {
	return computeV1Hex(secret, timestamp.Unix(), body)
}

func computeV1Hex(secret []byte, tsUnix int64, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	// Canonical string = decimal-ascii(timestamp) || 0x2E || body bytes.
	mac.Write([]byte(strconv.FormatInt(tsUnix, 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

// VerifyParams is the input to Verify.
type VerifyParams struct {
	// Headers is the inbound HTTP headers. Lookup is case-insensitive --
	// either http.Header (which is canonical-cased on read) or a plain
	// map of original casing works.
	Headers map[string]string

	// Body is the raw inbound request body. AWSP signs the literal bytes
	// the Sender wrote on the wire; verification MUST happen against the
	// same buffer the request was received on, before any parsing.
	Body []byte

	// Secrets maps kid -> raw secret bytes. The Receiver's accept list.
	Secrets map[string][]byte

	// ReplayWindowSeconds, if zero, defaults to DefaultReplayWindowSeconds.
	// Spec-conformant values are in [60, 600]; out-of-range values cause
	// Verify to return a result with Reason="malformed_header" and
	// Err=ErrReplayWindowRange.
	ReplayWindowSeconds int

	// ReplayStore is optional. If nil, replay protection is skipped.
	ReplayStore ReplayStore

	// ReplayConfigID is the partition key passed to ReplayStore. Most
	// callers pass the webhook configuration id; tests pass "" or any
	// stable string.
	ReplayConfigID string

	// Now is injectable for deterministic testing. If nil, time.Now is
	// used.
	Now func() time.Time
}

// VerifyResult reports the outcome of Verify.
//
// On success, OK is true and MatchedKid / Timestamp / Nonce identify the
// authenticated Delivery. On failure, OK is false, Reason carries the
// stable wire-facing enum, and Err carries the typed error sentinel for
// callers that want errors.Is matching.
type VerifyResult struct {
	OK     bool
	Reason string // empty on success; one of the spec section 9 enum values otherwise

	// MatchedKid is the kid whose secret produced the matching HMAC.
	MatchedKid string
	// Timestamp is the parsed t= value.
	Timestamp time.Time
	// Nonce is the parsed n= value (base64url string).
	Nonce string

	// Err is the typed error sentinel matching Reason. Wrapped with
	// fmt.Errorf("...: %w", sentinel) for diagnostic context.
	Err error
}

// Verify checks an inbound AWSP-signed request.
//
// Order of checks (cheap before expensive, and to avoid wasting nonce
// storage on forged requests):
//
//  1. Header parse (malformed_header / unknown_algorithm)
//  2. Replay window (stale / future)
//  3. Kid lookup (unknown_kid)
//  4. HMAC compare (bad_hmac), constant-time across all candidate
//     (secret, signature) pairs
//  5. Replay store check (replayed)
//
// Verify never panics on bad input -- malformed inputs become
// VerifyResult with OK=false.
func Verify(p VerifyParams) VerifyResult {
	window := p.ReplayWindowSeconds
	if window == 0 {
		window = DefaultReplayWindowSeconds
	}
	if window < MinReplayWindowSeconds || window > MaxReplayWindowSeconds {
		return failResult(ErrMalformedHeader, fmt.Errorf("%w: %d", ErrReplayWindowRange, window))
	}

	rawHeader, ok := lookupHeader(p.Headers, "X-A2A-Signature")
	if !ok {
		return failResult(ErrMalformedHeader, fmt.Errorf("%w: missing X-A2A-Signature", ErrMalformedHeader))
	}

	parsed, err := parseSignatureHeader(rawHeader)
	if err != nil {
		if errors.Is(err, errParseUnknownAlgo) {
			return failResult(ErrUnknownAlgorithm, fmt.Errorf("%w: %v", ErrUnknownAlgorithm, err))
		}
		return failResult(ErrMalformedHeader, fmt.Errorf("%w: %v", ErrMalformedHeader, err))
	}

	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	skewSeconds := now.Unix() - parsed.Timestamp
	if skewSeconds > int64(window) {
		return failResult(ErrStaleTimestamp, fmt.Errorf("%w: timestamp %ds old", ErrStaleTimestamp, skewSeconds))
	}
	if skewSeconds < -int64(window) {
		return failResult(ErrFutureTimestamp, fmt.Errorf("%w: timestamp %ds in the future", ErrFutureTimestamp, -skewSeconds))
	}

	secret, hasKid := p.Secrets[parsed.Kid]
	if !hasKid {
		return failResult(ErrUnknownKid, fmt.Errorf("%w: no secret for kid=%s", ErrUnknownKid, parsed.Kid))
	}

	expectedHex := computeV1Hex(secret, parsed.Timestamp, p.Body)
	expectedBytes, decErr := hex.DecodeString(expectedHex)
	if decErr != nil {
		// Should be impossible: ComputeV1 always returns 64 lowercase hex.
		return failResult(ErrBadHMAC, fmt.Errorf("%w: internal hex decode: %v", ErrBadHMAC, decErr))
	}

	matched := false
	for _, candidate := range parsed.V1 {
		// parseSignatureHeader has already validated that candidate is
		// 64 lowercase hex chars, so DecodeString cannot fail. We still
		// use subtle.ConstantTimeCompare on the decoded bytes (32 bytes
		// each) to keep timing independent of which signature matched.
		candidateBytes, err := hex.DecodeString(candidate)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(expectedBytes, candidateBytes) == 1 {
			matched = true
			// Don't break -- keep comparing every candidate so total
			// verification time does not depend on which v1= matched.
		}
	}

	if !matched {
		return failResult(ErrBadHMAC, fmt.Errorf("%w: no signature matched", ErrBadHMAC))
	}

	if p.ReplayStore != nil {
		ttl := window + replayStoreTTLBufferSeconds
		// Use the raw nonce string bytes as the replay key. base64url is
		// already a flat ASCII string so no further encoding is needed.
		firstSeen, err := p.ReplayStore.CheckAndStore(p.ReplayConfigID, []byte(parsed.Nonce), ttl)
		if err != nil {
			// Treat replay-store errors as bad_hmac equivalent: refuse the
			// Delivery rather than admit one we couldn't deduplicate. The
			// reason is "replayed" because that's the closest spec enum.
			return failResult(ErrReplayed, fmt.Errorf("%w: replay store error: %v", ErrReplayed, err))
		}
		if !firstSeen {
			return failResult(ErrReplayed, fmt.Errorf("%w: nonce already seen", ErrReplayed))
		}
	}

	return VerifyResult{
		OK:         true,
		MatchedKid: parsed.Kid,
		Timestamp:  time.Unix(parsed.Timestamp, 0).UTC(),
		Nonce:      parsed.Nonce,
	}
}

// failResult builds a non-OK VerifyResult. The Reason is taken from the
// sentinel's Error() value (which matches the spec section 9 enum
// strings); Err is the wrapped error.
func failResult(reasonSentinel error, wrapped error) VerifyResult {
	return VerifyResult{
		OK:     false,
		Reason: reasonSentinel.Error(),
		Err:    wrapped,
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// lookupHeader does a case-insensitive lookup over a string-valued map.
// http.Header (which is map[string][]string) is not directly compatible
// with this signature; HTTPHeaderToMap below is the bridge.
func lookupHeader(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if equalFoldASCII(k, name) {
			return v, true
		}
	}
	return "", false
}

// HTTPHeaderToMap flattens an http.Header into a map[string]string,
// preserving the first value of any multi-valued header. Convenient when
// constructing VerifyParams from an http.Request.
func HTTPHeaderToMap(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

// equalFoldASCII is a fast case-insensitive ASCII compare. Header names
// are ASCII-only, so we don't need full Unicode case-folding.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// generateUUIDv4 returns a random UUIDv4 string. Stdlib doesn't ship a
// UUID helper, so we hand-format from crypto/rand bytes. RFC 4122 layout.
func generateUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}
