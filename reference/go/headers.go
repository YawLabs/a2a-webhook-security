// AWSP header parsing and serialization.
//
// X-A2A-Signature has the form:
//
//	t=<unix-seconds>,v1=<hex>[,v1=<hex>...],n=<nonce-b64url>,kid=<keyId>
//
// Order of fields is NOT significant. Multiple v1= values are allowed
// (algorithm rotation); receivers MUST accept the request if any one of
// them validates against any known secret.

package awsp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// parsedHeader is the internal parsed form of X-A2A-Signature.
type parsedHeader struct {
	Timestamp int64    // signer's clock at signing time
	V1        []string // all v1= signatures (lowercase hex, 64 chars each)
	Nonce     string   // base64url
	Kid       string   // opaque key identifier
}

// Header parse error sentinels. The public-facing reason strings on
// VerifyResult are derived from these.
var (
	errParseMalformed    = errors.New("awsp: malformed X-A2A-Signature header")
	errParseUnknownAlgo  = errors.New("awsp: header carries no recognized signature version")
	errParseMissingT     = errors.New("awsp: missing t= field")
	errParseMissingNonce = errors.New("awsp: missing n= field")
	errParseMissingKid   = errors.New("awsp: missing kid= field")
	errParseMissingSig   = errors.New("awsp: missing v1= field")
)

// maxHeaderLen is the cap recommended by the spec (section 5.1).
const maxHeaderLen = 4096

// parseSignatureHeader parses an X-A2A-Signature header value.
//
// On success it returns a parsedHeader with all four required fields.
// On failure it returns one of the err* sentinels above. Use errors.Is to
// classify (errors.Is(err, errParseUnknownAlgo) for the unknown_algorithm
// case; everything else maps to malformed_header).
func parseSignatureHeader(raw string) (parsedHeader, error) {
	if len(raw) == 0 {
		return parsedHeader{}, fmt.Errorf("%w: empty header", errParseMalformed)
	}
	if len(raw) > maxHeaderLen {
		return parsedHeader{}, fmt.Errorf("%w: header too long (%d bytes)", errParseMalformed, len(raw))
	}

	var (
		out            parsedHeader
		sawTimestamp   bool
		sawNonce       bool
		sawKid         bool
		sawUnknownAlgo bool
	)

	for _, part := range strings.Split(raw, ",") {
		eq := strings.IndexByte(part, '=')
		if eq <= 0 || eq == len(part)-1 {
			return parsedHeader{}, fmt.Errorf("%w: bad pair %q", errParseMalformed, part)
		}
		key := strings.TrimSpace(part[:eq])
		value := strings.TrimSpace(part[eq+1:])
		if len(key) == 0 || len(value) == 0 {
			return parsedHeader{}, fmt.Errorf("%w: empty key or value in %q", errParseMalformed, part)
		}

		switch {
		case key == "t":
			if sawTimestamp {
				return parsedHeader{}, fmt.Errorf("%w: duplicate t=", errParseMalformed)
			}
			if !isAsciiDigits(value) || len(value) > 15 {
				return parsedHeader{}, fmt.Errorf("%w: bad timestamp %q", errParseMalformed, value)
			}
			ts, err := strconv.ParseInt(value, 10, 64)
			if err != nil || ts < 0 {
				return parsedHeader{}, fmt.Errorf("%w: bad timestamp %q", errParseMalformed, value)
			}
			out.Timestamp = ts
			sawTimestamp = true
		case key == "v1":
			if !isLowerHex64(value) {
				return parsedHeader{}, fmt.Errorf("%w: v1= must be 64 lowercase hex chars", errParseMalformed)
			}
			out.V1 = append(out.V1, value)
		case isFutureVersionKey(key):
			// Future signature versions: receivers ignore unknown versions, but
			// remember we saw one so we can distinguish unknown_algorithm from
			// missing_signature later.
			sawUnknownAlgo = true
		case key == "n":
			if sawNonce {
				return parsedHeader{}, fmt.Errorf("%w: duplicate n=", errParseMalformed)
			}
			if !isValidNonce(value) {
				return parsedHeader{}, fmt.Errorf("%w: bad nonce", errParseMalformed)
			}
			out.Nonce = value
			sawNonce = true
		case key == "kid":
			if sawKid {
				return parsedHeader{}, fmt.Errorf("%w: duplicate kid=", errParseMalformed)
			}
			if !isValidKid(value) {
				return parsedHeader{}, fmt.Errorf("%w: bad kid", errParseMalformed)
			}
			out.Kid = value
			sawKid = true
		default:
			// Unknown field -- ignore for forward compatibility (spec 5.1).
		}
	}

	if !sawTimestamp {
		return parsedHeader{}, errParseMissingT
	}
	if !sawNonce {
		return parsedHeader{}, errParseMissingNonce
	}
	if len(out.V1) == 0 {
		if sawUnknownAlgo {
			return parsedHeader{}, errParseUnknownAlgo
		}
		return parsedHeader{}, errParseMissingSig
	}
	if !sawKid {
		return parsedHeader{}, errParseMissingKid
	}

	return out, nil
}

// serializeSignatureHeader writes the canonical "t=...,v1=...,n=...,kid=..."
// form. Field order is fixed: t, v1..., n, kid.
func serializeSignatureHeader(p parsedHeader) string {
	var b strings.Builder
	b.WriteString("t=")
	b.WriteString(strconv.FormatInt(p.Timestamp, 10))
	for _, v := range p.V1 {
		b.WriteString(",v1=")
		b.WriteString(v)
	}
	b.WriteString(",n=")
	b.WriteString(p.Nonce)
	b.WriteString(",kid=")
	b.WriteString(p.Kid)
	return b.String()
}

// ---------------------------------------------------------------------------
// Field-shape predicates
// ---------------------------------------------------------------------------

func isAsciiDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLowerAF := c >= 'a' && c <= 'f'
		if !isDigit && !isLowerAF {
			return false
		}
	}
	return true
}

// isFutureVersionKey reports whether key matches /^v[0-9]+$/ but is not "v1".
// (v1 is handled before this predicate is consulted.)
func isFutureVersionKey(key string) bool {
	if len(key) < 2 || key[0] != 'v' {
		return false
	}
	for i := 1; i < len(key); i++ {
		c := key[i]
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isValidNonce(s string) bool {
	if len(s) < 1 || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLower := c >= 'a' && c <= 'z'
		isUpper := c >= 'A' && c <= 'Z'
		isExtra := c == '_' || c == '-'
		if !isDigit && !isLower && !isUpper && !isExtra {
			return false
		}
	}
	return true
}

func isValidKid(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLower := c >= 'a' && c <= 'z'
		isUpper := c >= 'A' && c <= 'Z'
		isExtra := c == '.' || c == '_' || c == '-'
		if !isDigit && !isLower && !isUpper && !isExtra {
			return false
		}
	}
	return true
}
