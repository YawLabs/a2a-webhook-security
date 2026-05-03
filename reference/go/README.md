# awsp-go

Go reference implementation of [AWSP -- the A2A Webhook Security Profile](../../SPEC.md) v1.

AWSP is a single, interoperable wire format for signing, verifying, and
replay-protecting A2A push-notification webhooks. It pins HMAC-SHA256 over
`<timestamp>.<body-bytes>`, with a base64url nonce and a key identifier in
a comma-separated `X-A2A-Signature` header. See SPEC.md for the full text.

This module is dependency-free (Go stdlib only). Replay storage is pluggable
via the `ReplayStore` interface; an in-memory implementation ships for tests
and single-replica receivers.

* Apache-2.0 licensed.
* Conformance: passes all 50 vectors in [`test-vectors.json`](../../test-vectors.json).
* Module: `github.com/yawlabs/awsp-go`
* Go: 1.22+

## Install

```
go get github.com/yawlabs/awsp-go
```

## Sign (Sender side)

```go
package main

import (
    "bytes"
    "fmt"
    "net/http"

    awsp "github.com/yawlabs/awsp-go"
)

func sendWebhook(endpoint string, secret []byte, body []byte) error {
    headers, err := awsp.Sign(awsp.SignParams{
        Secret:    secret,
        Body:      body,
        KeyID:     "k_2026_05",
        EventType: "task.completed",
    })
    if err != nil {
        return err
    }
    req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
    if err != nil {
        return err
    }
    for k, v := range headers.ToHTTPHeader() {
        req.Header[k] = v
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode >= 400 {
        return fmt.Errorf("webhook delivery failed: %s", resp.Status)
    }
    return nil
}
```

`SignParams` lets the caller override `Timestamp`, `Nonce`, and `WebhookID`
for deterministic tests; defaults are `time.Now()`, 16 random bytes, and a
fresh UUIDv4 respectively.

## Verify (Receiver side, net/http)

```go
package main

import (
    "io"
    "log"
    "net/http"

    awsp "github.com/yawlabs/awsp-go"
)

var (
    secrets = map[string][]byte{
        "k_2026_05": loadSecret("k_2026_05"),
        "k_2026_06": loadSecret("k_2026_06"), // overlap during rotation
    }
    replayStore = awsp.NewInMemoryReplayStore() // swap for Redis in production
)

func handleWebhook(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "read body", http.StatusBadRequest)
        return
    }

    result := awsp.Verify(awsp.VerifyParams{
        Headers:        awsp.HTTPHeaderToMap(r.Header),
        Body:           body,
        Secrets:        secrets,
        ReplayStore:    replayStore,
        ReplayConfigID: "default", // partition key; use webhook config id
    })
    if !result.OK {
        // result.Reason is the spec-defined enum; safe to log, NOT to
        // include in the 401 body in adversarial environments.
        log.Printf("verify failed: %s", result.Reason)
        http.Error(w, `{"error":"invalid_signature","reason":"`+result.Reason+`"}`, http.StatusUnauthorized)
        return
    }

    // Authenticated. Decode body, dispatch event, reply.
    log.Printf("delivery from kid=%s nonce=%s", result.MatchedKid, result.Nonce)
    w.WriteHeader(http.StatusOK)
}

func main() {
    http.HandleFunc("/webhook", handleWebhook)
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func loadSecret(kid string) []byte { /* ... */ return nil }
```

## gorilla/mux drop-in middleware

```go
import (
    "io"
    "net/http"

    "github.com/gorilla/mux"
    awsp "github.com/yawlabs/awsp-go"
)

func AWSPMiddleware(secrets map[string][]byte, store awsp.ReplayStore) mux.MiddlewareFunc {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            body, err := io.ReadAll(r.Body)
            if err != nil {
                http.Error(w, "read body", http.StatusBadRequest)
                return
            }
            r.Body = io.NopCloser(bytes.NewReader(body))

            result := awsp.Verify(awsp.VerifyParams{
                Headers:     awsp.HTTPHeaderToMap(r.Header),
                Body:        body,
                Secrets:     secrets,
                ReplayStore: store,
            })
            if !result.OK {
                http.Error(w, `{"error":"invalid_signature","reason":"`+result.Reason+`"}`, http.StatusUnauthorized)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

func wireRoutes(r *mux.Router) {
    r.Use(AWSPMiddleware(secrets, store))
    r.HandleFunc("/webhook", handleAuthenticated)
}
```

## Custom ReplayStore (Redis example with go-redis)

The `ReplayStore` interface is one method:

```go
type ReplayStore interface {
    CheckAndStore(configID string, nonce []byte, ttlSeconds int) (firstSeen bool, err error)
}
```

A Redis-backed implementation using `SET key NX EX <ttl>`:

```go
package replay

import (
    "context"
    "time"

    "github.com/redis/go-redis/v9"
)

type RedisReplayStore struct {
    Client *redis.Client
}

func (s *RedisReplayStore) CheckAndStore(configID string, nonce []byte, ttlSeconds int) (bool, error) {
    key := "awsp:" + configID + ":" + string(nonce)
    // SET NX EX returns true only if the key was newly set.
    ok, err := s.Client.SetNX(context.Background(), key, "1", time.Duration(ttlSeconds)*time.Second).Result()
    if err != nil {
        return false, err
    }
    return ok, nil
}
```

Plug it in via `VerifyParams.ReplayStore = &RedisReplayStore{Client: rdb}`.

## Verification reasons

`VerifyResult.Reason` is the spec section 9 enum (also exposed as
`errors.Is`-friendly sentinels):

| Reason             | Sentinel                | Meaning                                                |
|--------------------|-------------------------|--------------------------------------------------------|
| `malformed_header` | `ErrMalformedHeader`    | Header missing, garbled, or fields out of shape.       |
| `unknown_algorithm`| `ErrUnknownAlgorithm`   | Header carried only `vN=` versions we don't understand.|
| `stale`            | `ErrStaleTimestamp`     | `t=` older than `replayWindow`.                        |
| `future`           | `ErrFutureTimestamp`    | `t=` newer than `replayWindow`.                        |
| `replayed`         | `ErrReplayed`           | Nonce already seen within the dedup horizon.           |
| `unknown_kid`      | `ErrUnknownKid`         | `kid=` did not match any provisioned secret.           |
| `bad_hmac`         | `ErrBadHMAC`            | HMAC mismatch for every candidate signature.           |

Receivers in adversarial environments MAY collapse all failures into a
single `bad_hmac` response; the spec recommends returning the discriminated
reason during rollout and rotation for dashboarding.

## Testing

The conformance test runner reads `../../test-vectors.json` and asserts
byte-for-byte equivalence on Sign and Verify outcomes for all 50 vectors:

```
cd packages/awsp/reference/go
go test ./... -v -count=1
go vet ./...
```

## License

Apache-2.0. See [LICENSE](./LICENSE).
