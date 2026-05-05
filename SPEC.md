# AWSP -- A2A Webhook Security Profile

**Version:** v1
**Status:** Draft 1 (publishable)
**Date:** 2026-05-02
**Editors:** Yaw Labs
**License:** Apache-2.0

## 1. Abstract

The Agent-to-Agent (A2A) protocol defines push-notification webhooks for delivering task updates from a Sender agent (or hosting platform) to a Receiver, but leaves the authentication, integrity, and replay-protection of those webhooks undefined. AWSP -- the A2A Webhook Security Profile -- specifies a single, interoperable wire format for signing, verifying, and replay-protecting those deliveries. It is modeled on the proven Stripe-Signature pattern (HMAC-SHA256, timestamp + nonce, multi-secret rotation) and adapted for inter-agent flows where Sender and Receiver are typically operated by different parties on different runtimes.

## 2. Motivation

The A2A specification (`/.well-known/agent.json`, JSON-RPC 2.0, `tasks/pushNotificationConfig/set`) standardizes the request/response shape of webhook configuration but does not define how a Receiver verifies that an incoming push really came from the Sender it expects, that the body has not been tampered with in flight, or that the same delivery is not being replayed by an attacker. Each implementer rolls their own scheme, often without replay protection or without a documented key-rotation story. The result is fragmentation -- every Sender-Receiver pair has to negotiate an ad-hoc shared format -- and a long tail of broken or absent verification on the Receiver side.

AWSP closes that gap. It defines:

1. A single header format (`X-A2A-Signature`) carrying timestamp, signature(s), nonce, and key identifier.
2. A canonical string for HMAC computation that is byte-exact regardless of body encoding.
3. Replay protection bounds (timestamp window + nonce uniqueness).
4. A key-rotation model with a published `kid` (key identifier) on every signature.
5. Sender-side SSRF defense for Receiver-supplied URLs.

The spec is small on purpose. It does what it needs to and stops.

## 3. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown here.

- **Sender** -- the party delivering the webhook. In A2A this is typically the agent or hosting platform producing task lifecycle events.
- **Receiver** -- the party operating the configured webhook URL and consuming events.
- **Secret** -- a shared symmetric key (raw bytes) used to compute the HMAC. AWSP does not specify how Sender and Receiver agree on a secret; that is part of the broader Sender/Receiver provisioning flow.
- **Key ID (`kid`)** -- an opaque short identifier (alphanumerics, `_`, `-`, `.`) labeling a specific Secret. Used to support multi-secret rotation.
- **Delivery** -- one HTTP POST from Sender to Receiver carrying one event. A Sender MAY retry a Delivery; retries reuse the same `X-A2A-Webhook-Id` (see section 5).
- **Nonce** -- a random, sufficiently-unique-per-Delivery identifier carried in the signature, used by the Receiver for replay rejection.

## 4. Threat model

AWSP defends against the following threats. See [THREAT_MODEL.md](./THREAT_MODEL.md) for elaboration.

| Threat                | Mitigation                                                                 |
|-----------------------|----------------------------------------------------------------------------|
| Forged sender         | HMAC-SHA256 with a shared Secret; Receiver rejects unknown signatures.     |
| Tampered body         | HMAC covers the raw body bytes; any in-flight modification breaks it.      |
| Replay                | `n=` nonce + timestamp window. Receiver MUST reject seen nonces.           |
| Stolen Secret         | Mitigated (not prevented) by `kid`-scoped rotation. Section 8.             |
| Clock skew            | +/- 300s tolerance window; configurable 60-600s.                           |
| Downgrade             | Only one signature version (v1) defined; future versions add new `vN=`.    |
| Algorithm confusion   | v1 is HMAC-SHA256 only -- no asymmetric variants in v1.                    |
| SSRF on Receiver URL  | Sender MUST resolve and gate the URL to public IPs (section 10).           |

Out of scope for AWSP v1:

- Confidentiality of the body. AWSP signs but does not encrypt. TLS handles transport confidentiality; payload-level encryption is left to operators.
- Authentication of the Receiver to the Sender. That is part of the broader A2A Sender/Receiver provisioning flow (Agent Card, OAuth, mTLS, etc.).
- Defense against compromise of the shared Secret. Once a Secret is leaked, an attacker can mint valid signatures until rotation completes.

## 5. Headers

A Sender MUST attach the following four headers to every Delivery.

### 5.1 `X-A2A-Signature`

```
X-A2A-Signature: t=<unix-seconds>,v1=<hex-hmac-sha256>,n=<nonce-base64url>,kid=<keyId>
```

The header value is a comma-separated list of `key=value` pairs. Field rules:

| Field   | Required | Format                                  | Notes |
|---------|----------|-----------------------------------------|-------|
| `t=`    | MUST     | Decimal ASCII unix-seconds              | The signer's clock at signing time. |
| `v1=`   | MUST     | 64 lowercase hex characters             | HMAC-SHA256 over the canonical string (section 6). MAY appear multiple times. |
| `n=`    | MUST     | base64url, 1-256 chars, no padding      | Per-Delivery random nonce. SHOULD be at least 16 bytes of entropy (24 base64url chars). |
| `kid=`  | MUST     | `[A-Za-z0-9._-]{1,128}`                 | Key identifier. Uniquely names the secret used to compute every `vN=` field in this header. |

Receivers:

- MUST treat the field order as insignificant.
- MUST NOT reject the header solely because it contains additional unknown `key=value` fields, but MUST ignore them.
- MUST treat the absence of any required field as `malformed_header`.
- MUST treat uppercase or non-hex `v1=` values as `malformed_header`.
- MUST accept multiple `v1=` fields in a single header (the Sender MAY include several signatures during algorithm rotation; Receivers MUST treat the request as authentic if any one valid `v1=` matches a known Secret).
- MUST treat unknown `vN=` fields (e.g. `v2=`, `v99=`) as informational. If the header carries no `v1=` AND at least one unknown `vN=`, Receivers MUST reject as `unknown_algorithm` rather than `malformed_header`.
- SHOULD impose a maximum total header length (e.g. 4096 bytes) and reject longer headers as `malformed_header`.

Future signature versions (v2, v3, ...) MAY be added to this spec. They will appear alongside `v1=` during rotation; receivers that understand both MUST verify the strongest version they recognize. Senders MUST NOT remove `v1=` until a future spec revision deprecates it.

### 5.2 `X-A2A-Webhook-Id`

```
X-A2A-Webhook-Id: <uuid>
```

A UUID (any version, but UUIDv4 RECOMMENDED) identifying this Delivery. On retry, the Sender MUST reuse the same `X-A2A-Webhook-Id`. Receivers MAY use this for application-level idempotency, independently of the `n=` nonce check.

### 5.3 `X-A2A-Event-Type`

```
X-A2A-Event-Type: <string>
```

A string naming the event class (e.g. `task.completed`, `task.failed`, `task.input_required`). Free-form for AWSP's purposes; A2A-level event vocabularies are layered on top.

### 5.4 `X-A2A-Timestamp`

```
X-A2A-Timestamp: <unix-seconds>
```

Redundant with `t=` inside `X-A2A-Signature`, but populated for log readability and easier triage. Receivers MUST verify against `t=` (which is covered by the HMAC), not `X-A2A-Timestamp`. If they disagree, the request MAY still be accepted -- the security-relevant value is `t=`.

## 6. Signature algorithm

### 6.1 Canonical string

The canonical string is the byte concatenation of:

```
<timestamp-decimal-ascii> + 0x2E (".") + <body-bytes>
```

Where:

- `<timestamp-decimal-ascii>` is the value of `t=` as decimal ASCII digits with no leading zeros and no sign.
- `<body-bytes>` is the raw body of the HTTP request -- the literal bytes the Sender wrote on the wire. NO transformation (no JSON re-serialization, no whitespace normalization, no character-set conversion). Receivers MUST verify against the raw body buffer they received before any parsing.

The canonical string is deliberately byte-exact and encoding-agnostic. A UTF-8 body, a UTF-16 body, and a binary body all sign the same way: HMAC over `t=...` || `.` || `<the body>`.

### 6.2 HMAC computation (v1)

```
v1 = lowercase_hex( HMAC-SHA256( key = secret_bytes, message = canonical_string ) )
```

- `secret_bytes` is the raw byte representation of the Secret. AWSP does not constrain length, but RECOMMENDS at least 32 bytes of entropy.
- The output is 32 bytes; serialized as 64 lowercase hexadecimal characters with no separators or prefix.
- Implementations MUST use a constant-time comparison when validating a candidate signature against the recomputed value.

### 6.3 Multi-secret support

A Sender may know about multiple Secrets simultaneously (e.g. during rotation). The Sender MUST place the kid of the secret it actually used to compute `v1=` in the `kid=` field of `X-A2A-Signature`, and MUST sign with the most recently provisioned Secret it has.

Receivers maintain an ordered list of `(kid, secret)` entries. On verification:

1. Filter the receiver's list to entries whose `kid` matches the header's `kid=`.
2. If no entries match, reject with `unknown_kid`.
3. For each matching entry, recompute the v1 HMAC and compare in constant time against every `v1=` value present in the header.
4. The request authenticates if any (entry, signature) pair matches.

A Receiver SHOULD complete every candidate comparison rather than short-circuit on the first failure, to keep total verification time independent of which entry / which signature matched.

## 7. Replay protection

Replay protection has two components:

### 7.1 Timestamp window

Let `now` be the Receiver's wall clock at the moment of verification, and `t` the value from `t=` in the header.

- The Receiver MUST reject the request as `stale` if `now - t > replayWindow`.
- The Receiver MUST reject the request as `future` if `t - now > replayWindow`.
- The exact boundary (`|now - t| == replayWindow`) MUST be accepted.

`replayWindow` defaults to **300 seconds**. Receivers MAY configure it as low as 60 seconds (tighter clock-skew requirement) or as high as 600 seconds. Values outside `[60, 600]` are non-conformant; Senders SHOULD assume Receivers run at the default.

### 7.2 Nonce uniqueness

The Receiver MUST maintain a store of recently-seen nonces. On verification:

- If `n=` has been seen within the past `replayWindow + 60` seconds, reject as `replayed`.
- Otherwise, atomically record `n=` with TTL `replayWindow + 60` seconds and proceed.

The 60-second buffer past `replayWindow` accommodates the case where two Receiver instances disagree by a few seconds about wall-clock time.

The nonce check SHOULD run AFTER HMAC verification. Storing nonces for forged or wrong-key requests is wasteful and may itself enable nonce-storage exhaustion as a denial vector.

Storage is implementation-defined. AWSP RECOMMENDS Redis `SET key NX EX <ttl>` (or equivalent) for multi-replica deployments. The reference TypeScript implementation includes `InMemoryReplayStore` for single-process / testing use.

Nonce uniqueness is **global to the Receiver**, not scoped per-`kid`. An attacker who has captured a delivery cannot replay it under a different `kid` claim (the HMAC under that `kid` won't validate anyway, but defense-in-depth is cheap here).

## 8. Key rotation

A Receiver maintains a list of valid `(kid, secret)` pairs. Rotation works as follows:

1. **Add new** -- provision the new Secret with a fresh `kid` (e.g. `k_2026_05` -> `k_2026_06`). Add it to the Receiver's accept list. Tell the Sender about it.
2. **Switch sender** -- the Sender starts signing with the new `kid`. The Receiver still accepts both kids.
3. **Overlap** -- both kids remain accepted for at least 24 hours. This window absorbs in-flight retries and delayed deliveries.
4. **Retire old** -- remove the old `(kid, secret)` from the Receiver's accept list. Future deliveries claiming the old kid will be rejected as `unknown_kid`.

Recommended overlap is at least 24 hours; teams running tighter delivery SLAs MAY shorten it, but MUST NOT make the overlap window shorter than the maximum retry horizon plus the replay window.

`kid` strings are opaque identifiers from AWSP's perspective. Senders SHOULD pick monotonically meaningful names (`k_2026_05`, `k_2026_06`) to make rotation auditable, but MUST NOT depend on lexicographic ordering for any security property.

## 9. Error responses

This section is informational guidance for Receivers; the actual HTTP semantics are application-layer.

When AWSP verification fails, Receivers SHOULD respond:

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{ "error": "invalid_signature", "reason": "<replayed|stale|future|bad_hmac|unknown_kid|malformed_header|unknown_algorithm>" }
```

The `reason` field is a stable enum from the set:

- `malformed_header` -- the `X-A2A-Signature` header was missing, garbled, or missing required fields.
- `unknown_algorithm` -- the header carried only `vN=` versions the Receiver does not recognize.
- `stale` -- timestamp older than `replayWindow`.
- `future` -- timestamp newer than `replayWindow`.
- `replayed` -- nonce already seen within the dedup horizon.
- `unknown_kid` -- kid did not match any of the Receiver's known keys.
- `bad_hmac` -- one or more `v1=` values were well-formed but did not match the recomputed signature for any candidate secret.

Including the `reason` is RECOMMENDED -- it enables Senders to dashboard root causes during rollout and rotation. Receivers operating in adversarial environments MAY collapse all failures to `bad_hmac` (or omit the field) at the cost of debuggability. Free-form diagnostic strings -- if any -- MUST NOT be returned in the response body, since they can leak internal state.

For retired endpoints (the Receiver no longer accepts deliveries here):

```
HTTP/1.1 410 Gone
Content-Type: application/json

{ "error": "endpoint_retired" }
```

Senders SHOULD treat 410 as a terminal failure for this Delivery and SHOULD NOT retry. Receivers MUST NOT serve 410 transiently (e.g. during deploys) -- 410 is a permanent signal.

A Sender MAY publish a `security.txt` file (RFC 9116) at `/.well-known/security.txt` advertising contact for AWSP-related issues; this is OPTIONAL and out of scope for verification.

## 10. SSRF defense (Sender side)

A Receiver supplies its webhook URL during configuration (typically via the A2A `tasks/pushNotificationConfig/set` flow). Without active defense, an attacker controlling the configuration call could point the URL at internal hosts (`http://169.254.169.254/`, `http://10.0.0.1/`, `http://localhost:5432/`) and trick the Sender into making requests on its behalf.

Senders MUST:

1. Resolve the URL's hostname to one or more IP addresses BEFORE connecting.
2. Reject the URL if any resolved address falls in a private, reserved, link-local, multicast, or loopback range, including:
   - IPv4: 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10 (RFC 6598), 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, 255.255.255.255/32.
   - IPv6: ::/128, ::1/128, ::ffff:0:0/96 (IPv4-mapped -- apply the IPv4 rules), 64:ff9b::/96, 100::/64, 2001::/23, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8.
3. Open the connection by IP, NOT by hostname, to defeat DNS-rebinding (the resolved IP is the connect target).
4. Refuse non-HTTPS schemes, with the exception that `http://` MAY be permitted only on Sender-internal test fixtures or explicit operator opt-in.
5. Cap response size, redirect-follows (deny by default), and total request time.

Receivers cannot enforce the SSRF defense -- it is a Sender-side responsibility. Receivers MAY publish their public IP allowlist in their Agent Card to help Senders configure outbound firewalling.

## 11. Test vectors

[`test-vectors.json`](./test-vectors.json) contains 50 deterministic vectors covering:

- 10 valid signatures (varying body sizes, ASCII / UTF-8 / binary, multiple kids, edge-of-window timestamps).
- 10 invalid HMACs (tampered body, wrong secret, wrong kid).
- 10 timestamp issues (stale, future, exact-edge accept).
- 10 replay cases (same nonce twice).
- 10 malformed headers (missing fields, uppercase hex, unknown algorithm, garbage).

Every vector specifies:

- `secret_hex` -- raw bytes of the Secret as hex.
- `body_hex` -- raw bytes of the body as hex.
- `timestamp` -- `t=` value.
- `nonce_b64url` -- `n=` value.
- `kid` -- `kid=` value.
- `expected_signature_hex` (for valid cases) -- the v1 HMAC the algorithm MUST produce.
- `expected_verify` -- either `"ok"` or `{ "error": "<reason>" }`.

Implementations are conformant to AWSP v1 if and only if all 50 vectors pass. New language ports SHOULD include the same suite as part of their CI.

## 12. Reference implementations

| Language   | Status   | Path / Package                                |
|------------|----------|-----------------------------------------------|
| TypeScript | Shipping | `@yawlabs/awsp` (npm) -- [reference/typescript](./reference/typescript) |
| Python     | Shipping | `yawlabs-awsp` (PyPI) -- [reference/python](./reference/python) |
| Go         | Shipping | `github.com/yawlabs/awsp-go` -- [reference/go](./reference/go) |
| Java       | Shipping | `com.yawlabs:awsp` (Maven) -- [reference/java](./reference/java) |
| .NET       | Shipping | `YawLabs.Awsp` (NuGet) -- [reference/dotnet](./reference/dotnet) |

The TypeScript implementation is the canonical reference. Other-language ports MUST pass [`test-vectors.json`](./test-vectors.json) verbatim.

All five reference implementations include a Sender-side SSRF helper (`assertPublicUrl` / `assert_public_url` / `AssertPublicURL` / `Ssrf.assertPublicUrl` / `Ssrf.AssertPublicUrlAsync`) implementing the IPv4 + IPv6 blocklist from section 10. Ports are dependency-free; SSRF gating uses each language's standard library.

## 13. License

This specification is published under the Apache License, Version 2.0. The reference implementations are licensed under the same terms. See [LICENSE](./reference/typescript/LICENSE).

## 14. Governance

AWSP is published and maintained at v1 by Yaw Labs. Yaw Labs commits to:

- Reviewing GitHub-issue-borne change proposals in public.
- Cutting backward-compatible spec revisions (v1.x) when they preserve the v1 wire format.
- Cutting major spec revisions (v2, v3, ...) when the wire format changes; new versions MUST be opt-in via a new `vN=` signature field, allowing a multi-month overlap.
- Donating spec stewardship to the Linux Foundation A2A project once production-implementation adoption signal lands. The reference implementations remain Apache-2.0 either way.

Change process and versioning details: see [GOVERNANCE.md](./GOVERNANCE.md).

## Appendix A: Open issues for v2 consideration

These were considered during v1 design and deferred. They are NOT v1 conformance requirements.

- **Asymmetric signatures.** Adding Ed25519 (`v2=`) would let Receivers verify without holding the Sender's signing key, simplifying multi-tenant trust. Deferred until at least one major Sender platform asks for it.
- **Body chunking / streaming.** v1 assumes the full body is available before signing. Streaming senders need a chunked variant -- left to v2 if/when streaming push notifications become real.
- **Mandatory `Content-Digest`.** Cross-signing the body via RFC 9530's `Content-Digest` header would let intermediaries validate body integrity without the AWSP secret. Deferred -- v1's HMAC over the raw body is sufficient for the threat model.
- **Sender-published key directories.** A `/.well-known/awsp-keys.json` JWKS-like document, useful when AWSP graduates to asymmetric signatures. Not needed for v1's symmetric model.
- **Algorithm agility.** A formal mechanism for a Sender to advertise which `vN` versions it produces, so a Receiver can negotiate down. v1 sidesteps this by mandating v1 as the floor.

## Appendix B: Worked example

Inputs:

- `secret` (32 bytes): `00010203040506070809101112131415161718192021222324252627282930ff` (hex)
- `kid`: `k_2026_05`
- `body` (UTF-8): `{"event":"task.completed","taskId":"tsk_abc"}`
- `timestamp`: `1777248000`
- `nonce` (base64url): `gNQ7bvcM2Y3xqW1dKpZJlw`

Canonical string (showing as ASCII for brevity; in practice raw bytes):

```
1777248000.{"event":"task.completed","taskId":"tsk_abc"}
```

That is: ASCII `1777248000`, then byte `0x2E` (`.`), then the 45-byte UTF-8 body.

`v1 = lowercase_hex(HMAC-SHA256(secret, canonical))` -- 64 hex chars.

Final header:

```
X-A2A-Signature: t=1777248000,v1=<64hex>,n=gNQ7bvcM2Y3xqW1dKpZJlw,kid=k_2026_05
```

End of specification.
