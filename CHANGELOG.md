# Changelog

All notable changes to AWSP (the spec) and its reference implementations are documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Spec and reference-implementation versions are tracked separately when their lifecycles diverge.

## 0.1.0 -- Unreleased

Initial public release. No artifacts published yet (no git tag, no npm/PyPI/Maven/NuGet entry); this section will be dated on tag.

### Spec

- AWSP v1 specification published.
- Defined `X-A2A-Signature` (with `t=`, `v1=`, `n=`, `kid=`), `X-A2A-Webhook-Id`, `X-A2A-Event-Type`, `X-A2A-Timestamp` headers.
- Canonical string: `<timestamp-decimal-ascii> + "." + <body-bytes>`. HMAC-SHA256, lowercase hex.
- Replay protection: +/- 300s default window (configurable 60-600s) plus nonce uniqueness with `window + 60s` TTL.
- Key rotation via `kid=`-scoped multi-secret support.
- Sender-side SSRF defense requirements.
- Threat model published as separate document.
- 50 deterministic test vectors (`test-vectors.json`) covering valid signatures, invalid HMACs, timestamp edge cases (including exact-window-boundary acceptance in both directions), replay rejection, and malformed-header handling. Every conforming port MUST pass all 50 vectors.

### Reference implementations

All five ports are zero-runtime-dependency, Apache-2.0 licensed, and pass the
full 50-vector conformance suite against the canonical `test-vectors.json`.
Every port also ships:

- A Sender-side SSRF helper (`assertPublicUrl` and language equivalents)
  implementing the IPv4 + IPv6 blocklist from SPEC.md section 10. Uses each
  language's standard library; no new dependencies.
- Adversarial parser tests (random-byte fuzz, byte-boundary truncation,
  duplicate fields, mixed-case keys, control-byte values, every spec error
  reason reachable). Go uses native `testing.F` fuzz; Python uses Hypothesis;
  Java/.NET use seeded parameterized tests.
- An amortized eviction strategy on the in-memory replay store (8192-entry
  threshold, sweeps every 256 calls past threshold) -- O(1) amortized instead
  of O(n) per call.

Per-port summary:

- **TypeScript** -- `@yawlabs/awsp` 0.1.0. `sign()` / `verify()`, `InMemoryReplayStore`, `assertPublicUrl()`. Node 18+. 291 tests.
- **Python** -- `yawlabs-awsp` 0.1.0. `sign()` / `verify()`, `InMemoryReplayStore`, `SecretEntry`, `assert_public_url()`. Python 3.10+, stdlib only. 294 tests.
- **Go** -- `github.com/yawlabs/awsp-go`. `awsp.Sign` / `awsp.Verify`, `NewInMemoryReplayStore`, `AssertPublicURL`, pluggable `ReplayStore` interface. Go 1.22+, stdlib only. 322 test cases plus `FuzzParseSignatureHeader`.
- **Java** -- `com.yawlabs:awsp` 1.0.0. `Awsp.sign` / `Awsp.verify`, `InMemoryReplayStore`, `Ssrf.assertPublicUrl`. JDK 17+, BCL only. 3151 test cases.
- **.NET** -- `YawLabs.Awsp` 0.1.0. `Awsp.Sign` / `Awsp.Verify`, `InMemoryReplayStore`, `IReplayStore`, `Ssrf.AssertPublicUrlAsync`. `net8.0`, BCL only. 203 test cases.

Note: the verify-failure result on every port carries only the structured
`reason` enum -- no free-form `message` / `detail` field. Diagnostics belong
in the receiver's logs, not in HTTP response bodies.
