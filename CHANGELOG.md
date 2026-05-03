# Changelog

All notable changes to AWSP (the spec) and `@yawlabs/awsp` (the TypeScript reference implementation) are documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Spec and reference-implementation versions are tracked separately when their lifecycles diverge.

## 0.1.0 -- 2026-05-02

Initial public release.

### Spec

- AWSP v1 specification published.
- Defined `X-A2A-Signature` (with `t=`, `v1=`, `n=`, `kid=`), `X-A2A-Webhook-Id`, `X-A2A-Event-Type`, `X-A2A-Timestamp` headers.
- Canonical string: `<timestamp-decimal-ascii> + "." + <body-bytes>`. HMAC-SHA256, lowercase hex.
- Replay protection: +/- 300s default window (configurable 60-600s) plus nonce uniqueness with `window + 60s` TTL.
- Key rotation via `kid=`-scoped multi-secret support.
- Sender-side SSRF defense requirements.
- Threat model published as separate document.

### Reference implementation (`@yawlabs/awsp` 0.1.0)

- TypeScript implementation of `sign()` and `verify()`.
- `InMemoryReplayStore` for tests / single-replica receivers.
- 50 deterministic test vectors covering valid, invalid-HMAC, timestamp issues, replay, and malformed-header cases.
- Zero runtime dependencies; works on Node 18+.
- 100% line coverage from the test suite.
- Apache-2.0 licensed.
