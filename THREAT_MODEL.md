# AWSP Threat Model

This document elaborates section 4 of [SPEC.md](./SPEC.md). It enumerates the threats AWSP defends against, the mitigation each receives, and the residual risk left after the spec is correctly implemented.

## Replay attack

**Threat.** An attacker captures a previously valid AWSP-signed Delivery (e.g. via a misconfigured proxy log, a man-in-the-middle on a non-TLS hop, or an exfiltrated webhook traffic dump) and resubmits it later. Without replay protection, the HMAC still verifies and the Receiver acts on a duplicate event.

**Mitigation.** Two layers:

1. The `t=` timestamp must be within `replayWindow` of the Receiver's wall clock. By default `replayWindow = 300` seconds, so any captured Delivery older than 5 minutes is rejected.
2. The `n=` nonce must not have been seen within `replayWindow + 60` seconds. Receivers maintain shared (across replicas) nonce storage with that TTL.

A captured Delivery thus has at most a 5-minute replay window, AND only the first replay attempt within that window can succeed -- subsequent attempts are rejected at the nonce check.

**Residual risk.** An attacker who replays within seconds of the original delivery, AFTER the original packet was lost in transit (so the Receiver never recorded the nonce), can succeed once. This is rare and bounded -- the replay window is small and the attack requires specific timing.

**Receiver responsibility.** Storage MUST be shared across Receiver replicas. A nonce check that lives on a single replica's local memory is not replay protection -- it just delays an attacker until they hit a different replica. Use Redis `SET NX EX`, a Postgres `UNIQUE` constraint, or equivalent.

## Tampered body

**Threat.** An attacker with a man-in-the-middle position modifies the body bytes between Sender and Receiver. Without integrity, the Receiver acts on the modified body believing it came from the Sender.

**Mitigation.** The HMAC is computed over `<timestamp>.<body-bytes>` -- exact byte concatenation. Any mutation of any body byte produces a different HMAC. The constant-time comparison on the Receiver side rejects the request without leaking which byte differed.

**Residual risk.** If the attacker also has the Secret, they can re-sign. That is the "stolen Secret" threat, addressed below. If the attacker only has the body but not the Secret, they cannot mint a valid signature.

**Sender responsibility.** Sign over the EXACT bytes that will be transmitted, including any whitespace or trailing newlines. JSON re-serialization between sign and send is a common bug class.

**Receiver responsibility.** Verify against the EXACT bytes received, before any parser touches them. Most HTTP frameworks parse the body before passing it to handlers; the framework's "raw body" hook (or content-type-parser bypass) must run first. The `@yawlabs/awsp` README documents the relevant hooks for Express, Fastify, and Hono.

## Stolen Secret

**Threat.** The shared Secret leaks -- via a code commit, a logged environment variable, an exfiltrated config file, or a compromised CI runner. An attacker can mint signatures for arbitrary bodies until the Secret is rotated out.

**Mitigation.** Partial. AWSP's `kid`-scoped rotation lets you cycle a Secret without coordinated downtime: provision a new `(kid, secret)`, switch the Sender, retire the old kid after an overlap. Detection is left to operators -- AWSP does not include a tamper-evident audit trail.

**Residual risk.** Between leak and rotation, the attacker can produce valid Deliveries indistinguishable from legitimate ones. Rotation does not retroactively invalidate signatures the attacker captured before rotation.

**Operator responsibility.** Treat AWSP Secrets like any high-sensitivity credential: rotate proactively, scope access, log every retrieval, alert on anomalies. AWSP cannot recover from a Secret compromise -- only rotation can.

## Clock skew

**Threat.** Sender and Receiver disagree on wall-clock time. A Receiver that requires the timestamp to be exactly the current second would reject every legitimate Delivery; a Receiver with no bound at all has no replay protection from the timestamp dimension.

**Mitigation.** AWSP's `replayWindow` defaults to +/- 300 seconds (5 minutes), which absorbs essentially all production NTP skew (typical drift: milliseconds to single-digit seconds). Receivers in tightly-clocked environments MAY shrink the window to 60 seconds for stricter replay defense; Receivers serving operators with poor NTP MAY widen it to 600 seconds.

**Residual risk.** A wider window is a strictly larger replay surface (an attacker has more time to replay a captured Delivery before the timestamp goes stale). The 300-second default is a balance; teams running 600-second windows accept a 2x increase in worst-case replay window.

**Operator responsibility.** Run NTP. The replay window is a tolerance for jitter, not a substitute for clock discipline.

## Downgrade attacks

**Threat.** An attacker who sees a Sender publishing both `v1=` and `v2=` strips the stronger `v2=` and presents only the weaker `v1=`, hoping a Receiver that supports both will fall back.

**Mitigation.** AWSP v1 defines only one signature version, `v1=`. There is nothing to downgrade. Future spec revisions that introduce `v2=` MUST explicitly require: "Receivers that recognize `v2=` MUST verify `v2=` rather than fall back to `v1=` if both are present." This precludes the downgrade strip.

**Residual risk.** None at v1. Future revisions need to actively design against this -- noted in section 14 / Appendix A of SPEC.md.

## Algorithm confusion

**Threat.** A naive parser interprets `v1=...` and an attacker-supplied `vSomething=...` as semantically equivalent and validates against the wrong field, or the algorithm field encodes a bytestring that the parser feeds back into the Secret derivation.

**Mitigation.** AWSP v1 has exactly one algorithm. The header parser explicitly recognizes `v1=` only and treats other `vN=` fields as informational. There is no algorithm-name field that gets fed back into key derivation -- the Secret is provisioned out-of-band and is never selected by header content (the `kid=` selects from a closed set of pre-provisioned secrets).

**Residual risk.** Implementation bugs (e.g. JWT-style "alg=none") are precluded by the spec design, but lazy parsers could still go wrong. The reference TypeScript implementation includes specific tests for each `vN=` confusion case.

## Slow-DoS / amplification

**Threat.** An attacker sends a stream of large-body, signature-failing requests. The Receiver computes HMAC-SHA256 over each body before rejecting, exhausting CPU. Or: the attacker sends genuine but high-volume Deliveries to amplify load.

**Mitigation.** AWSP cannot prevent this on its own -- HMAC verification is inherently O(body size). Mitigations layered on top:

1. Receivers SHOULD impose a max-body-size limit BEFORE HMAC verification. AWSP-conforming bodies are typically <16KB; Receivers can safely reject 1MB+ payloads at the framework layer.
2. Receivers SHOULD rate-limit per-webhook-config-id or per-source-IP. The `kid=` field gives a per-credential rate-limit dimension; Receivers can configure quotas per `kid`.
3. Receivers MAY perform a cheap pre-check (timestamp window) before the HMAC compute. The reference implementation does this -- stale/future are rejected without HMAC computation.

**Residual risk.** A determined attacker with valid signing material (i.e. who has compromised a Secret) can amplify legitimately. AWSP defers to standard rate-limiting and operator monitoring here.

## Out of scope

- **TLS interception by intermediaries.** AWSP defends body integrity even if TLS is intercepted, but does not address confidentiality. Use TLS plus payload encryption if confidentiality matters.
- **Receiver-side log leaks.** A Receiver that logs the request body in cleartext leaks event content even when AWSP verification succeeds. AWSP says nothing about this.
- **Sender impersonation at the Sender's edge.** If an attacker compromises the Sender's machine, they sign as the Sender. AWSP can't help -- it just signs whatever the Sender tells it to.
- **Sender-Receiver mutual authentication.** AWSP authenticates Deliveries (Receiver knows the Sender knows the Secret). It does not authenticate the Receiver to the Sender; that is the SSRF + URL-provisioning problem, partially addressed in section 10 of SPEC.md.
