// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.

package com.yawlabs.awsp;

/**
 * Replay-protection storage hook supplied by the receiver to
 * {@link Awsp#verify(VerifyParams)}.
 *
 * <p>An implementation MUST be atomic: between the "have I seen this nonce?"
 * check and the "record it" write, no other invocation may insert the same
 * (configId, nonce) pair. Redis {@code SET key NX EX <ttl>} is the canonical
 * recipe for multi-replica deployments. {@link InMemoryReplayStore} is the
 * reference implementation for single-process / testing use.
 *
 * <p>Per SPEC.md section 7.2, nonce uniqueness is global to the receiver --
 * the {@code configId} parameter exists so receivers managing many independent
 * webhook configurations on the same process may scope storage namespaces
 * (avoiding cross-config nonce-collision DoS), but a single shared scope is
 * spec-compliant.
 */
public interface ReplayStore {

    /**
     * Atomically: if {@code (configId, nonce)} has been seen within
     * {@code ttlSeconds}, return {@code false}. Otherwise record the nonce
     * with TTL {@code ttlSeconds} and return {@code true}.
     *
     * <p>The {@link Awsp#verify(VerifyParams)} entry point passes
     * {@code ttlSeconds = replayWindow + 60}, per spec.
     *
     * @param configId  opaque scoping label. Implementations SHOULD
     *                  combine with {@code nonce} when building the
     *                  storage key (e.g. {@code configId + ":" + nonce}).
     * @param nonce     base64url nonce as ASCII bytes.
     * @param ttlSeconds time to live, in seconds.
     * @return {@code true} if the nonce was unseen and is now recorded;
     *         {@code false} if it was already present (replay).
     */
    boolean checkAndStore(String configId, byte[] nonce, int ttlSeconds);
}
