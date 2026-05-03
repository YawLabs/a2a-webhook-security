// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.

package com.yawlabs.awsp;

/**
 * Result of {@link Awsp#verify(VerifyParams)}.
 *
 * <p>{@code ok} is {@code true} on success and {@code reason} is {@code null}.
 * On failure {@code ok} is {@code false} and {@code reason} is one of the
 * stable spec enum strings:
 *
 * <ul>
 *   <li>{@code "malformed_header"}</li>
 *   <li>{@code "unknown_algorithm"}</li>
 *   <li>{@code "stale"}</li>
 *   <li>{@code "future"}</li>
 *   <li>{@code "replayed"}</li>
 *   <li>{@code "unknown_kid"}</li>
 *   <li>{@code "bad_hmac"}</li>
 * </ul>
 *
 * <p>Receivers SHOULD propagate {@code reason} to the 401 response body for
 * sender-side debuggability. Receivers in adversarial environments MAY
 * collapse all failures to {@code bad_hmac}. See SPEC.md section 9.
 */
public record VerifyResult(boolean ok, String reason) {

    /** Build a successful result. */
    public static VerifyResult success() {
        return new VerifyResult(true, null);
    }

    /** Build a failure result with the given stable reason code. */
    public static VerifyResult fail(String reason) {
        return new VerifyResult(false, reason);
    }
}
