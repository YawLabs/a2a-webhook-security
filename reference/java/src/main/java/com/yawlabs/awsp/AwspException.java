// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.

package com.yawlabs.awsp;

/**
 * Unchecked exception raised by {@link Awsp#sign(SignParams)} when input
 * parameters are invalid (e.g. zero-length secret, missing key id).
 *
 * <p>Verification failures do <em>not</em> throw -- they return a
 * {@link VerifyResult} with {@code ok=false} and a stable {@code reason}
 * code from the spec. See {@link Awsp#verify(VerifyParams)}.
 */
public class AwspException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AwspException(String message) {
        super(message);
    }

    public AwspException(String message, Throwable cause) {
        super(message, cause);
    }
}
