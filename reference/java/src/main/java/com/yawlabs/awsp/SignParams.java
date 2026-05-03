// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.

package com.yawlabs.awsp;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

/**
 * Inputs to {@link Awsp#sign(SignParams)}.
 *
 * <p>Use {@link #builder()} to construct an instance. Required fields:
 * {@code secret}, {@code keyId}, {@code body}, {@code eventType}.
 * Optional fields default to:
 *
 * <ul>
 *   <li>{@code timestamp} -- current wall-clock unix-seconds.</li>
 *   <li>{@code nonce} -- 18 bytes of {@link SecureRandom} encoded as
 *       24-char base64url (no padding).</li>
 *   <li>{@code webhookId} -- a fresh random UUIDv4.</li>
 * </ul>
 *
 * <p>Instances are immutable.
 */
public final class SignParams {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final byte[] secret;
    private final String keyId;
    private final byte[] body;
    private final String eventType;
    private final long timestamp;
    private final String nonce;
    private final String webhookId;

    private SignParams(Builder b) {
        if (b.secret == null || b.secret.length == 0) {
            throw new AwspException("sign: secret must be non-empty");
        }
        if (b.keyId == null || b.keyId.isEmpty()) {
            throw new AwspException("sign: keyId required");
        }
        if (b.body == null) {
            throw new AwspException("sign: body must not be null (use new byte[0] for empty)");
        }
        if (b.eventType == null || b.eventType.isEmpty()) {
            throw new AwspException("sign: eventType required");
        }
        // Defensive copy of secret + body.
        this.secret = b.secret.clone();
        this.keyId = b.keyId;
        this.body = b.body.clone();
        this.eventType = b.eventType;
        this.timestamp = b.timestamp != null ? b.timestamp : (System.currentTimeMillis() / 1000L);
        this.nonce = b.nonce != null ? b.nonce : generateNonce();
        this.webhookId = b.webhookId != null ? b.webhookId : UUID.randomUUID().toString();
    }

    /** Raw secret bytes. The shared HMAC key. Returns a defensive copy. */
    public byte[] secret() {
        return secret.clone();
    }

    /** Identifier for this secret -- placed in the {@code kid=} field. */
    public String keyId() {
        return keyId;
    }

    /** Raw payload bytes signed verbatim. Returns a defensive copy. */
    public byte[] body() {
        return body.clone();
    }

    /** Event-type label for the {@code X-A2A-Event-Type} header. */
    public String eventType() {
        return eventType;
    }

    /** Unix-seconds timestamp placed in {@code t=}. */
    public long timestamp() {
        return timestamp;
    }

    /** Base64url nonce (no padding) placed in {@code n=}. */
    public String nonce() {
        return nonce;
    }

    /** UUID identifying the delivery; placed in {@code X-A2A-Webhook-Id}. */
    public String webhookId() {
        return webhookId;
    }

    /** Start a new builder. */
    public static Builder builder() {
        return new Builder();
    }

    private static String generateNonce() {
        byte[] raw = new byte[18];
        RNG.nextBytes(raw);
        return B64URL.encodeToString(raw);
    }

    /** Mutable builder for {@link SignParams}. */
    public static final class Builder {
        private byte[] secret;
        private String keyId;
        private byte[] body;
        private String eventType;
        private Long timestamp;
        private String nonce;
        private String webhookId;

        private Builder() {}

        /** Required. Raw secret bytes. */
        public Builder secret(byte[] secret) {
            this.secret = Objects.requireNonNull(secret, "secret");
            return this;
        }

        /** Required. Identifier for the secret (kid field). */
        public Builder keyId(String keyId) {
            this.keyId = Objects.requireNonNull(keyId, "keyId");
            return this;
        }

        /** Required. Raw payload bytes. */
        public Builder body(byte[] body) {
            this.body = Objects.requireNonNull(body, "body");
            return this;
        }

        /** Required. Event-type label. */
        public Builder eventType(String eventType) {
            this.eventType = Objects.requireNonNull(eventType, "eventType");
            return this;
        }

        /** Optional. Unix-seconds timestamp. Defaults to wall-clock now. */
        public Builder timestamp(long timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        /** Optional. base64url nonce. Defaults to 18 random bytes (24 chars). */
        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        /** Optional. Webhook delivery UUID. Defaults to a fresh UUIDv4. */
        public Builder webhookId(String webhookId) {
            this.webhookId = webhookId;
            return this;
        }

        public SignParams build() {
            return new SignParams(this);
        }
    }
}
