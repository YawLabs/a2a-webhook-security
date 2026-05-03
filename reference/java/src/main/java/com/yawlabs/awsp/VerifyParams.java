// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.

package com.yawlabs.awsp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Inputs to {@link Awsp#verify(VerifyParams)}.
 *
 * <p>Use {@link #builder()} to construct. Required fields: {@code headers},
 * {@code body}, {@code secrets}. Optional fields:
 *
 * <ul>
 *   <li>{@code replayStore} -- if absent, replay protection is skipped.</li>
 *   <li>{@code configId} -- opaque label for replay-store scoping. Defaults
 *       to {@code "default"}.</li>
 *   <li>{@code replayWindowSeconds} -- defaults to 300. Spec range [60, 600].</li>
 *   <li>{@code now} -- defaults to current wall-clock unix-seconds.</li>
 * </ul>
 *
 * <p>Instances are immutable.
 */
public final class VerifyParams {

    /** A (kid, secret) pair the receiver currently accepts. */
    public record SecretEntry(String kid, byte[] secret) {

        public SecretEntry {
            Objects.requireNonNull(kid, "kid");
            Objects.requireNonNull(secret, "secret");
            if (kid.isEmpty()) {
                throw new IllegalArgumentException("kid must not be empty");
            }
            if (secret.length == 0) {
                throw new IllegalArgumentException("secret must not be empty");
            }
            // Defensive copy. The accessor below also returns a copy.
            secret = secret.clone();
        }

        /** Returns a defensive copy of the secret bytes. */
        @Override
        public byte[] secret() {
            return secret.clone();
        }
    }

    private final Map<String, String> headers;
    private final byte[] body;
    private final List<SecretEntry> secrets;
    private final ReplayStore replayStore;
    private final String configId;
    private final int replayWindowSeconds;
    private final Long now;

    private VerifyParams(Builder b) {
        if (b.headers == null) {
            throw new AwspException("verify: headers required");
        }
        if (b.body == null) {
            throw new AwspException("verify: body required (use new byte[0] for empty)");
        }
        if (b.secrets == null) {
            throw new AwspException("verify: secrets required");
        }
        this.headers = Collections.unmodifiableMap(lowercaseKeys(b.headers));
        this.body = b.body.clone();
        this.secrets = List.copyOf(b.secrets);
        this.replayStore = b.replayStore;
        this.configId = b.configId != null ? b.configId : "default";
        this.replayWindowSeconds = b.replayWindowSeconds != null ? b.replayWindowSeconds : 300;
        this.now = b.now;
    }

    /** Lower-cased header map. Lookups in verify() use lowercase keys. */
    public Map<String, String> headers() {
        return headers;
    }

    /** Returns a defensive copy of the body bytes. */
    public byte[] body() {
        return body.clone();
    }

    /** All (kid, secret) entries the receiver currently accepts. */
    public List<SecretEntry> secrets() {
        return secrets;
    }

    /** Optional replay store. May be {@code null}. */
    public ReplayStore replayStore() {
        return replayStore;
    }

    /** Opaque config id used to scope replay-store entries. */
    public String configId() {
        return configId;
    }

    /** Replay window in seconds. Spec range [60, 600], default 300. */
    public int replayWindowSeconds() {
        return replayWindowSeconds;
    }

    /**
     * Optional override for the receiver's wall clock (unix-seconds).
     * {@code null} means "use {@code System.currentTimeMillis()/1000}".
     */
    public Long now() {
        return now;
    }

    public static Builder builder() {
        return new Builder();
    }

    private static Map<String, String> lowercaseKeys(Map<String, String> in) {
        // Preserve insertion order; collapse case via lowercase keys. If both
        // X-A2A-Signature and x-a2a-signature appear, the later wins.
        var out = new java.util.LinkedHashMap<String, String>(in.size() * 2);
        for (var e : in.entrySet()) {
            if (e.getKey() == null) continue;
            out.put(e.getKey().toLowerCase(java.util.Locale.ROOT), e.getValue());
        }
        return out;
    }

    /** Mutable builder for {@link VerifyParams}. */
    public static final class Builder {
        private Map<String, String> headers;
        private byte[] body;
        private List<SecretEntry> secrets;
        private ReplayStore replayStore;
        private String configId;
        private Integer replayWindowSeconds;
        private Long now;

        private Builder() {}

        /** Required. Request headers (case-insensitive lookup). */
        public Builder headers(Map<String, String> headers) {
            this.headers = Objects.requireNonNull(headers, "headers");
            return this;
        }

        /** Required. Raw request body bytes. */
        public Builder body(byte[] body) {
            this.body = Objects.requireNonNull(body, "body");
            return this;
        }

        /** Required. List of receiver-accepted (kid, secret) entries. */
        public Builder secrets(List<SecretEntry> secrets) {
            this.secrets = new ArrayList<>(Objects.requireNonNull(secrets, "secrets"));
            return this;
        }

        /** Convenience: single (kid, secret) pair. */
        public Builder secret(String kid, byte[] secret) {
            this.secrets = List.of(new SecretEntry(kid, secret));
            return this;
        }

        /** Optional. Without it, replay protection is skipped. */
        public Builder replayStore(ReplayStore replayStore) {
            this.replayStore = replayStore;
            return this;
        }

        /** Optional. Defaults to {@code "default"}. */
        public Builder configId(String configId) {
            this.configId = configId;
            return this;
        }

        /** Optional. Defaults to 300. Must be in [60, 600] per spec. */
        public Builder replayWindowSeconds(int replayWindowSeconds) {
            this.replayWindowSeconds = replayWindowSeconds;
            return this;
        }

        /** Optional. Override receiver wall-clock time for deterministic tests. */
        public Builder now(long now) {
            this.now = now;
            return this;
        }

        public VerifyParams build() {
            return new VerifyParams(this);
        }
    }
}
