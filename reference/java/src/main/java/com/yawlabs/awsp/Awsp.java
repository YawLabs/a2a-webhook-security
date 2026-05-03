// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.
//
// This package implements the v1 signing/verification algorithm defined in
// SPEC.md (packages/awsp/SPEC.md). It is dependency-free (only the standard
// library) and has no I/O of its own; replay storage is supplied by the
// caller via {@link ReplayStore}.
//
// Test vectors at packages/awsp/test-vectors.json are run by VectorTest.

package com.yawlabs.awsp;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Public entry point for AWSP signing and verification.
 *
 * <p>This class is non-instantiable. All operations are static.
 *
 * <p>Typical sender use:
 *
 * <pre>{@code
 * SignedHeaders headers = Awsp.sign(SignParams.builder()
 *     .secret(secretBytes)
 *     .keyId("k_2026_05")
 *     .body(payloadBytes)
 *     .eventType("task.completed")
 *     .build());
 * }</pre>
 *
 * <p>Typical receiver use:
 *
 * <pre>{@code
 * VerifyResult result = Awsp.verify(VerifyParams.builder()
 *     .headers(requestHeaderMap)
 *     .body(rawBodyBytes)
 *     .secrets(List.of(new VerifyParams.SecretEntry("k_2026_05", secretBytes)))
 *     .replayStore(myReplayStore)
 *     .build());
 * if (!result.ok()) {
 *     // 401 Unauthorized with {"error":"invalid_signature","reason":result.reason()}
 * }
 * }</pre>
 */
public final class Awsp {

    /** Replay window default per SPEC.md section 7.1. */
    public static final int DEFAULT_REPLAY_WINDOW_SECONDS = 300;

    /** Minimum receiver-allowed replay window. */
    public static final int MIN_REPLAY_WINDOW_SECONDS = 60;

    /** Maximum receiver-allowed replay window. */
    public static final int MAX_REPLAY_WINDOW_SECONDS = 600;

    /** Buffer added to {@code replayWindowSeconds} when computing replay-store TTL. */
    public static final int REPLAY_STORE_TTL_BUFFER_SECONDS = 60;

    private static final HexFormat LOWER_HEX = HexFormat.of();

    private Awsp() {
        // not instantiable
    }

    /**
     * Headers produced by {@link #sign(SignParams)}. All values are strings,
     * suitable for direct insertion into an HTTP request.
     */
    public record SignedHeaders(
            String xA2ASignature,
            String xA2AWebhookId,
            String xA2AEventType,
            String xA2ATimestamp) {

        /** Convert to a {@link Map} for HTTP-client APIs that take maps. */
        public Map<String, String> toMap() {
            // LinkedHashMap to make iteration order deterministic in tests.
            Map<String, String> m = new LinkedHashMap<>(8);
            m.put("X-A2A-Signature", xA2ASignature);
            m.put("X-A2A-Webhook-Id", xA2AWebhookId);
            m.put("X-A2A-Event-Type", xA2AEventType);
            m.put("X-A2A-Timestamp", xA2ATimestamp);
            return m;
        }
    }

    // -----------------------------------------------------------------------
    // Sign
    // -----------------------------------------------------------------------

    /**
     * Produce the four AWSP headers for a payload.
     *
     * <p>The HMAC is computed over {@code timestamp + "." + body}, where
     * {@code timestamp} is decimal ASCII unix-seconds with no leading zeros.
     *
     * @throws AwspException if any required field is missing or invalid.
     */
    public static SignedHeaders sign(SignParams params) {
        String v1Hex = computeV1(params.secret(), params.timestamp(), params.body());
        String header = Headers.serialize(params.timestamp(), List.of(v1Hex), params.nonce(), params.keyId());
        return new SignedHeaders(
                header,
                params.webhookId(),
                params.eventType(),
                Long.toString(params.timestamp()));
    }

    // -----------------------------------------------------------------------
    // Verify
    // -----------------------------------------------------------------------

    /**
     * Verify an incoming AWSP-signed request.
     *
     * <p>Step ordering (cheap rejections first, replay last so we don't
     * consume nonce-storage for forged requests):
     *
     * <ol>
     *   <li>Parse {@code X-A2A-Signature}. malformed_header / unknown_algorithm.</li>
     *   <li>Window check: {@code |now - t| <= replayWindowSeconds}. stale / future.</li>
     *   <li>Filter receiver secrets by {@code kid}. unknown_kid if none.</li>
     *   <li>Recompute HMAC for each candidate; constant-time compare against
     *       every {@code v1=} value. bad_hmac if no match.</li>
     *   <li>If a {@link ReplayStore} is supplied, atomically check-and-store
     *       the nonce. replayed if it was already present.</li>
     * </ol>
     */
    public static VerifyResult verify(VerifyParams params) {
        int window = params.replayWindowSeconds();
        if (window < MIN_REPLAY_WINDOW_SECONDS || window > MAX_REPLAY_WINDOW_SECONDS) {
            throw new AwspException(
                    "verify: replayWindowSeconds must be in ["
                            + MIN_REPLAY_WINDOW_SECONDS
                            + ", "
                            + MAX_REPLAY_WINDOW_SECONDS
                            + "], got "
                            + window);
        }

        String rawHeader = params.headers().get("x-a2a-signature");
        if (rawHeader == null) {
            return VerifyResult.fail("malformed_header");
        }

        Headers.Parsed parsed;
        try {
            parsed = Headers.parse(rawHeader);
        } catch (Headers.ParseException pe) {
            String reason = pe.failure == Headers.ParseFailure.UNKNOWN_ALGORITHM
                    ? "unknown_algorithm"
                    : "malformed_header";
            return VerifyResult.fail(reason);
        }

        long now = params.now() != null ? params.now() : (System.currentTimeMillis() / 1000L);
        long skew = now - parsed.timestamp;
        if (skew > window) {
            return VerifyResult.fail("stale");
        }
        if (skew < -window) {
            return VerifyResult.fail("future");
        }

        // Filter candidate (kid, secret) entries by the header's kid.
        List<VerifyParams.SecretEntry> candidates = params.secrets().stream()
                .filter(s -> s.kid().equals(parsed.kid))
                .toList();
        if (candidates.isEmpty()) {
            return VerifyResult.fail("unknown_kid");
        }

        // Constant-time HMAC verification. For each candidate (kid, secret),
        // recompute the v1 HMAC over the canonical string and compare against
        // every v1= value in the header using MessageDigest.isEqual.
        boolean matched = false;
        byte[] body = params.body();
        for (VerifyParams.SecretEntry entry : candidates) {
            byte[] expectedBytes = computeV1Bytes(entry.secret(), parsed.timestamp, body);
            for (String candidateHex : parsed.v1) {
                byte[] candidateBytes;
                try {
                    candidateBytes = LOWER_HEX.parseHex(candidateHex);
                } catch (IllegalArgumentException iae) {
                    // The parser already validated lowercase-hex shape; this
                    // can only happen if Headers.parse contracts change.
                    continue;
                }
                // MessageDigest.isEqual is documented constant-time across
                // equal-length inputs and false-fast on length mismatch.
                if (MessageDigest.isEqual(expectedBytes, candidateBytes)) {
                    matched = true;
                    // Per spec section 6.3, a receiver SHOULD complete every
                    // candidate comparison rather than short-circuit. We
                    // continue iterating to keep total verification time
                    // independent of which entry / signature matched.
                }
            }
        }

        if (!matched) {
            return VerifyResult.fail("bad_hmac");
        }

        ReplayStore store = params.replayStore();
        if (store != null) {
            int ttl = window + REPLAY_STORE_TTL_BUFFER_SECONDS;
            byte[] nonceBytes = parsed.nonce.getBytes(StandardCharsets.US_ASCII);
            boolean fresh = store.checkAndStore(params.configId(), nonceBytes, ttl);
            if (!fresh) {
                return VerifyResult.fail("replayed");
            }
        }

        return VerifyResult.success();
    }

    // -----------------------------------------------------------------------
    // Canonical string + HMAC (package-private for VectorTest)
    // -----------------------------------------------------------------------

    /**
     * Compute the v1 signature for a (timestamp, body) pair against a single
     * secret. Returns 64 lowercase hex characters.
     *
     * <p>The canonical string is {@code <decimal-ascii-timestamp> + 0x2E + body}.
     * No transformation is applied to the body; the byte sequence the sender
     * wrote on the wire is exactly the byte sequence that goes through the HMAC.
     */
    static String computeV1(byte[] secret, long timestamp, byte[] body) {
        // HexFormat.of() emits lowercase hex by default per its Javadoc.
        return LOWER_HEX.formatHex(computeV1Bytes(secret, timestamp, body));
    }

    private static byte[] computeV1Bytes(byte[] secret, long timestamp, byte[] body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] tsBytes = Long.toString(timestamp).getBytes(StandardCharsets.US_ASCII);
            mac.update(tsBytes);
            mac.update((byte) 0x2E); // '.'
            mac.update(body);
            return mac.doFinal();
        } catch (NoSuchAlgorithmException nsae) {
            throw new AwspException("HmacSHA256 unavailable in this JVM", nsae);
        } catch (InvalidKeyException ike) {
            throw new AwspException("invalid HMAC key", ike);
        }
    }
}
