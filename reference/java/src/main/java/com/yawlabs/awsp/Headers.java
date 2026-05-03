// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.

package com.yawlabs.awsp;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Parser and serializer for the {@code X-A2A-Signature} header.
 *
 * <p>Header form, per SPEC.md section 5.1:
 *
 * <pre>
 *   t=&lt;unix-seconds&gt;,v1=&lt;hex&gt;[,v1=&lt;hex&gt;...],n=&lt;nonce-b64url&gt;,kid=&lt;keyId&gt;
 * </pre>
 *
 * <p>Field order is not significant. Multiple {@code v1=} values are allowed
 * (algorithm rotation); receivers MUST accept the request if any one of them
 * validates against any known secret.
 *
 * <p>This class is package-private utility. Public callers go through
 * {@link Awsp#sign(SignParams)} / {@link Awsp#verify(VerifyParams)}.
 */
final class Headers {

    /** Maximum total header length. Longer headers are rejected as malformed. */
    static final int MAX_HEADER_LENGTH = 4096;

    private static final Pattern TIMESTAMP_RE = Pattern.compile("^[0-9]{1,15}$");
    private static final Pattern V1_HEX_RE = Pattern.compile("^[0-9a-f]{64}$");
    private static final Pattern UNKNOWN_VERSION_RE = Pattern.compile("^v[0-9]+$");
    private static final Pattern NONCE_RE = Pattern.compile("^[A-Za-z0-9_-]{1,256}$");
    private static final Pattern KID_RE = Pattern.compile("^[A-Za-z0-9._\\-]{1,128}$");

    private Headers() {}

    /** Parsed signature header fields. */
    static final class Parsed {
        final long timestamp;
        final List<String> v1;
        final String nonce;
        final String kid;

        Parsed(long timestamp, List<String> v1, String nonce, String kid) {
            this.timestamp = timestamp;
            this.v1 = List.copyOf(v1);
            this.nonce = nonce;
            this.kid = kid;
        }
    }

    /**
     * Parse error category. Mapped to a {@link VerifyResult} reason by
     * {@link Awsp#verify(VerifyParams)}.
     */
    enum ParseFailure {
        MALFORMED,
        UNKNOWN_ALGORITHM,
    }

    /** Thrown by {@link #parse(String)} on any parse error. */
    static final class ParseException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        final ParseFailure failure;

        ParseException(ParseFailure failure, String message) {
            super(message);
            this.failure = failure;
        }
    }

    /**
     * Parse a raw header value. Throws {@link ParseException} on any error.
     *
     * <p>Spec rules enforced:
     * <ul>
     *   <li>{@code t=} required, decimal ASCII unix-seconds, no sign.</li>
     *   <li>{@code v1=} required (one or more), 64 lowercase hex chars.</li>
     *   <li>{@code n=} required, base64url alphabet, 1..256 chars.</li>
     *   <li>{@code kid=} required, [A-Za-z0-9._-]{1,128}.</li>
     *   <li>Unknown {@code vN=} fields without any {@code v1=} -> unknown_algorithm.</li>
     *   <li>Other unknown fields are ignored (forward compatibility).</li>
     *   <li>Field order is insignificant; duplicate t/n/kid are malformed.</li>
     *   <li>Total header length capped at {@value #MAX_HEADER_LENGTH}.</li>
     * </ul>
     */
    static Parsed parse(String raw) {
        if (raw == null || raw.isEmpty()) {
            throw new ParseException(ParseFailure.MALFORMED, "empty header");
        }
        if (raw.length() > MAX_HEADER_LENGTH) {
            throw new ParseException(ParseFailure.MALFORMED, "header too long");
        }

        Long timestamp = null;
        List<String> v1 = new ArrayList<>(2);
        String nonce = null;
        String kid = null;
        boolean sawUnknownVersion = false;

        for (String part : raw.split(",", -1)) {
            int eq = part.indexOf('=');
            if (eq <= 0 || eq == part.length() - 1) {
                throw new ParseException(ParseFailure.MALFORMED, "bad pair: " + part);
            }
            String key = part.substring(0, eq).trim();
            String value = part.substring(eq + 1).trim();
            if (key.isEmpty() || value.isEmpty()) {
                throw new ParseException(ParseFailure.MALFORMED, "empty key or value: " + part);
            }

            switch (key) {
                case "t" -> {
                    if (timestamp != null) {
                        throw new ParseException(ParseFailure.MALFORMED, "duplicate t=");
                    }
                    if (!TIMESTAMP_RE.matcher(value).matches()) {
                        throw new ParseException(ParseFailure.MALFORMED, "bad timestamp");
                    }
                    try {
                        long ts = Long.parseLong(value);
                        if (ts < 0) {
                            throw new ParseException(ParseFailure.MALFORMED, "bad timestamp");
                        }
                        timestamp = ts;
                    } catch (NumberFormatException nfe) {
                        throw new ParseException(ParseFailure.MALFORMED, "bad timestamp");
                    }
                }
                case "v1" -> {
                    if (!V1_HEX_RE.matcher(value).matches()) {
                        throw new ParseException(
                                ParseFailure.MALFORMED, "bad v1 (must be 64 lowercase hex)");
                    }
                    v1.add(value);
                }
                case "n" -> {
                    if (nonce != null) {
                        throw new ParseException(ParseFailure.MALFORMED, "duplicate n=");
                    }
                    if (!NONCE_RE.matcher(value).matches()) {
                        throw new ParseException(
                                ParseFailure.MALFORMED, "bad nonce (must be base64url, 1-256 chars)");
                    }
                    nonce = value;
                }
                case "kid" -> {
                    if (kid != null) {
                        throw new ParseException(ParseFailure.MALFORMED, "duplicate kid=");
                    }
                    if (!KID_RE.matcher(value).matches()) {
                        throw new ParseException(ParseFailure.MALFORMED, "bad kid");
                    }
                    kid = value;
                }
                default -> {
                    if (UNKNOWN_VERSION_RE.matcher(key).matches()) {
                        // Future signature versions: ignore but flag for the
                        // unknown_algorithm check below.
                        sawUnknownVersion = true;
                    }
                    // Other unknown keys: forward-compatibility, ignore silently.
                }
            }
        }

        if (timestamp == null) {
            throw new ParseException(ParseFailure.MALFORMED, "t= required");
        }
        if (nonce == null) {
            throw new ParseException(ParseFailure.MALFORMED, "n= required");
        }
        if (v1.isEmpty()) {
            if (sawUnknownVersion) {
                throw new ParseException(
                        ParseFailure.UNKNOWN_ALGORITHM, "no supported signature version");
            }
            throw new ParseException(ParseFailure.MALFORMED, "v1= required");
        }
        if (kid == null) {
            // v1 mandates kid for forward-compatible rotation; absence is malformed.
            throw new ParseException(ParseFailure.MALFORMED, "kid= required");
        }

        return new Parsed(timestamp, v1, nonce, kid);
    }

    /**
     * Serialize a parsed signature back into wire form. Field order:
     * {@code t}, {@code v1...}, {@code n}, {@code kid}.
     */
    static String serialize(long timestamp, List<String> v1, String nonce, String kid) {
        StringBuilder sb = new StringBuilder(80 + 65 * v1.size());
        sb.append("t=").append(timestamp);
        for (String v : v1) {
            sb.append(",v1=").append(v);
        }
        sb.append(",n=").append(nonce);
        sb.append(",kid=").append(kid);
        return sb.toString();
    }
}
