// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.
//
// Runs every vector from packages/awsp/test-vectors.json against the Java
// sign / verify implementation. All 50 vectors must pass byte-for-byte; this
// is the conformance bar from SPEC.md section 11.

package com.yawlabs.awsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class VectorTest {

    private static final HexFormat HEX = HexFormat.of();

    /**
     * Load all vectors as a stream of {@code (name, vector)} pairs for
     * {@link MethodSource}. The display name shows up in the test report so
     * failures are diagnosable per-vector.
     */
    static Stream<org.junit.jupiter.params.provider.Arguments> vectors() throws IOException {
        @SuppressWarnings("unchecked")
        Map<String, Object> doc = (Map<String, Object>) MiniJson.parse(loadVectorJson());
        @SuppressWarnings("unchecked")
        List<Object> vectors = (List<Object>) doc.get("vectors");
        Number expectedCount = (Number) doc.get("vector_count");
        assertEquals(50L, expectedCount.longValue(), "spec asserts 50 vectors");
        assertEquals(50, vectors.size(), "vectors array must have 50 entries");

        List<org.junit.jupiter.params.provider.Arguments> args = new ArrayList<>(vectors.size());
        for (Object v : vectors) {
            @SuppressWarnings("unchecked")
            Map<String, Object> vec = (Map<String, Object>) v;
            args.add(org.junit.jupiter.params.provider.Arguments.of(vec.get("name"), vec));
        }
        return args.stream();
    }

    @Test
    void vectorFileLoads() throws IOException {
        @SuppressWarnings("unchecked")
        Map<String, Object> doc = (Map<String, Object>) MiniJson.parse(loadVectorJson());
        assertEquals("AWSP v1", doc.get("spec"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void vector(String name, Map<String, Object> vec) {
        byte[] secret = HEX.parseHex((String) vec.get("secret_hex"));
        byte[] body = HEX.parseHex((String) vec.get("body_hex"));
        long timestamp = ((Number) vec.get("timestamp")).longValue();
        long now = ((Number) vec.get("now")).longValue();
        String kid = (String) vec.get("kid");
        String nonceB64Url = (String) vec.get("nonce_b64url");

        // computeV1 is exercised on every vector so the canonical-string
        // concatenation is covered for every body shape and size.
        String computed = Awsp.computeV1(secret, timestamp, body);
        String expectedSig = (String) vec.get("expected_signature_hex");
        if (expectedSig != null) {
            assertEquals(expectedSig, computed, name + ": computeV1 mismatch");
        }

        // Build the X-A2A-Signature header that verify() will see.
        String presentedSig = (String) vec.get("presented_signature_hex");
        String sigHex = expectedSig != null ? expectedSig : (presentedSig != null ? presentedSig : computed);
        String rawHeader = (String) vec.get("raw_signature_header");
        String headerValue = rawHeader != null
                ? rawHeader
                : Headers.serialize(timestamp, List.of(sigHex), nonceB64Url, kid);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-A2A-Signature", headerValue);
        headers.put("X-A2A-Webhook-Id", "00000000-0000-4000-8000-000000000000");
        headers.put("X-A2A-Event-Type", "test.event");
        headers.put("X-A2A-Timestamp", Long.toString(timestamp));

        // Receiver secret list. Most vectors use the kid named in the vector;
        // the unknown_kid case specifies a different kid the receiver actually
        // knows about.
        String receiverKnownKid = (String) vec.get("receiver_known_kid");
        if (receiverKnownKid == null) {
            receiverKnownKid = kid;
        }
        List<VerifyParams.SecretEntry> secrets = List.of(new VerifyParams.SecretEntry(receiverKnownKid, secret));

        // Replay setup: if the vector seeds nonces, build a store and pre-seed it.
        InMemoryReplayStore replayStore = null;
        @SuppressWarnings("unchecked")
        Map<String, Object> replaySetup = (Map<String, Object>) vec.get("replay_setup");
        if (replaySetup != null) {
            final long nowFinal = now;
            replayStore = new InMemoryReplayStore(() -> nowFinal);
            @SuppressWarnings("unchecked")
            List<Object> seeds = (List<Object>) replaySetup.get("seed_nonces");
            for (Object n : seeds) {
                replayStore.checkAndStore("default", ((String) n).getBytes(StandardCharsets.US_ASCII), 360);
            }
        }

        VerifyParams.Builder vpb = VerifyParams.builder()
                .headers(headers)
                .body(body)
                .secrets(secrets)
                .replayWindowSeconds(300)
                .now(now);
        if (replayStore != null) {
            vpb.replayStore(replayStore);
        }

        VerifyResult result = Awsp.verify(vpb.build());

        Object expectedVerify = vec.get("expected_verify");
        if ("ok".equals(expectedVerify)) {
            assertTrue(result.ok(), () -> name + ": expected ok, got reason=" + result.reason());
        } else {
            assertTrue(!result.ok(), () -> name + ": expected error, got ok");
            @SuppressWarnings("unchecked")
            Map<String, Object> err = (Map<String, Object>) expectedVerify;
            String wantReason = (String) err.get("error");
            assertEquals(wantReason, result.reason(), () -> name + ": reason mismatch");
        }
    }

    // -----------------------------------------------------------------------
    // Vector file loading. Mapped via pom.xml's <testResource> from
    // packages/awsp/test-vectors.json. We also fall back to walking up from
    // user.dir so an IDE that does not honor the resource mapping still works.
    // -----------------------------------------------------------------------

    private static String loadVectorJson() throws IOException {
        // Preferred: classpath resource (mvn test).
        try (InputStream in = VectorTest.class.getResourceAsStream("/test-vectors.json")) {
            if (in != null) {
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
        // Fallback: walk up from user.dir looking for packages/awsp/test-vectors.json.
        Path cwd = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        for (Path p = cwd; p != null; p = p.getParent()) {
            Path candidate = p.resolve("test-vectors.json");
            if (Files.exists(candidate)) {
                return Files.readString(candidate, StandardCharsets.UTF_8);
            }
            Path nested = p.resolve("packages").resolve("awsp").resolve("test-vectors.json");
            if (Files.exists(nested)) {
                return Files.readString(nested, StandardCharsets.UTF_8);
            }
            // Also: from reference/java go up two and look at ../../test-vectors.json
            Path twoUp = p.resolve("..").resolve("..").resolve("test-vectors.json").normalize();
            if (Files.exists(twoUp)) {
                return Files.readString(twoUp, StandardCharsets.UTF_8);
            }
        }
        throw new IOException("test-vectors.json not found on classpath or filesystem");
    }
}
