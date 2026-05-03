// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.

package com.yawlabs.awsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HeadersTest {

    private static final String GOOD_V1 = "a8a83abd144feeb2f481bd997757faf5555354074ca05d2270fac24bd234ec96";
    private static final String GOOD_NONCE = "AAAAAAAAAAAAAAAAAAAAAAAA";
    private static final String GOOD_KID = "k_2026_05";

    private static final String GOOD_HEADER =
            "t=1777248000,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;

    @Test
    void parsesHappyPath() {
        Headers.Parsed p = Headers.parse(GOOD_HEADER);
        assertEquals(1777248000L, p.timestamp);
        assertEquals(List.of(GOOD_V1), p.v1);
        assertEquals(GOOD_NONCE, p.nonce);
        assertEquals(GOOD_KID, p.kid);
    }

    @Test
    void fieldOrderInsignificant() {
        String reordered = "kid=" + GOOD_KID + ",n=" + GOOD_NONCE + ",v1=" + GOOD_V1 + ",t=1777248000";
        Headers.Parsed p = Headers.parse(reordered);
        assertEquals(1777248000L, p.timestamp);
        assertEquals(GOOD_KID, p.kid);
    }

    @Test
    void multipleV1ValuesAccepted() {
        String alt = "0".repeat(64);
        String header = "t=1777248000,v1=" + GOOD_V1 + ",v1=" + alt + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        Headers.Parsed p = Headers.parse(header);
        assertEquals(2, p.v1.size());
        assertEquals(GOOD_V1, p.v1.get(0));
        assertEquals(alt, p.v1.get(1));
    }

    @Test
    void unknownFieldsIgnored() {
        String header = "t=1777248000,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID
                + ",future_field=hello";
        Headers.Parsed p = Headers.parse(header);
        assertEquals(1777248000L, p.timestamp);
    }

    @Test
    void unknownAlgorithmAlone() {
        String header = "t=1777248000,v99=somefuture,n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        Headers.ParseException ex = assertThrows(Headers.ParseException.class, () -> Headers.parse(header));
        assertEquals(Headers.ParseFailure.UNKNOWN_ALGORITHM, ex.failure);
    }

    @Test
    void unknownAlgorithmAlongsideV1Accepted() {
        // SPEC.md section 5.1: unknown vN= are informational; if v1= is also
        // present the request is verifiable.
        String header = "t=1777248000,v1=" + GOOD_V1 + ",v2=futurestuff,n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        Headers.Parsed p = Headers.parse(header);
        assertEquals(1, p.v1.size());
    }

    @Test
    void rejectsEmpty() {
        assertThrows(Headers.ParseException.class, () -> Headers.parse(""));
    }

    @Test
    void rejectsOversize() {
        StringBuilder sb = new StringBuilder("t=1777248000");
        while (sb.length() <= 4096) {
            sb.append(",pad=").append("x".repeat(50));
        }
        assertThrows(Headers.ParseException.class, () -> Headers.parse(sb.toString()));
    }

    @Test
    void rejectsUppercaseV1() {
        String header = "t=1777248000,v1=" + GOOD_V1.toUpperCase()
                + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        Headers.ParseException ex = assertThrows(Headers.ParseException.class, () -> Headers.parse(header));
        assertEquals(Headers.ParseFailure.MALFORMED, ex.failure);
    }

    @Test
    void rejectsNonHexV1() {
        String header = "t=1777248000,v1=" + "z".repeat(64) + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(header));
    }

    @Test
    void rejectsMissingT() {
        String header = "v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(header));
    }

    @Test
    void rejectsMissingV1() {
        String header = "t=1777248000,n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(header));
    }

    @Test
    void rejectsMissingNonce() {
        String header = "t=1777248000,v1=" + GOOD_V1 + ",kid=" + GOOD_KID;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(header));
    }

    @Test
    void rejectsMissingKid() {
        String header = "t=1777248000,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(header));
    }

    @Test
    void rejectsDuplicateT() {
        String header =
                "t=1777248000,t=1777248001,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(header));
    }

    @Test
    void rejectsNegativeTimestamp() {
        String header = "t=-1,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(header));
    }

    @Test
    void rejectsGarbage() {
        assertThrows(Headers.ParseException.class, () -> Headers.parse("this is not a signature header"));
    }

    @Test
    void serializeProducesParseableHeader() {
        String h = Headers.serialize(1777248000L, List.of(GOOD_V1), GOOD_NONCE, GOOD_KID);
        Headers.Parsed p = Headers.parse(h);
        assertEquals(1777248000L, p.timestamp);
        assertEquals(GOOD_KID, p.kid);
        assertEquals(GOOD_NONCE, p.nonce);
        assertEquals(1, p.v1.size());
    }

    // -------------------------------------------------------------------------
    // High-level Awsp tests that exercise verify() corner cases not covered by
    // a vector. Living next to HeadersTest because they're small and share
    // setup constants.
    // -------------------------------------------------------------------------

    @Test
    void signProducesAllFourHeaders() {
        Awsp.SignedHeaders h = Awsp.sign(SignParams.builder()
                .secret(new byte[32])
                .keyId("k_test")
                .body("{\"a\":1}".getBytes())
                .eventType("test.created")
                .timestamp(1777248000L)
                .nonce(GOOD_NONCE)
                .webhookId("00000000-0000-4000-8000-000000000000")
                .build());
        assertNotNull(h.xA2ASignature());
        assertNotNull(h.xA2AWebhookId());
        assertNotNull(h.xA2AEventType());
        assertNotNull(h.xA2ATimestamp());
        Headers.Parsed p = Headers.parse(h.xA2ASignature());
        assertEquals(1777248000L, p.timestamp);
        assertEquals("k_test", p.kid);
        assertEquals(1, p.v1.size());
    }

    @Test
    void signRejectsZeroLengthSecret() {
        assertThrows(AwspException.class, () -> Awsp.sign(SignParams.builder()
                .secret(new byte[0])
                .keyId("k")
                .body(new byte[0])
                .eventType("e")
                .build()));
    }

    @Test
    void verifyMissingSignatureHeaderIsMalformed() {
        VerifyResult r = Awsp.verify(VerifyParams.builder()
                .headers(Map.of())
                .body(new byte[0])
                .secrets(List.of(new VerifyParams.SecretEntry("k", new byte[32])))
                .now(1777248000L)
                .build());
        assertEquals(false, r.ok());
        assertEquals("malformed_header", r.reason());
    }

    @Test
    void verifyRejectsOutOfRangeReplayWindow() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-A2A-Signature", GOOD_HEADER);
        assertThrows(AwspException.class, () -> Awsp.verify(VerifyParams.builder()
                .headers(headers)
                .body(new byte[0])
                .secrets(List.of(new VerifyParams.SecretEntry("k_2026_05", new byte[32])))
                .replayWindowSeconds(30)
                .build()));
        assertThrows(AwspException.class, () -> Awsp.verify(VerifyParams.builder()
                .headers(headers)
                .body(new byte[0])
                .secrets(List.of(new VerifyParams.SecretEntry("k_2026_05", new byte[32])))
                .replayWindowSeconds(700)
                .build()));
    }

    @Test
    void verifyMultiV1HeaderValidatesIfAnyMatches() {
        byte[] secret = new byte[16];
        for (int i = 0; i < 16; i++) secret[i] = (byte) i;
        long t = 1777248000L;
        byte[] body = "hi".getBytes();
        String goodSig = Awsp.computeV1(secret, t, body);
        String badSig = "0".repeat(64);
        // Bad first, good second -- proves verify does not short-circuit on
        // the first failure.
        String header = Headers.serialize(t, List.of(badSig, goodSig), GOOD_NONCE, "k");
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-A2A-Signature", header);
        VerifyResult r = Awsp.verify(VerifyParams.builder()
                .headers(headers)
                .body(body)
                .secrets(List.of(new VerifyParams.SecretEntry("k", secret)))
                .now(t)
                .build());
        assertTrue(r.ok(), () -> "expected ok, got reason=" + r.reason());
    }

    @Test
    void verifyRotationOldAndNewSecretsBothAccepted() {
        byte[] oldSecret = new byte[16];
        byte[] newSecret = new byte[16];
        for (int i = 0; i < 16; i++) {
            oldSecret[i] = 1;
            newSecret[i] = 2;
        }
        long t = 1777248000L;
        byte[] body = "payload".getBytes();
        Awsp.SignedHeaders h = Awsp.sign(SignParams.builder()
                .secret(oldSecret)
                .keyId("k_old")
                .body(body)
                .eventType("e")
                .timestamp(t)
                .nonce(GOOD_NONCE)
                .webhookId("00000000-0000-4000-8000-000000000000")
                .build());
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-A2A-Signature", h.xA2ASignature());
        VerifyResult r = Awsp.verify(VerifyParams.builder()
                .headers(headers)
                .body(body)
                .secrets(List.of(
                        new VerifyParams.SecretEntry("k_old", oldSecret),
                        new VerifyParams.SecretEntry("k_new", newSecret)))
                .now(t)
                .build());
        assertTrue(r.ok());
    }

    @Test
    void verifyReplayStoreRejectsSecondCall() {
        byte[] secret = new byte[16];
        java.util.Arrays.fill(secret, (byte) 7);
        long t = 1777248000L;
        byte[] body = new byte[0];
        Awsp.SignedHeaders h = Awsp.sign(SignParams.builder()
                .secret(secret)
                .keyId("k")
                .body(body)
                .eventType("e")
                .timestamp(t)
                .nonce(GOOD_NONCE)
                .webhookId("00000000-0000-4000-8000-000000000000")
                .build());
        InMemoryReplayStore store = new InMemoryReplayStore(() -> t);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-A2A-Signature", h.xA2ASignature());
        VerifyResult r1 = Awsp.verify(VerifyParams.builder()
                .headers(headers)
                .body(body)
                .secrets(List.of(new VerifyParams.SecretEntry("k", secret)))
                .replayStore(store)
                .now(t)
                .build());
        assertTrue(r1.ok());
        VerifyResult r2 = Awsp.verify(VerifyParams.builder()
                .headers(headers)
                .body(body)
                .secrets(List.of(new VerifyParams.SecretEntry("k", secret)))
                .replayStore(store)
                .now(t)
                .build());
        assertEquals(false, r2.ok());
        assertEquals("replayed", r2.reason());
    }

    @Test
    void inMemoryReplayStoreEvictsAfterTtl() {
        long[] now = {1000L};
        InMemoryReplayStore store = new InMemoryReplayStore(() -> now[0]);
        byte[] n1 = "n1".getBytes();
        assertTrue(store.checkAndStore("default", n1, 60));
        assertTrue(!store.checkAndStore("default", n1, 60));
        now[0] = 1061L;
        assertTrue(store.checkAndStore("default", n1, 60));
    }
}
