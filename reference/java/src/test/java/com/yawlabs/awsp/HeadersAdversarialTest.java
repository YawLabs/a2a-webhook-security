// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.
//
// Adversarial parser tests for Headers.parse. The contract is: for ANY input
// (including random bytes), the parser MUST EITHER return a valid Headers.Parsed
// OR throw Headers.ParseException -- never NullPointerException, never
// IndexOutOfBoundsException, never any other unchecked exception.
//
// This file complements HeadersTest (which covers the spec-shaped happy and
// sad paths) by hammering the parser with truncations, oversized inputs,
// duplicates, mixed case, control bytes, extreme integers, and pure fuzz.

package com.yawlabs.awsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Random;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class HeadersAdversarialTest {

    private static final String GOOD_V1 = "a8a83abd144feeb2f481bd997757faf5555354074ca05d2270fac24bd234ec96";
    private static final String GOOD_NONCE = "AAAAAAAAAAAAAAAAAAAAAAAA";
    private static final String GOOD_KID = "k_2026_05";
    private static final String GOOD_HEADER =
            "t=1777248000,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;

    /**
     * The parser MUST never throw anything other than ParseException. Wraps a
     * call so a JUnit failure on a surprise exception type lists the input.
     */
    private static void parseSafely(String input) {
        try {
            Headers.parse(input);
        } catch (Headers.ParseException expected) {
            // ok -- spec-defined failure
        } catch (RuntimeException re) {
            fail("parser threw unexpected " + re.getClass().getSimpleName()
                    + " for input (length=" + (input == null ? -1 : input.length())
                    + "): " + sanitize(input) + " -- " + re.getMessage());
        }
    }

    private static String sanitize(String s) {
        if (s == null) return "<null>";
        StringBuilder sb = new StringBuilder(s.length() + 8);
        sb.append('"');
        for (int i = 0; i < Math.min(s.length(), 200); i++) {
            char c = s.charAt(i);
            if (c >= 0x20 && c < 0x7f) {
                sb.append(c);
            } else {
                sb.append(String.format("\\u%04x", (int) c));
            }
        }
        if (s.length() > 200) sb.append("...");
        sb.append('"');
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // Targeted: truncate the good header at every byte boundary.
    // -------------------------------------------------------------------------

    @Test
    void truncationAtEveryBoundaryNeverCrashes() {
        for (int i = 0; i <= GOOD_HEADER.length(); i++) {
            String truncated = GOOD_HEADER.substring(0, i);
            parseSafely(truncated);
        }
    }

    // -------------------------------------------------------------------------
    // Targeted: oversized header (>4096 bytes) -- spec rejects as malformed.
    // -------------------------------------------------------------------------

    @Test
    void oversizedHeaderRejected() {
        StringBuilder sb = new StringBuilder(GOOD_HEADER);
        while (sb.length() <= 4096) {
            sb.append(",pad=").append("x".repeat(50));
        }
        Headers.ParseException ex = assertThrows(Headers.ParseException.class, () -> Headers.parse(sb.toString()));
        assertEquals(Headers.ParseFailure.MALFORMED, ex.failure);
    }

    @Test
    void exactly4097BytesRejected() {
        StringBuilder sb = new StringBuilder("t=1777248000,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID);
        while (sb.length() < 4097) {
            sb.append(",x=y");
        }
        // Trim to exactly 4097.
        String s = sb.substring(0, 4097);
        Headers.ParseException ex = assertThrows(Headers.ParseException.class, () -> Headers.parse(s));
        assertEquals(Headers.ParseFailure.MALFORMED, ex.failure);
    }

    // -------------------------------------------------------------------------
    // Targeted: duplicates of the at-most-once fields.
    // -------------------------------------------------------------------------

    @Test
    void duplicateTimestampRejected() {
        String h = "t=1777248000,t=1777248001,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        Headers.ParseException ex = assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
        assertEquals(Headers.ParseFailure.MALFORMED, ex.failure);
    }

    @Test
    void duplicateNonceRejected() {
        String h = "t=1777248000,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",n=other,kid=" + GOOD_KID;
        Headers.ParseException ex = assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
        assertEquals(Headers.ParseFailure.MALFORMED, ex.failure);
    }

    @Test
    void duplicateKidRejected() {
        String h = "t=1777248000,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID + ",kid=k2";
        Headers.ParseException ex = assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
        assertEquals(Headers.ParseFailure.MALFORMED, ex.failure);
    }

    // -------------------------------------------------------------------------
    // Targeted: multiple v1= -- spec REQUIRES accumulation (rotation).
    // -------------------------------------------------------------------------

    @Test
    void multipleV1ValuesAccumulate() {
        String alt = "1".repeat(64);
        String h = "t=1777248000,v1=" + GOOD_V1 + ",v1=" + alt + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        Headers.Parsed p = Headers.parse(h);
        assertEquals(2, p.v1.size());
    }

    @Test
    void manyV1ValuesAccumulate() {
        StringBuilder sb = new StringBuilder("t=1777248000");
        // Build 10 v1 values (header still well under 4096 bytes).
        for (int i = 0; i < 10; i++) {
            sb.append(",v1=").append(GOOD_V1);
        }
        sb.append(",n=").append(GOOD_NONCE).append(",kid=").append(GOOD_KID);
        Headers.Parsed p = Headers.parse(sb.toString());
        assertEquals(10, p.v1.size());
    }

    // -------------------------------------------------------------------------
    // Targeted: mixed case in keys. Spec defines keys case-sensitively (lower).
    // -------------------------------------------------------------------------

    @Test
    void uppercaseKeyTreatedAsUnknownAndRejected() {
        // T= (uppercase) is unknown, so timestamp is missing.
        String h = "T=1777248000,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        Headers.ParseException ex = assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
        assertEquals(Headers.ParseFailure.MALFORMED, ex.failure);
    }

    @Test
    void uppercaseV1KeyTreatedAsUnknown() {
        // V1= (uppercase) is unknown, so v1 is missing.
        String h = "t=1777248000,V1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        Headers.ParseException ex = assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
        assertEquals(Headers.ParseFailure.MALFORMED, ex.failure);
    }

    // -------------------------------------------------------------------------
    // Targeted: whitespace, tabs, control bytes in values.
    // -------------------------------------------------------------------------

    @Test
    void whitespaceInsideKidRejected() {
        String h = "t=1777248000,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=k 2026";
        assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
    }

    @Test
    void tabInsideNonceRejected() {
        String h = "t=1777248000,v1=" + GOOD_V1 + ",n=AB\tCD,kid=" + GOOD_KID;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
    }

    @Test
    void nullByteInValueDoesNotCrash() {
        // Whatever the parser decides, it must not crash.
        String h = "t=1777248000,v1=" + GOOD_V1 + ",n=AA BB,kid=" + GOOD_KID;
        parseSafely(h);
    }

    @Test
    void controlBytesAcrossHeaderDoNotCrash() {
        for (int b = 0; b < 0x20; b++) {
            String injected = GOOD_HEADER + ",extra=x" + (char) b + "y";
            parseSafely(injected);
        }
    }

    @Test
    void leadingTrailingWhitespaceTrimmedFromKeysAndValues() {
        // The parser trims around '='; leading/trailing whitespace inside
        // a part is tolerated for keys/values that happen to round-trip.
        String h = " t = 1777248000 , v1 = " + GOOD_V1 + " , n = " + GOOD_NONCE + " , kid = " + GOOD_KID + " ";
        parseSafely(h);
    }

    // -------------------------------------------------------------------------
    // Targeted: extreme timestamp values.
    // -------------------------------------------------------------------------

    @Test
    void veryHighTimestampAccepted() {
        // Up to 15 digits is allowed by the regex. 999_999_999_999_999 (15 nines)
        // is well past Long.MAX_VALUE in seconds-since-epoch terms but parses fine.
        String h = "t=999999999999999,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        Headers.Parsed p = Headers.parse(h);
        assertEquals(999999999999999L, p.timestamp);
    }

    @Test
    void timestamp16DigitsRejected() {
        // 16 digits trips the regex.
        String h = "t=1234567890123456,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
    }

    @Test
    void negativeTimestampRejected() {
        String h = "t=-1,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        Headers.ParseException ex = assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
        assertEquals(Headers.ParseFailure.MALFORMED, ex.failure);
    }

    @Test
    void timestampWithLeadingPlusRejected() {
        String h = "t=+1777248000,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
    }

    @Test
    void timestampWithFractionRejected() {
        String h = "t=1777248000.5,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
    }

    @Test
    void zeroTimestampAccepted() {
        // Spec doesn't forbid t=0 -- the window check rejects it elsewhere.
        String h = "t=0,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        Headers.Parsed p = Headers.parse(h);
        assertEquals(0L, p.timestamp);
    }

    // -------------------------------------------------------------------------
    // Targeted: empty values, bare keys, bare equals.
    // -------------------------------------------------------------------------

    @Test
    void bareEqualsRejected() {
        assertThrows(Headers.ParseException.class, () -> Headers.parse("="));
        assertThrows(Headers.ParseException.class, () -> Headers.parse("=value"));
        assertThrows(Headers.ParseException.class, () -> Headers.parse("key="));
    }

    @Test
    void bareKeyRejected() {
        assertThrows(Headers.ParseException.class, () -> Headers.parse("t"));
        assertThrows(Headers.ParseException.class, () -> Headers.parse("kid"));
    }

    @Test
    void bareCommaRejected() {
        assertThrows(Headers.ParseException.class, () -> Headers.parse(","));
        assertThrows(Headers.ParseException.class, () -> Headers.parse(",,,"));
    }

    @Test
    void emptyValuesRejected() {
        // t=,v1=...,n=...,kid=... -- empty value
        String h = "t=,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID;
        assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
    }

    @Test
    void onlyCommas() {
        // Pure separators with no key=value pairs.
        for (int i = 1; i <= 16; i++) {
            String h = ",".repeat(i);
            assertThrows(Headers.ParseException.class, () -> Headers.parse(h));
        }
    }

    // -------------------------------------------------------------------------
    // Targeted: every spec-defined error reason reachable.
    // -------------------------------------------------------------------------

    @Test
    void everyParseFailureReasonReachable() {
        // MALFORMED: empty
        Headers.ParseException e1 = assertThrows(Headers.ParseException.class, () -> Headers.parse(""));
        assertEquals(Headers.ParseFailure.MALFORMED, e1.failure);

        // MALFORMED: too long
        StringBuilder sb = new StringBuilder("t=1777248000");
        while (sb.length() <= 4096) sb.append(",pad=").append("x".repeat(50));
        Headers.ParseException e2 = assertThrows(Headers.ParseException.class, () -> Headers.parse(sb.toString()));
        assertEquals(Headers.ParseFailure.MALFORMED, e2.failure);

        // MALFORMED: bad pair shape
        Headers.ParseException e3 = assertThrows(Headers.ParseException.class, () -> Headers.parse("nokv"));
        assertEquals(Headers.ParseFailure.MALFORMED, e3.failure);

        // MALFORMED: bad timestamp
        Headers.ParseException e4 = assertThrows(Headers.ParseException.class,
                () -> Headers.parse("t=abc,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID));
        assertEquals(Headers.ParseFailure.MALFORMED, e4.failure);

        // MALFORMED: bad v1 (uppercase hex)
        Headers.ParseException e5 = assertThrows(Headers.ParseException.class,
                () -> Headers.parse("t=1,v1=" + GOOD_V1.toUpperCase()
                        + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID));
        assertEquals(Headers.ParseFailure.MALFORMED, e5.failure);

        // MALFORMED: bad nonce (illegal char)
        Headers.ParseException e6 = assertThrows(Headers.ParseException.class,
                () -> Headers.parse("t=1,v1=" + GOOD_V1 + ",n=bad!nonce,kid=" + GOOD_KID));
        assertEquals(Headers.ParseFailure.MALFORMED, e6.failure);

        // MALFORMED: bad kid
        Headers.ParseException e7 = assertThrows(Headers.ParseException.class,
                () -> Headers.parse("t=1,v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=bad/kid"));
        assertEquals(Headers.ParseFailure.MALFORMED, e7.failure);

        // MALFORMED: missing required field
        Headers.ParseException e8 = assertThrows(Headers.ParseException.class,
                () -> Headers.parse("v1=" + GOOD_V1 + ",n=" + GOOD_NONCE + ",kid=" + GOOD_KID));
        assertEquals(Headers.ParseFailure.MALFORMED, e8.failure);

        // UNKNOWN_ALGORITHM: only vN= for unknown N
        Headers.ParseException e9 = assertThrows(Headers.ParseException.class,
                () -> Headers.parse("t=1,v99=zz,n=" + GOOD_NONCE + ",kid=" + GOOD_KID));
        assertEquals(Headers.ParseFailure.UNKNOWN_ALGORITHM, e9.failure);
    }

    // -------------------------------------------------------------------------
    // Fuzz: ~1000 iterations of seedable random bytes.
    // -------------------------------------------------------------------------

    static Stream<Integer> fuzzSeeds() {
        // Deterministic: same suite every run, but enough variety that any
        // input shape that crashes the parser is overwhelmingly likely to be
        // hit. Caller controls reproducibility via the seed.
        return IntStream.range(0, 1000).boxed();
    }

    @ParameterizedTest(name = "fuzz seed={0}")
    @MethodSource("fuzzSeeds")
    void fuzzNeverCrashes(int seed) {
        Random rng = new Random(seed);
        // Build a payload of random length 0..200 from the printable + special
        // ASCII alphabet (incl. ',', '=', and a few control bytes).
        int len = rng.nextInt(201);
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            int pick = rng.nextInt(100);
            if (pick < 60) {
                // Normal printable.
                sb.append((char) (0x20 + rng.nextInt(95)));
            } else if (pick < 80) {
                // Structural chars the parser cares about.
                sb.append(",= \t".charAt(rng.nextInt(4)));
            } else if (pick < 95) {
                // Embedded keyword fragments.
                String[] frags = {"t=", "v1=", "n=", "kid=", "v99=", "future=", "1777248000", GOOD_V1, GOOD_NONCE, GOOD_KID};
                sb.append(frags[rng.nextInt(frags.length)]);
            } else {
                // Random control/high byte.
                sb.append((char) rng.nextInt(0x80));
            }
        }
        parseSafely(sb.toString());
    }

    @ParameterizedTest(name = "mutate seed={0}")
    @MethodSource("fuzzSeeds")
    void fuzzGoodHeaderMutationsNeverCrash(int seed) {
        // Take the good header and mutate a few bytes.
        Random rng = new Random(seed ^ 0x5a5a5a5a);
        char[] buf = GOOD_HEADER.toCharArray();
        int mutations = 1 + rng.nextInt(8);
        for (int i = 0; i < mutations; i++) {
            int idx = rng.nextInt(buf.length);
            int op = rng.nextInt(3);
            if (op == 0) {
                // Replace.
                buf[idx] = (char) rng.nextInt(0x100);
            } else if (op == 1) {
                // Set to structural char.
                buf[idx] = ",= ".charAt(rng.nextInt(3));
            } else {
                // Set to digit.
                buf[idx] = (char) ('0' + rng.nextInt(10));
            }
        }
        parseSafely(new String(buf));
    }

    @ParameterizedTest(name = "splice seed={0}")
    @MethodSource("fuzzSeeds")
    void fuzzSpliceFragmentsNeverCrashes(int seed) {
        // Splice random fragments together with random separators -- exercises
        // the duplicate-detection / unknown-key paths heavily.
        Random rng = new Random(seed ^ 0x12345678);
        String[] frags = {
            "t=1777248000",
            "t=" + Long.toString(rng.nextInt() & 0x7fffffff),
            "t=-1",
            "t=999999999999999",
            "v1=" + GOOD_V1,
            "v1=" + "0".repeat(64),
            "v1=" + "z".repeat(64),
            "v2=somefuture",
            "v99=somefuture",
            "n=" + GOOD_NONCE,
            "n=tooshort",
            "n=" + "A".repeat(257),  // over-length
            "kid=" + GOOD_KID,
            "kid=k$bad",  // illegal char in kid
            "kid=" + "x".repeat(129),  // over-length
            "future=field",
        };
        int n = 1 + rng.nextInt(8);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(',');
            sb.append(frags[rng.nextInt(frags.length)]);
        }
        parseSafely(sb.toString());
    }

    // -------------------------------------------------------------------------
    // Sanity: the good header still parses across all the additional surface.
    // -------------------------------------------------------------------------

    @Test
    void goodHeaderStillParses() {
        Headers.Parsed p = Headers.parse(GOOD_HEADER);
        assertNotNull(p);
        assertEquals(1777248000L, p.timestamp);
        assertEquals(GOOD_KID, p.kid);
    }
}
