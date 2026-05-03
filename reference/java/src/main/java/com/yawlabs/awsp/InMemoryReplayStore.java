// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.

package com.yawlabs.awsp;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Reference {@link ReplayStore} backed by an in-memory map. Suitable for
 * tests and single-process receivers; production multi-replica deployments
 * should use Redis ({@code SET key NX EX}) or equivalent so replay state is
 * shared across nodes.
 *
 * <p>This implementation is thread-safe (via {@link ConcurrentHashMap}) but
 * its eviction sweep is best-effort -- it runs only when the map crosses an
 * internal size threshold. Memory use is bounded by the volume of distinct
 * nonces seen within {@code ttlSeconds}.
 */
public final class InMemoryReplayStore implements ReplayStore {

    /** Map size threshold above which {@link #evict(long)} sweeps expired entries. */
    private static final int EVICT_THRESHOLD = 4096;

    private final ConcurrentHashMap<String, Long> seen = new ConcurrentHashMap<>();
    private final LongSupplier clock;

    /** Construct with the system clock (unix-seconds resolution). */
    public InMemoryReplayStore() {
        this(() -> System.currentTimeMillis() / 1000L);
    }

    /** Construct with a custom clock. Useful for deterministic tests. */
    public InMemoryReplayStore(LongSupplier clock) {
        this.clock = clock;
    }

    /** Construct from a {@link Clock} instance. */
    public InMemoryReplayStore(Clock javaClock) {
        this(() -> javaClock.instant().getEpochSecond());
    }

    @Override
    public boolean checkAndStore(String configId, byte[] nonce, int ttlSeconds) {
        long now = clock.getAsLong();
        evict(now);
        String key = makeKey(configId, nonce);
        long expiresAt = now + ttlSeconds;
        // putIfAbsent semantics: returns null if the key was unseen and
        // we successfully claimed it. Otherwise returns the existing value
        // -- we then check whether it has already expired (in which case
        // we replace and accept the nonce as fresh).
        Long prior = seen.putIfAbsent(key, expiresAt);
        if (prior == null) {
            return true;
        }
        if (prior <= now) {
            // Stale entry left behind by a slow eviction sweep. Race-safely
            // try to replace it with the fresher expiry.
            if (seen.replace(key, prior, expiresAt)) {
                return true;
            }
            // Lost the race -- some other caller already inserted a fresh
            // entry. That's a replay, fall through.
        }
        return false;
    }

    /** Number of nonces currently tracked (including expired-but-not-swept). */
    public int size() {
        return seen.size();
    }

    private static String makeKey(String configId, byte[] nonce) {
        // Nonces are base64url ASCII per the spec; UTF-8 round-trips them
        // unambiguously. Concatenating with a separator that cannot appear
        // in either field keeps configId-vs-nonce ambiguity from arising.
        // (configId is opaque, but ":" is the conventional split char.)
        String n = new String(nonce, StandardCharsets.UTF_8);
        return configId + ":" + n;
    }

    private void evict(long now) {
        if (seen.size() < EVICT_THRESHOLD) return;
        // O(n) sweep -- only triggers above threshold, so amortized cost is
        // bounded by throughput / threshold. For higher-throughput needs,
        // wrap a TTL-aware data structure (Caffeine, etc.) instead.
        Iterator<Map.Entry<String, Long>> it = seen.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Long> e = it.next();
            if (e.getValue() <= now) {
                it.remove();
            }
        }
    }
}
