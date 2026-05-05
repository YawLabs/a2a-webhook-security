// AWSP -- A2A Webhook Security Profile reference implementation.
// Copyright 2026 Yaw Labs. Licensed under the Apache License, Version 2.0.

package com.yawlabs.awsp;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Reference {@link ReplayStore} backed by an in-memory map. Suitable for
 * tests and single-process receivers; production multi-replica deployments
 * should use Redis ({@code SET key NX EX}) or equivalent so replay state is
 * shared across nodes.
 *
 * <p>This implementation is thread-safe (via {@link ConcurrentHashMap}). Its
 * eviction sweep is best-effort: above {@link #EVICT_THRESHOLD} entries the
 * sweep runs at most once every {@link #EVICT_SWEEP_INTERVAL} calls (so the
 * amortized per-call cost stays O(1) instead of O(n) once the map fills).
 *
 * <p>Bound on map size: at steady state the map holds at most
 * {@code peak_arrival_rate * (ttlSeconds + EVICT_SWEEP_INTERVAL)} entries --
 * the sweep window adds at most {@code EVICT_SWEEP_INTERVAL} extra entries
 * past the natural TTL bound before eviction reclaims them.
 */
public final class InMemoryReplayStore implements ReplayStore {

    /** Map size at or above which the eviction sweep is considered. */
    private static final int EVICT_THRESHOLD = 8192;

    /**
     * Once above {@link #EVICT_THRESHOLD}, run the O(n) sweep at most once
     * per this many calls. Cheap counter-modulo amortizes the sweep cost
     * across the call stream.
     */
    private static final int EVICT_SWEEP_INTERVAL = 256;

    private final ConcurrentHashMap<String, Long> seen = new ConcurrentHashMap<>();
    private final LongSupplier clock;
    private final AtomicLong callsSinceSweep = new AtomicLong();

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
        if (seen.size() < EVICT_THRESHOLD) {
            // Map is small. Reset the counter so the first sweep above the
            // threshold runs immediately rather than after the modulo cycle.
            callsSinceSweep.set(0);
            return;
        }
        // O(n) sweep -- only runs once per EVICT_SWEEP_INTERVAL calls past
        // the threshold, so amortized cost per call stays O(1). Memory is
        // bounded by arrival rate x (ttl + EVICT_SWEEP_INTERVAL); for
        // higher-throughput needs, wrap a TTL-aware data structure
        // (Caffeine, etc.) instead.
        long n = callsSinceSweep.getAndIncrement();
        if (n % EVICT_SWEEP_INTERVAL != 0) {
            return;
        }
        Iterator<Map.Entry<String, Long>> it = seen.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Long> e = it.next();
            if (e.getValue() <= now) {
                it.remove();
            }
        }
    }
}
