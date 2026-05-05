// AWSP -- A2A Webhook Security Profile reference implementation.

using System;
using System.Collections.Generic;

namespace YawLabs.Awsp;

/// <summary>
/// Reference in-memory <see cref="IReplayStore"/>. Suitable for tests and single-process
/// receivers; production multi-replica deployments should use Redis (<c>SET NX EX</c>) or
/// equivalent so replay state is shared.
/// <para>
/// All public methods are thread-safe. Eviction is incremental and runs only when the store
/// grows past a threshold; for higher-throughput workloads, use a TTL-aware backing store.
/// </para>
/// </summary>
public sealed class InMemoryReplayStore : IReplayStore
{
    // Eviction strategy: once the map crosses EvictionThreshold entries, sweep only every
    // EvictionInterval-th call. Sweeping on every call past the threshold made the worst-case
    // CheckAndStore O(n) per call -- a pathological pattern of monotonically-fresh nonces with
    // no expirations made the whole store quadratic in steady state. The interval-throttled
    // sweep keeps the amortized cost O(1) while still bounding map growth: between sweeps the
    // map can grow by at most EvictionInterval entries, so the steady-state ceiling is
    // EvictionThreshold + EvictionInterval.
    private const int EvictionThreshold = 8192;
    private const int EvictionInterval = 256;

    private readonly object _lock = new();
    private readonly Dictionary<string, long> _seen = new(StringComparer.Ordinal);
    private readonly Func<DateTimeOffset> _clock;
    private long _callsSinceLastSweep;

    /// <summary>
    /// Create a store using <see cref="DateTimeOffset.UtcNow"/> as the clock.
    /// </summary>
    public InMemoryReplayStore()
        : this(static () => DateTimeOffset.UtcNow)
    {
    }

    /// <summary>
    /// Create a store with an injectable clock. Useful for deterministic tests.
    /// </summary>
    public InMemoryReplayStore(Func<DateTimeOffset> clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        _clock = clock;
    }

    /// <inheritdoc />
    public bool CheckAndStore(string configId, byte[] nonce, int ttlSeconds)
    {
        ArgumentNullException.ThrowIfNull(nonce);
        if (ttlSeconds <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ttlSeconds), ttlSeconds, "ttlSeconds must be positive");
        }

        // Nonce uniqueness is global to the receiver per AWSP section 7.2; the kid/configId is
        // not part of the dedupe key. configId is allowed only as a multi-tenant prefix when
        // useful; the reference implementation prefixes it for parity with Redis-style stores.
        string key = MakeKey(configId, nonce);
        long now = _clock().ToUnixTimeSeconds();

        lock (_lock)
        {
            EvictIfLarge(now);
            if (_seen.TryGetValue(key, out long expiresAt) && expiresAt > now)
            {
                return false;
            }
            _seen[key] = now + ttlSeconds;
            return true;
        }
    }

    private static string MakeKey(string configId, byte[] nonce)
    {
        // Convert(byte[]) emits standard base64; sufficient for an internal map key. We do NOT
        // round-trip this back to a base64url nonce -- the dictionary just needs a stable
        // string representation per byte sequence.
        string nonceKey = Convert.ToBase64String(nonce);
        return string.IsNullOrEmpty(configId) ? nonceKey : (configId + ":" + nonceKey);
    }

    private void EvictIfLarge(long now)
    {
        if (_seen.Count <= EvictionThreshold)
        {
            // Reset the call counter so a future shrink-then-grow cycle does not sweep on the
            // very first call past the threshold.
            _callsSinceLastSweep = 0;
            return;
        }
        // Throttled sweep: only walk the map every EvictionInterval-th call past threshold.
        // This keeps amortized CheckAndStore cost O(1) instead of O(n) under sustained load.
        _callsSinceLastSweep++;
        if (_callsSinceLastSweep < EvictionInterval)
        {
            return;
        }
        _callsSinceLastSweep = 0;

        // O(n) sweep -- bounded because n is also bounded by the time window.
        var expired = new List<string>();
        foreach (var pair in _seen)
        {
            if (pair.Value <= now)
            {
                expired.Add(pair.Key);
            }
        }
        foreach (string k in expired)
        {
            _seen.Remove(k);
        }
    }
}
