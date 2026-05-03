// AWSP -- A2A Webhook Security Profile reference implementation.

namespace YawLabs.Awsp;

/// <summary>
/// Replay-protection storage hook.
/// <para>
/// Implementations include Redis <c>SET key NX EX</c>, Memcached <c>add</c>, or an in-memory
/// dictionary for tests (see <see cref="InMemoryReplayStore"/>). For multi-replica deployments
/// the store MUST be shared across replicas.
/// </para>
/// </summary>
public interface IReplayStore
{
    /// <summary>
    /// Atomically check whether <paramref name="nonce"/> has been seen within the past
    /// <paramref name="ttlSeconds"/> seconds. If unseen, record it with TTL = <paramref name="ttlSeconds"/>
    /// and return <c>true</c>. If already seen, return <c>false</c> without modifying state.
    /// </summary>
    /// <param name="configId">
    /// Optional namespace for nonces. AWSP nonce uniqueness is global to the receiver, but a
    /// store backing multiple unrelated tenants MAY use this as a key prefix. The reference
    /// in-memory implementation ignores it.
    /// </param>
    /// <param name="nonce">Raw nonce bytes from the <c>n=</c> field (already base64url-decoded).</param>
    /// <param name="ttlSeconds">TTL for the recorded nonce.</param>
    /// <returns><c>true</c> if the nonce was unseen and is now recorded; <c>false</c> if it was a replay.</returns>
    bool CheckAndStore(string configId, byte[] nonce, int ttlSeconds);
}
