// AWSP -- A2A Webhook Security Profile reference implementation.

using System;
using System.Collections.Generic;

namespace YawLabs.Awsp;

/// <summary>
/// Input to <see cref="Awsp.Verify"/>.
/// </summary>
/// <param name="Headers">
/// Incoming HTTP headers. Lookup is case-insensitive -- pass any
/// <see cref="IReadOnlyDictionary{TKey, TValue}"/> whose comparer is
/// <see cref="StringComparer.OrdinalIgnoreCase"/> for ideal performance, but a default-comparer
/// dictionary works too (the implementation falls back to a linear case-insensitive scan).
/// </param>
/// <param name="Body">Raw request body bytes -- the literal bytes received on the wire.</param>
/// <param name="Secrets">
/// The receiver's accepted <c>kid -> secret</c> table, keyed by exact match on <c>kid</c>. Because
/// the type is <see cref="IReadOnlyDictionary{TKey, TValue}"/> there is exactly ONE secret per
/// kid; <see cref="Awsp.Verify"/> fetches that single secret via a dictionary lookup. To rotate,
/// publish the new secret under a DISTINCT kid and let senders cut over -- you cannot stage two
/// secrets under the same kid here. This is intentionally narrower than the spec's
/// list-of-<c>(kid, secret)</c> model (which lets multiple secrets share a kid and tries each);
/// the other language ports implement that broader model, this reference does not.
/// </param>
/// <param name="ReplayWindowSeconds">
/// Default 300. Spec allows 60-600. Values outside that range cause Verify to return a
/// malformed_header result for the call (configuration error -- treat as a non-conformant
/// receiver build).
/// </param>
/// <param name="ReplayStore">
/// Optional. Without one, replay protection is skipped (single-process tests, single-replica
/// deployments that accept the risk, or callers running their own dedupe).
/// </param>
/// <param name="Now">
/// Optional clock override. Defaults to <see cref="DateTimeOffset.UtcNow"/>.
/// </param>
public sealed record VerifyParams(
    IReadOnlyDictionary<string, string> Headers,
    byte[] Body,
    IReadOnlyDictionary<string, byte[]> Secrets,
    int ReplayWindowSeconds = 300,
    IReplayStore? ReplayStore = null,
    Func<DateTimeOffset>? Now = null);
