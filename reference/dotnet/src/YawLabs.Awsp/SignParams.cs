// AWSP -- A2A Webhook Security Profile reference implementation.
// See ../../SPEC.md for the wire format. Test vectors are at ../../test-vectors.json.

using System;

namespace YawLabs.Awsp;

/// <summary>
/// Input to <see cref="Awsp.Sign"/>.
/// </summary>
/// <param name="Secret">Raw secret bytes (the shared HMAC key). Must be non-empty.</param>
/// <param name="Body">Raw payload bytes. The HMAC is computed over <c>timestamp + "." + body-bytes</c>.</param>
/// <param name="KeyId">Identifier for the secret. Placed in the <c>kid=</c> field.</param>
/// <param name="EventType">Event class label, placed in <c>X-A2A-Event-Type</c>.</param>
/// <param name="Timestamp">
/// Optional. Defaults to <see cref="DateTimeOffset.UtcNow"/>. Only the unix-seconds part is used.
/// </param>
/// <param name="Nonce">
/// Optional. Raw nonce bytes; serialized as base64url. Defaults to 18 cryptographically random
/// bytes (24 base64url chars, no padding).
/// </param>
/// <param name="WebhookId">
/// Optional. UUID identifying the delivery. Defaults to a generated UUIDv4. On retry the Sender
/// MUST reuse the same value.
/// </param>
public sealed record SignParams(
    byte[] Secret,
    byte[] Body,
    string KeyId,
    string EventType,
    DateTimeOffset? Timestamp = null,
    byte[]? Nonce = null,
    string? WebhookId = null);
