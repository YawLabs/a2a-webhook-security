// AWSP -- A2A Webhook Security Profile reference implementation.
//
// This file implements the v1 signing/verification algorithm defined in SPEC.md at the package
// root. It is BCL-only (System.Security.Cryptography.HMACSHA256 + CryptographicOperations) and
// has no I/O of its own; replay storage is a hook supplied by the caller.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace YawLabs.Awsp;

/// <summary>
/// Top-level entry point for AWSP signing and verification. See <see cref="Sign"/> and
/// <see cref="Verify"/>.
/// </summary>
public static class Awsp
{
    private const int MinReplayWindowSeconds = 60;
    private const int MaxReplayWindowSeconds = 600;
    private const int ReplayStoreTtlBufferSeconds = 60;
    private const int DefaultNonceBytes = 18; // 18 bytes -> 24 base64url chars, no padding.

    // ----------------------------------------------------------------------
    // Sign
    // ----------------------------------------------------------------------

    /// <summary>
    /// Produce the four AWSP headers for a payload.
    /// <para>
    /// The HMAC is computed over <c>timestamp + "." + body-bytes</c>. The timestamp is formatted
    /// as decimal ASCII with no leading zeros.
    /// </para>
    /// </summary>
    /// <exception cref="ArgumentNullException">A required parameter is null.</exception>
    /// <exception cref="ArgumentException">A required parameter is empty or invalid.</exception>
    public static SignedHeaders Sign(SignParams p)
    {
        ArgumentNullException.ThrowIfNull(p);
        ArgumentNullException.ThrowIfNull(p.Secret);
        ArgumentNullException.ThrowIfNull(p.Body);
        ArgumentException.ThrowIfNullOrEmpty(p.KeyId);
        ArgumentException.ThrowIfNullOrEmpty(p.EventType);
        if (p.Secret.Length == 0)
        {
            throw new ArgumentException("Secret must be non-empty.", nameof(p));
        }

        long timestamp = (p.Timestamp ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        if (timestamp < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(p), timestamp, "Timestamp must be non-negative unix seconds.");
        }

        string nonceB64 = p.Nonce is null
            ? GenerateNonce()
            : EncodeBase64UrlNoPadding(p.Nonce);

        string webhookId = p.WebhookId ?? GenerateUuidV4();

        string v1Hex = ComputeV1(p.Secret, timestamp, p.Body);
        string signatureHeader = Headers.Serialize(timestamp, new[] { v1Hex }, nonceB64, p.KeyId);

        return new SignedHeaders(
            XA2ASignature: signatureHeader,
            XA2AWebhookId: webhookId,
            XA2AEventType: p.EventType,
            XA2ATimestamp: timestamp.ToString(CultureInfo.InvariantCulture));
    }

    // ----------------------------------------------------------------------
    // Verify
    // ----------------------------------------------------------------------

    /// <summary>
    /// Verify an incoming AWSP-signed request.
    /// <para>
    /// Steps, in order:
    /// </para>
    /// <list type="number">
    ///   <item><description>Look up <c>X-A2A-Signature</c> case-insensitively. Missing => malformed_header.</description></item>
    ///   <item><description>Parse it. Fields out of grammar => malformed_header. Only future <c>vN=</c> versions => unknown_algorithm.</description></item>
    ///   <item><description>Window check: <c>|now - t| &lt;= replayWindowSeconds</c>. Else stale or future.</description></item>
    ///   <item><description>Match the <c>kid=</c> against the receiver's secret table. No match => unknown_kid.</description></item>
    ///   <item><description>Recompute HMAC for each candidate secret; constant-time compare against every <c>v1=</c>. No match => bad_hmac.</description></item>
    ///   <item><description>Replay check: <c>ReplayStore.CheckAndStore</c> with TTL = window + 60s. False => replayed.</description></item>
    /// </list>
    /// <para>
    /// Replay is intentionally last so forged or wrong-key requests do not consume nonce-storage
    /// capacity (would itself enable a denial vector against the replay store).
    /// </para>
    /// </summary>
    public static VerifyResult Verify(VerifyParams p)
    {
        ArgumentNullException.ThrowIfNull(p);
        ArgumentNullException.ThrowIfNull(p.Headers);
        ArgumentNullException.ThrowIfNull(p.Body);
        ArgumentNullException.ThrowIfNull(p.Secrets);

        int window = p.ReplayWindowSeconds;
        if (window < MinReplayWindowSeconds || window > MaxReplayWindowSeconds)
        {
            // Configuration error -- treat as malformed so callers get a stable enum back
            // rather than a thrown exception in the hot path.
            return new VerifyResult(false, "malformed_header");
        }

        string? rawHeader = LookupHeader(p.Headers, "X-A2A-Signature");
        if (rawHeader is null)
        {
            return new VerifyResult(false, "malformed_header");
        }

        var parseResult = Headers.Parse(rawHeader);
        if (parseResult.Failure.HasValue)
        {
            return parseResult.Failure.Value switch
            {
                HeaderParseFailure.UnknownAlgorithm => new VerifyResult(false, "unknown_algorithm"),
                _ => new VerifyResult(false, "malformed_header"),
            };
        }
        ParsedSignatureHeader parsed = parseResult.Parsed!;

        long now = (p.Now is null ? DateTimeOffset.UtcNow : p.Now()).ToUnixTimeSeconds();
        long skew = now - parsed.Timestamp;
        if (skew > window)
        {
            return new VerifyResult(false, "stale");
        }
        if (skew < -window)
        {
            return new VerifyResult(false, "future");
        }

        // The contract uses IReadOnlyDictionary<string, byte[]> for secrets. Multi-secret
        // rotation in v1 is one secret per kid (the dictionary key); a future revision MAY
        // extend this to a list, at which point both the spec and the contract change together.
        if (!p.Secrets.TryGetValue(parsed.Kid, out byte[]? secret) || secret is null)
        {
            return new VerifyResult(false, "unknown_kid");
        }

        bool matched = TryMatchAnyV1(secret, parsed.Timestamp, p.Body, parsed.V1);
        if (!matched)
        {
            return new VerifyResult(false, "bad_hmac");
        }

        if (p.ReplayStore is not null)
        {
            int ttl = window + ReplayStoreTtlBufferSeconds;
            byte[] nonceBytes = DecodeBase64UrlNoPadding(parsed.Nonce);
            // configId is left empty -- AWSP nonce uniqueness is global to the receiver.
            // Multi-tenant deployments MAY supply a tenant-scoped configId via a custom store
            // wrapper; the reference store treats empty as "single namespace".
            bool fresh = p.ReplayStore.CheckAndStore(string.Empty, nonceBytes, ttl);
            if (!fresh)
            {
                return new VerifyResult(false, "replayed");
            }
        }

        return new VerifyResult(true, null);
    }

    // ----------------------------------------------------------------------
    // Internal helpers, exposed for tests.
    // ----------------------------------------------------------------------

    /// <summary>
    /// Compute the v1 HMAC-SHA256 signature for a (timestamp, body) pair against a single
    /// secret. Returns 64 lowercase hex characters.
    /// </summary>
    /// <remarks>
    /// Exposed so test vectors and other-language ports can cross-check the canonical-string
    /// concatenation: <c>HMAC-SHA256(secret, ascii(timestamp) || 0x2E || body)</c>.
    /// </remarks>
    public static string ComputeV1(byte[] secret, long timestamp, byte[] body)
    {
        ArgumentNullException.ThrowIfNull(secret);
        ArgumentNullException.ThrowIfNull(body);

        string tsAscii = timestamp.ToString(CultureInfo.InvariantCulture);
        // Hot path: single allocation for the canonical string.
        int tsByteCount = Encoding.ASCII.GetByteCount(tsAscii);
        byte[] canonical = new byte[tsByteCount + 1 + body.Length];
        Encoding.ASCII.GetBytes(tsAscii, 0, tsAscii.Length, canonical, 0);
        canonical[tsByteCount] = (byte)'.';
        Buffer.BlockCopy(body, 0, canonical, tsByteCount + 1, body.Length);

        byte[] mac = HMACSHA256.HashData(secret, canonical);
        return ToLowerHex(mac);
    }

    private static bool TryMatchAnyV1(byte[] secret, long timestamp, byte[] body, IReadOnlyList<string> presented)
    {
        // Compute the expected HMAC once. Compare against every presented v1= in constant time.
        // We deliberately iterate ALL candidates rather than short-circuit: total work depends
        // on the count of presented signatures, not on which one (if any) matched -- that hides
        // a tiny side-channel for which v1= position validated.
        string expectedHex = ComputeV1(secret, timestamp, body);
        byte[] expectedBytes = HexToBytes(expectedHex);

        bool any = false;
        foreach (string candidate in presented)
        {
            // Header parsing already guaranteed candidate is 64 lowercase hex; defensive equal-
            // length check kept anyway.
            if (candidate.Length != expectedHex.Length)
            {
                continue;
            }
            byte[] candidateBytes = HexToBytes(candidate);
            if (CryptographicOperations.FixedTimeEquals(expectedBytes, candidateBytes))
            {
                any = true;
                // Do NOT break -- keep timing constant across the candidate list.
            }
        }

        return any;
    }

    private static string GenerateNonce()
    {
        Span<byte> bytes = stackalloc byte[DefaultNonceBytes];
        RandomNumberGenerator.Fill(bytes);
        return EncodeBase64UrlNoPadding(bytes);
    }

    private static string GenerateUuidV4()
    {
        // Guid.NewGuid() is RFC 4122 v4 on Windows; on .NET it uses CryptoAPI / OpenSSL.
        return Guid.NewGuid().ToString("D", CultureInfo.InvariantCulture);
    }

    private static string? LookupHeader(IReadOnlyDictionary<string, string> headers, string name)
    {
        // Fast path: dictionary configured with a case-insensitive comparer.
        if (headers.TryGetValue(name, out string? direct))
        {
            return direct;
        }
        // Slow path: linear scan, case-insensitive. Common when callers pass a default-comparer
        // dictionary built from request metadata.
        foreach (var pair in headers)
        {
            if (string.Equals(pair.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return pair.Value;
            }
        }
        return null;
    }

    private static string EncodeBase64UrlNoPadding(ReadOnlySpan<byte> bytes)
    {
        // Base64Url.EncodeToString (.NET 9+) is not available on net8.0; emulate by encoding
        // standard base64, then translating + -> -, / -> _, and stripping = padding.
        string b64 = Convert.ToBase64String(bytes);
        Span<char> buf = b64.Length <= 1024 ? stackalloc char[b64.Length] : new char[b64.Length];
        int written = 0;
        foreach (char c in b64)
        {
            if (c == '=')
            {
                continue;
            }
            buf[written++] = c switch
            {
                '+' => '-',
                '/' => '_',
                _ => c,
            };
        }
        return new string(buf[..written]);
    }

    private static byte[] DecodeBase64UrlNoPadding(string input)
    {
        // Translate base64url -> base64, then pad to a multiple of 4, then decode.
        Span<char> buf = input.Length + 4 <= 1024 ? stackalloc char[input.Length + 4] : new char[input.Length + 4];
        for (int i = 0; i < input.Length; i++)
        {
            buf[i] = input[i] switch
            {
                '-' => '+',
                '_' => '/',
                _ => input[i],
            };
        }
        int padded = input.Length;
        while (padded % 4 != 0)
        {
            buf[padded++] = '=';
        }
        return Convert.FromBase64CharArray(buf[..padded].ToArray(), 0, padded);
    }

    private static string ToLowerHex(byte[] bytes)
    {
        // Convert.ToHexString returns uppercase; the spec mandates lowercase, so we lower in place.
        Span<char> buf = bytes.Length * 2 <= 1024 ? stackalloc char[bytes.Length * 2] : new char[bytes.Length * 2];
        const string Hex = "0123456789abcdef";
        for (int i = 0; i < bytes.Length; i++)
        {
            buf[i * 2] = Hex[(bytes[i] >> 4) & 0x0F];
            buf[i * 2 + 1] = Hex[bytes[i] & 0x0F];
        }
        return new string(buf);
    }

    private static byte[] HexToBytes(string hex)
    {
        // Caller has already validated that hex is even-length lowercase [0-9a-f].
        byte[] result = new byte[hex.Length / 2];
        for (int i = 0; i < result.Length; i++)
        {
            int hi = HexNibble(hex[i * 2]);
            int lo = HexNibble(hex[i * 2 + 1]);
            result[i] = (byte)((hi << 4) | lo);
        }
        return result;
    }

    private static int HexNibble(char c)
    {
        if (c >= '0' && c <= '9')
        {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f')
        {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F')
        {
            return c - 'A' + 10;
        }
        // Unreachable on validated input.
        throw new FormatException("Invalid hex character.");
    }
}
