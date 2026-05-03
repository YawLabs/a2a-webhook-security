// AWSP -- A2A Webhook Security Profile reference implementation.
//
// Edge-case unit tests for header parsing and the public Sign / Verify surface that aren't
// covered by the deterministic vector suite.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace YawLabs.Awsp.Tests;

public sealed class HeadersTests
{
    private const string ValidV1 = "a8a83abd144feeb2f481bd997757faf5555354074ca05d2270fac24bd234ec96";
    private const string ValidNonce = "AAAAAAAAAAAAAAAAAAAAAAAA";

    // --------------------------------------------------------------------
    // Parse: round-trip and field-order independence
    // --------------------------------------------------------------------

    [Fact]
    public void Parse_FieldOrderIndependent()
    {
        // The spec says receivers MUST treat field order as insignificant.
        string canonical = $"t=1777248000,v1={ValidV1},n={ValidNonce},kid=k_2026_05";
        string reordered = $"kid=k_2026_05,n={ValidNonce},v1={ValidV1},t=1777248000";

        AssertParseSucceeds(canonical);
        AssertParseSucceeds(reordered);
    }

    [Fact]
    public void Parse_AcceptsMultipleV1Values()
    {
        // Two valid v1= entries; one good HMAC over an empty body, one all-zero.
        long t = 1777248000;
        byte[] secret = new byte[32];
        string goodSig = Awsp.ComputeV1(secret, t, Array.Empty<byte>());
        string raw = $"t={t},v1={goodSig},v1={new string('0', 64)},n={ValidNonce},kid=k";

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["x-a2a-signature"] = raw,
        };
        var result = Awsp.Verify(new VerifyParams(
            Headers: headers,
            Body: Array.Empty<byte>(),
            Secrets: new Dictionary<string, byte[]> { ["k"] = secret },
            Now: () => DateTimeOffset.FromUnixTimeSeconds(t)));
        Assert.True(result.Ok, $"expected ok with two v1=, got {result.Reason}");
    }

    [Fact]
    public void Parse_IgnoresUnknownNonVersionFields()
    {
        // Spec: "MUST NOT reject the header solely because it contains additional unknown
        // key=value fields, but MUST ignore them."
        string raw = $"t=1777248000,v1={ValidV1},n={ValidNonce},kid=k,extra=ignored,x_a2a_future=1";
        AssertParseSucceeds(raw);
    }

    [Fact]
    public void Parse_RejectsTooLongHeader()
    {
        // 4096-byte cap per spec section 5.1.
        string raw = "t=1777248000,v1=" + ValidV1 + ",n=" + ValidNonce + ",kid=" + new string('k', 4096);
        Assert.Equal("malformed_header", ParseReasonOnly(raw));
    }

    // --------------------------------------------------------------------
    // Parse failures we want pinned at this layer.
    // --------------------------------------------------------------------

    [Theory]
    // Empty header.
    [InlineData("")]
    // Pair with empty key.
    [InlineData("=")]
    // Missing required field: kid.
    [InlineData("t=1,v1=a8a83abd144feeb2f481bd997757faf5555354074ca05d2270fac24bd234ec96,n=AAAAAAAAAAAAAAAAAAAAAAAA")]
    // Empty values for required fields.
    [InlineData("t=1777248000,v1=a8a83abd144feeb2f481bd997757faf5555354074ca05d2270fac24bd234ec96,n=,kid=k")]
    [InlineData("t=1777248000,v1=a8a83abd144feeb2f481bd997757faf5555354074ca05d2270fac24bd234ec96,n=AAAAAAAAAAAAAAAAAAAAAAAA,kid=")]
    [InlineData("t=,v1=a8a83abd144feeb2f481bd997757faf5555354074ca05d2270fac24bd234ec96,n=AAAAAAAAAAAAAAAAAAAAAAAA,kid=k")]
    [InlineData("t=1777248000,v1=,n=AAAAAAAAAAAAAAAAAAAAAAAA,kid=k")]
    // v1= contains non-hex characters.
    [InlineData("t=1777248000,v1=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz,n=AAAAAAAAAAAAAAAAAAAAAAAA,kid=k")]
    // v1= wrong length.
    [InlineData("t=1777248000,v1=a8a83abd,n=AAAAAAAAAAAAAAAAAAAAAAAA,kid=k")]
    public void Parse_Malformed_ReturnsMalformedHeader(string raw)
    {
        Assert.Equal("malformed_header", ParseReasonOnly(raw));
    }

    [Fact]
    public void Parse_NoV1ButFutureVersionPresent_ReturnsUnknownAlgorithm()
    {
        // Spec: "If the header carries no v1= AND at least one unknown vN=, Receivers MUST
        // reject as unknown_algorithm rather than malformed_header."
        string raw = $"t=1777248000,v99=somefuture,n={ValidNonce},kid=k_2026_05";
        Assert.Equal("unknown_algorithm", ParseReasonOnly(raw));
    }

    [Fact]
    public void Parse_DuplicateRequiredField_IsMalformed()
    {
        string dupT = $"t=1,t=2,v1={ValidV1},n={ValidNonce},kid=k";
        Assert.Equal("malformed_header", ParseReasonOnly(dupT));

        string dupNonce = $"t=1,v1={ValidV1},n={ValidNonce},n=other,kid=k";
        Assert.Equal("malformed_header", ParseReasonOnly(dupNonce));

        string dupKid = $"t=1,v1={ValidV1},n={ValidNonce},kid=a,kid=b";
        Assert.Equal("malformed_header", ParseReasonOnly(dupKid));
    }

    [Fact]
    public void Parse_RejectsUppercaseV1()
    {
        string raw = $"t=1777248000,v1={ValidV1.ToUpperInvariant()},n={ValidNonce},kid=k";
        Assert.Equal("malformed_header", ParseReasonOnly(raw));
    }

    [Fact]
    public void Parse_RejectsKidWithInvalidChars()
    {
        // kid grammar is [A-Za-z0-9._-]{1,128}; '/' is not in it.
        string raw = $"t=1777248000,v1={ValidV1},n={ValidNonce},kid=bad/kid";
        Assert.Equal("malformed_header", ParseReasonOnly(raw));
    }

    // --------------------------------------------------------------------
    // Sign / Verify integration sanity (vector suite handles correctness;
    // these exercise defaults and edge inputs).
    // --------------------------------------------------------------------

    [Fact]
    public void Sign_ProducesAllFourHeaders_AndDefaultsArePopulated()
    {
        SignedHeaders headers = Awsp.Sign(new SignParams(
            Secret: new byte[32],
            Body: Encoding.UTF8.GetBytes("{\"a\":1}"),
            KeyId: "k_test",
            EventType: "test.created"));

        Assert.False(string.IsNullOrEmpty(headers.XA2ASignature));
        Assert.Matches(@"^[0-9a-f-]{36}$", headers.XA2AWebhookId);
        Assert.Equal("test.created", headers.XA2AEventType);
        Assert.True(long.TryParse(headers.XA2ATimestamp, out long ts) && ts > 1700000000);

        // The signature header round-trips through Parse with kid intact.
        Assert.Contains("kid=k_test", headers.XA2ASignature, StringComparison.Ordinal);
    }

    [Fact]
    public void Sign_ExplicitTimestampAndNonceAndWebhookId()
    {
        var ts = DateTimeOffset.FromUnixTimeSeconds(1777248000);
        byte[] nonceBytes = new byte[18];
        for (int i = 0; i < nonceBytes.Length; i++) nonceBytes[i] = (byte)i;

        SignedHeaders headers = Awsp.Sign(new SignParams(
            Secret: new byte[] { 1, 2, 3, 4 },
            Body: Array.Empty<byte>(),
            KeyId: "k",
            EventType: "e",
            Timestamp: ts,
            Nonce: nonceBytes,
            WebhookId: "00000000-0000-4000-8000-000000000000"));

        Assert.Equal("1777248000", headers.XA2ATimestamp);
        Assert.Equal("00000000-0000-4000-8000-000000000000", headers.XA2AWebhookId);

        // Pull the nonce out of the signature header and confirm it round-trips back to the
        // input bytes. Avoid hard-coding the base64url string -- exercising the round-trip
        // catches any +/- substitution bug regardless of which input bytes happen to be used.
        string sig = headers.XA2ASignature;
        int nIdx = sig.IndexOf(",n=", StringComparison.Ordinal);
        Assert.True(nIdx > 0, $"no n= field found in {sig}");
        int nEnd = sig.IndexOf(',', nIdx + 3);
        string presentedNonce = nEnd > 0 ? sig.Substring(nIdx + 3, nEnd - (nIdx + 3)) : sig.Substring(nIdx + 3);
        Assert.Equal(24, presentedNonce.Length); // 18 bytes -> 24 base64url chars
        // Round-trip: decode and compare to the original bytes.
        byte[] decoded = DecodeBase64UrlNoPaddingForTest(presentedNonce);
        Assert.Equal(nonceBytes, decoded);
    }

    private static byte[] DecodeBase64UrlNoPaddingForTest(string input)
    {
        char[] buf = new char[input.Length + 4];
        for (int i = 0; i < input.Length; i++)
        {
            buf[i] = input[i] switch { '-' => '+', '_' => '/', _ => input[i] };
        }
        int padded = input.Length;
        while (padded % 4 != 0) buf[padded++] = '=';
        return Convert.FromBase64CharArray(buf, 0, padded);
    }

    [Fact]
    public void Sign_RejectsZeroLengthSecret()
    {
        Assert.ThrowsAny<ArgumentException>(() => Awsp.Sign(new SignParams(
            Secret: Array.Empty<byte>(),
            Body: Array.Empty<byte>(),
            KeyId: "k",
            EventType: "e")));
    }

    [Fact]
    public void Sign_RejectsNullSecret()
    {
        Assert.Throws<ArgumentNullException>(() => Awsp.Sign(new SignParams(
            Secret: null!,
            Body: Array.Empty<byte>(),
            KeyId: "k",
            EventType: "e")));
    }

    [Fact]
    public void Sign_RejectsEmptyKeyIdOrEventType()
    {
        Assert.ThrowsAny<ArgumentException>(() => Awsp.Sign(new SignParams(
            Secret: new byte[] { 1 },
            Body: Array.Empty<byte>(),
            KeyId: "",
            EventType: "e")));
        Assert.ThrowsAny<ArgumentException>(() => Awsp.Sign(new SignParams(
            Secret: new byte[] { 1 },
            Body: Array.Empty<byte>(),
            KeyId: "k",
            EventType: "")));
    }

    [Fact]
    public void Verify_MissingSignatureHeader_ReturnsMalformedHeader()
    {
        var result = Awsp.Verify(new VerifyParams(
            Headers: new Dictionary<string, string>(),
            Body: Array.Empty<byte>(),
            Secrets: new Dictionary<string, byte[]> { ["k"] = new byte[32] },
            Now: () => DateTimeOffset.FromUnixTimeSeconds(1777248000)));

        Assert.False(result.Ok);
        Assert.Equal("malformed_header", result.Reason);
    }

    [Theory]
    [InlineData(30)]   // below floor
    [InlineData(700)]  // above ceiling
    public void Verify_OutOfRangeReplayWindow_ReturnsMalformedHeader(int window)
    {
        var result = Awsp.Verify(new VerifyParams(
            Headers: new Dictionary<string, string> { ["x-a2a-signature"] = $"t=1,v1={new string('0', 64)},n=A,kid=k" },
            Body: Array.Empty<byte>(),
            Secrets: new Dictionary<string, byte[]>(),
            ReplayWindowSeconds: window));

        Assert.False(result.Ok);
        Assert.Equal("malformed_header", result.Reason);
    }

    [Fact]
    public void Verify_MultipleV1_AnyMatchAuthenticates()
    {
        byte[] secret = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        long t = 1777248000;
        byte[] body = Encoding.UTF8.GetBytes("hi");
        string goodSig = Awsp.ComputeV1(secret, t, body);
        string badSig = new('0', 64);

        // Place the good sig second to confirm the verifier checks all candidates.
        string headerValue = $"t={t},v1={badSig},v1={goodSig},n={ValidNonce},kid=k";

        var result = Awsp.Verify(new VerifyParams(
            Headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["x-a2a-signature"] = headerValue },
            Body: body,
            Secrets: new Dictionary<string, byte[]> { ["k"] = secret },
            Now: () => DateTimeOffset.FromUnixTimeSeconds(t)));

        Assert.True(result.Ok);
    }

    [Fact]
    public void Verify_KeyRotation_OldAndNewBothAccepted()
    {
        byte[] oldSecret = Enumerable.Repeat((byte)1, 16).ToArray();
        byte[] newSecret = Enumerable.Repeat((byte)2, 16).ToArray();
        long t = 1777248000;
        byte[] body = Encoding.UTF8.GetBytes("payload");

        // Sender signs with the old kid.
        SignedHeaders signed = Awsp.Sign(new SignParams(
            Secret: oldSecret,
            Body: body,
            KeyId: "k_old",
            EventType: "e",
            Timestamp: DateTimeOffset.FromUnixTimeSeconds(t),
            Nonce: new byte[18],
            WebhookId: "00000000-0000-4000-8000-000000000000"));

        // Receiver knows both old and new.
        var result = Awsp.Verify(new VerifyParams(
            Headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["x-a2a-signature"] = signed.XA2ASignature },
            Body: body,
            Secrets: new Dictionary<string, byte[]>
            {
                ["k_old"] = oldSecret,
                ["k_new"] = newSecret,
            },
            Now: () => DateTimeOffset.FromUnixTimeSeconds(t)));

        Assert.True(result.Ok);
    }

    [Fact]
    public void Verify_ReplayStore_RejectsSecondCall()
    {
        byte[] secret = Enumerable.Repeat((byte)7, 16).ToArray();
        long t = 1777248000;
        byte[] body = Array.Empty<byte>();

        SignedHeaders signed = Awsp.Sign(new SignParams(
            Secret: secret,
            Body: body,
            KeyId: "k",
            EventType: "e",
            Timestamp: DateTimeOffset.FromUnixTimeSeconds(t),
            Nonce: new byte[18],
            WebhookId: "00000000-0000-4000-8000-000000000000"));

        var store = new InMemoryReplayStore(() => DateTimeOffset.FromUnixTimeSeconds(t));
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["x-a2a-signature"] = signed.XA2ASignature,
        };
        var secrets = new Dictionary<string, byte[]> { ["k"] = secret };

        var first = Awsp.Verify(new VerifyParams(
            Headers: headers,
            Body: body,
            Secrets: secrets,
            ReplayStore: store,
            Now: () => DateTimeOffset.FromUnixTimeSeconds(t)));
        Assert.True(first.Ok);

        var second = Awsp.Verify(new VerifyParams(
            Headers: headers,
            Body: body,
            Secrets: secrets,
            ReplayStore: store,
            Now: () => DateTimeOffset.FromUnixTimeSeconds(t)));
        Assert.False(second.Ok);
        Assert.Equal("replayed", second.Reason);
    }

    [Fact]
    public void InMemoryReplayStore_EvictsAfterTtl()
    {
        long now = 1000;
        var store = new InMemoryReplayStore(() => DateTimeOffset.FromUnixTimeSeconds(now));
        byte[] nonce = new byte[] { 1, 2, 3 };

        Assert.True(store.CheckAndStore(string.Empty, nonce, 60));
        Assert.False(store.CheckAndStore(string.Empty, nonce, 60));
        now = 1061; // past TTL
        Assert.True(store.CheckAndStore(string.Empty, nonce, 60));
    }

    // --------------------------------------------------------------------
    // Helpers
    // --------------------------------------------------------------------

    private static string? ParseReasonOnly(string raw)
    {
        // We don't need access to the internal ParsedSignatureHeader -- failures are what these
        // tests pin down. Parse via the public Verify surface and read the reason string.
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["x-a2a-signature"] = raw,
        };
        var result = Awsp.Verify(new VerifyParams(
            Headers: headers,
            Body: Array.Empty<byte>(),
            Secrets: new Dictionary<string, byte[]> { ["k"] = new byte[32] },
            Now: () => DateTimeOffset.FromUnixTimeSeconds(1777248000)));
        // Two outcomes shape this method's contract:
        //   - Verify says ok            -> return null (parse succeeded, deeper checks happened)
        //   - Verify says failure       -> return the reason string
        // For tests that pass a malformed header, Verify will short-circuit at parse with the
        // appropriate failure tag.
        return result.Ok ? null : result.Reason;
    }

    private static void AssertParseSucceeds(string raw)
    {
        // We can't see the parsed struct from outside, but we can prove parse succeeded by
        // observing that Verify proceeded past the parse step (its eventual failure reason
        // is something other than malformed_header / unknown_algorithm).
        string? reason = ParseReasonOnly(raw);
        Assert.True(
            reason is null or "stale" or "future" or "bad_hmac" or "unknown_kid" or "replayed",
            $"expected post-parse outcome, got {reason ?? "ok"}");
    }
}
