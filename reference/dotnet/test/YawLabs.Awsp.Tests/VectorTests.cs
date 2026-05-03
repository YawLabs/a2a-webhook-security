// AWSP -- A2A Webhook Security Profile reference implementation.
//
// Runs every vector from packages/awsp/test-vectors.json against the reference Sign / Verify
// implementation. All 50 vectors must pass.

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;

namespace YawLabs.Awsp.Tests;

public sealed class VectorTests
{
    [Fact]
    public void Loads_50_Vectors()
    {
        VectorFile file = VectorData.LoadFile();
        Assert.Equal(50, file.VectorCount);
        Assert.Equal(50, file.Vectors.Count);
    }

    [Theory]
    [ClassData(typeof(VectorData))]
    public void Vector_Verifies(Vector v)
    {
        byte[] secret = HexToBytes(v.SecretHex);
        byte[] body = HexToBytes(v.BodyHex);

        // ComputeV1 is exercised on every vector so the canonical-string concatenation is
        // covered for every body shape (empty, ASCII, UTF-8 multibyte, 1KB, 64KB, binary).
        string computed = Awsp.ComputeV1(secret, v.Timestamp, body);
        if (!string.IsNullOrEmpty(v.ExpectedSignatureHex))
        {
            Assert.True(
                string.Equals(computed, v.ExpectedSignatureHex, StringComparison.Ordinal),
                $"computeV1 mismatch for {v.Name}: expected {v.ExpectedSignatureHex}, got {computed}");
        }

        // Build the X-A2A-Signature header value the verifier will see.
        string sigHex = v.ExpectedSignatureHex ?? v.PresentedSignatureHex ?? computed;
        string headerValue = v.RawSignatureHeader ?? BuildHeader(v.Timestamp, sigHex, v.NonceB64Url, v.Kid);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["x-a2a-signature"] = headerValue,
            ["x-a2a-webhook-id"] = "00000000-0000-4000-8000-000000000000",
            ["x-a2a-event-type"] = "test.event",
            ["x-a2a-timestamp"] = v.Timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };

        // The receiver's accept list. The unknown_kid vector specifies a kid that differs from
        // the one inside the header; everything else uses the vector's own kid.
        string receiverKid = string.IsNullOrEmpty(v.ReceiverKnownKid) ? v.Kid : v.ReceiverKnownKid;
        var secrets = new Dictionary<string, byte[]>(StringComparer.Ordinal)
        {
            [receiverKid] = secret,
        };

        // Replay setup: when the vector seeds nonces, instantiate a store pre-populated with
        // them. Otherwise pass null so the replay branch is entirely skipped.
        InMemoryReplayStore? replayStore = null;
        if (v.ReplaySetup is { SeedNonces.Count: > 0 })
        {
            replayStore = new InMemoryReplayStore(() => DateTimeOffset.FromUnixTimeSeconds(v.Now));
            foreach (string seed in v.ReplaySetup.SeedNonces)
            {
                byte[] seedBytes = DecodeBase64UrlNoPadding(seed);
                Assert.True(replayStore.CheckAndStore(string.Empty, seedBytes, 360));
            }
        }

        VerifyResult result = Awsp.Verify(new VerifyParams(
            Headers: headers,
            Body: body,
            Secrets: secrets,
            ReplayWindowSeconds: 300,
            ReplayStore: replayStore,
            Now: () => DateTimeOffset.FromUnixTimeSeconds(v.Now)));

        AssertVerifyResult(result, v);
    }

    // --------------------------------------------------------------------
    // Helpers
    // --------------------------------------------------------------------

    private static string BuildHeader(long t, string v1, string n, string kid)
        => $"t={t.ToString(System.Globalization.CultureInfo.InvariantCulture)},v1={v1},n={n},kid={kid}";

    private static void AssertVerifyResult(VerifyResult result, Vector v)
    {
        if (v.IsExpectedOk)
        {
            Assert.True(result.Ok, $"{v.Name}: expected ok, got reason={result.Reason}");
            Assert.Null(result.Reason);
        }
        else
        {
            Assert.False(result.Ok, $"{v.Name}: expected error={v.ExpectedErrorReason}, got ok");
            Assert.Equal(v.ExpectedErrorReason, result.Reason);
        }
    }

    private static byte[] HexToBytes(string hex)
    {
        if (string.IsNullOrEmpty(hex))
        {
            return Array.Empty<byte>();
        }
        if ((hex.Length & 1) != 0)
        {
            throw new FormatException("Hex string must be even-length.");
        }
        byte[] result = new byte[hex.Length / 2];
        for (int i = 0; i < result.Length; i++)
        {
            result[i] = (byte)((Nibble(hex[i * 2]) << 4) | Nibble(hex[i * 2 + 1]));
        }
        return result;

        static int Nibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw new FormatException($"Invalid hex char '{c}'.");
        }
    }

    private static byte[] DecodeBase64UrlNoPadding(string input)
    {
        char[] buf = new char[input.Length + 4];
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
        return Convert.FromBase64CharArray(buf, 0, padded);
    }
}

// ----------------------------------------------------------------------
// Vector source for [ClassData(typeof(VectorData))].
// ----------------------------------------------------------------------

public sealed class VectorData : IEnumerable<object[]>
{
    public IEnumerator<object[]> GetEnumerator()
    {
        VectorFile file = LoadFile();
        foreach (Vector v in file.Vectors)
        {
            yield return new object[] { v };
        }
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public static VectorFile LoadFile()
    {
        // The csproj copies test-vectors.json into the test bin dir as a linked Content item.
        // AppContext.BaseDirectory is the bin output directory at run time.
        string path = Path.Combine(AppContext.BaseDirectory, "test-vectors.json");
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                $"test-vectors.json not found at {path}. " +
                "Ensure the test csproj's <Content Include=...test-vectors.json> entry is intact.");
        }
        string json = File.ReadAllText(path);
        VectorFile? file = JsonSerializer.Deserialize<VectorFile>(json, JsonOptions);
        if (file is null)
        {
            throw new InvalidOperationException("Failed to deserialize vector file.");
        }
        return file;
    }

    // Property names are explicit on every field via [JsonPropertyName]; we don't lean on a
    // naming policy. PropertyNameCaseInsensitive is on as a defensive measure if the upstream
    // vector file ever capitalizes a field.
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };
}

public sealed class VectorFile
{
    [JsonPropertyName("spec")]
    public string Spec { get; set; } = string.Empty;

    [JsonPropertyName("vector_count")]
    public int VectorCount { get; set; }

    [JsonPropertyName("vectors")]
    public List<Vector> Vectors { get; set; } = new();
}

public sealed class Vector
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("secret_hex")]
    public string SecretHex { get; set; } = string.Empty;

    [JsonPropertyName("kid")]
    public string Kid { get; set; } = string.Empty;

    [JsonPropertyName("body_hex")]
    public string BodyHex { get; set; } = string.Empty;

    [JsonPropertyName("timestamp")]
    public long Timestamp { get; set; }

    [JsonPropertyName("nonce_b64url")]
    public string NonceB64Url { get; set; } = string.Empty;

    [JsonPropertyName("now")]
    public long Now { get; set; }

    [JsonPropertyName("expected_signature_hex")]
    public string? ExpectedSignatureHex { get; set; }

    [JsonPropertyName("presented_signature_hex")]
    public string? PresentedSignatureHex { get; set; }

    [JsonPropertyName("raw_signature_header")]
    public string? RawSignatureHeader { get; set; }

    [JsonPropertyName("replay_setup")]
    public ReplaySetup? ReplaySetup { get; set; }

    [JsonPropertyName("receiver_known_kid")]
    public string? ReceiverKnownKid { get; set; }

    /// <summary>
    /// expected_verify is either the literal string "ok" or an object {"error": "&lt;reason&gt;"}.
    /// JsonElement carries the raw parse so we can branch in <see cref="IsExpectedOk"/>.
    /// </summary>
    [JsonPropertyName("expected_verify")]
    public JsonElement ExpectedVerify { get; set; }

    [JsonPropertyName("note")]
    public string? Note { get; set; }

    [JsonIgnore]
    public bool IsExpectedOk =>
        ExpectedVerify.ValueKind == JsonValueKind.String &&
        string.Equals(ExpectedVerify.GetString(), "ok", StringComparison.Ordinal);

    [JsonIgnore]
    public string? ExpectedErrorReason
    {
        get
        {
            if (ExpectedVerify.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            return ExpectedVerify.TryGetProperty("error", out JsonElement err)
                ? err.GetString()
                : null;
        }
    }

    public override string ToString() => Name;
}

public sealed class ReplaySetup
{
    [JsonPropertyName("seed_nonces")]
    public List<string> SeedNonces { get; set; } = new();
}
