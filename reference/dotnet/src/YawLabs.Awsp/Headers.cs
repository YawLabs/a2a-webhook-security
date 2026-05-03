// AWSP -- A2A Webhook Security Profile reference implementation.
//
// X-A2A-Signature has the form:
//   t=<unix-seconds>,v1=<hex>[,v1=<hex>...],n=<nonce-b64url>,kid=<keyId>
//
// Field order is NOT significant. Multiple v1= values are allowed. Unknown vN= fields are
// informational; if the header carries no v1= AND at least one vN= for some N != 1, parsing
// surfaces unknown_algorithm rather than malformed_header.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace YawLabs.Awsp;

/// <summary>
/// Parsed view of an X-A2A-Signature header. Internal -- the public surface is the
/// <see cref="VerifyResult.Reason"/> enum returned by <see cref="Awsp.Verify"/>.
/// </summary>
internal sealed record ParsedSignatureHeader(
    long Timestamp,
    IReadOnlyList<string> V1,
    string Nonce,
    string Kid);

internal enum HeaderParseFailure
{
    MalformedHeader,
    UnknownAlgorithm,
}

internal readonly record struct HeaderParseResult(
    ParsedSignatureHeader? Parsed,
    HeaderParseFailure? Failure)
{
    public static HeaderParseResult Ok(ParsedSignatureHeader p) => new(p, null);
    public static HeaderParseResult Fail(HeaderParseFailure f) => new(null, f);
}

internal static class Headers
{
    private const int MaxHeaderLength = 4096;
    private const int MinNonceLength = 1;
    private const int MaxNonceLength = 256;
    private const int MaxKidLength = 128;
    private const int V1HexLength = 64;

    /// <summary>
    /// Parse the value of an X-A2A-Signature header. Returns either a
    /// <see cref="ParsedSignatureHeader"/> or a failure tag (malformed / unknown_algorithm).
    /// </summary>
    public static HeaderParseResult Parse(string raw)
    {
        if (raw is null || raw.Length == 0)
        {
            return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
        }
        if (raw.Length > MaxHeaderLength)
        {
            return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
        }

        long? timestamp = null;
        var v1 = new List<string>();
        string? nonce = null;
        string? kid = null;
        bool sawUnknownVersion = false;

        foreach (var part in raw.Split(','))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0 || eq == part.Length - 1)
            {
                return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
            }

            // Spec ABNF treats fields as bare key=value with no implicit whitespace; the TS
            // reference trims defensively, so we mirror that here.
            string key = part.Substring(0, eq).Trim();
            string value = part.Substring(eq + 1).Trim();
            if (key.Length == 0 || value.Length == 0)
            {
                return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
            }

            if (key == "t")
            {
                if (timestamp.HasValue)
                {
                    return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
                }
                if (!IsAsciiDigits(value) || value.Length > 15)
                {
                    return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
                }
                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long t) || t < 0)
                {
                    return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
                }
                timestamp = t;
            }
            else if (key == "v1")
            {
                if (value.Length != V1HexLength || !IsLowerHex(value))
                {
                    return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
                }
                v1.Add(value);
            }
            else if (IsFutureSignatureVersion(key))
            {
                // v2=, v3=, ... are recorded only as a tag; their values are not validated.
                sawUnknownVersion = true;
            }
            else if (key == "n")
            {
                if (nonce is not null)
                {
                    return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
                }
                if (value.Length < MinNonceLength || value.Length > MaxNonceLength || !IsBase64Url(value))
                {
                    return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
                }
                nonce = value;
            }
            else if (key == "kid")
            {
                if (kid is not null)
                {
                    return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
                }
                if (value.Length > MaxKidLength || !IsKidChars(value))
                {
                    return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
                }
                kid = value;
            }
            else
            {
                // Unknown non-version field -- ignore for forward compatibility.
            }
        }

        if (!timestamp.HasValue)
        {
            return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
        }
        if (nonce is null)
        {
            return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
        }
        if (v1.Count == 0)
        {
            // No v1= present. If the sender included only newer-version signatures the spec
            // says reject as unknown_algorithm; otherwise it is just a malformed header.
            return HeaderParseResult.Fail(
                sawUnknownVersion ? HeaderParseFailure.UnknownAlgorithm : HeaderParseFailure.MalformedHeader);
        }
        if (kid is null)
        {
            // v1 mandates kid for forward-compatible rotation.
            return HeaderParseResult.Fail(HeaderParseFailure.MalformedHeader);
        }

        return HeaderParseResult.Ok(new ParsedSignatureHeader(timestamp.Value, v1, nonce, kid));
    }

    /// <summary>
    /// Serialize a parsed header. Field order: t, v1..., n, kid. Used by Sign and by tests.
    /// </summary>
    public static string Serialize(long timestamp, IReadOnlyList<string> v1, string nonce, string kid)
    {
        var sb = new StringBuilder(64 + v1.Count * 70);
        sb.Append("t=").Append(timestamp.ToString(CultureInfo.InvariantCulture));
        foreach (string v in v1)
        {
            sb.Append(",v1=").Append(v);
        }
        sb.Append(",n=").Append(nonce);
        sb.Append(",kid=").Append(kid);
        return sb.ToString();
    }

    private static bool IsAsciiDigits(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c < '0' || c > '9')
            {
                return false;
            }
        }
        return s.Length > 0;
    }

    private static bool IsLowerHex(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            bool digit = c >= '0' && c <= '9';
            bool lowerAf = c >= 'a' && c <= 'f';
            if (!digit && !lowerAf)
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsBase64Url(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            bool digit = c >= '0' && c <= '9';
            bool upper = c >= 'A' && c <= 'Z';
            bool lower = c >= 'a' && c <= 'z';
            bool punct = c == '-' || c == '_';
            if (!digit && !upper && !lower && !punct)
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsKidChars(string s)
    {
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            bool digit = c >= '0' && c <= '9';
            bool upper = c >= 'A' && c <= 'Z';
            bool lower = c >= 'a' && c <= 'z';
            bool punct = c == '-' || c == '_' || c == '.';
            if (!digit && !upper && !lower && !punct)
            {
                return false;
            }
        }
        return true;
    }

    private static bool IsFutureSignatureVersion(string key)
    {
        // Match /^v[0-9]+$/ excluding the literal "v1" (which is handled above).
        if (key.Length < 2 || key[0] != 'v')
        {
            return false;
        }
        for (int i = 1; i < key.Length; i++)
        {
            char c = key[i];
            if (c < '0' || c > '9')
            {
                return false;
            }
        }
        return key != "v1";
    }
}
