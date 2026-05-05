# YawLabs.Awsp

Reference .NET implementation of [AWSP](../../SPEC.md) -- the A2A Webhook Security Profile.

HMAC-SHA256 signing + verification, key rotation, and replay protection for push-notification webhooks delivered between A2A agents.

- Target framework: `net8.0`
- Zero runtime dependencies (BCL only -- `System.Security.Cryptography.HMACSHA256`, `CryptographicOperations.FixedTimeEquals`, `System.Net.Sockets.Dns`, etc.)
- Apache-2.0 licensed
- Conforms to AWSP v1; passes all 50 [test vectors](../../test-vectors.json) plus an adversarial / fuzz suite for the header parser

## Install

The package is being prepared for nuget.org. Until it ships, reference the project directly:

```xml
<ProjectReference Include="path/to/YawLabs.Awsp/YawLabs.Awsp.csproj" />
```

## Quick start

### Sign a webhook payload (sender side)

```csharp
using YawLabs.Awsp;
using System.Text;

byte[] body = Encoding.UTF8.GetBytes("""{"event":"task.completed","taskId":"tsk_123"}""");
byte[] secret = Convert.FromHexString(Environment.GetEnvironmentVariable("AWSP_SECRET_HEX")!);

SignedHeaders headers = Awsp.Sign(new SignParams(
    Secret: secret,
    Body: body,
    KeyId: "k_2026_05",
    EventType: "task.completed"));

using var http = new HttpClient();
var req = new HttpRequestMessage(HttpMethod.Post, receiverUrl)
{
    Content = new ByteArrayContent(body),
};
req.Headers.Add("X-A2A-Signature", headers.XA2ASignature);
req.Headers.Add("X-A2A-Webhook-Id", headers.XA2AWebhookId);
req.Headers.Add("X-A2A-Event-Type", headers.XA2AEventType);
req.Headers.Add("X-A2A-Timestamp", headers.XA2ATimestamp);
req.Content.Headers.ContentType = new("application/json");

await http.SendAsync(req);
```

### Verify an incoming webhook (ASP.NET Core minimal API)

```csharp
using YawLabs.Awsp;

var builder = WebApplication.CreateBuilder(args);

// Singleton -- shared across requests so nonces dedupe correctly.
builder.Services.AddSingleton<IReplayStore, InMemoryReplayStore>();

// (kid, secret) lookup. In production this comes from Secrets Manager / KeyVault.
builder.Services.AddSingleton<IReadOnlyDictionary<string, byte[]>>(_ => new Dictionary<string, byte[]>
{
    ["k_2026_05"] = Convert.FromHexString(Environment.GetEnvironmentVariable("AWSP_SECRET_OLD")!),
    ["k_2026_06"] = Convert.FromHexString(Environment.GetEnvironmentVariable("AWSP_SECRET_NEW")!),
});

var app = builder.Build();

app.MapPost("/webhook", async (HttpRequest request,
    IReplayStore replayStore,
    IReadOnlyDictionary<string, byte[]> secrets) =>
{
    // Read the body BEFORE any parsing -- the HMAC is over the raw bytes the sender wrote.
    using var ms = new MemoryStream();
    await request.Body.CopyToAsync(ms);
    byte[] body = ms.ToArray();

    // Project request headers into a flat case-insensitive dictionary.
    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    foreach (var (key, value) in request.Headers)
    {
        headers[key] = value.ToString();
    }

    var result = Awsp.Verify(new VerifyParams(
        Headers: headers,
        Body: body,
        Secrets: secrets,
        ReplayStore: replayStore));

    if (!result.Ok)
    {
        // Per SPEC.md section 9: stable enum reason; never the free-form diagnostic.
        return Results.Json(
            new { error = "invalid_signature", reason = result.Reason },
            statusCode: StatusCodes.Status401Unauthorized);
    }

    // Parse and dispatch.
    return Results.Ok();
});

app.Run();
```

### Verify with plain `HttpListener` (no ASP.NET Core)

```csharp
using System.Net;
using System.Text.Json;
using YawLabs.Awsp;

var replayStore = new InMemoryReplayStore();
var secrets = new Dictionary<string, byte[]>
{
    ["k_2026_05"] = Convert.FromHexString(Environment.GetEnvironmentVariable("AWSP_SECRET")!),
};

var listener = new HttpListener();
listener.Prefixes.Add("http://localhost:8080/webhook/");
listener.Start();

while (listener.IsListening)
{
    HttpListenerContext ctx = await listener.GetContextAsync();
    if (ctx.Request.HttpMethod != "POST")
    {
        ctx.Response.StatusCode = 405;
        ctx.Response.Close();
        continue;
    }

    using var ms = new MemoryStream();
    await ctx.Request.InputStream.CopyToAsync(ms);
    byte[] body = ms.ToArray();

    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    foreach (string? key in ctx.Request.Headers.AllKeys)
    {
        if (key is null) continue;
        headers[key] = ctx.Request.Headers[key] ?? string.Empty;
    }

    VerifyResult result = Awsp.Verify(new VerifyParams(
        Headers: headers,
        Body: body,
        Secrets: secrets,
        ReplayStore: replayStore));

    if (!result.Ok)
    {
        ctx.Response.StatusCode = 401;
        ctx.Response.ContentType = "application/json";
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            error = "invalid_signature",
            reason = result.Reason,
        });
        await ctx.Response.OutputStream.WriteAsync(payload);
        ctx.Response.Close();
        continue;
    }

    // Dispatch the event...
    ctx.Response.StatusCode = 200;
    ctx.Response.Close();
}
```

### Sender-side SSRF defense

A Receiver supplies its webhook URL during configuration. Without active defense, a hostile configuration call could point that URL at internal hosts (`http://169.254.169.254/`, `http://10.0.0.1/`, `http://localhost:5432/`) and trick your Sender into making requests on its behalf.

`Ssrf.AssertPublicUrlAsync` resolves the host, rejects any private / reserved / link-local / multicast / loopback address per [SPEC.md section 10](../../SPEC.md), and returns a URI rewritten to the resolved public IP literal so you connect by IP and defeat DNS-rebinding.

```csharp
using YawLabs.Awsp;

try
{
    Uri safeUri = await Ssrf.AssertPublicUrlAsync(receiverConfiguredUrl);

    // Connect by IP literal -- defeats DNS-rebinding between assert and connect.
    var req = new HttpRequestMessage(HttpMethod.Post, safeUri)
    {
        Content = new ByteArrayContent(body),
    };
    // ... attach AWSP headers, send, etc.
}
catch (SsrfBlockedException ex)
{
    // ex.Reason: PrivateIp | InvalidUrl | DnsFailure | SchemeNotAllowed
    // ex.Url:    the original input string
    // ex.ResolvedIp: the address that triggered the block (null on pre-DNS failures)
    logger.LogWarning("Refusing to deliver to {Url}: {Reason} ({Ip})", ex.Url, ex.Reason, ex.ResolvedIp);
    throw;
}
```

For Sender-internal test fixtures or explicit operator opt-in, `http://` can be permitted:

```csharp
Uri safeUri = await Ssrf.AssertPublicUrlAsync(
    receiverConfiguredUrl,
    new AssertPublicUrlOptions { AllowHttp = true });
```

The `Resolve` option lets you inject a custom DNS resolver -- handy for tests, or to enforce a specific resolver in production:

```csharp
var opts = new AssertPublicUrlOptions
{
    Resolve = (host, ct) => Dns.GetHostAddressesAsync(host, ct),
};
Uri safeUri = await Ssrf.AssertPublicUrlAsync(url, opts);
```

Body-size caps, redirect-follow refusal, and total request time are caller responsibilities -- configure them on `HttpClient` / `HttpClientHandler`.

### Custom replay store (Redis example)

For multi-replica receivers, swap `InMemoryReplayStore` for a shared backing store. Below is a sketch using StackExchange.Redis -- the package is NOT a dependency of `YawLabs.Awsp`; install it in the application that needs it.

```csharp
using StackExchange.Redis;
using YawLabs.Awsp;

public sealed class RedisReplayStore : IReplayStore
{
    private readonly IDatabase _db;
    private readonly string _keyPrefix;

    public RedisReplayStore(IConnectionMultiplexer mux, string keyPrefix = "awsp:nonce:")
    {
        _db = mux.GetDatabase();
        _keyPrefix = keyPrefix;
    }

    public bool CheckAndStore(string configId, byte[] nonce, int ttlSeconds)
    {
        // Atomic SET NX EX. Returns true only when the key did not exist.
        string key = _keyPrefix + (string.IsNullOrEmpty(configId) ? string.Empty : configId + ":")
            + Convert.ToBase64String(nonce);
        return _db.StringSet(
            key,
            value: "1",
            expiry: TimeSpan.FromSeconds(ttlSeconds),
            when: When.NotExists);
    }
}
```

Wire it up in `Program.cs`:

```csharp
builder.Services.AddSingleton<IConnectionMultiplexer>(_ =>
    ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis")!));
builder.Services.AddSingleton<IReplayStore, RedisReplayStore>();
```

## API surface

```csharp
public static class Awsp
{
    public static SignedHeaders Sign(SignParams p);
    public static VerifyResult Verify(VerifyParams p);
    public static string ComputeV1(byte[] secret, long timestamp, byte[] body); // exposed for cross-impl checks
}

public sealed record SignParams(
    byte[] Secret,
    byte[] Body,
    string KeyId,
    string EventType,
    DateTimeOffset? Timestamp = null,
    byte[]? Nonce = null,
    string? WebhookId = null);

public sealed record SignedHeaders(
    string XA2ASignature,
    string XA2AWebhookId,
    string XA2AEventType,
    string XA2ATimestamp);

public sealed record VerifyParams(
    IReadOnlyDictionary<string, string> Headers,
    byte[] Body,
    IReadOnlyDictionary<string, byte[]> Secrets,
    int ReplayWindowSeconds = 300,
    IReplayStore? ReplayStore = null,
    Func<DateTimeOffset>? Now = null);

public sealed record VerifyResult(bool Ok, string? Reason);

public interface IReplayStore
{
    bool CheckAndStore(string configId, byte[] nonce, int ttlSeconds);
}

public sealed class InMemoryReplayStore : IReplayStore { /* ... */ }

public static class Ssrf
{
    public static Task<Uri> AssertPublicUrlAsync(
        string rawUrl,
        AssertPublicUrlOptions? opts = null,
        CancellationToken ct = default);
}

public class AssertPublicUrlOptions
{
    public bool AllowHttp { get; init; }
    public Func<string, CancellationToken, Task<IPAddress[]>>? Resolve { get; init; }
}

public class SsrfBlockedException : Exception
{
    public enum SsrfReason { PrivateIp, InvalidUrl, DnsFailure, SchemeNotAllowed }
    public SsrfReason Reason { get; }
    public string Url { get; }
    public string? ResolvedIp { get; }
}
```

`Reason` on a failed `VerifyResult` is one of the stable enum values from SPEC.md section 9:
`"malformed_header" | "unknown_algorithm" | "stale" | "future" | "replayed" | "unknown_kid" | "bad_hmac"`.

## Build / test

```bash
cd packages/awsp/reference/dotnet
dotnet restore
dotnet build -c Release
dotnet test -c Release --no-build
```

The test project loads `../../test-vectors.json` (copied into the test bin directory by an MSBuild `<Content Include>`). All 50 vectors are run via xUnit `[Theory] [ClassData(typeof(VectorData))]`.

The test suite also includes:

- `HeadersAdversarialTests` -- targeted [Theory] / [InlineData] cases plus ~1000 seeded fuzz iterations confirming the parser EITHER returns a spec-defined `VerifyResult` OR throws a documented exception type. Parser-bug exceptions (`NullReferenceException`, `IndexOutOfRangeException`, `ArgumentOutOfRangeException` from internal slicing, `FormatException` from internal hex/base64 decoders, `OverflowException`) MUST NOT leak from `Awsp.Verify`.
- `SsrfTests` -- one test per IPv4 + IPv6 CIDR range from SPEC.md section 10, plus invalid URL, DNS failure, scheme rejection, and the `AllowHttp` opt-in.

## License

Apache License 2.0. See [LICENSE](./LICENSE).
