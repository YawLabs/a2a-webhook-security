# YawLabs.Awsp

Reference .NET implementation of [AWSP](../../SPEC.md) -- the A2A Webhook Security Profile.

HMAC-SHA256 signing + verification, key rotation, and replay protection for push-notification webhooks delivered between A2A agents.

- Target framework: `net8.0`
- Zero runtime dependencies (BCL only -- `System.Security.Cryptography.HMACSHA256`, `CryptographicOperations.FixedTimeEquals`, etc.)
- Apache-2.0 licensed
- Conforms to AWSP v1; passes all 50 [test vectors](../../test-vectors.json)

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

## License

Apache License 2.0. See [LICENSE](./LICENSE).
