# AWSP -- Java reference implementation

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Java reference implementation of the [A2A Webhook Security Profile (AWSP)](../../SPEC.md) v1.

* JDK 17+ (records, pattern matching).
* Zero runtime dependencies. Uses only `javax.crypto.Mac`, `java.security.MessageDigest`, `java.util.HexFormat`, `java.util.concurrent.ConcurrentHashMap`, etc.
* Conformance bar: all 50 vectors in [`packages/awsp/test-vectors.json`](../../test-vectors.json) pass byte-for-byte.

## Install

Until this artifact is published to Maven Central, depend on it via your local build:

```xml
<dependency>
    <groupId>com.yawlabs</groupId>
    <artifactId>awsp</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Quick start

### Sender

```java
import com.yawlabs.awsp.Awsp;
import com.yawlabs.awsp.SignParams;

byte[] secret = ...;     // raw bytes of the shared HMAC secret
byte[] body   = ...;     // exact bytes you will write on the wire

Awsp.SignedHeaders signed = Awsp.sign(SignParams.builder()
    .secret(secret)
    .keyId("k_2026_05")
    .body(body)
    .eventType("task.completed")
    .build());

httpRequest.setHeader("X-A2A-Signature", signed.xA2ASignature());
httpRequest.setHeader("X-A2A-Webhook-Id", signed.xA2AWebhookId());
httpRequest.setHeader("X-A2A-Event-Type", signed.xA2AEventType());
httpRequest.setHeader("X-A2A-Timestamp", signed.xA2ATimestamp());
```

### Receiver

```java
import com.yawlabs.awsp.Awsp;
import com.yawlabs.awsp.InMemoryReplayStore;
import com.yawlabs.awsp.ReplayStore;
import com.yawlabs.awsp.VerifyParams;
import com.yawlabs.awsp.VerifyResult;

ReplayStore store = new InMemoryReplayStore();   // or a Redis-backed impl

VerifyResult result = Awsp.verify(VerifyParams.builder()
    .headers(requestHeaderMap)                   // case-insensitive
    .body(rawBodyBytes)                          // bytes BEFORE parsing
    .secrets(List.of(
        new VerifyParams.SecretEntry("k_2026_05", currentSecret),
        new VerifyParams.SecretEntry("k_2026_04", priorSecret)))   // rotation
    .replayStore(store)
    .build());

if (!result.ok()) {
    response.setStatus(401);
    response.setHeader("Content-Type", "application/json");
    response.getWriter().write(
        "{\"error\":\"invalid_signature\",\"reason\":\"" + result.reason() + "\"}");
    return;
}
```

The receiver MUST verify against the **raw body bytes** (see SPEC.md section 6.1). If your framework auto-parses JSON before your handler runs, capture the body buffer earlier in the pipeline (servlet filter, Spring's `ContentCachingRequestWrapper`, etc.).

## Integration recipes

### Servlet API filter (Jakarta or javax)

```java
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class AwspFilter implements Filter {

    private final List<VerifyParams.SecretEntry> secrets;
    private final ReplayStore replayStore;

    public AwspFilter(List<VerifyParams.SecretEntry> secrets, ReplayStore replayStore) {
        this.secrets = secrets;
        this.replayStore = replayStore;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest http = (HttpServletRequest) req;
        HttpServletResponse out = (HttpServletResponse) res;

        // Capture the body. Real deployments wrap the request in a buffering
        // wrapper so the downstream handler can re-read it.
        BufferedRequestWrapper wrapped = new BufferedRequestWrapper(http);
        byte[] body = wrapped.bodyBytes();

        Map<String, String> headers = new HashMap<>();
        for (var names = http.getHeaderNames(); names.hasMoreElements();) {
            String name = names.nextElement();
            headers.put(name, http.getHeader(name));
        }

        VerifyResult r = Awsp.verify(VerifyParams.builder()
                .headers(headers)
                .body(body)
                .secrets(secrets)
                .replayStore(replayStore)
                .build());

        if (!r.ok()) {
            out.setStatus(401);
            out.setContentType("application/json");
            out.getWriter().write(
                "{\"error\":\"invalid_signature\",\"reason\":\"" + r.reason() + "\"}");
            return;
        }

        chain.doFilter(wrapped, res);
    }
}
```

`BufferedRequestWrapper` is a standard `HttpServletRequestWrapper` that reads the InputStream once and then serves it from a `byte[]` for downstream handlers. See, e.g., Spring's `ContentCachingRequestWrapper` for a production-grade implementation.

### Spring Boot WebFilter (reactive)

```java
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import reactor.core.publisher.Mono;

public class AwspWebFilter implements WebFilter {

    private final List<VerifyParams.SecretEntry> secrets;
    private final ReplayStore replayStore;

    public AwspWebFilter(List<VerifyParams.SecretEntry> secrets, ReplayStore replayStore) {
        this.secrets = secrets;
        this.replayStore = replayStore;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return DataBufferUtils.join(exchange.getRequest().getBody())
            .defaultIfEmpty(exchange.getResponse().bufferFactory().wrap(new byte[0]))
            .flatMap(buffer -> {
                byte[] body = new byte[buffer.readableByteCount()];
                buffer.read(body);
                DataBufferUtils.release(buffer);

                Map<String, String> headers = new HashMap<>();
                exchange.getRequest().getHeaders()
                    .forEach((k, v) -> headers.put(k, String.join(",", v)));

                VerifyResult r = Awsp.verify(VerifyParams.builder()
                        .headers(headers)
                        .body(body)
                        .secrets(secrets)
                        .replayStore(replayStore)
                        .build());

                if (!r.ok()) {
                    exchange.getResponse().setRawStatusCode(401);
                    exchange.getResponse().getHeaders().add("Content-Type", "application/json");
                    DataBuffer out = exchange.getResponse().bufferFactory().wrap(
                        ("{\"error\":\"invalid_signature\",\"reason\":\""
                            + r.reason() + "\"}").getBytes());
                    return exchange.getResponse().writeWith(Mono.just(out));
                }

                // Replay the body for downstream handlers.
                ServerWebExchange decorated = exchange.mutate().request(
                    new BodyReplayingRequestDecorator(exchange.getRequest(), body)).build();
                return chain.filter(decorated);
            });
    }
}
```

### Spring Boot HandlerInterceptor (servlet stack)

If you're on the blocking servlet stack, the recipe is the Servlet filter above plus registering it via `WebMvcConfigurer`:

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Bean
    public FilterRegistrationBean<AwspFilter> awspFilter(
            List<VerifyParams.SecretEntry> secrets, ReplayStore replayStore) {
        FilterRegistrationBean<AwspFilter> bean = new FilterRegistrationBean<>(
            new AwspFilter(secrets, replayStore));
        bean.addUrlPatterns("/webhooks/*");
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }
}
```

### Plain JDK 17 HttpServer

```java
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;

HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
server.createContext("/webhook", (HttpHandler) exchange -> {
    byte[] body = exchange.getRequestBody().readAllBytes();

    Map<String, String> headers = new HashMap<>();
    exchange.getRequestHeaders().forEach((k, v) -> headers.put(k, v.get(0)));

    VerifyResult r = Awsp.verify(VerifyParams.builder()
            .headers(headers)
            .body(body)
            .secrets(secrets)
            .replayStore(store)
            .build());

    if (!r.ok()) {
        byte[] msg = ("{\"error\":\"invalid_signature\",\"reason\":\""
            + r.reason() + "\"}").getBytes();
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(401, msg.length);
        exchange.getResponseBody().write(msg);
        exchange.close();
        return;
    }

    // ... handle the verified delivery ...
    exchange.sendResponseHeaders(204, -1);
    exchange.close();
});
server.start();
```

## Building

```bash
cd packages/awsp/reference/java
mvn -B compile
mvn -B test
mvn -B verify
```

The test suite reads `../../test-vectors.json` via the Maven `<testResource>` mapping in `pom.xml`. Running tests from inside an IDE that does not honor that mapping falls back to walking up from `user.dir` looking for `packages/awsp/test-vectors.json`.

## Replay store

The reference `InMemoryReplayStore` is suitable for a single-process receiver (test fixtures, hobby deployments). Multi-replica deployments MUST share replay state across nodes -- the canonical recipe is Redis:

```java
public class RedisReplayStore implements ReplayStore {

    private final UnifiedJedis jedis;

    public RedisReplayStore(UnifiedJedis jedis) {
        this.jedis = jedis;
    }

    @Override
    public boolean checkAndStore(String configId, byte[] nonce, int ttlSeconds) {
        String key = "awsp:replay:" + configId + ":" + new String(nonce, StandardCharsets.US_ASCII);
        SetParams params = new SetParams().nx().ex(ttlSeconds);
        // SET key 1 NX EX <ttl> -- atomic check-and-store. Returns "OK" if set.
        String r = jedis.set(key, "1", params);
        return "OK".equals(r);
    }
}
```

Memcached `add` and equivalents work the same way.

## SSRF defense (sender side)

SPEC.md section 10 requires senders to gate every receiver-supplied URL
through a private-IP / reserved-range blocklist BEFORE connecting, so a
hostile receiver configuration cannot redirect the sender at internal hosts
(cloud IMDS, RFC1918 ranges, loopback, etc.). The reference helper is
`com.yawlabs.awsp.Ssrf`:

```java
import com.yawlabs.awsp.Ssrf;

import java.net.URI;

Ssrf.Options opts = new Ssrf.Options();
// opts.allowHttp = true;          // default false; set only for internal test fixtures
// opts.resolver = customResolver; // default uses InetAddress.getAllByName

try {
    URI safe = Ssrf.assertPublicUrl(receiverWebhookUrl, opts);
    // 'safe' has the host rewritten to the resolved public IP. Dial it
    // literally; do NOT re-resolve the original hostname (DNS-rebinding
    // defense per SPEC.md section 10 step 3).
    httpClient.connect(safe);
} catch (Ssrf.SsrfBlockedException e) {
    // e.reason is one of: PRIVATE_IP, INVALID_URL, DNS_FAILURE, SCHEME_NOT_ALLOWED.
    // e.url and e.resolvedIp give context for logging.
    log.warn("rejected webhook URL: reason={} url={} resolved={}",
        e.reason, e.url, e.resolvedIp);
    throw e;
}
```

The blocklist covers every IPv4 and IPv6 range listed in SPEC.md section 10
(0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24,
192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4,
255.255.255.255/32; ::/128, ::1/128, ::ffff:0:0/96 unwrapped to its IPv4
form, 64:ff9b::/96, 100::/64, 2001::/23, 2001:db8::/32, fc00::/7, fe80::/10,
ff00::/8). Zero new dependencies -- CIDR matching uses `java.math.BigInteger`
on the raw address bytes.

## Spec conformance

This implementation is conformant with AWSP v1 if and only if all 50 vectors
in `test-vectors.json` pass. The conformance suite is run as part of
`mvn test` (parameterized via JUnit 5 `@MethodSource`). Beyond the vector
suite, the parser is hammered by `HeadersAdversarialTest` (truncations at
every byte boundary, oversized inputs, duplicates, mixed case, control
bytes, extreme integers, plus ~3000 fuzz iterations across three seedable
strategies) -- the contract is that for any input the parser must EITHER
return a valid result OR throw `Headers.ParseException`, never an unchecked
crash.

## License

Apache-2.0. See [LICENSE](LICENSE).
