# @yawlabs/awsp

Reference TypeScript implementation of [AWSP](../../SPEC.md) -- the A2A Webhook Security Profile.

HMAC-SHA256 signing + verification, key rotation, replay protection, and SSRF defense for push-notification webhooks delivered between A2A agents.

- Zero runtime dependencies (Node built-in `crypto`, `dns`, `net` only)
- Works in Node 18+ (uses `node:crypto`, `Buffer.from(s, 'base64url')`)
- Apache-2.0 licensed
- Conforms to AWSP v1; passes all 50 [test vectors](../../test-vectors.json) plus
  ~200 additional adversarial parser fuzz cases and the full SPEC.md section 10
  SSRF blocklist

## Install

```bash
npm install @yawlabs/awsp
```

## Sign a webhook payload (sender side)

```ts
import { sign } from '@yawlabs/awsp';

const body = Buffer.from(JSON.stringify({ event: 'task.completed', taskId: 'tsk_123' }));

const headers = sign({
  secret: Buffer.from(process.env.AWSP_SECRET_HEX, 'hex'),
  keyId: 'k_2026_05',
  body,
  eventType: 'task.completed',
});

// Send body and `headers` to the receiver URL.
await fetch(receiverUrl, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...headers },
  body,
});
```

`headers` always carries:

- `X-A2A-Signature: t=...,v1=...,n=...,kid=...`
- `X-A2A-Webhook-Id: <uuid>`
- `X-A2A-Event-Type: <eventType>`
- `X-A2A-Timestamp: <unix-seconds>`

## Sender-side SSRF defense

SPEC.md section 10 requires Senders to refuse Receiver-supplied URLs that
resolve to private, reserved, link-local, multicast, or loopback addresses
(both IPv4 and IPv6, including IPv4-mapped IPv6 like `::ffff:127.0.0.1`).
Use `assertPublicUrl` before every webhook delivery:

```ts
import { assertPublicUrl, sign, SsrfBlockedError } from '@yawlabs/awsp';

async function deliver(receiverUrl: string, body: Uint8Array, secret: Uint8Array) {
  let safeUrl: URL;
  try {
    safeUrl = await assertPublicUrl(receiverUrl);
    // safeUrl.hostname is rewritten to the resolved public IP -- this is the
    // DNS-rebinding defense. The HTTP client connects to that IP, not to the
    // hostname (which a hostile DNS server could re-resolve to a private IP
    // between this check and the actual connect).
  } catch (err) {
    if (err instanceof SsrfBlockedError) {
      // err.reason is one of: private_ip, invalid_url, dns_failure, scheme_not_allowed
      // err.url is the original input; err.resolvedIp is set when reason is private_ip
      throw new Error(`refused to deliver to ${err.url}: ${err.reason}`);
    }
    throw err;
  }

  const headers = sign({
    secret,
    keyId: 'k_2026_05',
    body,
    eventType: 'task.completed',
  });

  await fetch(safeUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body,
    redirect: 'error', // SPEC.md section 10: deny redirects by default
  });
}
```

`assertPublicUrl` rejects:

- Non-HTTPS schemes (HTTP only with `allowHttp: true` for explicit operator opt-in)
- Hostnames that resolve to any IP in SPEC.md section 10's blocklist
- Hostnames whose resolution returns ANY private IP, even alongside public IPs
- Bare invalid URL strings (parse failures)
- DNS lookup failures

For tests, inject a stub resolver:

```ts
await assertPublicUrl('https://example.com/', {
  resolve: async () => ['8.8.8.8'], // skip real DNS
});
```

A note on TLS / SNI: rewriting the URL hostname to an IP literal means `fetch`
will use the IP for both the connect and the SNI. Most TLS servers will not
present a certificate for an IP literal, so production callers using
hostname-based TLS need to send the IP for the connect but the original
hostname for SNI. Node's built-in `fetch` doesn't expose that split; for
production multi-hostname senders, prefer `undici.Agent` with a custom
`connect` hook (or `node:https` directly) so you can connect to the resolved
IP while keeping the SNI / Host header on the original hostname.

## Verify an incoming webhook (receiver side)

```ts
import { verify, InMemoryReplayStore } from '@yawlabs/awsp';

// Singleton -- shared across requests.
const replayStore = new InMemoryReplayStore();
const secrets = [
  { kid: 'k_2026_05', secret: Buffer.from(process.env.AWSP_SECRET_OLD, 'hex') },
  { kid: 'k_2026_06', secret: Buffer.from(process.env.AWSP_SECRET_NEW, 'hex') },
];

const result = await verify({
  headers: req.headers,           // Node-style headers: case-insensitive lookup
  body: rawBodyBuffer,            // raw bytes -- NOT JSON.parse'd
  secrets,
  replayStore,
  replayWindowSeconds: 300,       // optional, default 300
});

if (!result.ok) {
  // result.reason is one of: malformed_header, unknown_algorithm, stale,
  // future, replayed, unknown_kid, bad_hmac
  res.status(401).json({ error: 'invalid_signature', reason: result.reason });
  return;
}
// signature valid: result.kid, result.timestamp, result.nonce
```

### Critical: pass the RAW body

The HMAC is computed over the raw bytes the sender wrote on the wire. If you
re-serialize the parsed JSON (whitespace, key reordering), the HMAC won't
match. Capture the raw body before any JSON middleware.

## Framework integrations

### Plain Node http

```ts
import http from 'node:http';
import { verify, InMemoryReplayStore } from '@yawlabs/awsp';

const replayStore = new InMemoryReplayStore();
const secrets = [{ kid: 'k1', secret: SECRET }];

http.createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks);

  const result = await verify({ headers: req.headers, body, secrets, replayStore });
  if (!result.ok) {
    res.statusCode = 401;
    res.end(JSON.stringify({ error: 'invalid_signature', reason: result.reason }));
    return;
  }
  // ... process JSON.parse(body.toString('utf8')) ...
  res.statusCode = 202;
  res.end();
});
```

### Express

Use `express.raw()` so the body remains a Buffer:

```ts
import express from 'express';
import { verify, InMemoryReplayStore } from '@yawlabs/awsp';

const app = express();
const replayStore = new InMemoryReplayStore();
const secrets = [{ kid: 'k1', secret: SECRET }];

app.post(
  '/webhooks/a2a',
  express.raw({ type: '*/*', limit: '1mb' }),
  async (req, res) => {
    const result = await verify({
      headers: req.headers,
      body: req.body,
      secrets,
      replayStore,
    });
    if (!result.ok) {
      return res.status(401).json({ error: 'invalid_signature', reason: result.reason });
    }
    const event = JSON.parse(req.body.toString('utf8'));
    // ... handle event ...
    res.status(202).end();
  },
);
```

### Fastify

Register a content type parser that preserves the raw body:

```ts
import Fastify from 'fastify';
import { verify, InMemoryReplayStore } from '@yawlabs/awsp';

const app = Fastify();
const replayStore = new InMemoryReplayStore();
const secrets = [{ kid: 'k1', secret: SECRET }];

app.addContentTypeParser('*', { parseAs: 'buffer' }, (_req, body, done) => {
  done(null, body);
});

app.post('/webhooks/a2a', async (req, reply) => {
  const result = await verify({
    headers: req.headers as Record<string, string>,
    body: req.body as Buffer,
    secrets,
    replayStore,
  });
  if (!result.ok) {
    return reply.code(401).send({ error: 'invalid_signature', reason: result.reason });
  }
  const event = JSON.parse((req.body as Buffer).toString('utf8'));
  // ... handle event ...
  reply.code(202).send();
});
```

### Hono (Node / Bun / Deno / Workers)

```ts
import { Hono } from 'hono';
import { verify, InMemoryReplayStore } from '@yawlabs/awsp';

const app = new Hono();
const replayStore = new InMemoryReplayStore();
const secrets = [{ kid: 'k1', secret: SECRET }];

app.post('/webhooks/a2a', async (c) => {
  const body = new Uint8Array(await c.req.arrayBuffer());
  const headers: Record<string, string> = {};
  c.req.raw.headers.forEach((v, k) => { headers[k] = v; });
  const result = await verify({ headers, body, secrets, replayStore });
  if (!result.ok) {
    return c.json({ error: 'invalid_signature', reason: result.reason }, 401);
  }
  // ... handle event ...
  return c.body(null, 202);
});
```

(In Cloudflare Workers, swap `InMemoryReplayStore` for a Durable-Object-backed
or KV-backed store so replay state is shared across worker instances.)

## Production replay storage

`InMemoryReplayStore` is included for tests and single-replica receivers.
Multi-replica deployments need shared storage so a nonce seen on replica A is
also rejected on replica B.

Recommended: Redis with `SET key NX EX <ttl>`. The bool returned by `SET` is
exactly the `checkAndStore` contract.

```ts
import { Redis } from 'ioredis';
import type { ReplayStore } from '@yawlabs/awsp';

class RedisReplayStore implements ReplayStore {
  constructor(private redis: Redis) {}
  async checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean> {
    const result = await this.redis.set(`awsp:nonce:${nonce}`, '1', 'EX', ttlSeconds, 'NX');
    return result === 'OK';
  }
}
```

## Key rotation

Add the new `(kid, secret)` to the `secrets` list 24h before retiring the old
one. The sender starts signing with the new kid; the receiver continues to
accept the old kid until rotation is complete. Then drop the old entry.

```ts
// During rotation window:
const secrets = [
  { kid: 'k_2026_05', secret: OLD_SECRET },  // accepted but not used by sender
  { kid: 'k_2026_06', secret: NEW_SECRET },  // sender signs with this
];
```

## Testing against the published vectors

The package includes `test/index.test.ts` which loads
`../../test-vectors.json` and runs every case. Other-language implementations
should do the same.

```bash
npm test
```

## License

Apache-2.0. See [LICENSE](./LICENSE).
