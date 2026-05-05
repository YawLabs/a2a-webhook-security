# yawlabs-awsp (Python)

Reference Python implementation of [AWSP](../../SPEC.md) -- the A2A Webhook Security Profile.

HMAC-SHA256 signing + verification, key rotation, and replay protection for push-notification webhooks delivered between A2A agents.

- Zero runtime dependencies (Python stdlib only)
- Python 3.10+
- Apache-2.0 licensed
- Conforms to AWSP v1; passes all 50 [test vectors](../../test-vectors.json) plus adversarial parser fuzz (1000+ iterations of random and Hypothesis-generated inputs)

## Install

```bash
pip install yawlabs-awsp
```

## Sign a webhook payload (sender side)

```python
import json
import os
import urllib.request

from yawlabs_awsp import sign

body = json.dumps({"event": "task.completed", "taskId": "tsk_123"}).encode("utf-8")

headers = sign(
    secret=bytes.fromhex(os.environ["AWSP_SECRET_HEX"]),
    key_id="k_2026_05",
    body=body,
    event_type="task.completed",
)

# Send body and `headers` to the receiver URL.
req = urllib.request.Request(
    receiver_url,
    method="POST",
    data=body,
    headers={"Content-Type": "application/json", **headers},
)
urllib.request.urlopen(req)
```

`headers` always carries:

- `X-A2A-Signature: t=...,v1=...,n=...,kid=...`
- `X-A2A-Webhook-Id: <uuid>`
- `X-A2A-Event-Type: <event_type>`
- `X-A2A-Timestamp: <unix-seconds>`

## SSRF defense (sender side)

[SPEC.md section 10](../../SPEC.md) requires Senders to gate Receiver-supplied
URLs before dispatch -- otherwise an attacker controlling the webhook
configuration can point the URL at internal services
(`http://169.254.169.254/`, RFC 1918, loopback) and have your Sender make
the request on their behalf.

`assert_public_url` resolves the URL's hostname, refuses any IP in the
spec's blocklist (private, reserved, link-local, multicast, loopback --
IPv4 and IPv6, including `::ffff:` IPv4-mapped variants), and returns a
URL with the hostname rewritten to the resolved public IP. Connecting by
IP defeats DNS-rebinding -- the IP we resolved is the IP we connect to.

```python
from urllib.parse import urlparse

import requests  # or httpx

from yawlabs_awsp import SsrfBlockedError, assert_public_url, sign

try:
    safe_url = assert_public_url(receiver_url)  # https only by default
except SsrfBlockedError as err:
    # err.reason is one of: private_ip, invalid_url, dns_failure, scheme_not_allowed
    # err.url, err.resolved_ip populated for logging / metrics
    raise

headers = sign(secret=SECRET, key_id="k_2026_05", body=body, event_type="task.completed")

# Connect by IP, but preserve the original Host header so TLS SNI and
# HTTP virtual hosting still work.
original_host = urlparse(receiver_url).netloc
requests.post(
    safe_url,
    data=body,
    headers={"Host": original_host, "Content-Type": "application/json", **headers},
)
```

Allow `http://` only on internal test fixtures (CI, local-dev receivers):

```python
safe_url = assert_public_url(receiver_url, allow_http=True)
```

For testing, inject a stub resolver instead of hitting DNS:

```python
safe = assert_public_url(
    "https://example.com/webhook",
    resolve=lambda host: ["93.184.216.34"],
)
```

## Verify an incoming webhook (receiver side)

```python
import os

from yawlabs_awsp import InMemoryReplayStore, SecretEntry, verify

# Singleton: shared across requests.
replay_store = InMemoryReplayStore()
secrets = [
    SecretEntry(kid="k_2026_05", secret=bytes.fromhex(os.environ["AWSP_SECRET_OLD"])),
    SecretEntry(kid="k_2026_06", secret=bytes.fromhex(os.environ["AWSP_SECRET_NEW"])),
]

result = verify(
    headers=request_headers,        # case-insensitive lookup
    body=raw_body_bytes,            # raw bytes, NOT json.loads'd
    secrets=secrets,
    replay_store=replay_store,
    replay_window_seconds=300,      # optional, default 300
)

if not result.ok:
    # result.reason is one of: malformed_header, unknown_algorithm, stale,
    # future, replayed, unknown_kid, bad_hmac
    return ({"error": "invalid_signature", "reason": result.reason}, 401)

# Signature valid: result.kid, result.timestamp, result.nonce
```

### Critical: pass the RAW body

The HMAC is computed over the raw bytes the sender wrote on the wire. If
you re-serialize parsed JSON (whitespace, key reordering), the HMAC won't
match. Capture the raw body before any JSON middleware.

## Framework integrations

### Plain stdlib http.server

```python
from http.server import BaseHTTPRequestHandler, HTTPServer

from yawlabs_awsp import InMemoryReplayStore, SecretEntry, verify

replay_store = InMemoryReplayStore()
secrets = [SecretEntry(kid="k1", secret=SECRET)]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        # http.server gives headers as a Message; coerce to a plain dict.
        headers = {k: v for k, v in self.headers.items()}

        result = verify(
            headers=headers,
            body=body,
            secrets=secrets,
            replay_store=replay_store,
        )
        if not result.ok:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(
                f'{{"error":"invalid_signature","reason":"{result.reason}"}}'.encode()
            )
            return
        # ... process json.loads(body) ...
        self.send_response(202)
        self.end_headers()


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
```

### Flask

Read the raw body via `request.get_data(cache=True)` so flask doesn't
preempt it with JSON parsing:

```python
from flask import Flask, jsonify, request

from yawlabs_awsp import InMemoryReplayStore, SecretEntry, verify

app = Flask(__name__)
replay_store = InMemoryReplayStore()
secrets = [SecretEntry(kid="k1", secret=SECRET)]


@app.post("/webhooks/a2a")
def webhook():
    body = request.get_data(cache=True)  # raw bytes
    result = verify(
        headers=dict(request.headers),
        body=body,
        secrets=secrets,
        replay_store=replay_store,
    )
    if not result.ok:
        return jsonify(error="invalid_signature", reason=result.reason), 401
    # ... handle event ...
    return "", 202
```

### FastAPI

Read raw bytes via `await request.body()` before any model coercion:

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from yawlabs_awsp import InMemoryReplayStore, SecretEntry, verify

app = FastAPI()
replay_store = InMemoryReplayStore()
secrets = [SecretEntry(kid="k1", secret=SECRET)]


@app.post("/webhooks/a2a")
async def webhook(request: Request):
    body = await request.body()
    result = verify(
        headers=dict(request.headers),
        body=body,
        secrets=secrets,
        replay_store=replay_store,
    )
    if not result.ok:
        return JSONResponse(
            {"error": "invalid_signature", "reason": result.reason},
            status_code=401,
        )
    # ... handle event ...
    return JSONResponse(None, status_code=202)
```

## Production replay storage

`InMemoryReplayStore` is included for tests and single-replica receivers.
Multi-replica deployments need shared storage so a nonce seen on replica
A is also rejected on replica B.

Recommended: Redis with `SET key NX EX <ttl>`. The bool returned by the
SET reply is exactly the `check_and_store` contract.

```python
import redis  # pip install redis

from yawlabs_awsp import ReplayStore


class RedisReplayStore:
    def __init__(self, client: redis.Redis) -> None:
        self.client = client

    def check_and_store(self, nonce: str, ttl_seconds: int) -> bool:
        result = self.client.set(
            f"awsp:nonce:{nonce}", "1", nx=True, ex=ttl_seconds
        )
        return bool(result)
```

## Key rotation

Add the new `(kid, secret)` to the `secrets` list 24h before retiring the
old one. The sender starts signing with the new kid; the receiver continues
to accept the old kid until rotation is complete. Then drop the old entry.

```python
# During rotation window:
secrets = [
    SecretEntry(kid="k_2026_05", secret=OLD_SECRET),  # accepted
    SecretEntry(kid="k_2026_06", secret=NEW_SECRET),  # sender uses this
]
```

## Testing against the published vectors

The package's `tests/test_vectors.py` loads
`../../test-vectors.json` and runs every case. Other-language ports
should do the same.

```bash
pip install -e ".[test]"
python -m pytest tests/ -v
```

## License

Apache-2.0. See [LICENSE](./LICENSE).
