// Runs every vector from packages/awsp/test-vectors.json against the
// reference sign / verify implementation. All 50 vectors must pass.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  InMemoryReplayStore,
  type SecretEntry,
  type VerifyResult,
  computeV1,
  parseSignatureHeader,
  serializeSignatureHeader,
  sign,
  verify,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(here, '..', '..', '..', 'test-vectors.json');
const file = JSON.parse(readFileSync(vectorsPath, 'utf8')) as VectorFile;

interface VectorFile {
  spec: string;
  vector_count: number;
  vectors: Vector[];
}

interface Vector {
  name: string;
  description: string;
  secret_hex: string;
  kid: string;
  body_hex: string;
  timestamp: number;
  nonce_b64url: string;
  now: number;
  expected_signature_hex?: string;
  presented_signature_hex?: string;
  raw_signature_header?: string;
  replay_setup?: { seed_nonces: string[] };
  receiver_known_kid?: string;
  expected_verify: 'ok' | { error: string };
  note?: string;
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

test(`${file.spec}: 50 vectors loaded`, () => {
  assert.equal(file.vectors.length, 50);
  assert.equal(file.vector_count, 50);
});

for (const v of file.vectors) {
  test(`vector: ${v.name}`, async () => {
    const secret = hexToBytes(v.secret_hex);
    const body = hexToBytes(v.body_hex);

    // Compute what the algorithm should produce -- always exercised so the
    // canonical-string concatenation is covered for every body.
    const computed = computeV1(secret, v.timestamp, body);
    if (v.expected_signature_hex !== undefined) {
      assert.equal(computed, v.expected_signature_hex, `computeV1 result mismatch for ${v.name}`);
    }

    // Build the headers that will be presented to verify().
    const sigHex = v.expected_signature_hex ?? v.presented_signature_hex ?? computed;
    const headerValue = v.raw_signature_header ?? buildHeader(v.timestamp, sigHex, v.nonce_b64url, v.kid);
    const headers = {
      'x-a2a-signature': headerValue,
      'x-a2a-webhook-id': '00000000-0000-4000-8000-000000000000',
      'x-a2a-event-type': 'test.event',
      'x-a2a-timestamp': String(v.timestamp),
    };

    // Receiver secret list. Most vectors use the kid in the vector itself.
    // The unknown_kid vector specifies which kid the receiver actually knows.
    const receiverKid = v.receiver_known_kid ?? v.kid;
    const secrets: SecretEntry[] = [{ kid: receiverKid, secret }];
    // Multi-secret receivers also accept SECRET_B/KID_B vectors.
    if (v.kid === 'k_2026_06') {
      // already covered by the entry above (receiverKid === v.kid)
    }

    // Replay setup: if the vector seeds nonces, use a store and pre-seed it.
    const replayStore = v.replay_setup ? new InMemoryReplayStore(() => v.now) : undefined;
    if (replayStore && v.replay_setup) {
      for (const n of v.replay_setup.seed_nonces) {
        await replayStore.checkAndStore(n, 360);
      }
    }

    const result = await verify({
      headers,
      body,
      secrets,
      replayStore,
      replayWindowSeconds: 300,
      now: v.now,
    });

    assertVerifyResult(result, v);
  });
}

function buildHeader(t: number, v1: string, n: string, kid: string): string {
  return `t=${t},v1=${v1},n=${n},kid=${kid}`;
}

function assertVerifyResult(result: VerifyResult, v: Vector): void {
  if (v.expected_verify === 'ok') {
    assert.equal(result.ok, true, `${v.name} expected ok, got ${JSON.stringify(result)}`);
  } else {
    assert.equal(result.ok, false, `${v.name} expected error, got ok`);
    if (!result.ok) {
      assert.equal(
        result.reason,
        v.expected_verify.error,
        `${v.name} expected reason=${v.expected_verify.error}, got ${result.reason}`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Sign output format checks
// ---------------------------------------------------------------------------

test('sign(): produces all four headers', () => {
  const secret = new Uint8Array(32);
  const headers = sign({
    secret,
    keyId: 'k_test',
    body: new TextEncoder().encode('{"a":1}'),
    eventType: 'test.created',
    timestamp: 1777248000,
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAA',
    webhookId: '00000000-0000-4000-8000-000000000000',
  });
  assert.equal(typeof headers['X-A2A-Signature'], 'string');
  assert.equal(typeof headers['X-A2A-Webhook-Id'], 'string');
  assert.equal(typeof headers['X-A2A-Event-Type'], 'string');
  assert.equal(typeof headers['X-A2A-Timestamp'], 'string');
  const parsed = parseSignatureHeader(headers['X-A2A-Signature']);
  assert.equal(parsed.timestamp, 1777248000);
  assert.equal(parsed.kid, 'k_test');
  assert.equal(parsed.v1.length, 1);
});

test('sign(): default timestamp / nonce / webhookId are populated', () => {
  const headers = sign({
    secret: new Uint8Array([1, 2, 3, 4]),
    keyId: 'k',
    body: new Uint8Array(0),
    eventType: 'e',
  });
  const parsed = parseSignatureHeader(headers['X-A2A-Signature']);
  // Just sanity: timestamp is a recent epoch and nonce decodes.
  assert.ok(parsed.timestamp > 1700000000, 'timestamp populated');
  assert.match(parsed.nonce, /^[A-Za-z0-9_-]+$/);
  assert.match(headers['X-A2A-Webhook-Id'], /^[0-9a-f-]{36}$/);
});

test('sign(): rejects zero-length secret', () => {
  assert.throws(() =>
    sign({
      secret: new Uint8Array(0),
      keyId: 'k',
      body: new Uint8Array(0),
      eventType: 'e',
    }),
  );
});

// ---------------------------------------------------------------------------
// Verify edge cases
// ---------------------------------------------------------------------------

test('verify(): missing signature header => malformed_header', async () => {
  const r = await verify({
    headers: {},
    body: new Uint8Array(0),
    secrets: [{ kid: 'k', secret: new Uint8Array(32) }],
    now: 1777248000,
  });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, 'malformed_header');
});

test('verify(): rejects out-of-range replay window', async () => {
  await assert.rejects(
    verify({
      headers: { 'x-a2a-signature': `t=1,v1=${'0'.repeat(64)},n=A,kid=k` },
      body: new Uint8Array(0),
      secrets: [],
      replayWindowSeconds: 30,
    }),
  );
  await assert.rejects(
    verify({
      headers: { 'x-a2a-signature': `t=1,v1=${'0'.repeat(64)},n=A,kid=k` },
      body: new Uint8Array(0),
      secrets: [],
      replayWindowSeconds: 700,
    }),
  );
});

test('verify(): multi-v1 header validates if any matches', async () => {
  const secret = new Uint8Array(16);
  for (let i = 0; i < 16; i++) secret[i] = i;
  const t = 1777248000;
  const body = new TextEncoder().encode('hi');
  const goodSig = computeV1(secret, t, body);
  const badSig = '0'.repeat(64);
  const header = serializeSignatureHeader({
    timestamp: t,
    v1: [badSig, goodSig], // good one is second
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAA',
    kid: 'k',
  });
  const r = await verify({
    headers: { 'x-a2a-signature': header },
    body,
    secrets: [{ kid: 'k', secret }],
    now: t,
  });
  assert.equal(r.ok, true);
});

test('verify(): rotation -- old + new secrets both accepted', async () => {
  const oldSecret = new Uint8Array(16).fill(1);
  const newSecret = new Uint8Array(16).fill(2);
  const t = 1777248000;
  const body = new TextEncoder().encode('payload');

  // Sender signs with old kid.
  const headers = sign({
    secret: oldSecret,
    keyId: 'k_old',
    body,
    eventType: 'e',
    timestamp: t,
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAA',
    webhookId: '00000000-0000-4000-8000-000000000000',
  });

  const r = await verify({
    headers: { 'x-a2a-signature': headers['X-A2A-Signature'] },
    body,
    secrets: [
      { kid: 'k_old', secret: oldSecret },
      { kid: 'k_new', secret: newSecret },
    ],
    now: t,
  });
  assert.equal(r.ok, true);
  if (r.ok) assert.equal(r.kid, 'k_old');
});

test('verify(): replay store returns false on second call', async () => {
  const secret = new Uint8Array(16).fill(7);
  const t = 1777248000;
  const body = new Uint8Array(0);
  const headers = sign({
    secret,
    keyId: 'k',
    body,
    eventType: 'e',
    timestamp: t,
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAA',
    webhookId: '00000000-0000-4000-8000-000000000000',
  });
  const store = new InMemoryReplayStore(() => t);
  const r1 = await verify({
    headers: { 'x-a2a-signature': headers['X-A2A-Signature'] },
    body,
    secrets: [{ kid: 'k', secret }],
    replayStore: store,
    now: t,
  });
  assert.equal(r1.ok, true);
  const r2 = await verify({
    headers: { 'x-a2a-signature': headers['X-A2A-Signature'] },
    body,
    secrets: [{ kid: 'k', secret }],
    replayStore: store,
    now: t,
  });
  assert.equal(r2.ok, false);
  if (!r2.ok) assert.equal(r2.reason, 'replayed');
});

test('InMemoryReplayStore: evicts after TTL', async () => {
  let now = 1000;
  const store = new InMemoryReplayStore(() => now);
  assert.equal(await store.checkAndStore('n1', 60), true);
  assert.equal(await store.checkAndStore('n1', 60), false);
  now = 1061; // past TTL
  assert.equal(await store.checkAndStore('n1', 60), true);
});
