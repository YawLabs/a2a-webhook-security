// Generates packages/awsp/test-vectors.json deterministically.
// Run from packages/awsp/reference/typescript: `node scripts/generate-vectors.mjs`.
//
// All inputs (secrets, bodies, timestamps, nonces) are fixed strings; no RNG.

import { createHmac } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(here, '..', '..', '..', 'test-vectors.json');

function hex(bufOrString) {
  if (typeof bufOrString === 'string') return Buffer.from(bufOrString, 'utf8').toString('hex');
  return Buffer.from(bufOrString).toString('hex');
}

function bodyHexFromUtf8(s) {
  return Buffer.from(s, 'utf8').toString('hex');
}

function bodyHexFromBytes(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function computeV1(secretBytes, timestamp, bodyBytes) {
  const tsBytes = Buffer.from(String(timestamp), 'ascii');
  const dot = Buffer.from('.', 'ascii');
  const canonical = Buffer.concat([tsBytes, dot, Buffer.from(bodyBytes)]);
  return createHmac('sha256', Buffer.from(secretBytes)).update(canonical).digest('hex');
}

// Reference timestamp -- 2026-05-02T00:00:00Z = 1777248000 (UTC)
const T0 = 1777248000;

// Fixed secrets
const SECRET_A = Buffer.from('a'.repeat(64), 'utf8'); // 64 bytes
const SECRET_B = Buffer.from('b'.repeat(64), 'utf8');
const SECRET_RAW32 = Buffer.alloc(32);
for (let i = 0; i < 32; i++) SECRET_RAW32[i] = i; // 0x00..0x1f
const SECRET_RAW16 = Buffer.alloc(16);
for (let i = 0; i < 16; i++) SECRET_RAW16[i] = (i * 17) & 0xff;

const KID_A = 'k_2026_05';
const KID_B = 'k_2026_06';

const NONCE_FIXED = 'AAAAAAAAAAAAAAAAAAAAAAAA'; // 24-char base64url (18 raw bytes of 0)
const NONCE_2 = 'BBBBBBBBBBBBBBBBBBBBBBBB';
const NONCE_3 = 'CCCCCCCCCCCCCCCCCCCCCCCC';

// Bodies
const BODY_EMPTY = Buffer.alloc(0);
const BODY_HELLO = Buffer.from('{"hello":"world"}', 'utf8');
// UTF-8 body: {"emoji":"☃","kanji":"中文"} -- snowman + "Chinese".
// Built from hex to keep the source ASCII-only.
const BODY_UTF8 = Buffer.from('7b22656d6f6a69223a22e29883222c226b616e6a69223a22e4b8ade69687227d', 'hex');
const BODY_1KB = Buffer.from('x'.repeat(1024), 'utf8');
const BODY_64KB = Buffer.from('y'.repeat(65536), 'utf8');
const BODY_BINARY = Buffer.alloc(256);
for (let i = 0; i < 256; i++) BODY_BINARY[i] = i;
const BODY_LARGE_JSON = Buffer.from(
  JSON.stringify({ event: 'task.completed', taskId: 'tsk_abc123', payload: { result: 42 } }),
  'utf8',
);

const vectors = [];

// ---------------------------------------------------------------------------
// Category 1: 10 valid
// ---------------------------------------------------------------------------

const valids = [
  {
    name: 'valid_empty_body',
    secret: SECRET_A,
    kid: KID_A,
    body: BODY_EMPTY,
    t: T0,
    n: NONCE_FIXED,
    desc: 'Empty body, ASCII secret, on-time.',
  },
  {
    name: 'valid_small_json',
    secret: SECRET_A,
    kid: KID_A,
    body: BODY_HELLO,
    t: T0,
    n: NONCE_FIXED,
    desc: 'Small JSON object body.',
  },
  {
    name: 'valid_utf8_multibyte',
    secret: SECRET_A,
    kid: KID_A,
    body: BODY_UTF8,
    t: T0,
    n: NONCE_FIXED,
    desc: 'UTF-8 body with multibyte characters; HMAC is over body bytes, encoding-agnostic.',
  },
  {
    name: 'valid_1kb_body',
    secret: SECRET_A,
    kid: KID_A,
    body: BODY_1KB,
    t: T0,
    n: NONCE_FIXED,
    desc: '1024-byte ASCII body.',
  },
  {
    name: 'valid_64kb_body',
    secret: SECRET_A,
    kid: KID_A,
    body: BODY_64KB,
    t: T0,
    n: NONCE_FIXED,
    desc: '65536-byte ASCII body.',
  },
  {
    name: 'valid_binary_body',
    secret: SECRET_A,
    kid: KID_A,
    body: BODY_BINARY,
    t: T0,
    n: NONCE_FIXED,
    desc: 'Body is bytes 0x00..0xff -- proves canonical string is byte-exact.',
  },
  {
    name: 'valid_raw32_secret',
    secret: SECRET_RAW32,
    kid: KID_A,
    body: BODY_HELLO,
    t: T0,
    n: NONCE_FIXED,
    desc: '32-byte raw-bytes secret (NUL bytes inclusive).',
  },
  {
    name: 'valid_short_secret',
    secret: SECRET_RAW16,
    kid: KID_A,
    body: BODY_HELLO,
    t: T0,
    n: NONCE_FIXED,
    desc: '16-byte raw-bytes secret.',
  },
  {
    name: 'valid_kid_b',
    secret: SECRET_B,
    kid: KID_B,
    body: BODY_LARGE_JSON,
    t: T0,
    n: NONCE_FIXED,
    desc: 'Different kid + secret pair; receiver must select by kid.',
  },
  {
    name: 'valid_at_window_edge_minus',
    secret: SECRET_A,
    kid: KID_A,
    body: BODY_HELLO,
    t: T0 - 300,
    n: NONCE_FIXED,
    desc: 'Timestamp exactly 300s old; default window allows it.',
  },
];

for (const v of valids) {
  vectors.push({
    name: v.name,
    description: v.desc,
    secret_hex: v.secret.toString('hex'),
    kid: v.kid,
    body_hex: v.body.toString('hex'),
    timestamp: v.t,
    nonce_b64url: v.n,
    now: T0,
    expected_signature_hex: computeV1(v.secret, v.t, v.body),
    expected_verify: 'ok',
  });
}

// ---------------------------------------------------------------------------
// Category 2: 10 invalid HMAC
// ---------------------------------------------------------------------------

// 2a: tampered body (signature computed over body X, header presents body Y)
{
  const realSig = computeV1(SECRET_A, T0, BODY_HELLO);
  const tamperedBody = Buffer.from('{"hello":"WORLD"}', 'utf8'); // capital
  vectors.push({
    name: 'invalid_tampered_body_capitalized',
    description: 'Signature was generated for {"hello":"world"} but body delivered is {"hello":"WORLD"}.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: tamperedBody.toString('hex'),
    timestamp: T0,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: realSig,
    expected_verify: { error: 'bad_hmac' },
  });
}

// 2b: tampered body (one byte changed)
{
  const realSig = computeV1(SECRET_A, T0, BODY_BINARY);
  const tamperedBody = Buffer.from(BODY_BINARY);
  tamperedBody[42] = 0xff;
  vectors.push({
    name: 'invalid_tampered_body_one_byte',
    description: 'Single byte at offset 42 changed after signing.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: tamperedBody.toString('hex'),
    timestamp: T0,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: realSig,
    expected_verify: { error: 'bad_hmac' },
  });
}

// 2c: tampered body (truncated)
{
  const realSig = computeV1(SECRET_A, T0, BODY_LARGE_JSON);
  const tamperedBody = BODY_LARGE_JSON.subarray(0, BODY_LARGE_JSON.length - 1);
  vectors.push({
    name: 'invalid_truncated_body',
    description: 'Last byte of body removed after signing.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: tamperedBody.toString('hex'),
    timestamp: T0,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: realSig,
    expected_verify: { error: 'bad_hmac' },
  });
}

// 2d: extended body
{
  const realSig = computeV1(SECRET_A, T0, BODY_HELLO);
  const tamperedBody = Buffer.concat([BODY_HELLO, Buffer.from(' ', 'utf8')]);
  vectors.push({
    name: 'invalid_extended_body',
    description: 'Trailing space appended to body after signing.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: tamperedBody.toString('hex'),
    timestamp: T0,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: realSig,
    expected_verify: { error: 'bad_hmac' },
  });
}

// 2e: wrong secret (header signed with B, receiver knows only A)
{
  const wrongSig = computeV1(SECRET_B, T0, BODY_HELLO);
  vectors.push({
    name: 'invalid_wrong_secret_same_kid',
    description: 'Signature was computed with SECRET_B, but receiver only has SECRET_A under this kid.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: T0,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: wrongSig,
    expected_verify: { error: 'bad_hmac' },
  });
}

// 2f: garbage signature (right shape, wrong hex)
vectors.push({
  name: 'invalid_garbage_signature',
  description: 'Signature is 64 lowercase hex but unrelated to body.',
  secret_hex: SECRET_A.toString('hex'),
  kid: KID_A,
  body_hex: BODY_HELLO.toString('hex'),
  timestamp: T0,
  nonce_b64url: NONCE_FIXED,
  now: T0,
  presented_signature_hex: 'deadbeef'.repeat(8),
  expected_verify: { error: 'bad_hmac' },
});

// 2g: timestamp mismatch (header has t=T0+1 but signature computed with t=T0)
{
  const sigForT0 = computeV1(SECRET_A, T0, BODY_HELLO);
  vectors.push({
    name: 'invalid_signature_timestamp_drift',
    description: 'Signature was computed with timestamp T0 but header carries t=T0+1.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: T0 + 1,
    nonce_b64url: NONCE_FIXED,
    now: T0 + 1,
    presented_signature_hex: sigForT0,
    expected_verify: { error: 'bad_hmac' },
  });
}

// 2h: unknown kid (header kid doesn't match any known secret)
{
  const realSig = computeV1(SECRET_A, T0, BODY_HELLO);
  vectors.push({
    name: 'invalid_unknown_kid',
    description: 'Header carries kid=k_unknown_2099; receiver does not have it.',
    secret_hex: SECRET_A.toString('hex'),
    kid: 'k_unknown_2099',
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: T0,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: realSig,
    expected_verify: { error: 'unknown_kid' },
    receiver_known_kid: KID_A,
  });
}

// 2i: bit-flipped signature
{
  const realSig = computeV1(SECRET_A, T0, BODY_HELLO);
  const flipped = realSig.slice(0, -1) + (realSig.endsWith('0') ? '1' : '0');
  vectors.push({
    name: 'invalid_signature_last_nibble_flipped',
    description: 'Last hex nibble of valid signature flipped to a different value.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: T0,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: flipped,
    expected_verify: { error: 'bad_hmac' },
  });
}

// 2j: kid swapped (both kids known but secret presented for the wrong slot)
{
  const sigB = computeV1(SECRET_B, T0, BODY_HELLO);
  vectors.push({
    name: 'invalid_kid_swap',
    description:
      'Signature computed with SECRET_B but header carries kid for SECRET_A. Multi-kid receiver still rejects.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: T0,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: sigB,
    expected_verify: { error: 'bad_hmac' },
  });
}

// ---------------------------------------------------------------------------
// Category 3: 10 timestamp issues
// ---------------------------------------------------------------------------

// 3a: stale, just past 300s
{
  const t = T0 - 301;
  const sig = computeV1(SECRET_A, t, BODY_HELLO);
  vectors.push({
    name: 'invalid_stale_301s',
    description: 'Timestamp 301 seconds in the past -- 1s past default window.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: t,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: sig,
    expected_verify: { error: 'stale' },
  });
}

// 3b: stale, 1 hour
{
  const t = T0 - 3600;
  const sig = computeV1(SECRET_A, t, BODY_HELLO);
  vectors.push({
    name: 'invalid_stale_one_hour',
    description: 'Timestamp 3600s old.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: t,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: sig,
    expected_verify: { error: 'stale' },
  });
}

// 3c: stale, far past
{
  const t = T0 - 86400;
  const sig = computeV1(SECRET_A, t, BODY_HELLO);
  vectors.push({
    name: 'invalid_stale_one_day',
    description: 'Timestamp 86400s old.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: t,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: sig,
    expected_verify: { error: 'stale' },
  });
}

// 3d: future, just past +300s
{
  const t = T0 + 301;
  const sig = computeV1(SECRET_A, t, BODY_HELLO);
  vectors.push({
    name: 'invalid_future_301s',
    description: 'Timestamp 301 seconds in the future.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: t,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: sig,
    expected_verify: { error: 'future' },
  });
}

// 3e: future, far ahead
{
  const t = T0 + 86400;
  const sig = computeV1(SECRET_A, t, BODY_HELLO);
  vectors.push({
    name: 'invalid_future_one_day',
    description: 'Timestamp 86400s in the future.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: t,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: sig,
    expected_verify: { error: 'future' },
  });
}

// 3f: edge minus 300 exact (allowed)
{
  const t = T0 - 300;
  const sig = computeV1(SECRET_A, t, BODY_HELLO);
  vectors.push({
    name: 'valid_edge_minus_300_exact',
    description: 'Timestamp exactly 300s in the past -- on the boundary, accepted.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: t,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    expected_signature_hex: sig,
    expected_verify: 'ok',
  });
}

// 3g: edge plus 300 exact (allowed)
{
  const t = T0 + 300;
  const sig = computeV1(SECRET_A, t, BODY_HELLO);
  vectors.push({
    name: 'valid_edge_plus_300_exact',
    description: 'Timestamp exactly 300s in the future -- on the boundary, accepted.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: t,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    expected_signature_hex: sig,
    expected_verify: 'ok',
  });
}

// 3h: minimum window 60s -- with default 300 should be valid; receivers running 60s window would reject
{
  const t = T0 - 120;
  const sig = computeV1(SECRET_A, t, BODY_HELLO);
  vectors.push({
    name: 'valid_120s_old_default_window',
    description:
      'Timestamp 120s old. Valid under default 300s window. (Receivers running tighter 60s window would reject; not tested here.)',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: t,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    expected_signature_hex: sig,
    expected_verify: 'ok',
  });
}

// 3i: epoch zero (clearly stale relative to T0)
{
  const t = 0;
  const sig = computeV1(SECRET_A, t, BODY_HELLO);
  vectors.push({
    name: 'invalid_timestamp_epoch_zero',
    description: 'Timestamp = 0 (Unix epoch). Stale.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: t,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: sig,
    expected_verify: { error: 'stale' },
  });
}

// 3j: way-future
{
  const t = T0 + 10 * 365 * 86400;
  const sig = computeV1(SECRET_A, t, BODY_HELLO);
  vectors.push({
    name: 'invalid_timestamp_ten_years_future',
    description: 'Timestamp 10 years in the future.',
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: t,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    presented_signature_hex: sig,
    expected_verify: { error: 'future' },
  });
}

// ---------------------------------------------------------------------------
// Category 4: 10 replay
//
// Each replay vector has `replay_setup` -- nonces to pre-populate the replay
// store before verifying. Implementations replay-test by seeding the store,
// then running verify, expecting `replayed`.
// ---------------------------------------------------------------------------

const replayCases = [
  {
    name: 'replay_simple',
    body: BODY_HELLO,
    n: NONCE_FIXED,
    t: T0,
    kid: KID_A,
    secret: SECRET_A,
    desc: 'Same nonce already seen. Reject.',
  },
  {
    name: 'replay_same_nonce_different_body',
    body: BODY_LARGE_JSON,
    n: NONCE_FIXED,
    t: T0,
    kid: KID_A,
    secret: SECRET_A,
    desc: 'Different body but nonce reused. Reject.',
  },
  {
    name: 'replay_same_nonce_different_kid',
    body: BODY_HELLO,
    n: NONCE_FIXED,
    t: T0,
    kid: KID_B,
    secret: SECRET_B,
    desc: 'Same nonce as previous delivery, different kid. Reject -- nonce uniqueness is global, not kid-scoped.',
  },
  {
    name: 'replay_nonce_2',
    body: BODY_HELLO,
    n: NONCE_2,
    t: T0,
    kid: KID_A,
    secret: SECRET_A,
    desc: 'Different nonce, also seeded. Reject.',
  },
  {
    name: 'replay_nonce_3',
    body: BODY_HELLO,
    n: NONCE_3,
    t: T0,
    kid: KID_A,
    secret: SECRET_A,
    desc: 'Third reused nonce. Reject.',
  },
  {
    name: 'replay_at_minus_300',
    body: BODY_HELLO,
    n: NONCE_FIXED,
    t: T0 - 300,
    kid: KID_A,
    secret: SECRET_A,
    desc: 'Replay at the oldest timestamp the window admits. Still rejected by nonce check.',
  },
  {
    name: 'replay_with_utf8_body',
    body: BODY_UTF8,
    n: NONCE_FIXED,
    t: T0,
    kid: KID_A,
    secret: SECRET_A,
    desc: 'UTF-8 body, replayed nonce.',
  },
  {
    name: 'replay_with_64kb_body',
    body: BODY_64KB,
    n: NONCE_FIXED,
    t: T0,
    kid: KID_A,
    secret: SECRET_A,
    desc: '64KB body, replayed nonce. Replay check happens AFTER HMAC, so cost is full HMAC + storage hit.',
  },
  {
    name: 'replay_with_binary_body',
    body: BODY_BINARY,
    n: NONCE_FIXED,
    t: T0,
    kid: KID_A,
    secret: SECRET_A,
    desc: 'Binary body, replayed nonce.',
  },
  {
    name: 'replay_with_kid_b',
    body: BODY_HELLO,
    n: NONCE_FIXED,
    t: T0,
    kid: KID_B,
    secret: SECRET_B,
    desc: 'Replay using a different (valid) kid; nonce check is kid-agnostic.',
  },
];

for (const r of replayCases) {
  vectors.push({
    name: r.name,
    description: r.desc,
    secret_hex: r.secret.toString('hex'),
    kid: r.kid,
    body_hex: r.body.toString('hex'),
    timestamp: r.t,
    nonce_b64url: r.n,
    now: T0,
    presented_signature_hex: computeV1(r.secret, r.t, r.body),
    replay_setup: { seed_nonces: [r.n] },
    expected_verify: { error: 'replayed' },
  });
}

// ---------------------------------------------------------------------------
// Category 5: 10 malformed headers
// ---------------------------------------------------------------------------

const sigGood = computeV1(SECRET_A, T0, BODY_HELLO);

const malformeds = [
  {
    name: 'malformed_missing_t',
    description: 'Header has no t= field.',
    raw_header: `v1=${sigGood},n=${NONCE_FIXED},kid=${KID_A}`,
    error: 'malformed_header',
  },
  {
    name: 'malformed_missing_v1',
    description: 'Header has no v1= field; receiver also does not understand any vN= present.',
    raw_header: `t=${T0},n=${NONCE_FIXED},kid=${KID_A}`,
    error: 'malformed_header',
  },
  {
    name: 'malformed_missing_nonce',
    description: 'Header has no n= field.',
    raw_header: `t=${T0},v1=${sigGood},kid=${KID_A}`,
    error: 'malformed_header',
  },
  {
    name: 'malformed_missing_kid',
    description: 'Header has no kid= field. v1 mandates kid; receivers MUST reject.',
    raw_header: `t=${T0},v1=${sigGood},n=${NONCE_FIXED}`,
    error: 'malformed_header',
  },
  {
    name: 'malformed_garbage',
    description: 'Header is not even a list of pairs.',
    raw_header: 'this is not a signature header',
    error: 'malformed_header',
  },
  {
    name: 'malformed_v1_not_hex',
    description: 'v1= value contains non-hex characters.',
    raw_header: `t=${T0},v1=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz,n=${NONCE_FIXED},kid=${KID_A}`,
    error: 'malformed_header',
  },
  {
    name: 'malformed_v1_uppercase_hex',
    description: 'v1= value uses uppercase hex (spec mandates lowercase).',
    raw_header: `t=${T0},v1=${sigGood.toUpperCase()},n=${NONCE_FIXED},kid=${KID_A}`,
    error: 'malformed_header',
  },
  {
    name: 'malformed_unknown_algorithm_only',
    description: 'Header carries v99= but no v1=.',
    raw_header: `t=${T0},v99=somefuture,n=${NONCE_FIXED},kid=${KID_A}`,
    error: 'unknown_algorithm',
  },
  {
    name: 'malformed_negative_timestamp',
    description: 'Timestamp is negative.',
    raw_header: `t=-1,v1=${sigGood},n=${NONCE_FIXED},kid=${KID_A}`,
    error: 'malformed_header',
  },
  {
    name: 'malformed_empty_header',
    description: 'Empty string header.',
    raw_header: '',
    error: 'malformed_header',
  },
];

for (const m of malformeds) {
  vectors.push({
    name: m.name,
    description: m.description,
    raw_signature_header: m.raw_header,
    secret_hex: SECRET_A.toString('hex'),
    kid: KID_A,
    body_hex: BODY_HELLO.toString('hex'),
    timestamp: T0,
    nonce_b64url: NONCE_FIXED,
    now: T0,
    expected_verify: { error: m.error },
    ...(m.note ? { note: m.note } : {}),
  });
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

const out = {
  spec: 'AWSP v1',
  description:
    'Test vectors for the AWSP signing/verification algorithm. body_hex is hex of the raw body bytes; secret_hex is hex of the raw secret bytes; signature is HMAC-SHA256 over `<timestamp>.<body-bytes>` -- timestamp formatted as decimal ASCII, body bytes appended verbatim. Outputs are lowercase hex.',
  reference_timestamp_iso: '2026-05-02T00:00:00Z',
  reference_timestamp_unix: T0,
  default_replay_window_seconds: 300,
  vector_count: vectors.length,
  vectors,
};

writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`);
console.log(`wrote ${outPath} -- ${vectors.length} vectors`);
