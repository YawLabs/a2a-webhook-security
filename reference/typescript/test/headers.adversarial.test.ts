// Adversarial / fuzz tests for parseSignatureHeader.
//
// Goal: prove the parser never crashes on hostile input and that every
// stated reason code is reachable. The fuzz loop uses a seeded mulberry32
// PRNG (no deps, deterministic across runs / CI / language ports).

import assert from 'node:assert/strict';
import test from 'node:test';
import { HeaderParseError, parseSignatureHeader } from '../src/headers.js';

const VALID_HEX = 'a'.repeat(64);

// ---------------------------------------------------------------------------
// Mulberry32 -- 32-bit seedable PRNG. Public domain. ~5 lines.
// ---------------------------------------------------------------------------

function mulberry32(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---------------------------------------------------------------------------
// Fuzz: 1000 iterations of random-byte input
// ---------------------------------------------------------------------------

test('parser fuzz: 1000 random-byte inputs never crash', () => {
  const rand = mulberry32(0x42424242);
  for (let i = 0; i < 1000; i++) {
    const len = Math.floor(rand() * 200); // 0..199 bytes
    let raw = '';
    for (let j = 0; j < len; j++) {
      // Span the full ASCII range plus a few high-bit chars to stress UTF-8.
      const code = Math.floor(rand() * 256);
      raw += String.fromCharCode(code);
    }
    try {
      const parsed = parseSignatureHeader(raw);
      // If it accepted, must have all required fields populated.
      assert.equal(typeof parsed.timestamp, 'number');
      assert.ok(Array.isArray(parsed.v1));
      assert.ok(parsed.v1.length >= 1);
      assert.equal(typeof parsed.nonce, 'string');
      assert.equal(typeof parsed.kid, 'string');
    } catch (err) {
      // Only HeaderParseError is acceptable.
      assert.ok(
        err instanceof HeaderParseError,
        `iteration ${i}: unexpected throw type ${err?.constructor?.name}: ${(err as Error).message}\nInput: ${JSON.stringify(raw)}`,
      );
    }
  }
});

test('parser fuzz: 1000 plausibly-shaped inputs (varied separators, fields)', () => {
  // A second fuzz pass that biases toward "looks-like-a-header" inputs --
  // random combinations of valid-ish field tokens with random separators
  // and ordering. Stresses the parser's structural handling more than the
  // pure-random pass.
  const rand = mulberry32(0xdeadbeef);
  const tokens = [
    't=1',
    't=99999999',
    't=-5',
    't=abc',
    't=', // bare equals
    `v1=${VALID_HEX}`,
    `v1=${'A'.repeat(64)}`, // uppercase
    `v1=${'a'.repeat(63)}`, // wrong length
    `v1=${'g'.repeat(64)}`, // non-hex
    'v2=anything',
    'v99=foo',
    'n=AAAA',
    'n=', // bare equals
    'n=has space',
    'kid=k',
    'kid=',
    'kid=has space',
    '=value',
    'key=',
    'garbage',
    '',
  ];
  for (let i = 0; i < 1000; i++) {
    const fields: string[] = [];
    const count = 1 + Math.floor(rand() * 6);
    for (let j = 0; j < count; j++) {
      fields.push(tokens[Math.floor(rand() * tokens.length)] as string);
    }
    const raw = fields.join(',');
    try {
      parseSignatureHeader(raw);
    } catch (err) {
      assert.ok(
        err instanceof HeaderParseError,
        `iteration ${i}: unexpected throw on ${JSON.stringify(raw)}: ${(err as Error).message}`,
      );
    }
  }
});

// ---------------------------------------------------------------------------
// Truncation: every byte boundary of a valid header
// ---------------------------------------------------------------------------

test('parser: truncation at every byte boundary throws HeaderParseError', () => {
  const valid = `t=1777248000,v1=${VALID_HEX},n=AAAA,kid=k_x`;
  // Truncating off the end produces incrementally shorter strings; every
  // one of them must either parse cleanly or throw HeaderParseError -- never
  // a TypeError, RangeError, or other runtime crash.
  for (let i = 0; i < valid.length; i++) {
    const truncated = valid.slice(0, i);
    try {
      parseSignatureHeader(truncated);
    } catch (err) {
      assert.ok(
        err instanceof HeaderParseError,
        `truncation len=${i} ${JSON.stringify(truncated)} threw ${err?.constructor?.name}`,
      );
    }
  }
});

// ---------------------------------------------------------------------------
// Oversized headers
// ---------------------------------------------------------------------------

test('parser: header >4096 bytes => malformed_header', () => {
  const padding = ',junk=value'.repeat(500); // ~5000 bytes
  const raw = `t=1,v1=${VALID_HEX},n=N,kid=k${padding}`;
  assert.ok(raw.length > 4096);
  assert.throws(
    () => parseSignatureHeader(raw),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

test('parser: header at exactly 4096 bytes parses if valid', () => {
  const base = `t=1,v1=${VALID_HEX},n=N,kid=k`;
  const slack = 4096 - base.length;
  // Pad with comma-separated unknown fields up to the boundary.
  const filler = `,x=${'a'.repeat(slack - 3)}`;
  const raw = base + filler;
  assert.equal(raw.length, 4096);
  const p = parseSignatureHeader(raw);
  assert.equal(p.timestamp, 1);
});

test('parser: header at exactly 4097 bytes => malformed_header', () => {
  const base = `t=1,v1=${VALID_HEX},n=N,kid=k`;
  const slack = 4097 - base.length;
  const filler = `,x=${'a'.repeat(slack - 3)}`;
  const raw = base + filler;
  assert.equal(raw.length, 4097);
  assert.throws(
    () => parseSignatureHeader(raw),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

// ---------------------------------------------------------------------------
// Duplicate fields
// ---------------------------------------------------------------------------

test('parser: duplicate t= rejected as malformed_header', () => {
  assert.throws(
    () => parseSignatureHeader(`t=1,t=2,v1=${VALID_HEX},n=N,kid=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

test('parser: duplicate n= rejected as malformed_header', () => {
  assert.throws(
    () => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=A,n=B,kid=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

test('parser: duplicate kid= rejected as malformed_header', () => {
  assert.throws(
    () => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=N,kid=a,kid=b`),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

test('parser: multiple v1= are accumulated, not deduplicated', () => {
  const a = 'a'.repeat(64);
  const b = 'b'.repeat(64);
  const c = 'c'.repeat(64);
  const p = parseSignatureHeader(`t=1,v1=${a},v1=${b},v1=${c},n=N,kid=k`);
  assert.deepEqual(p.v1, [a, b, c]);
});

test('parser: same v1= value twice still appears twice (no dedup)', () => {
  const p = parseSignatureHeader(`t=1,v1=${VALID_HEX},v1=${VALID_HEX},n=N,kid=k`);
  assert.equal(p.v1.length, 2);
});

// ---------------------------------------------------------------------------
// Mixed case in field keys
// ---------------------------------------------------------------------------

test('parser: uppercase T= not recognized as t= (missing_timestamp)', () => {
  assert.throws(
    () => parseSignatureHeader(`T=1,v1=${VALID_HEX},n=N,kid=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'missing_timestamp',
  );
});

test('parser: uppercase N= not recognized as n= (missing_nonce)', () => {
  assert.throws(
    () => parseSignatureHeader(`t=1,v1=${VALID_HEX},N=N,kid=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'missing_nonce',
  );
});

test('parser: uppercase KID= not recognized as kid= (malformed_header)', () => {
  assert.throws(
    () => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=N,KID=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

test('parser: uppercase V1= not recognized as v1= (missing_signature)', () => {
  // V1= falls through to "unknown field, ignore" -- no v1= present, so
  // missing_signature is the right outcome.
  assert.throws(
    () => parseSignatureHeader(`t=1,V1=${VALID_HEX},n=N,kid=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'missing_signature',
  );
});

// ---------------------------------------------------------------------------
// Whitespace / non-printables in values
// ---------------------------------------------------------------------------

test('parser: leading/trailing whitespace on key/value tolerated', () => {
  // The parser .trim()s both key and value -- so " t = 1 " is equivalent to "t=1".
  const p = parseSignatureHeader(` t=1 , v1=${VALID_HEX} , n=N , kid=k `);
  assert.equal(p.timestamp, 1);
  assert.equal(p.kid, 'k');
});

test('parser: tab character inside value violates charset rules', () => {
  // \t between two valid kid chars passes the trim but fails the kid charset check.
  assert.throws(() => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=N,kid=a\tb`));
});

test('parser: NUL byte in value rejected', () => {
  assert.throws(() => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=A\0B,kid=k`));
});

test('parser: high-bit byte in value rejected', () => {
  assert.throws(() => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=AÿB,kid=k`));
});

// ---------------------------------------------------------------------------
// Timestamp edge cases
// ---------------------------------------------------------------------------

test('parser: timestamp >15 digits rejected (post-Number.MAX_SAFE_INTEGER)', () => {
  assert.throws(
    () => parseSignatureHeader(`t=9999999999999999,v1=${VALID_HEX},n=N,kid=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

test('parser: timestamp with 16+ digits rejected', () => {
  assert.throws(() =>
    parseSignatureHeader(`t=12345678901234567890,v1=${VALID_HEX},n=N,kid=k`),
  );
});

test('parser: negative timestamp rejected', () => {
  assert.throws(
    () => parseSignatureHeader(`t=-1,v1=${VALID_HEX},n=N,kid=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

test('parser: leading zero timestamp value parses to the integer (no octal)', () => {
  // 015 would be octal 13 in C; JS parseInt(s, 10) reads it as 15. The
  // intent here is "decimal ASCII, no surprises". /^[0-9]{1,15}$/ allows
  // leading zeros, so this parses; just verify no octal interpretation.
  const p = parseSignatureHeader(`t=015,v1=${VALID_HEX},n=N,kid=k`);
  assert.equal(p.timestamp, 15);
});

test('parser: non-digit characters in timestamp rejected', () => {
  assert.throws(() => parseSignatureHeader(`t=12a4,v1=${VALID_HEX},n=N,kid=k`));
  assert.throws(() => parseSignatureHeader(`t=1.5,v1=${VALID_HEX},n=N,kid=k`));
  assert.throws(() => parseSignatureHeader(`t=+1,v1=${VALID_HEX},n=N,kid=k`));
  assert.throws(() => parseSignatureHeader(`t=1e3,v1=${VALID_HEX},n=N,kid=k`));
});

// ---------------------------------------------------------------------------
// Empty values, bare keys, bare equals
// ---------------------------------------------------------------------------

test('parser: bare = (no key, no value) rejected', () => {
  assert.throws(() => parseSignatureHeader('='));
});

test('parser: key= with empty value rejected', () => {
  assert.throws(() => parseSignatureHeader('t='));
  assert.throws(() => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=N,kid=`));
});

test('parser: =value (no key) rejected', () => {
  assert.throws(() => parseSignatureHeader('=value'));
});

test('parser: bare key with no = rejected', () => {
  assert.throws(() => parseSignatureHeader('garbage'));
  assert.throws(() => parseSignatureHeader(`t=1,garbage,v1=${VALID_HEX},n=N,kid=k`));
});

test('parser: empty header rejected', () => {
  assert.throws(() => parseSignatureHeader(''));
});

test('parser: whitespace-only header rejected', () => {
  assert.throws(() => parseSignatureHeader('   '));
});

// ---------------------------------------------------------------------------
// Reachability of every reason code
// ---------------------------------------------------------------------------

test('reason code reachable: malformed_header (empty header)', () => {
  assert.throws(
    () => parseSignatureHeader(''),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

test('reason code reachable: malformed_header (oversize)', () => {
  assert.throws(
    () => parseSignatureHeader('a'.repeat(5000)),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

test('reason code reachable: missing_timestamp', () => {
  assert.throws(
    () => parseSignatureHeader(`v1=${VALID_HEX},n=N,kid=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'missing_timestamp',
  );
});

test('reason code reachable: missing_signature', () => {
  assert.throws(
    () => parseSignatureHeader('t=1,n=N,kid=k'),
    (err) => err instanceof HeaderParseError && err.reason === 'missing_signature',
  );
});

test('reason code reachable: missing_nonce', () => {
  assert.throws(
    () => parseSignatureHeader(`t=1,v1=${VALID_HEX},kid=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'missing_nonce',
  );
});

test('reason code reachable: unknown_algorithm', () => {
  assert.throws(
    () => parseSignatureHeader('t=1,v99=anything,n=N,kid=k'),
    (err) => err instanceof HeaderParseError && err.reason === 'unknown_algorithm',
  );
});

test('reason code reachable: malformed_header (missing kid)', () => {
  // kid= is required in v1; absence is malformed_header (not a missing_kid code).
  assert.throws(
    () => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=N`),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

// ---------------------------------------------------------------------------
// unknown_algorithm precedence: if BOTH v1= and unknown vN= present, v1 wins
// ---------------------------------------------------------------------------

test('parser: v1= + v99= present => parses (v99 ignored, no unknown_algorithm)', () => {
  const p = parseSignatureHeader(`t=1,v1=${VALID_HEX},v99=ignored,n=N,kid=k`);
  assert.deepEqual(p.v1, [VALID_HEX]);
});

test('parser: only v0= (zero, not v1) => unknown_algorithm', () => {
  // v0 is a valid /^v[0-9]+$/ match but != "v1" so it's treated as unknown.
  assert.throws(
    () => parseSignatureHeader('t=1,v0=anything,n=N,kid=k'),
    (err) => err instanceof HeaderParseError && err.reason === 'unknown_algorithm',
  );
});

// ---------------------------------------------------------------------------
// kid charset: explicit allow / deny boundary
// ---------------------------------------------------------------------------

test('parser: kid with all allowed chars (alphanumerics + . _ -) accepted', () => {
  const kid = 'k_2026.05-AB';
  const p = parseSignatureHeader(`t=1,v1=${VALID_HEX},n=N,kid=${kid}`);
  assert.equal(p.kid, kid);
});

test('parser: kid with disallowed char (slash) rejected', () => {
  assert.throws(() => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=N,kid=a/b`));
});

test('parser: kid >128 chars rejected', () => {
  const kid = 'a'.repeat(129);
  assert.throws(() => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=N,kid=${kid}`));
});

test('parser: nonce >256 chars rejected', () => {
  const nonce = 'A'.repeat(257);
  assert.throws(() => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=${nonce},kid=k`));
});

test('parser: nonce with all allowed base64url chars accepted', () => {
  const nonce = 'AZaz09_-';
  const p = parseSignatureHeader(`t=1,v1=${VALID_HEX},n=${nonce},kid=k`);
  assert.equal(p.nonce, nonce);
});

test('parser: nonce with padding (=) rejected (spec requires unpadded)', () => {
  assert.throws(() => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=AAAA==,kid=k`));
});
