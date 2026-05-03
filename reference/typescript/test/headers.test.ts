import assert from 'node:assert/strict';
import test from 'node:test';
import { HeaderParseError, parseSignatureHeader, serializeSignatureHeader } from '../src/headers.js';
import { timingSafeEqualHex } from '../src/timing-safe-equal.js';

const VALID_HEX = 'a'.repeat(64);

test('parse: minimal valid', () => {
  const p = parseSignatureHeader(`t=1777248000,v1=${VALID_HEX},n=AAAA,kid=k_x`);
  assert.equal(p.timestamp, 1777248000);
  assert.deepEqual(p.v1, [VALID_HEX]);
  assert.equal(p.nonce, 'AAAA');
  assert.equal(p.kid, 'k_x');
});

test('parse: field order does not matter', () => {
  const p = parseSignatureHeader(`kid=k,n=N,v1=${VALID_HEX},t=1`);
  assert.equal(p.timestamp, 1);
  assert.equal(p.kid, 'k');
});

test('parse: multiple v1 values', () => {
  const a = 'a'.repeat(64);
  const b = 'b'.repeat(64);
  const p = parseSignatureHeader(`t=1,v1=${a},v1=${b},n=N,kid=k`);
  assert.deepEqual(p.v1, [a, b]);
});

test('parse: missing kid => malformed_header', () => {
  assert.throws(
    () => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=N`),
    (err) => err instanceof HeaderParseError && err.reason === 'malformed_header',
  );
});

test('parse: unknown vN ignored when v1 also present', () => {
  const p = parseSignatureHeader(`t=1,v1=${VALID_HEX},v2=anything,n=N,kid=k`);
  assert.deepEqual(p.v1, [VALID_HEX]);
});

test('parse: only future-version signature => unknown_algorithm', () => {
  assert.throws(
    () => parseSignatureHeader('t=1,v99=foo,n=N,kid=k'),
    (err) => err instanceof HeaderParseError && err.reason === 'unknown_algorithm',
  );
});

test('parse: missing t => missing_timestamp', () => {
  assert.throws(
    () => parseSignatureHeader(`v1=${VALID_HEX},n=N,kid=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'missing_timestamp',
  );
});

test('parse: missing v1 => missing_signature', () => {
  assert.throws(
    () => parseSignatureHeader('t=1,n=N,kid=k'),
    (err) => err instanceof HeaderParseError && err.reason === 'missing_signature',
  );
});

test('parse: missing nonce => missing_nonce', () => {
  assert.throws(
    () => parseSignatureHeader(`t=1,v1=${VALID_HEX},kid=k`),
    (err) => err instanceof HeaderParseError && err.reason === 'missing_nonce',
  );
});

test('parse: bad pair => malformed_header', () => {
  assert.throws(() => parseSignatureHeader('garbage'));
  assert.throws(() => parseSignatureHeader('=value'));
  assert.throws(() => parseSignatureHeader('key='));
});

test('parse: empty header => malformed_header', () => {
  assert.throws(() => parseSignatureHeader(''));
});

test('parse: oversize header => malformed_header', () => {
  assert.throws(() => parseSignatureHeader(`t=1,v1=${'a'.repeat(64)}${','.repeat(5000)}`));
});

test('parse: uppercase hex rejected', () => {
  assert.throws(() => parseSignatureHeader(`t=1,v1=${'A'.repeat(64)},n=N,kid=k`));
});

test('parse: bad nonce charset rejected', () => {
  assert.throws(() => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=has space,kid=k`));
});

test('parse: bad kid charset rejected', () => {
  assert.throws(() => parseSignatureHeader(`t=1,v1=${VALID_HEX},n=N,kid=has space`));
});

test('parse: duplicate t rejected', () => {
  assert.throws(() => parseSignatureHeader(`t=1,t=2,v1=${VALID_HEX},n=N,kid=k`));
});

test('parse: negative timestamp rejected', () => {
  assert.throws(() => parseSignatureHeader(`t=-5,v1=${VALID_HEX},n=N,kid=k`));
});

test('serialize round-trip', () => {
  const original = `t=1,v1=${VALID_HEX},n=N,kid=k`;
  const reparsed = parseSignatureHeader(original);
  assert.equal(serializeSignatureHeader(reparsed), original);
});

test('serialize: kid always emitted', () => {
  const s = serializeSignatureHeader({
    timestamp: 1,
    v1: [VALID_HEX],
    nonce: 'N',
    kid: 'k_required',
  });
  assert.equal(s, `t=1,v1=${VALID_HEX},n=N,kid=k_required`);
});

// ---------------------------------------------------------------------------
// timing-safe-equal
// ---------------------------------------------------------------------------

test('timingSafeEqualHex: equal values', () => {
  assert.equal(timingSafeEqualHex('deadbeef', 'deadbeef'), true);
});

test('timingSafeEqualHex: unequal values', () => {
  assert.equal(timingSafeEqualHex('deadbeef', 'deadbeee'), false);
});

test('timingSafeEqualHex: different lengths => false', () => {
  assert.equal(timingSafeEqualHex('deadbeef', 'deadbeefab'), false);
});

test('timingSafeEqualHex: rejects uppercase / non-hex', () => {
  assert.equal(timingSafeEqualHex('DEADBEEF', 'deadbeef'), false);
  assert.equal(timingSafeEqualHex('zzzzzzzz', 'zzzzzzzz'), false);
});

test('timingSafeEqualHex: empty strings equal', () => {
  assert.equal(timingSafeEqualHex('', ''), true);
});

test('timingSafeEqualHex: non-string arguments => false', () => {
  // intentional bad cast to test runtime guard
  assert.equal(timingSafeEqualHex(undefined as unknown as string, ''), false);
});
