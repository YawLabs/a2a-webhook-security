// AWSP -- A2A Webhook Security Profile reference implementation.
//
// This module implements the v1 signing/verification algorithm defined in
// SPEC.md at the package root. It is dependency-free (Node built-in crypto)
// and has no I/O of its own; replay storage is a hook supplied by the caller.
//
// See SPEC.md for the wire format. Test vectors are at test-vectors.json.

import { createHmac, randomBytes } from 'node:crypto';
import { HeaderParseError, parseSignatureHeader, serializeSignatureHeader } from './headers.js';
import { timingSafeEqualHex } from './timing-safe-equal.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** A (kid, secret) pair the receiver knows about. */
export interface SecretEntry {
  /** Key identifier matching the kid= field on incoming signatures. */
  kid: string;
  /** Raw secret bytes. */
  secret: Uint8Array;
}

/** Headers produced by sign(). All values are strings, suitable for HTTP. */
export interface SignedHeaders {
  'X-A2A-Signature': string;
  'X-A2A-Webhook-Id': string;
  'X-A2A-Event-Type': string;
  'X-A2A-Timestamp': string;
}

/** Input to sign(). */
export interface SignOptions {
  /** Raw secret bytes. The shared HMAC key. */
  secret: Uint8Array;
  /** Identifier for this secret -- placed in the kid= field. */
  keyId: string;
  /** Raw payload bytes. The HMAC is computed over `<timestamp>.<body-bytes>`. */
  body: Uint8Array;
  /** Event type label, placed in X-A2A-Event-Type. */
  eventType: string;
  /** Optional UUID for the delivery. Defaults to a generated UUIDv4. */
  webhookId?: string;
  /** Optional unix-seconds timestamp. Defaults to Math.floor(Date.now()/1000). */
  timestamp?: number;
  /** Optional base64url nonce. Defaults to 18 random bytes => 24-char nonce. */
  nonce?: string;
}

/** Replay-protection storage hook. Returns true if the nonce was unseen. */
export interface ReplayStore {
  /**
   * Atomically: if the nonce has been seen within `ttlSeconds`, return false.
   * Otherwise record the nonce with TTL = ttlSeconds and return true.
   *
   * Implementations include Redis SETEX-NX, Memcached add, or an in-memory
   * Map for tests. Storage MUST be shared across receiver replicas.
   */
  checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean>;
}

/** Input to verify(). */
export interface VerifyOptions {
  /** HTTP headers (case-insensitive lookup). */
  headers: Record<string, string | string[] | undefined>;
  /** Raw request body bytes. */
  body: Uint8Array;
  /** All (kid, secret) entries the receiver currently accepts. */
  secrets: ReadonlyArray<SecretEntry>;
  /** Optional replay store. Without one, replay protection is skipped. */
  replayStore?: ReplayStore;
  /** Default 300 seconds. Spec allows 60-600. */
  replayWindowSeconds?: number;
  /** Default Math.floor(Date.now()/1000). Override for deterministic tests. */
  now?: number;
}

export type VerifyErrorReason =
  | 'malformed_header'
  | 'unknown_algorithm'
  | 'stale'
  | 'future'
  | 'replayed'
  | 'unknown_kid'
  | 'bad_hmac';

/**
 * Result of verify().
 *
 * Failure cases carry only a stable `reason` enum; no human-readable
 * `message`. This is intentional: the spec (section 9) states that any
 * free-form diagnostic from the reference implementation MUST NOT appear
 * in the 401 response body, since it can leak internal state. Removing
 * the field entirely (rather than documenting "do not return this") makes
 * the safe path the only path.
 */
export type VerifyResult =
  | {
      ok: true;
      /** Which kid validated. */
      kid: string;
      /** Signer's timestamp (seconds). */
      timestamp: number;
      /** Nonce from the header. */
      nonce: string;
    }
  | {
      ok: false;
      reason: VerifyErrorReason;
    };

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_REPLAY_WINDOW_SECONDS = 300;
const MIN_REPLAY_WINDOW_SECONDS = 60;
const MAX_REPLAY_WINDOW_SECONDS = 600;
const REPLAY_STORE_TTL_BUFFER_SECONDS = 60;

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

/**
 * Produce the four AWSP headers for a payload.
 *
 * The HMAC is computed over `timestamp + "." + body-bytes`. The timestamp is
 * formatted as decimal ASCII with no leading zeros.
 */
export function sign(options: SignOptions): SignedHeaders {
  const { secret, keyId, body, eventType } = options;
  if (!(secret instanceof Uint8Array) || secret.length === 0) {
    throw new TypeError('sign: secret must be a non-empty Uint8Array');
  }
  if (typeof keyId !== 'string' || keyId.length === 0) {
    throw new TypeError('sign: keyId required');
  }
  if (!(body instanceof Uint8Array)) {
    throw new TypeError('sign: body must be a Uint8Array');
  }
  if (typeof eventType !== 'string' || eventType.length === 0) {
    throw new TypeError('sign: eventType required');
  }

  const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
  const nonce = options.nonce ?? generateNonce();
  const webhookId = options.webhookId ?? generateUuidV4();

  const v1Hex = computeV1(secret, timestamp, body);

  const signatureHeader = serializeSignatureHeader({
    timestamp,
    v1: [v1Hex],
    nonce,
    kid: keyId,
  });

  return {
    'X-A2A-Signature': signatureHeader,
    'X-A2A-Webhook-Id': webhookId,
    'X-A2A-Event-Type': eventType,
    'X-A2A-Timestamp': String(timestamp),
  };
}

/**
 * Compute the v1 signature for a (timestamp, body) pair against a single
 * secret. Exposed so test vectors and other-language implementations can
 * cross-check the canonical string concatenation.
 */
export function computeV1(secret: Uint8Array, timestamp: number, body: Uint8Array): string {
  const tsBytes = Buffer.from(String(timestamp), 'ascii');
  const dot = Buffer.from('.', 'ascii');
  const canonical = Buffer.concat([tsBytes, dot, Buffer.from(body)]);
  return createHmac('sha256', Buffer.from(secret)).update(canonical).digest('hex');
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

/**
 * Verify an incoming AWSP-signed request.
 *
 * Steps:
 *   1. Parse X-A2A-Signature.
 *   2. Window check: |now - t| <= replayWindowSeconds.
 *   3. Recompute HMAC for each candidate secret (filtered by kid if present);
 *      reject if no candidate matches in constant time.
 *   4. Replay check: ask replayStore.checkAndStore(nonce, window+60). Reject
 *      if it returns false.
 *
 * The order matters: cheap rejections (window) first, then HMAC, then replay.
 * Replay is last because we don't want to consume nonce-storage capacity for
 * forged requests.
 */
export async function verify(options: VerifyOptions): Promise<VerifyResult> {
  const window = options.replayWindowSeconds ?? DEFAULT_REPLAY_WINDOW_SECONDS;
  if (!Number.isInteger(window) || window < MIN_REPLAY_WINDOW_SECONDS || window > MAX_REPLAY_WINDOW_SECONDS) {
    throw new RangeError(
      `verify: replayWindowSeconds must be an integer in [${MIN_REPLAY_WINDOW_SECONDS}, ${MAX_REPLAY_WINDOW_SECONDS}]`,
    );
  }

  const rawHeader = lookupHeader(options.headers, 'X-A2A-Signature');
  if (rawHeader === undefined) {
    return { ok: false, reason: 'malformed_header' };
  }

  let parsed: ReturnType<typeof parseSignatureHeader>;
  try {
    parsed = parseSignatureHeader(rawHeader);
  } catch (err) {
    if (err instanceof HeaderParseError) {
      const reason = err.reason === 'unknown_algorithm' ? 'unknown_algorithm' : 'malformed_header';
      return { ok: false, reason };
    }
    throw err;
  }

  const now = options.now ?? Math.floor(Date.now() / 1000);
  const skew = now - parsed.timestamp;
  if (skew > window) {
    return { ok: false, reason: 'stale' };
  }
  if (skew < -window) {
    return { ok: false, reason: 'future' };
  }

  // Filter candidate secrets by kid (required in v1).
  const candidates = options.secrets.filter((s) => s.kid === parsed.kid);

  if (candidates.length === 0) {
    return { ok: false, reason: 'unknown_kid' };
  }

  let matchedKid: string | undefined;
  for (const entry of candidates) {
    const expected = computeV1(entry.secret, parsed.timestamp, options.body);
    for (const candidate of parsed.v1) {
      // timingSafeEqualHex is constant-time across equal-length inputs and
      // false-fast on length mismatch (which here is impossible -- both are
      // guaranteed 64 hex chars by parseSignatureHeader -- but keeping the
      // pattern makes future signature versions safer).
      if (timingSafeEqualHex(expected, candidate)) {
        matchedKid = entry.kid;
        break;
      }
    }
    if (matchedKid !== undefined) break;
  }

  if (matchedKid === undefined) {
    return { ok: false, reason: 'bad_hmac' };
  }

  if (options.replayStore !== undefined) {
    const ttl = window + REPLAY_STORE_TTL_BUFFER_SECONDS;
    const fresh = await options.replayStore.checkAndStore(parsed.nonce, ttl);
    if (!fresh) {
      return { ok: false, reason: 'replayed' };
    }
  }

  return { ok: true, kid: matchedKid, timestamp: parsed.timestamp, nonce: parsed.nonce };
}

// ---------------------------------------------------------------------------
// In-memory replay store (for tests / single-replica receivers)
// ---------------------------------------------------------------------------

/**
 * Reference in-memory ReplayStore. Suitable for tests and single-process
 * receivers; production multi-replica deployments should use Redis (SET NX EX)
 * or equivalent so replay state is shared.
 *
 * Map size is bounded by `EVICTION_THRESHOLD + EVICTION_INTERVAL` worth of
 * still-live nonces -- in the worst case ~8448 entries (~8K * average key
 * length) before a sweep brings it back down.
 */
export class InMemoryReplayStore implements ReplayStore {
  // Sweep is amortized: scan the whole Map once per EVICTION_INTERVAL calls,
  // and only when size has grown past EVICTION_THRESHOLD. This makes per-call
  // work O(1) amortized (one Map.set + one Map.get) rather than O(n) on every
  // call past the threshold.
  private static readonly EVICTION_THRESHOLD = 8192;
  private static readonly EVICTION_INTERVAL = 256;

  private readonly seen = new Map<string, number>();
  private callCounter = 0;

  constructor(private readonly clock: () => number = () => Math.floor(Date.now() / 1000)) {}

  async checkAndStore(nonce: string, ttlSeconds: number): Promise<boolean> {
    const now = this.clock();
    this.maybeEvict(now);
    const expiresAt = this.seen.get(nonce);
    if (expiresAt !== undefined && expiresAt > now) {
      return false;
    }
    this.seen.set(nonce, now + ttlSeconds);
    return true;
  }

  private maybeEvict(now: number): void {
    this.callCounter++;
    if (this.seen.size <= InMemoryReplayStore.EVICTION_THRESHOLD) return;
    if (this.callCounter % InMemoryReplayStore.EVICTION_INTERVAL !== 0) return;
    for (const [k, v] of this.seen) {
      if (v <= now) this.seen.delete(k);
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function lookupHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const target = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === target) {
      const v = headers[key];
      if (Array.isArray(v)) return v[0];
      return v;
    }
  }
  return undefined;
}

function generateNonce(): string {
  // 18 bytes -> 24 base64url chars, no padding.
  return randomBytes(18).toString('base64url');
}

function generateUuidV4(): string {
  const bytes = randomBytes(16);
  // Set version (4) and variant (10xx) per RFC 4122.
  bytes[6] = ((bytes[6] as number) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] as number) & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return (
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20, 32)}`
  );
}

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

export { parseSignatureHeader, serializeSignatureHeader, HeaderParseError } from './headers.js';
export type { ParsedSignatureHeader, ParseErrorReason } from './headers.js';
export { timingSafeEqualHex } from './timing-safe-equal.js';
export { assertPublicUrl, SsrfBlockedError, isPrivateIp } from './ssrf.js';
export type { AssertPublicUrlOptions, SsrfBlockedReason } from './ssrf.js';
