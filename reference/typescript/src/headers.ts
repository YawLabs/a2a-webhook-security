// AWSP header parsing and serialization.
//
// X-A2A-Signature has the form:
//   t=<unix-seconds>,v1=<hex>[,v1=<hex>...],n=<nonce-b64url>,kid=<keyId>
//
// Order of fields is NOT significant. Multiple v* values are allowed
// (algorithm rotation); receivers MUST accept the request if any one of
// them validates against any known secret.

export interface ParsedSignatureHeader {
  /** Unix timestamp in seconds (signer's clock). */
  timestamp: number;
  /** All v1 (HMAC-SHA256, lowercase hex) signatures present, in order. */
  v1: string[];
  /** Base64url-encoded nonce. */
  nonce: string;
  /** Key identifier (opaque string). REQUIRED in v1. */
  kid: string;
}

export class HeaderParseError extends Error {
  readonly reason: ParseErrorReason;
  constructor(reason: ParseErrorReason, message: string) {
    super(message);
    this.name = 'HeaderParseError';
    this.reason = reason;
  }
}

export type ParseErrorReason =
  | 'malformed_header'
  | 'missing_timestamp'
  | 'missing_signature'
  | 'missing_nonce'
  | 'unknown_algorithm';

/** Parse the X-A2A-Signature header value. Throws HeaderParseError on failure. */
export function parseSignatureHeader(raw: string): ParsedSignatureHeader {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new HeaderParseError('malformed_header', 'empty header');
  }
  if (raw.length > 4096) {
    throw new HeaderParseError('malformed_header', 'header too long');
  }

  const parts = raw.split(',');
  let timestamp: number | undefined;
  const v1: string[] = [];
  let nonce: string | undefined;
  let kid: string | undefined;
  let sawUnknownVersion = false;

  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq <= 0 || eq === part.length - 1) {
      throw new HeaderParseError('malformed_header', `bad pair: ${part}`);
    }
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key.length === 0 || value.length === 0) {
      throw new HeaderParseError('malformed_header', `empty key or value: ${part}`);
    }

    if (key === 't') {
      if (timestamp !== undefined) {
        throw new HeaderParseError('malformed_header', 'duplicate t=');
      }
      if (!/^[0-9]{1,15}$/.test(value)) {
        throw new HeaderParseError('malformed_header', 'bad timestamp');
      }
      timestamp = Number.parseInt(value, 10);
      if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
        throw new HeaderParseError('malformed_header', 'bad timestamp');
      }
    } else if (key === 'v1') {
      if (!/^[0-9a-f]{64}$/.test(value)) {
        throw new HeaderParseError('malformed_header', 'bad v1 (must be 64 lowercase hex)');
      }
      v1.push(value);
    } else if (/^v[0-9]+$/.test(key)) {
      // Future signature versions: receivers ignore unknown versions.
      sawUnknownVersion = true;
    } else if (key === 'n') {
      if (nonce !== undefined) {
        throw new HeaderParseError('malformed_header', 'duplicate n=');
      }
      if (!/^[A-Za-z0-9_-]{1,256}$/.test(value)) {
        throw new HeaderParseError('malformed_header', 'bad nonce (must be base64url, 1-256 chars)');
      }
      nonce = value;
    } else if (key === 'kid') {
      if (kid !== undefined) {
        throw new HeaderParseError('malformed_header', 'duplicate kid=');
      }
      if (!/^[A-Za-z0-9._-]{1,128}$/.test(value)) {
        throw new HeaderParseError('malformed_header', 'bad kid');
      }
      kid = value;
    } else {
      // Unknown field -- ignore for forward compatibility.
    }
  }

  if (timestamp === undefined) {
    throw new HeaderParseError('missing_timestamp', 't= required');
  }
  if (nonce === undefined) {
    throw new HeaderParseError('missing_nonce', 'n= required');
  }
  if (v1.length === 0) {
    if (sawUnknownVersion) {
      throw new HeaderParseError('unknown_algorithm', 'no supported signature version');
    }
    throw new HeaderParseError('missing_signature', 'v1= required');
  }
  if (kid === undefined) {
    // v1 mandates kid for forward-compatible rotation; receivers MUST reject
    // missing kid.
    throw new HeaderParseError('malformed_header', 'kid= required');
  }

  return { timestamp, v1, nonce, kid };
}

/** Serialize a signature header. Field order: t, v1..., n, kid. */
export function serializeSignatureHeader(parsed: ParsedSignatureHeader): string {
  const fields: string[] = [`t=${parsed.timestamp}`];
  for (const v of parsed.v1) fields.push(`v1=${v}`);
  fields.push(`n=${parsed.nonce}`);
  fields.push(`kid=${parsed.kid}`);
  return fields.join(',');
}
