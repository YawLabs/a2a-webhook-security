// Constant-time hex comparison wrapper.
//
// Why we wrap timingSafeEqual: timingSafeEqual throws RangeError when the two
// buffers differ in length, which would itself leak that the candidate was
// the wrong length. We normalize to false on length mismatch up front.

import { timingSafeEqual as nodeTimingSafeEqual } from 'node:crypto';

/**
 * Constant-time comparison of two lowercase hex strings.
 *
 * Returns false (not throws) when lengths differ. Both arguments are
 * compared byte-for-byte using Node's timingSafeEqual on the decoded bytes.
 */
export function timingSafeEqualHex(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  if (a.length === 0) return true;
  // Buffer.from with 'hex' silently drops invalid chars and odd-length tails,
  // which would defeat constant-time intent. Validate first.
  if (!isLowerHex(a) || !isLowerHex(b)) return false;
  const aBuf = Buffer.from(a, 'hex');
  const bBuf = Buffer.from(b, 'hex');
  if (aBuf.length !== bBuf.length) return false;
  return nodeTimingSafeEqual(aBuf, bBuf);
}

function isLowerHex(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const isDigit = c >= 0x30 && c <= 0x39;
    const isLowerAF = c >= 0x61 && c <= 0x66;
    if (!isDigit && !isLowerAF) return false;
  }
  return true;
}
