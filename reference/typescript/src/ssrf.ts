// AWSP Sender-side SSRF defense.
//
// SPEC.md section 10 requires Senders to:
//   1. Resolve the URL hostname to one or more IPs BEFORE connecting.
//   2. Reject the URL if any resolved address is private, reserved, link-local,
//      multicast, or loopback.
//   3. Connect by IP, not hostname (defeats DNS rebinding).
//   4. Refuse non-HTTPS schemes by default; allow http only as an explicit
//      escape hatch (test fixtures, internal opt-in).
//   5. Cap response size, redirect-follow, and total request time. Those are
//      transport-layer concerns; this module covers (1)-(4).
//
// This module is dependency-free. IP-range matching uses node:net.isIP() to
// validate the address shape, then a small CIDR matcher walks the spec's
// blocklist.
//
// Usage:
//   const safeUrl = await assertPublicUrl(receiverUrl);
//   await fetch(safeUrl, { redirect: 'error', ... });

import { isIP, isIPv4, isIPv6 } from 'node:net';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type SsrfBlockedReason =
  | 'private_ip'
  | 'invalid_url'
  | 'dns_failure'
  | 'scheme_not_allowed';

export class SsrfBlockedError extends Error {
  readonly reason: SsrfBlockedReason;
  readonly url: string;
  readonly resolvedIp?: string;
  constructor(reason: SsrfBlockedReason, url: string, message: string, resolvedIp?: string) {
    super(message);
    this.name = 'SsrfBlockedError';
    this.reason = reason;
    this.url = url;
    if (resolvedIp !== undefined) this.resolvedIp = resolvedIp;
  }
}

export interface AssertPublicUrlOptions {
  /** Allow http:// (default false). For test fixtures only. */
  allowHttp?: boolean;
  /** Inject a resolver for testing. Default: node:dns/promises lookup. */
  resolve?: (hostname: string) => Promise<string[]>;
}

/**
 * Validate that a URL is safe for outbound webhook delivery per SPEC.md
 * section 10. Returns a URL with the hostname rewritten to the resolved
 * public IP (so the caller's HTTP client connects to that IP, defeating
 * DNS rebinding). Throws SsrfBlockedError on any failure.
 *
 * The returned URL preserves the original hostname in its `host` only if
 * the original input was an IP literal. For DNS-resolved hostnames, the
 * caller MUST forward the original hostname in the Host / SNI headers
 * (e.g. `fetch(safeUrl, { headers: { Host: originalHostname } })`) -- this
 * function does not handle TLS SNI; that is the HTTP client's job.
 */
export async function assertPublicUrl(
  url: string | URL,
  opts: AssertPublicUrlOptions = {},
): Promise<URL> {
  const allowHttp = opts.allowHttp === true;
  const resolver = opts.resolve ?? defaultResolver;

  const inputStr = typeof url === 'string' ? url : url.toString();
  let parsed: URL;
  try {
    parsed = typeof url === 'string' ? new URL(url) : new URL(url.toString());
  } catch {
    throw new SsrfBlockedError('invalid_url', inputStr, 'URL parse failed');
  }

  // Scheme check.
  if (parsed.protocol === 'https:') {
    // OK.
  } else if (parsed.protocol === 'http:') {
    if (!allowHttp) {
      throw new SsrfBlockedError(
        'scheme_not_allowed',
        inputStr,
        'http:// is not allowed (set allowHttp: true to override)',
      );
    }
  } else {
    throw new SsrfBlockedError(
      'scheme_not_allowed',
      inputStr,
      `scheme ${parsed.protocol} is not allowed (https:// only, http:// with allowHttp)`,
    );
  }

  // Hostname required.
  const hostname = parsed.hostname;
  if (hostname.length === 0) {
    throw new SsrfBlockedError('invalid_url', inputStr, 'URL has no hostname');
  }

  // If the hostname is an IP literal, validate it directly. Strip the
  // bracketed IPv6 form that URL.hostname returns ("[::1]" -> "::1").
  const literalIp = stripBrackets(hostname);
  if (isIP(literalIp) !== 0) {
    if (isPrivateIp(literalIp)) {
      throw new SsrfBlockedError(
        'private_ip',
        inputStr,
        `IP ${literalIp} is in a blocked range`,
        literalIp,
      );
    }
    // Already an IP, no DNS step needed; return as-is (URL already shaped).
    return parsed;
  }

  // DNS resolution.
  let addrs: string[];
  try {
    addrs = await resolver(hostname);
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'DNS lookup failed';
    throw new SsrfBlockedError('dns_failure', inputStr, msg);
  }
  if (!Array.isArray(addrs) || addrs.length === 0) {
    throw new SsrfBlockedError('dns_failure', inputStr, 'no addresses returned');
  }

  // Reject if ANY resolved address is in a blocked range. This is
  // intentionally strict -- if a hostname resolves to one public + one
  // private IP, we refuse the URL rather than picking the public one
  // (defense in depth: a multi-record hostname with a private IP is a
  // strong DNS-rebinding signal).
  for (const addr of addrs) {
    if (isIP(addr) === 0) {
      throw new SsrfBlockedError(
        'dns_failure',
        inputStr,
        `resolver returned non-IP value: ${addr}`,
      );
    }
    if (isPrivateIp(addr)) {
      throw new SsrfBlockedError(
        'private_ip',
        inputStr,
        `${hostname} resolves to ${addr} which is in a blocked range`,
        addr,
      );
    }
  }

  // Pick the first resolved address as the connect target. Rewrite the URL
  // so the caller's HTTP client connects to the IP rather than re-resolving
  // the hostname (DNS-rebinding defense).
  const connectIp = addrs[0] as string;
  const rewritten = new URL(parsed.toString());
  rewritten.hostname = isIPv6(connectIp) ? `[${connectIp}]` : connectIp;
  return rewritten;
}

// ---------------------------------------------------------------------------
// Default resolver (node:dns/promises)
// ---------------------------------------------------------------------------

async function defaultResolver(hostname: string): Promise<string[]> {
  // Lazy import so the module doesn't pull dns at import time (slightly
  // friendlier to bundlers that strip unused deps).
  const dns = await import('node:dns/promises');
  // `all: true` returns every A and AAAA record we get back.
  const results = await dns.lookup(hostname, { all: true, verbatim: true });
  return results.map((r) => r.address);
}

// ---------------------------------------------------------------------------
// IP range matching
// ---------------------------------------------------------------------------

/** Strip the bracketed IPv6 wrapper that URL.hostname returns. */
function stripBrackets(host: string): string {
  if (host.length >= 2 && host.charCodeAt(0) === 0x5b /* [ */ && host.endsWith(']')) {
    return host.slice(1, -1);
  }
  return host;
}

/** Returns true if `ip` is in any blocked range from SPEC.md section 10. */
export function isPrivateIp(ip: string): boolean {
  if (isIPv4(ip)) {
    return isPrivateIpv4(ip);
  }
  if (isIPv6(ip)) {
    return isPrivateIpv6(ip);
  }
  // Anything not parseable as IP is treated as private (fail closed).
  return true;
}

// IPv4 blocklist from SPEC.md section 10.
const IPV4_BLOCKED_CIDRS: ReadonlyArray<readonly [string, number]> = [
  ['0.0.0.0', 8], //         "this network" (RFC 1122)
  ['10.0.0.0', 8], //        private (RFC 1918)
  ['100.64.0.0', 10], //     CGNAT (RFC 6598)
  ['127.0.0.0', 8], //       loopback
  ['169.254.0.0', 16], //    link-local (incl. AWS/GCP metadata 169.254.169.254)
  ['172.16.0.0', 12], //     private (RFC 1918)
  ['192.0.0.0', 24], //      IETF Protocol Assignments (RFC 6890)
  ['192.0.2.0', 24], //      TEST-NET-1 (RFC 5737)
  ['192.168.0.0', 16], //    private (RFC 1918)
  ['198.18.0.0', 15], //     benchmark (RFC 2544)
  ['198.51.100.0', 24], //   TEST-NET-2 (RFC 5737)
  ['203.0.113.0', 24], //    TEST-NET-3 (RFC 5737)
  ['224.0.0.0', 4], //       multicast (RFC 5771)
  ['240.0.0.0', 4], //       reserved future (RFC 1112) -- includes 255.255.255.255
];

function isPrivateIpv4(ip: string): boolean {
  const addr = ipv4ToUint32(ip);
  if (addr === undefined) return true; // malformed -> fail closed
  for (const [base, prefix] of IPV4_BLOCKED_CIDRS) {
    const baseInt = ipv4ToUint32(base);
    if (baseInt === undefined) continue; // unreachable -- base list is curated
    if (matchesCidr32(addr, baseInt, prefix)) return true;
  }
  return false;
}

function ipv4ToUint32(ip: string): number | undefined {
  const parts = ip.split('.');
  if (parts.length !== 4) return undefined;
  let out = 0;
  for (const p of parts) {
    if (p.length === 0 || p.length > 3) return undefined;
    if (!/^[0-9]+$/.test(p)) return undefined;
    const n = Number.parseInt(p, 10);
    if (n < 0 || n > 255) return undefined;
    out = (out * 256 + n) >>> 0; // keep unsigned
  }
  return out;
}

function matchesCidr32(addr: number, base: number, prefix: number): boolean {
  if (prefix === 0) return true;
  // JS shift on 32-bit ints: handle the prefix=32 edge to avoid the shift-by-32
  // becoming shift-by-0.
  const mask = prefix === 32 ? 0xffffffff : (~0 << (32 - prefix)) >>> 0;
  return (addr & mask) === (base & mask);
}

// IPv6 blocklist from SPEC.md section 10.
const IPV6_BLOCKED_CIDRS: ReadonlyArray<readonly [string, number]> = [
  ['::', 128], //          unspecified  ::/128
  ['::1', 128], //         loopback     ::1/128
  // ::ffff:0:0/96 -- IPv4-mapped -- handled by the dedicated branch below.
  ['64:ff9b::', 96], //    NAT64 well-known prefix (RFC 6052)
  ['100::', 64], //        discard prefix (RFC 6666)
  ['2001::', 23], //       IETF Protocol Assignments (RFC 2928)
  ['2001:db8::', 32], //   documentation (RFC 3849)
  ['fc00::', 7], //        unique local (RFC 4193)
  ['fe80::', 10], //       link-local (RFC 4291)
  ['ff00::', 8], //        multicast (RFC 4291)
];

function isPrivateIpv6(ip: string): boolean {
  // Normalize to 8 16-bit groups.
  const groups = expandIpv6(ip);
  if (groups === undefined) return true; // fail closed

  // ::ffff:0:0/96 -- IPv4-mapped IPv6 addresses. Apply IPv4 rules to the
  // embedded v4 octets. Per SPEC.md section 10, the v4 rules apply.
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff
  ) {
    const g6 = groups[6] ?? 0;
    const g7 = groups[7] ?? 0;
    const v4 = `${(g6 >>> 8) & 0xff}.${g6 & 0xff}.${(g7 >>> 8) & 0xff}.${g7 & 0xff}`;
    // Treat any IPv4-mapped as if it were that v4 (whether private or not).
    return isPrivateIpv4(v4);
  }

  for (const [base, prefix] of IPV6_BLOCKED_CIDRS) {
    const baseGroups = expandIpv6(base);
    if (baseGroups === undefined) continue;
    if (matchesCidr128(groups, baseGroups, prefix)) return true;
  }
  return false;
}

/**
 * Parse an IPv6 string into 8 uint16 groups. Returns undefined on malformed
 * input. Handles `::` shorthand and embedded v4 (e.g. `::ffff:1.2.3.4`).
 */
function expandIpv6(ip: string): number[] | undefined {
  // node:net.isIPv6 validates shape; we still need to do the actual parsing.
  if (!isIPv6(ip)) return undefined;

  // Embedded v4: detect a trailing dotted-quad and convert it to two hex
  // groups so the rest of the parser only deals with colon-separated hex.
  let work = ip;
  if (ip.indexOf('.') !== -1) {
    const lastColon = ip.lastIndexOf(':');
    if (lastColon === -1) return undefined;
    const tail = ip.slice(lastColon + 1);
    const tailInt = ipv4ToUint32(tail);
    if (tailInt === undefined) return undefined;
    const hi = ((tailInt >>> 16) & 0xffff).toString(16);
    const lo = (tailInt & 0xffff).toString(16);
    work = `${ip.slice(0, lastColon)}:${hi}:${lo}`;
  }

  // Split on `::` (RFC 4291 allows at most one).
  const parts = work.split('::');
  if (parts.length > 2) return undefined;

  const parseGroup = (g: string): number | undefined => {
    if (g.length === 0 || g.length > 4) return undefined;
    if (!/^[0-9a-fA-F]+$/.test(g)) return undefined;
    return Number.parseInt(g, 16);
  };

  if (parts.length === 1) {
    // No `::`; must be exactly 8 groups.
    const groups = (parts[0] ?? '').split(':');
    if (groups.length !== 8) return undefined;
    const out: number[] = [];
    for (const g of groups) {
      const n = parseGroup(g);
      if (n === undefined) return undefined;
      out.push(n);
    }
    return out;
  }

  // `::` present; left and right may be empty.
  const leftStr = parts[0] ?? '';
  const rightStr = parts[1] ?? '';
  const left = leftStr === '' ? [] : leftStr.split(':');
  const right = rightStr === '' ? [] : rightStr.split(':');

  const leftGroups: number[] = [];
  for (const g of left) {
    const n = parseGroup(g);
    if (n === undefined) return undefined;
    leftGroups.push(n);
  }
  const rightGroups: number[] = [];
  for (const g of right) {
    const n = parseGroup(g);
    if (n === undefined) return undefined;
    rightGroups.push(n);
  }

  const fillCount = 8 - leftGroups.length - rightGroups.length;
  if (fillCount < 0) return undefined;
  return [...leftGroups, ...zeroFill(fillCount), ...rightGroups];
}

function zeroFill(n: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < n; i++) out.push(0);
  return out;
}

function matchesCidr128(addr: number[], base: number[], prefix: number): boolean {
  if (prefix === 0) return true;
  let remaining = prefix;
  for (let i = 0; i < 8 && remaining > 0; i++) {
    const groupBits = remaining >= 16 ? 16 : remaining;
    const mask = groupBits === 16 ? 0xffff : ((0xffff << (16 - groupBits)) & 0xffff);
    if (((addr[i] ?? 0) & mask) !== ((base[i] ?? 0) & mask)) return false;
    remaining -= groupBits;
  }
  return true;
}
