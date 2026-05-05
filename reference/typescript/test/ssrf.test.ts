// SSRF defense tests for assertPublicUrl().
//
// Coverage strategy: one PASS test per CIDR in SPEC.md section 10's blocklist
// (proves the matcher's ranges are correct), plus the negative cases
// (invalid URL, dns failure, scheme rejection, allowHttp escape hatch).

import assert from 'node:assert/strict';
import test from 'node:test';
import { SsrfBlockedError, assertPublicUrl, isPrivateIp } from '../src/ssrf.js';

// ---------------------------------------------------------------------------
// Stub resolver helpers
// ---------------------------------------------------------------------------

function fixedResolver(addrs: string[]): (host: string) => Promise<string[]> {
  return async () => addrs;
}

function failingResolver(message: string): (host: string) => Promise<string[]> {
  return async () => {
    throw new Error(message);
  };
}

async function expectBlocked(
  promise: Promise<unknown>,
  reason: SsrfBlockedError['reason'],
): Promise<SsrfBlockedError> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof SsrfBlockedError) {
      assert.equal(err.reason, reason, `expected reason=${reason}, got ${err.reason}: ${err.message}`);
      return err;
    }
    throw err;
  }
  throw new Error(`expected SsrfBlockedError(${reason}), got fulfillment`);
}

// ---------------------------------------------------------------------------
// IPv4 blocklist -- one PASS test per CIDR in SPEC.md section 10
// ---------------------------------------------------------------------------

const IPV4_BLOCKED_SAMPLES: ReadonlyArray<readonly [string, string]> = [
  ['0.0.0.0/8', '0.0.0.0'],
  ['0.0.0.0/8', '0.255.255.255'],
  ['10.0.0.0/8', '10.0.0.1'],
  ['10.0.0.0/8', '10.255.255.255'],
  ['100.64.0.0/10', '100.64.0.1'],
  ['100.64.0.0/10', '100.127.255.255'],
  ['127.0.0.0/8', '127.0.0.1'],
  ['127.0.0.0/8', '127.255.255.255'],
  ['169.254.0.0/16', '169.254.169.254'], // EC2 / GCP metadata
  ['169.254.0.0/16', '169.254.0.1'],
  ['172.16.0.0/12', '172.16.0.1'],
  ['172.16.0.0/12', '172.31.255.255'],
  ['192.0.0.0/24', '192.0.0.1'],
  ['192.0.2.0/24', '192.0.2.42'],
  ['192.168.0.0/16', '192.168.0.1'],
  ['192.168.0.0/16', '192.168.255.255'],
  ['198.18.0.0/15', '198.18.0.1'],
  ['198.18.0.0/15', '198.19.255.255'],
  ['198.51.100.0/24', '198.51.100.5'],
  ['203.0.113.0/24', '203.0.113.5'],
  ['224.0.0.0/4', '224.0.0.1'],
  ['224.0.0.0/4', '239.255.255.255'],
  ['240.0.0.0/4', '240.0.0.1'],
  ['240.0.0.0/4', '255.255.255.255'],
];

for (const [range, ip] of IPV4_BLOCKED_SAMPLES) {
  test(`ssrf: IPv4 ${range} (${ip}) -- isPrivateIp returns true`, () => {
    assert.equal(isPrivateIp(ip), true, `expected ${ip} (${range}) to be flagged private`);
  });

  test(`ssrf: IPv4 ${range} (${ip}) -- assertPublicUrl rejects when DNS resolves there`, async () => {
    const err = await expectBlocked(
      assertPublicUrl('https://attacker.example/', { resolve: fixedResolver([ip]) }),
      'private_ip',
    );
    assert.equal(err.resolvedIp, ip);
  });

  test(`ssrf: IPv4 ${range} (${ip}) -- assertPublicUrl rejects URL literal`, async () => {
    await expectBlocked(assertPublicUrl(`https://${ip}/`), 'private_ip');
  });
}

// ---------------------------------------------------------------------------
// IPv6 blocklist -- one PASS test per CIDR in SPEC.md section 10
// ---------------------------------------------------------------------------

const IPV6_BLOCKED_SAMPLES: ReadonlyArray<readonly [string, string]> = [
  ['::/128 (unspecified)', '::'],
  ['::1/128 (loopback)', '::1'],
  // ::ffff:0:0/96 -- IPv4-mapped, applies IPv4 rules
  ['::ffff:0:0/96 -> 127.x', '::ffff:127.0.0.1'],
  ['::ffff:0:0/96 -> 169.254.169.254', '::ffff:169.254.169.254'],
  ['::ffff:0:0/96 -> 10.0.0.1', '::ffff:10.0.0.1'],
  ['64:ff9b::/96 (NAT64)', '64:ff9b::1'],
  ['64:ff9b::/96 (NAT64)', '64:ff9b::ffff:ffff'],
  ['100::/64 (discard)', '100::1'],
  ['100::/64 (discard)', '100::ffff:ffff:ffff:ffff'],
  ['2001::/23 (IETF)', '2001::1'],
  ['2001::/23 (IETF)', '2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff'],
  ['2001:db8::/32 (docs)', '2001:db8::1'],
  ['2001:db8::/32 (docs)', '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'],
  ['fc00::/7 (ULA)', 'fc00::1'],
  ['fc00::/7 (ULA)', 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
  ['fe80::/10 (link-local)', 'fe80::1'],
  ['fe80::/10 (link-local)', 'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
  ['ff00::/8 (multicast)', 'ff00::1'],
  ['ff00::/8 (multicast)', 'ff02::1'], // all-nodes
];

for (const [range, ip] of IPV6_BLOCKED_SAMPLES) {
  test(`ssrf: IPv6 ${range} (${ip}) -- isPrivateIp returns true`, () => {
    assert.equal(isPrivateIp(ip), true, `expected ${ip} (${range}) to be flagged private`);
  });

  test(`ssrf: IPv6 ${range} (${ip}) -- assertPublicUrl rejects when DNS resolves there`, async () => {
    const err = await expectBlocked(
      assertPublicUrl('https://attacker.example/', { resolve: fixedResolver([ip]) }),
      'private_ip',
    );
    assert.equal(err.resolvedIp, ip);
  });

  test(`ssrf: IPv6 ${range} (${ip}) -- assertPublicUrl rejects URL literal`, async () => {
    await expectBlocked(assertPublicUrl(`https://[${ip}]/`), 'private_ip');
  });
}

// ---------------------------------------------------------------------------
// Public-IP positive cases (these MUST be allowed)
// ---------------------------------------------------------------------------

test('ssrf: public IPv4 (8.8.8.8) is allowed', async () => {
  const out = await assertPublicUrl('https://example.com/path?q=1', {
    resolve: fixedResolver(['8.8.8.8']),
  });
  // Hostname rewritten to the resolved IP -- defeats DNS rebinding.
  assert.equal(out.hostname, '8.8.8.8');
  assert.equal(out.protocol, 'https:');
  assert.equal(out.pathname, '/path');
  assert.equal(out.search, '?q=1');
});

test('ssrf: public IPv6 (2606:4700:4700::1111) is allowed', async () => {
  const out = await assertPublicUrl('https://example.com/', {
    resolve: fixedResolver(['2606:4700:4700::1111']),
  });
  assert.equal(out.hostname, '[2606:4700:4700::1111]');
});

test('ssrf: literal public IPv4 in URL is passed through', async () => {
  const out = await assertPublicUrl('https://1.1.1.1/');
  assert.equal(out.hostname, '1.1.1.1');
});

test('ssrf: literal public IPv6 in URL is passed through', async () => {
  const out = await assertPublicUrl('https://[2606:4700:4700::1111]/');
  assert.equal(out.hostname, '[2606:4700:4700::1111]');
});

test('ssrf: rejects URL if any one of multiple resolved IPs is private', async () => {
  await expectBlocked(
    assertPublicUrl('https://mixed.example/', {
      resolve: fixedResolver(['8.8.8.8', '127.0.0.1']),
    }),
    'private_ip',
  );
});

test('ssrf: picks first resolved IP as connect target', async () => {
  const out = await assertPublicUrl('https://multi.example/', {
    resolve: fixedResolver(['8.8.8.8', '1.1.1.1']),
  });
  assert.equal(out.hostname, '8.8.8.8');
});

// ---------------------------------------------------------------------------
// Scheme rejection
// ---------------------------------------------------------------------------

test('ssrf: http:// rejected by default', async () => {
  await expectBlocked(
    assertPublicUrl('http://example.com/', { resolve: fixedResolver(['8.8.8.8']) }),
    'scheme_not_allowed',
  );
});

test('ssrf: http:// allowed with allowHttp=true', async () => {
  const out = await assertPublicUrl('http://example.com/', {
    allowHttp: true,
    resolve: fixedResolver(['8.8.8.8']),
  });
  assert.equal(out.protocol, 'http:');
  assert.equal(out.hostname, '8.8.8.8');
});

test('ssrf: http:// + private IP still rejected as private_ip with allowHttp', async () => {
  // allowHttp does not weaken the IP check.
  await expectBlocked(
    assertPublicUrl('http://example.com/', {
      allowHttp: true,
      resolve: fixedResolver(['127.0.0.1']),
    }),
    'private_ip',
  );
});

test('ssrf: ftp:// rejected', async () => {
  await expectBlocked(assertPublicUrl('ftp://example.com/'), 'scheme_not_allowed');
});

test('ssrf: file:// rejected', async () => {
  await expectBlocked(assertPublicUrl('file:///etc/passwd'), 'scheme_not_allowed');
});

test('ssrf: gopher:// rejected', async () => {
  await expectBlocked(assertPublicUrl('gopher://example.com/'), 'scheme_not_allowed');
});

// ---------------------------------------------------------------------------
// Invalid URL
// ---------------------------------------------------------------------------

test('ssrf: malformed URL string rejected', async () => {
  await expectBlocked(assertPublicUrl('not a url'), 'invalid_url');
});

test('ssrf: empty string rejected', async () => {
  await expectBlocked(assertPublicUrl(''), 'invalid_url');
});

test('ssrf: URL with no hostname rejected', async () => {
  // "https:" (no //, no host) -- the WHATWG URL parser will throw.
  await expectBlocked(assertPublicUrl('https:'), 'invalid_url');
});

// ---------------------------------------------------------------------------
// DNS failures
// ---------------------------------------------------------------------------

test('ssrf: DNS lookup throwing -> dns_failure', async () => {
  await expectBlocked(
    assertPublicUrl('https://nxdomain.example/', {
      resolve: failingResolver('ENOTFOUND'),
    }),
    'dns_failure',
  );
});

test('ssrf: empty DNS result -> dns_failure', async () => {
  await expectBlocked(
    assertPublicUrl('https://blank.example/', { resolve: fixedResolver([]) }),
    'dns_failure',
  );
});

test('ssrf: resolver returning non-IP -> dns_failure', async () => {
  await expectBlocked(
    assertPublicUrl('https://bogus.example/', { resolve: fixedResolver(['not-an-ip']) }),
    'dns_failure',
  );
});

// ---------------------------------------------------------------------------
// Accepts URL or string input
// ---------------------------------------------------------------------------

test('ssrf: accepts URL object input', async () => {
  const u = new URL('https://example.com/x');
  const out = await assertPublicUrl(u, { resolve: fixedResolver(['8.8.8.8']) });
  assert.equal(out.hostname, '8.8.8.8');
  assert.equal(out.pathname, '/x');
});

// ---------------------------------------------------------------------------
// Boundary cases on IPv4 ranges (just outside should pass)
// ---------------------------------------------------------------------------

const IPV4_PUBLIC_BOUNDARY_SAMPLES: ReadonlyArray<readonly [string, string]> = [
  ['9.255.255.255 (just below 10/8)', '9.255.255.255'],
  ['11.0.0.0 (just above 10/8)', '11.0.0.0'],
  ['100.63.255.255 (just below CGNAT)', '100.63.255.255'],
  ['100.128.0.0 (just above CGNAT)', '100.128.0.0'],
  ['126.255.255.255 (just below loopback)', '126.255.255.255'],
  ['128.0.0.0 (just above loopback)', '128.0.0.0'],
  ['169.253.255.255 (just below link-local)', '169.253.255.255'],
  ['169.255.0.0 (just above link-local)', '169.255.0.0'],
  ['172.15.255.255 (just below 172.16/12)', '172.15.255.255'],
  ['172.32.0.0 (just above 172.16/12)', '172.32.0.0'],
  ['192.167.255.255 (just below 192.168/16)', '192.167.255.255'],
  ['192.169.0.0 (just above 192.168/16)', '192.169.0.0'],
  ['223.255.255.255 (just below multicast)', '223.255.255.255'],
];

for (const [label, ip] of IPV4_PUBLIC_BOUNDARY_SAMPLES) {
  test(`ssrf: public boundary ${label} is NOT blocked`, () => {
    assert.equal(isPrivateIp(ip), false, `${ip} (${label}) should be public`);
  });
}
