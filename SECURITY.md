# Security Policy

AWSP -- the A2A Webhook Security Profile -- is a security spec. Bugs in the spec
text or in any of the reference implementations can have real impact on the
agents that consume them. We take reports seriously and respond on a published
timeline.

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.**

Email security disclosures to **security@yaw.labs**. Encrypt with the Yaw Labs
security PGP key on request if your report contains exploitation details that
should not traverse plaintext mail.

A useful report includes:

- Which component is affected (`SPEC.md` section, `reference/<lang>`,
  `test-vectors.json`).
- The version (commit SHA, package version, or spec version `v1`).
- A concrete description of the issue, ideally with a reproducer or proof of
  concept.
- Your assessment of impact and exploitability.
- Whether you intend to publish a writeup, and on what timeline.

We acknowledge receipt within **3 business days** and follow up with an initial
triage assessment (severity class, plan, ETA) within **10 business days**.

## Disclosure timeline

Standard coordinated-disclosure window: **90 days** from initial report to
public disclosure.

- We aim to ship a fix in the affected reference implementation(s) and an
  advisory before the 90-day mark.
- We may request a short extension for spec-level changes that require a wire
  format revision (these are rare and would target a `v2`-style migration, not
  a silent v1 fix).
- We may shorten the window if the issue is being actively exploited or has
  been independently disclosed.
- We credit reporters in the advisory unless the reporter prefers to remain
  anonymous.

If you have not heard back within the acknowledgment window above, please
follow up. Mail loss is rare but real.

## Supported versions

| Version | Status         |
|---------|----------------|
| AWSP v1 (`0.1.0`) | Supported -- security fixes land in `v1.x` patches and corresponding reference-implementation patch releases. |
| Pre-v1 / draft   | Not supported. There were no pre-v1 public releases; if you are running one, upgrade to `v1` (`0.1.0`). |

When AWSP v2 lands (wire-format change), v1 will continue to receive security
fixes for at least 12 months after the v2 release, per the
[GOVERNANCE.md](./GOVERNANCE.md) versioning policy.

## Scope

In scope:

- The AWSP v1 specification text in [`SPEC.md`](./SPEC.md). Spec defects with
  security impact (replay-protection bypass, signature confusion, key-rotation
  ambiguity, SSRF gap, etc.) are in scope.
- The threat model in [`THREAT_MODEL.md`](./THREAT_MODEL.md), if a stated
  defense does not actually hold.
- The five reference implementations under `reference/`:
  - `reference/typescript` -- `@yawlabs/awsp` (npm)
  - `reference/python` -- `yawlabs-awsp` (PyPI)
  - `reference/go` -- `github.com/yawlabs/awsp-go`
  - `reference/java` -- `com.yawlabs:awsp` (Maven)
  - `reference/dotnet` -- `YawLabs.Awsp` (NuGet)
- The conformance test vectors in [`test-vectors.json`](./test-vectors.json).
  Bugs that let a non-conforming implementation pass, or that reject a
  conforming one, are in scope.

Out of scope:

- Operator deployments running an AWSP-conforming Receiver. Misconfiguration in
  a third-party deployment (wrong replay window, no nonce store, leaked
  Secret) is the operator's responsibility, not ours.
- Downstream applications that import a reference implementation but use it
  incorrectly (e.g. verifying against re-serialized JSON instead of the raw
  body buffer). The reference READMEs call this out; bugs in downstream code
  are downstream issues.
- Transport-layer concerns. AWSP signs but does not encrypt; TLS handles
  transport confidentiality. Issues in TLS, the underlying HTTP stack, or
  network infrastructure are out of scope.
- Theoretical attacks on HMAC-SHA256 itself. If SHA-2 is broken, a wire-format
  revision (a new `vN=`) is the path forward, tracked separately.

## Hall of fame

We will list reporters here as advisories ship. The list is currently empty
because AWSP is newly public.

## Governance

For how spec changes flow (RFC process, versioning, donation intent), see
[GOVERNANCE.md](./GOVERNANCE.md). Security-driven changes follow the same
process but on a compressed timeline coordinated with the reporter.
