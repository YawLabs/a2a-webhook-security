# AWSP Governance

## Stewardship at v1

AWSP is published and maintained by [Yaw Labs](https://yaw.labs) at v1. Until donation lands (see "Donation intent" below), Yaw Labs is the sole steward. In practice that means:

- The specification source of truth is `packages/awsp/` in the [a2a-hosting](https://github.com/YawLabs/a2a-hosting) repository.
- Yaw Labs reviews and merges all spec PRs.
- Yaw Labs cuts spec releases (tags `awsp-spec-vX.Y.Z`) and coordinates reference-implementation releases.
- All review and decision-making happens in public on GitHub. There is no private steering committee, mailing list, or out-of-band fork.

Yaw Labs commits to running the steward role transparently: every accepted change has a public PR; every rejected change has a public rationale. If that posture slips, please file an issue.

## Change process

Changes to AWSP follow an RFC-style flow:

### 1. Open an issue

For any non-trivial change, open a GitHub issue describing:

- The problem you're seeing (concrete examples beat abstractions).
- Your proposed change to the spec text or wire format.
- Backward-compatibility implications for existing Senders and Receivers.

For trivial typos or clarifications that do not change semantics, you can skip straight to a PR -- just say "trivial clarification" in the description.

### 2. Discussion in the issue

Spec reviewers from Yaw Labs and the broader community comment. The goal of this stage is to converge on whether the change is wanted at all and what the wire format / semantics implications look like.

A change is unlikely to land if it:

- Breaks the v1 wire format (those go in v2 -- see "Versioning" below).
- Adds optional knobs that only one Sender / Receiver needs (those should live in implementation-specific config, not in the spec).
- Reduces the security floor without strong justification.

### 3. Open a PR

Once the issue has rough consensus, file a PR that updates `SPEC.md`, the threat model if relevant, and the test vectors if the change affects the wire format. Reference implementations follow in subsequent PRs.

A spec PR MUST:

- Update `SPEC.md` and explicitly call out the version impact (clarification, v1.x, or v2 / wire-format-breaking).
- Update `CHANGELOG.md`.
- Include test vectors that distinguish the new behavior from the old (when applicable).
- NOT silently break the wire format. Wire-format changes require a new `vN=` signature version and a multi-month overlap window.

### 4. Merge and release

Yaw Labs merges and tags the spec release. Reference implementations release on their own cadence; the TypeScript impl typically releases within days of a spec change.

## Versioning

AWSP versions and reference-implementation versions are separate, both [semver](https://semver.org/).

### Spec versioning

- **Patch (`v1.0.x`)** -- editorial fixes, clarifications, typo corrections. No behavioral change for any conforming implementation.
- **Minor (`v1.x.0`)** -- new optional features, additional reason codes, expanded threat model coverage. Existing conforming implementations remain conformant.
- **Major (`v2.0.0`, `v3.0.0`, ...)** -- wire-format change. Senders and Receivers MUST coordinate. New major versions are introduced via a new `vN=` field on `X-A2A-Signature`, allowing both versions to coexist on every Delivery during a multi-month overlap. The previous major MUST be supported by the spec for at least 12 months after a new major lands.

### Reference-implementation versioning

Each reference implementation (`@yawlabs/awsp`, future `awsp` Python package, etc.) is versioned independently and follows semver against its own public API:

- **Patch** -- bug fixes, performance improvements.
- **Minor** -- new public API, expanded options.
- **Major** -- breaking API change.

A reference implementation's version does NOT have to match the spec version. (`@yawlabs/awsp@1.4.0` may implement AWSP v1.0.)

## Donation intent

Yaw Labs's stated intent is to donate AWSP stewardship to the Linux Foundation A2A project once production-implementation adoption signal lands. Concretely:

- "Adoption signal lands" means at least three independent operators have shipped AWSP-conforming Receivers in production, AND the LF A2A project has expressed interest in adopting the spec.
- On donation, the spec's source of truth moves to the LF A2A project's repository structure. Reference implementations remain Apache-2.0 either way.
- Yaw Labs commits to a clean handoff: no transition fee, no retained veto, no encumbered IP.

This intent is non-binding -- adoption signal may not land, the LF A2A project may decline, or circumstances may change. But it is the explicit direction we are steering towards, and we will not silently retract it.

## Code of conduct

Discussion in issues and PRs follows the [Contributor Covenant](https://www.contributor-covenant.org/) (or equivalent) standards. Yaw Labs reserves the right to lock issues and remove comments that are abusive, off-topic, or operating in bad faith.

## Reaching us

- GitHub issues: [YawLabs/a2a-hosting](https://github.com/YawLabs/a2a-hosting/issues) -- tag with `awsp` for spec issues, `awsp-ts` for TypeScript reference issues.
- Security disclosures: see the project security policy. Do not file security issues in public.
