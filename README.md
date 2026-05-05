# AWSP -- A2A Webhook Security Profile

An open spec and reference implementations for authenticating push-notification webhooks delivered between A2A (Agent-to-Agent) agents. AWSP defines a single interoperable wire format -- HMAC-SHA256 over the raw body, timestamp window + nonce uniqueness for replay protection, key-rotation via kid, and Sender-side SSRF defense -- so that any A2A Sender and any A2A Receiver can verify each other's webhooks without negotiating an ad-hoc scheme.

Modeled on the proven Stripe-Signature pattern, adapted for inter-agent flows.

**Repository:** [github.com/YawLabs/a2a-webhook-security](https://github.com/YawLabs/a2a-webhook-security)

## Documents

- [SPEC.md](./SPEC.md) -- the v1 specification (publishable, no TBDs)
- [THREAT_MODEL.md](./THREAT_MODEL.md) -- threats AWSP defends against and the residual risk
- [GOVERNANCE.md](./GOVERNANCE.md) -- stewardship, change process, donation intent
- [CONTRIBUTING.md](./CONTRIBUTING.md) -- how to contribute, run tests, add ports
- [SECURITY.md](./SECURITY.md) -- vulnerability reporting and disclosure timeline
- [CHANGELOG.md](./CHANGELOG.md) -- version history
- [test-vectors.json](./test-vectors.json) -- 50 deterministic vectors all conforming implementations MUST pass

## Reference implementations

| Language   | Status   | Path / Package                                |
|------------|----------|-----------------------------------------------|
| TypeScript | Shipping | `@yawlabs/awsp` (npm) -- [reference/typescript](./reference/typescript) |
| Python     | Shipping | `yawlabs-awsp` (PyPI) -- [reference/python](./reference/python) |
| Go         | Shipping | `github.com/yawlabs/awsp-go` -- [reference/go](./reference/go) |
| Java       | Shipping | `com.yawlabs:awsp` (Maven) -- [reference/java](./reference/java) |
| .NET       | Shipping | `YawLabs.Awsp` (NuGet) -- [reference/dotnet](./reference/dotnet) |

The TypeScript implementation is the canonical reference. Other-language ports MUST pass [`test-vectors.json`](./test-vectors.json) verbatim.

## License

Apache-2.0. See [reference/typescript/LICENSE](./reference/typescript/LICENSE).

The spec and reference implementations are intentionally permissively licensed so they can ship anywhere -- including in agent runtimes that don't share Yaw Labs's commercial posture.

## Governance

Yaw Labs publishes and maintains this spec at v1. We intend to donate stewardship to the Linux Foundation A2A project once production-implementation adoption signal lands. The reference implementations remain Apache-2.0 either way. See [GOVERNANCE.md](./GOVERNANCE.md) for the change process.

## Contributing

- Bug reports and clarification questions: open a GitHub issue.
- Proposed changes to the spec: file an RFC-style issue first, then a PR. The change process and versioning rules are in [GOVERNANCE.md](./GOVERNANCE.md).
- New language ports: open an issue describing the port; align with `test-vectors.json` before submitting.
- Practical "how do I get started" -- test commands per port, conformance contract, style notes -- is in [CONTRIBUTING.md](./CONTRIBUTING.md).
- Security disclosures: see [SECURITY.md](./SECURITY.md). Do not file security issues in public.

## Quick links

If you are...

- ...building a Sender, start at [SPEC.md section 10 (SSRF defense)](./SPEC.md#10-ssrf-defense-sender-side) and the [TypeScript README's "Sign a webhook payload"](./reference/typescript/README.md#sign-a-webhook-payload-sender-side).
- ...building a Receiver, start at [SPEC.md section 7 (Replay protection)](./SPEC.md#7-replay-protection) and the [TypeScript README's "Verify an incoming webhook"](./reference/typescript/README.md#verify-an-incoming-webhook-receiver-side).
- ...porting the spec to another language, start at [test-vectors.json](./test-vectors.json) and align your output before publishing.
