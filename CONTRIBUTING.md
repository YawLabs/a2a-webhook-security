# Contributing to AWSP

Thanks for considering a contribution. AWSP is a small, focused spec plus five
reference implementations -- the contribution surface is correspondingly small,
and we want to keep it that way.

For the long-form change process, governance, and donation intent, see
[GOVERNANCE.md](./GOVERNANCE.md). This file is the practical "how do I get
started" companion.

## What kinds of contributions land

**Welcome:**

- Bug fixes in any reference implementation, with a test vector or unit test
  that reproduces the bug.
- Clarifications to `SPEC.md` that do not change wire-format semantics. These
  ride as patch releases (`v1.0.x`) and need no RFC.
- New language ports (see "New language ports" below).
- Conformance fixes that align a reference implementation more tightly with
  `test-vectors.json`.
- Documentation improvements (READMEs, `THREAT_MODEL.md`, this file).

**Need an RFC issue first** (per [GOVERNANCE.md](./GOVERNANCE.md)):

- Anything that changes the wire format. These are `v2`-class changes and
  require a multi-month overlap window.
- New optional spec features (additional reason codes, expanded SSRF rules,
  new headers).
- Anything that reduces the security floor.

**Unlikely to land without strong justification:**

- Optional knobs that only one Sender / Receiver pair needs.
- Adding runtime dependencies to any reference implementation. The whole
  point of the reference suite is "stdlib only" -- new deps need a strong
  argument.

## Change process (short version)

1. **Open an issue** for any non-trivial change. Describe the problem
   concretely, your proposed change, and backward-compat implications. For
   typo fixes or strictly-editorial clarifications you can skip straight to a
   PR.
2. **Discussion** in the issue converges on whether the change is wanted and
   what the wire-format / semantics implications look like.
3. **PR.** Update `SPEC.md` (if applicable), the affected reference
   implementations, `test-vectors.json` (if the change affects the wire
   format), and `CHANGELOG.md`.
4. **Merge.** Yaw Labs merges and tags spec releases. Reference
   implementations release on their own cadence.

The full version, including versioning rules and merge criteria, lives in
[GOVERNANCE.md](./GOVERNANCE.md). Read it before opening a substantive PR.

## The conformance contract

Every reference implementation MUST pass every vector in
[`test-vectors.json`](./test-vectors.json) byte-for-byte. There are 50 vectors
covering:

- 10 valid signatures (varying body sizes, ASCII / UTF-8 / binary, multiple
  kids, edge-of-window timestamps in both directions).
- 10 invalid HMACs (tampered body, wrong secret, wrong kid).
- 10 timestamp issues (stale, future, exact-edge accept).
- 10 replay cases (same nonce twice).
- 10 malformed headers (missing fields, uppercase hex, unknown algorithm,
  garbage).

This is the conformance bar. A change that breaks even one vector is either:

- a wire-format break (requires an RFC and a `v2`-style migration -- see
  GOVERNANCE.md), or
- a regression (fix the implementation, not the vector).

If you are proposing an addition to `test-vectors.json`, all five reference
implementations MUST be updated in the same PR (or a coordinated series of
PRs) and continue to pass.

## Running the tests

Each port has its own toolchain. Run from the repository root unless noted.

### TypeScript -- `reference/typescript`

```bash
cd reference/typescript
npm install
npm test
```

Optional: `npm run lint` (Biome) and `npm run lint:fix`.

### Python -- `reference/python`

```bash
cd reference/python
pip install -e ".[test]"
python -m pytest tests/ -v
```

Python 3.10+. Stdlib only at runtime; `pytest` for tests.

### Go -- `reference/go`

```bash
cd reference/go
go test ./... -v -count=1
go vet ./...
```

Go 1.22+. Stdlib only.

### Java -- `reference/java`

```bash
cd reference/java
mvn -B compile
mvn -B test
mvn -B verify
```

JDK 17+. The Maven build pulls `test-vectors.json` from the repo root via the
`<testResource>` mapping in `pom.xml`.

### .NET -- `reference/dotnet`

```bash
cd reference/dotnet
dotnet restore
dotnet build -c Release
dotnet test -c Release --no-build
```

`net8.0`. The test project copies `test-vectors.json` into the test bin
directory via an MSBuild `<Content Include>`.

## Style

- TypeScript / JavaScript: Biome -- `npm run lint:fix` in `reference/typescript`
  before committing. Biome formatting diffs break CI.
- Python: standard PEP 8; the `[tool.mypy]` config in `pyproject.toml` is
  `strict = true`. Run `mypy yawlabs_awsp` if you have it installed.
- Go: `gofmt` and `go vet ./...`.
- Java / .NET: match existing file style; the `pom.xml` and `.csproj` enable
  warnings-as-errors for the .NET build, so address compiler warnings rather
  than suppressing them.

`SPEC.md` itself uses RFC-style "MUST / SHOULD / MAY" per BCP 14. New normative
text MUST follow the same convention. Editorial prose can be conversational;
normative requirements MUST NOT.

## New language ports

We welcome additional ports. Before opening a port PR:

1. **Open an issue** describing the port (target language version, runtime
   constraints, package coordinates you intend to publish under).
2. **Pass `test-vectors.json` end to end** before submitting. The conformance
   bar is non-negotiable.
3. **Match the existing layout**: `reference/<lang>/` with sources, tests, a
   README following the template established by the existing ports, and a
   loader that reads `test-vectors.json` from the repository root (do not
   duplicate the file).
4. **Stdlib-only at runtime** is the strong default. Test-time deps (a JUnit,
   a pytest, a tsx) are fine; runtime deps need justification.

Once accepted, the port lands under the same Apache-2.0 license and is added
to the table in `README.md` and `SPEC.md` section 12.

## Reporting security issues

Do NOT open a public issue for security bugs. See [SECURITY.md](./SECURITY.md)
for the disclosure process.

## Code of conduct

Be excellent to each other. Discussion in issues and PRs follows the
[Contributor Covenant](https://www.contributor-covenant.org/) (or equivalent)
standards. Yaw Labs reserves the right to lock issues and remove comments that
are abusive, off-topic, or operating in bad faith.
