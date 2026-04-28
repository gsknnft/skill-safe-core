# Supply Chain Security

`skill-safe` is a security tool. It must hold itself to a higher standard than
the packages it audits. This document covers the supply chain threat model,
controls in place, and the publishing process.

---

## Threat Model

| Threat | Description | Control |
|---|---|---|
| Compromised publish token | Attacker uses stolen npm token to push a malicious version | OIDC provenance — no long-lived tokens in CI |
| Dependency takeover | A devDep is compromised and its payload reaches the build | Zero runtime deps; build surface asserted in CI |
| Tarball tampering | Published tarball content differs from the source commit | npm provenance links registry entry to exact git SHA |
| Lockfile injection | `pnpm-lock.yaml` is modified to pull a backdoored dep version | Lockfile committed; `pnpm audit` runs on every push |
| Test file leakage | `tests/` included in tarball, exposing attack surface info | Pack dry-run asserts `tests/` is absent |
| Source drift | `dist/` modified between build and publish | Build always runs fresh in publish workflow; never cached |
| Malicious SKILL.md in examples | Example fixtures used as vectors to test malicious patterns in CI | SARIF self-scan uses `--fail-on never` — fixtures are intentional |

---

## npm Provenance Attestation

Every release is published with `--provenance` using GitHub Actions OIDC.
This creates a verifiable, tamper-proof link between the npm registry entry
and the exact git commit and workflow run that produced it — with no
long-lived secret tokens involved.

### Verify a published release

```sh
# npm >= 9.5 required
npm audit signatures @gsknnft/skill-safe

# Verify a specific version
npm install @gsknnft/skill-safe@0.3.0 --dry-run
npm audit signatures
```

The attestation is publicly visible on [npmjs.com](https://www.npmjs.com/package/@gsknnft/skill-safe)
under the package's "Provenance" tab. It shows the repository, workflow file,
git ref, and commit SHA.

### How the OIDC publish works

The `publish.yml` workflow uses `id-token: write` permission. GitHub's OIDC
provider mints a short-lived token scoped to that single job run. npm uses it
to attach a Sigstore attestation at publish time. No `NPM_TOKEN` secret with
static credentials is needed or stored.

```yaml
permissions:
  id-token: write   # OIDC token for provenance attestation
  contents: read
```

```sh
pnpm publish --provenance --access public
```

---

## Signing and SLSA

- **npm tarball integrity**: Every locked dep has a SHA-512 integrity hash in
  `pnpm-lock.yaml`. The lockfile is committed and used with `--frozen-lockfile`
  in CI.
- **git tag signing**: Release tags should be signed with the maintainer's GPG
  key: `git tag -s v0.3.0 -m "v0.3.0"`. Verify: `git verify-tag v0.3.0`.
- **SLSA Build Level 2**: Provenance attestations satisfy SLSA L2 — hosted
  build platform, parameterized build, no persistent credentials.

---

## Lockfile Security

`pnpm-lock.yaml` is committed and enforced in CI:

```sh
pnpm install --frozen-lockfile   # used in all CI jobs
pnpm audit --prod                # production dep CVE check
git diff pnpm-lock.yaml          # detect unexpected lockfile changes
```

The lockfile pins every transitive dependency to an exact version and
integrity hash. Direct lockfile edits without running `pnpm install` are
detectable via `git diff`. PRs that modify the lockfile should be reviewed
carefully before merge.

---

## Zero Runtime Dependencies — Rationale

`skill-safe` has zero runtime dependencies by design and this is asserted in CI.

1. **Reduced attack surface** — nothing is pulled transitively into user
   environments from a compromised upstream package.
2. **Full auditability** — the entire shipped `dist/` is self-contained and
   readable; no hidden dependency tree.
3. **Embeddability** — works in CLIs, serverless, workers, and edge runtimes
   without conflicts.
4. **CI-enforced** — the `supply-chain` job fails immediately if a runtime dep
   is added unintentionally.

---

## CI Security Lane

Three jobs run on every push and weekly (Mondays 08:00 UTC):

### `audit` — Dependency audit
```sh
pnpm audit --prod --audit-level moderate
```
Fails if any production dependency has a known CVE at moderate or higher.
DevDeps are excluded (they are not shipped in the tarball).

### `self-scan` — SARIF upload
skill-safe scans its own example skills and uploads the SARIF report to
GitHub Code Scanning. Validates the CLI works end-to-end and that SARIF is
well-formed. Uses `--fail-on never` so the intentional malicious fixture
does not break CI.

### `supply-chain` — Package surface assertions
- Zero runtime dependencies (programmatic check)
- Fresh build from source
- Pack dry-run: `dist/cli.js` present, `tests/` absent
- Lockfile integrity via `--frozen-lockfile` install

See [`.github/workflows/security.yml`](../.github/workflows/security.yml).

---

## Repository Settings

Recommended GitHub repository configuration for maintainers:

- Protect `main` — require CI + security workflow to pass before merge
- Require signed commits or signed tags for public releases
- Use GitHub's private "Report a vulnerability" feature — do not use public issues for security reports
- Keep npm package ownership limited to trusted maintainers
- Require 2FA/passkeys on all maintainer npm accounts
- Disable npm automation tokens; use OIDC trusted publishing instead

---

## Downstream: Wallet and Safe{Core} Hosts

`skill-safe` does not run transactions or integrate with Safe{Core} directly.
Wallet-aware hosts can use it as the first gate in a layered defense:

1. Scan candidate skills before install (`skill-safe`)
2. Quarantine or block dangerous findings
3. Require human approval for `review`-level findings
4. Require multisig or Safe policy for asset-moving actions
5. Enforce runtime tool constraints independently

This keeps the core scanner useful for all agent environments while still
supporting high-assurance wallet and NFT workflows.

---

## Publishing Checklist

Before cutting a release, verify locally:

- [ ] `pnpm test` — all tests passing
- [ ] `pnpm tsc:noemit` — no type errors
- [ ] `pnpm validate:mappings` — all rules mapped
- [ ] `pnpm example:smoke` — integration smoke passes
- [ ] `pnpm pack:check` — tarball is clean
- [ ] `pnpm audit --prod` — no high/critical CVEs
- [ ] CHANGELOG updated with the new version
- [ ] Version bumped in `package.json`
- [ ] Git tag signed: `git tag -s v0.x.0 -m "v0.x.0"`
- [ ] Push tag: `git push origin v0.x.0`

The `publish.yml` workflow triggers on a tag push and handles the npm publish
with provenance automatically — do not run `pnpm publish` manually from a
local machine.

---

## Future Hardening

Items tracked for upcoming releases:

- **Lockfile-lint in CI** — assert no unexpected registry sources in the lockfile
- **Release artifact checksums** — publish SHA-256 checksums for each tarball
  alongside the GitHub release
- **Fixture coverage report** — verify which rule IDs have corresponding
  `good.md` and `bad.md` fixtures before each minor release
- **Call-graph static analysis** — move beyond pattern matching to trace if a
  skill's entry points can reach dangerous functions (`skill-safe-judge` layer)
- **Runtime containment pointer** — CI integration guide for wrapping
  skill-safe with container isolation for high-assurance environments
