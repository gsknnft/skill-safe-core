# skill-safe Roadmap

`@gsknnft/skill-safe` should stay the deterministic, zero-runtime-dependency
gate for agent skill markdown. The core package should remain small,
auditable, and embeddable in CLIs, marketplaces, local apps, and CI.

## v0.3.0 Released

v0.3.0 is the released baseline.

**Rules and policy**

- Policy presets: `strict | marketplace | workspace` with CLI `--preset`.
- Suppression audit: `--audit-suppressions` for invalid and unused suppressions.
- Suppression modes: `report-only` (default), `honor`, and `disabled`.
- 14 static hardening rules for credentials, remote execution, destructive
  operations, persistence, and clipboard access (`SS100`-`SS140`).
- Structured governance mappings with category defaults and rule overrides.
- `pnpm validate:mappings` CI guard.
- `resolveMarkdownFile()` for GitHub-compatible contents APIs, with zero
  runtime dependencies.

**Reports and release infrastructure**

- `docs/SKILL_SUITE.md` for canonical package boundaries.
- `docs/SUPPLY_CHAIN.md` for threat model, provenance, and lockfile security.
- `docs/RISK_SCORING.md` for scoring algorithm and risk bands.
- OIDC/npm provenance publish workflow.
- `examples/suite/` canonical fixtures and reports.
- `pnpm demo` one-command scan and suppression-audit demo.
- Package badges, limitations, policy tables, and integration docs.

## v0.4.0 Release Target

v0.4.0 is the production-hardening pass after the 0.3.0 release.

Implemented for v0.4.0:

- `skill-safe.config.json` support for project-level policy:
  `preset`, `failOn`, `suppressionMode`, npm policy, and scan include/exclude
  settings.
- Configured scan includes: running the CLI with no explicit target can scan
  the project paths declared in config.
- Per-file source override support in directory scans through the library
  `resolveSource(file)` hook, enabling mixed-trust workspace scans.
- `permissive` preset for local development and exploration:
  `failOn: "never"`, report-only suppressions, and no npm age gate.
- Suppression expiry:
  `<!-- skill-safe-ignore SS001: reason -- expires: 2026-06-01 -->`.
- Suppression audit now reports invalid, unused, and expired suppressions.
- `--coverage` report for batch scans, plus public coverage helpers and
  `@gsknnft/skill-safe/coverage` subpath export.
- v0.4 static rules:
  - `SS150` Git credential helper and `.git-credentials` reads.
  - `SS151` cloud instance metadata endpoint access.
  - `SS152` container escape and host privilege primitives.
  - `SS153` token, API key, secret, or password leakage through URL queries.
- Socket/supply-chain hardening:
  - no implicit environment-token lookup in `resolveMarkdownFile()`
  - built-in network resolvers require an explicit host-provided `fetcher`
  - CI uses frozen lockfile installs
  - publish workflow uses OIDC provenance instead of long-lived npm tokens

## v0.5 Candidates

High-value work that should not be confused with the v0.3.0 or v0.4.0 cuts:

- Rule fixture suite: one `good.md`, `bad.md`, and optional `obfuscated.md` per
  rule family, modeled after Semgrep's fixture-per-rule pattern.
- Fixture coverage gate: CI asserts every built-in rule has a negative fixture
  before each minor release.
- More source-policy checks:
  - npm maintainer account age
  - repository archived/disabled status via GitHub API
  - SPDX license mismatch between package metadata and expected policy
- Defense-in-depth URL validation:
  - verify forwarded GitHub Contents API URLs stay on expected GitHub API hosts
  - reject credentialed resolver hops to non-allowlisted hosts
- Namespaced identity helpers for large ingestion systems:
  - preserve `relativePath` for local scans
  - optionally derive report IDs from package/source namespace plus path
  - reduce SARIF/result collisions when multiple packages contain `SKILL.md`
- Release artifact checksums:
  - publish SHA-256 digest alongside each GitHub release
  - document tarball verification flow
- Optional lockfile-lint style CI check for unexpected registry origins.
- Configurable policy packs for marketplace, workspace, wallet host, and
  high-assurance review queues.
- Provenance expansion:
  - document npm trusted-publishing verification more explicitly
  - keep resolver hooks ready for signed-build / attestation metadata
  - expose signed-source evidence to `skill-ledger` when hosts can provide it

## Host-Integration Recipes

These should stay as docs and examples unless a host package needs code:

- Wallet / NFT host flow: scan first, then multisig/Safe policy for actual
  asset-moving actions.
- Marketplace ingestion flow: `skill-ledger` discover, `skill-safe` scan,
  `skill-ui` review.
- Local workspace flow: scan, suppression audit, then runtime allowlist.
- CI flow: strict preset, SARIF upload, coverage report, and suppression audit.
- AI-BOM flow: `skill-ledger` records source, integrity, static report, optional
  judge report, runtime policy, and host trust decision.
- Danger-diff flow: `skill-ui` compares old/new reports and highlights exactly
  which findings caused a trust downgrade.
- TOCTOU flow: a host or `skill-ledger` snapshots vetted content by integrity
  before symlinking or activating it.

## Out Of Scope For Core

These belong in companion packages or host runtimes, not the zero-dep core
scanner:

- Call-graph static analysis.
- Runtime containment or sandboxing.
- LLM-based semantic scanning.
- Blockchain transaction approval.
- Safe{Core} SDK wrappers.
- Wallet key custody.
- Agent tool-call authorization.

The core scanner should keep producing deterministic evidence. Hosts decide
what to do with that evidence.

## v1.0 Readiness Bar

- Stable public API and package exports.
- Stable report schema with additive-only changes.
- Stable `SS###` rule IDs.
- Complete rules reference with fixture examples per rule.
- CI verifies install, typecheck, build, tests, mapping validation, example
  smoke, coverage smoke, and pack dry-run.
- Security CI verifies dependency audit, self-scan with SARIF upload, zero-dep
  assertion, and frozen lockfile install.
- Contribution guide covers rules, mappings, tests, report schema, SARIF,
  suppressions, and coverage.
- Security policy covers responsible disclosure, supported versions, and
  contact path.

## Adjacent Packages

These stay separate from the deterministic core:

- `@gsknnft/skill-safe-judge`: optional LLM semantic review layer.
- `@gsknnft/skill-safe-runtime`: runtime tool-call and trace enforcement.
- `@gsknnft/skill-ledger`: installation, manifesting, sync, and inventory.
- `@gsknnft/skill-ui`: review workbench and manager surface.

The core scanner produces evidence. Host applications decide whether to
install, warn, quarantine, require review, or block.
