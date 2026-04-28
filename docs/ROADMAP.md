# skill-safe Roadmap

`@gsknnft/skill-safe` should stay the deterministic, zero-runtime-dependency
gate for agent skill markdown. The core package should remain small,
auditable, and embeddable in CLIs, marketplaces, local apps, and CI.

## v0.3.0 Shipped

**Rules (56 total)**
- Policy presets: `strict | marketplace | workspace` with CLI `--preset`
- Suppression audit: `--audit-suppressions` (invalid rule IDs, unused suppressions)
- Suppression modes: `report-only` (default) / `honor` / `disabled`
- 14 new static rules — credentials, RCE, destructive ops, persistence, clipboard (SS100–SS140)
- All rule-specific governance mappings migrated to structured `GovernanceMapping[]` — legacy flat strings removed
- `rule.governance` field flattened via `toReportArrays` at flag-push time — consistent with category defaults
- Governance mapping registry (`mappings.ts`) with 4-framework coverage per category
- `pnpm validate:mappings` CI guard
- `resolveMarkdownFile()` — GitHub-compatible contents API resolver, zero dependencies
- Security CI lane: dependency audit, self-scan with SARIF upload, supply-chain assertions
- 119 tests, all passing

**Documentation and release infrastructure:**
- `docs/SKILL_SUITE.md` — canonical boundary definitions for all five packages
- `docs/SUPPLY_CHAIN.md` — full threat model, provenance verification, lockfile security
- `docs/RISK_SCORING.md` — accurate scoring algorithm, risk legend, composite escalation
- `.github/workflows/publish.yml` — OIDC provenance publish workflow (no long-lived tokens)
- `examples/suite/` — canonical fixture set: clean, malicious, suppressed + canonical JSON reports
- `pnpm demo` — one-command scan → audit demo
- Policy preset table in README, package badges, "known limitations" blocks across all three packages

**What's clean:**
- Zero runtime dependencies — asserted in CI
- Typecheck clean, `pnpm pack --dry-run` clean
- `--audit-suppressions` now emits scan report + audit together (not audit-only)
- SARIF upload in security CI self-scans example skills on every push
- Supply chain CI: lockfile registry source check, frozen lockfile install

## v0.4 Candidates

**Highest value:**

- **`skill-safe.config.json`** — project-level policy (preset, extraRules, npmPolicy, failOn)
  without CLI flag repetition. Required for monorepos and marketplace integrations.
- **Per-file source override in directory scans** — let callers map file paths to
  different trust sources, enabling mixed-trust workspace scans.
- **Suppression expiry** — `<!-- skill-safe-ignore SS001: reason -- expires: 2026-06-01 -->`
  so suppressions auto-flag when they age out.
- **Rule fixture suite** — one `good.md` / `bad.md` / `obfuscated.md` per rule category,
  run as integration tests. Modeled after Semgrep's fixture-per-rule pattern.
- **`--coverage` report** — which rules fired across the batch; which never fired.
  Surfaces dead rules and helps operators tune presets.
- **`permissive` preset** — for local dev where blocking on `review` is too noisy.
- **More source-policy checks:**
  - npm maintainer account age (new maintainer = supply-chain risk)
  - repository archived/disabled status via GitHub API
  - license mismatch between package.json and SPDX registry
- **Release provenance docs and templates**:
  - npm trusted publishing / provenance checklist
  - signed tag guidance
  - release tarball verification
  - CI example for strict marketplace ingestion
- **Host-integration recipes**:
  - wallet / NFT host flow: scan first, multisig or Safe policy later
  - marketplace ingestion flow: ledger discover, safe scan, UI review
  - local workspace flow: scan, suppressions audit, runtime allowlist

**Rule additions (next batch):**
- Git credential helper reads (`git credential`, `~/.git-credentials`)
- Cloud metadata endpoint access (`169.254.169.254`)
- Container escape patterns (`--privileged`, `hostPID`, `/proc/1/root`)
- Token leakage via URLs (auth tokens in query strings)

**Supply chain hardening (next batch):**
- Lockfile-lint in CI — assert no unexpected registry sources programmatically
- Release artifact checksums — SHA-256 digest published alongside each GitHub release
- Fixture coverage report — CI assert every rule has a `bad.md` before each minor
- npm `--provenance` verification guide in contributor docs

## Out Of Scope For Core

These belong in companion packages or host runtimes, not the zero-dep core scanner:

- **Call-graph static analysis** (`skill-safe-judge` or a dedicated static layer)
  — tracing whether entry points can reach dangerous functions like `fs.rm` or `fetch`
- **Runtime containment** (`skill-safe-runtime`)
  — container isolation, blast-radius constraints, tool allowlists at execution time
- **LLM-based semantic scanning** (`skill-safe-judge`)
  — reading natural-language instructions to catch intent-based evasion
- blockchain transaction approval
- Safe{Core} SDK wrappers
- wallet key custody
- LLM semantic classification
- agent tool-call authorization

The core scanner should keep producing deterministic evidence. Hosts decide
what to do with that evidence.

## v1.0 Readiness Bar

- Stable public API and package exports — no breaking changes after 1.0.
- Stable report schema — additive-only changes, versioned.
- Stable `SS###` rule IDs — IDs are never reassigned.
- Complete rules reference with fixture examples per rule.
- CI verifies: install, typecheck, build, tests, mapping validation, example smoke, pack dry-run.
- Security CI: dependency audit, self-scan with SARIF upload, zero-dep assertion.
- Contribution guide covers: rules, mappings, tests, report schema, SARIF.
- Security policy with responsible disclosure, supported versions, and contact.

## Adjacent Packages

These stay separate from the deterministic core:

- **`@gsknnft/skill-safe-judge`** — optional LLM semantic review layer.
- **`@gsknnft/skill-safe-runtime`** — runtime tool-call and trace enforcement.
- **`@gsknnft/skill-ledger`** — installation, manifesting, sync, and inventory.

The core scanner produces evidence. Host applications decide whether to
install, warn, quarantine, require review, or block.
