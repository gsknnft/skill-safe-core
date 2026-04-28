# Changelog

All notable changes to `@gsknnft/skill-safe` are documented here.

## 0.3.1 - Unreleased

### Security

- Removed implicit environment-token lookup from `resolveMarkdownFile()`.
- Built-in network resolvers now require an explicit `fetcher` from the host.
  The CLI still injects `globalThis.fetch` because remote source scanning is an
  explicit CLI feature.
- Reduced static-analysis false positives in package scanners by removing
  executable-looking `eval()` and `process.env` literals from scanner internals
  and docs.
- Restored frozen lockfile install in the publish workflow.

## 0.3.0 - 2026-04-27

### Added

- Added structured governance mapping registry:
  - `GovernanceFramework`
  - `MappingConfidence`
  - `GovernanceMapping`
  - `CATEGORY_MAPPINGS`
  - `getMappingsForCategory()`
  - `toReportArrays()`
  - `getCategoryReportArrays()`
- Added package subpath export:
  - `@gsknnft/skill-safe/mappings`
- Added versioned governance mapping metadata for:
  - OWASP Agentic AI
  - OWASP LLM Top 10
  - MITRE ATLAS
  - NIST AI RMF
- Added mapping confidence metadata:
  - `direct`
  - `related`
  - `inferred`
- Added suppression comment support — `<!-- skill-safe-ignore SS001: reason -->`.
- Added three-mode `SuppressionMode`: `"report-only"` (default), `"honor"`, `"disabled"`.
  - **Security note:** default is `"report-only"` — untrusted skills cannot silence their own findings.
- Added CLI flags `--honor-suppressions` and `--no-suppressions`.
- Added public `parseSuppressions()` API.
- Added `SanitizationSuppression` metadata (`ruleId`, `reason`, `line`) to `SanitizationResult`.
- Added suppression aggregate count to `SkillSafeReportSummary`.
- Added `suppressionMode` option to `ScanSkillFilesOptions` and `ScanSkillDirectoryOptions`.
- Added `SanitizationOptions` object form for `sanitizeSkillMarkdown()` (backward-compatible with legacy `RuleDefinition[]` positional arg).
- Added governance mapping validation script: `pnpm validate:mappings`.
- Added tests for mapping coverage, suppression parsing, and all new rules (112 tests total).
- Added 14 new static detection rules (SS100–SS140):
  - **SS100** — SSH private key read
  - **SS101** — `.env` secrets file read
  - **SS102** — AWS credentials file read
  - **SS103** — API key / secret env-var access
  - **SS110** — `curl | bash` remote shell execution
  - **SS111** — `wget | sh` remote shell execution
  - **SS112** — PowerShell IEX download dropper
  - **SS113** — Remote prompt load (indirect prompt injection)
  - **SS120** — Recursive force-delete (`rm -rf /`)
  - **SS121** — Disk format / zero-fill command
  - **SS130** — Shell profile write (persistence mechanism)
  - **SS131** — Crontab modification (scheduled persistence)
  - **SS140** — Clipboard exfiltration
- Added zero-dependency `resolveMarkdownFile()` / `resolveGitHubMarkdownFile()` helpers for GitHub-compatible contents APIs.
- Added v0.3+ roadmap, contribution guide, security policy, and package-local CI workflow.
- Added package subpath export:
  - `@gsknnft/skill-safe/resolve-markdown-file`
- Added policy presets:
  - `strict`
  - `marketplace`
  - `workspace`
- Added CLI flag `--preset strict|marketplace|workspace`.
- Added `POLICY_PRESETS`, `getPolicyPreset()`, and `isPolicyPreset()` public APIs.
- Added suppression audit:
  - `auditSuppressions()`
  - `--audit-suppressions`
  - invalid rule detection
  - unused suppression detection
- Added package subpath export:
  - `@gsknnft/skill-safe/policy`
- Added package subpath export:
  - `@gsknnft/skill-safe/suppression-audit`
- Added governance mapping validation script:

```bash
pnpm validate:mappings
```
- Added tests for mapping coverage and suppression parsing.

## Security
Suppression comments are parsed for audit, but not honored by default when scanning untrusted content.

### Changed

- Moved category-level governance mappings out of `rules.ts` into a dedicated mapping registry.
- Report mapping arrays are now generated from the structured registry while preserving backward-compatible report output.
- Built-in rule mappings now resolve through the shared registry fallback path.
- `resolveMarkdownFile()` now uses injected/global `fetch` instead of `axios`.
- CLI source resolution now applies preset-driven npm policy.
- Improved SS113 remote prompt loading detection to catch variable URL fetches
  before instruction/system-prompt use.

### Fixed

- Fixed `resolveMarkdownFile.ts` so it preserves the package's zero-runtime-dependency contract.

### Tests

- Current package test coverage: `119` passing tests.
- Mapping validator confirms:
  - every category has governance mappings
  - content categories cover all four frameworks
  - all built-in rules resolve to mappings
  - supply-chain categories include MITRE `AML.T0010`

## 0.2.1 - 2026-04-27

### Added

- Added stable `SS###` rule IDs and short rule names for every built-in static
  rule.
- Added source-level synthetic rule IDs for invisible-content, composite-risk,
  npm package age, and missing-provenance findings.
- Added line, column, UTF-16 offset, and UTF-8 byte offset evidence to
  content-backed findings.
- Added rule IDs and location regions to SARIF output.
- Added rule/location details to Markdown reports.

## 0.2.0 - 2026-04-26

### Added

- Added a public batch scanner API:
  - `scanSkillDirectory()`
  - `scanSkillFiles()`
  - `ScanSkillDirectoryOptions`
  - `ScanSkillFilesOptions`
  - `ScannedSkillFile`
- Added CLI directory ingestion:
  - `skill-safe ./skills --json`
  - `skill-safe --dir ./skills --json`
- Added marketplace-style example skills under `examples/skills`.
- Added `example:batch` script for directory scan smoke testing.
- Added full JSON and Markdown report helpers:
  - `createSkillSafeDocumentReport()`
  - `createSkillSafeReport()`
  - `stringifySkillSafeReportJson()`
  - `formatSkillSafeReportMarkdown()`
- Added resolver support for source-level findings through `sourceFlags`.
- Added npm source policy support:
  - package minimum-age checks
  - optional provenance requirement checks
- Added explicit governance mapping fields in reports:
  - OWASP
  - MITRE ATLAS
  - NIST AI RMF
- Added category-level default governance mappings so every finding category
  contributes OWASP / MITRE ATLAS / NIST AI RMF context to reports.
- Added new scan categories:
  - `package-age`
  - `missing-provenance`
- Added SARIF rule metadata for npm package age and missing provenance findings.
- Added source integrity helpers:
  - `computeContentIntegrity()`
  - `toSriString()`
- Added package subpath exports for:
  - `@gsknnft/skill-safe/resolver`
  - `@gsknnft/skill-safe/scanner`
  - `@gsknnft/skill-safe/sarif`
  - `@gsknnft/skill-safe/integrity`

### Changed

- Refactored the CLI into a thin wrapper over library APIs.
- Directory scanning now defaults to recursive `SKILL.md` / `skill.md` entrypoints
  instead of scanning arbitrary Markdown files.
- Full report output now includes per-document pass/review/block counts.
- Example smoke output now separates batch-fail reports from safe-only reports.
- Matched evidence truncation now uses ASCII `...` for stable terminal output.

### Fixed

- Fixed scoped npm package handling such as `npm:@scope/package`.
- Fixed npm package specs with optional nested paths.
- Fixed incomplete resolver return paths so resolved sources always include
  `sourceFlags`.
- Fixed generated report artifacts being accidentally included in package
  publish contents.

### Tests

- Added batch scanner tests.
- Added npm age-gate and provenance resolver tests.
- Current package test coverage: `76` passing tests.

## 0.1.0 - 2026-04-26

### Added

- Initial zero-dependency static skill scanner.
- Prompt injection, identity hijack, jailbreak, data exfiltration, script
  injection, format injection, hidden content, HITL bypass, and excessive-claim
  rules.
- Hidden content detection included zero-width/invisible Unicode checks,
  Unicode escapes, HTML entities, spaced command/protocol words, and large
  base64-like payload detection.
- Composite "Lethal Trifecta" escalation.
- Trust-level normalization for verified, managed, workspace, community, and
  unknown sources.
- Structured `SkillScanReport` output with governance mapping fields for OWASP,
  MITRE ATLAS, and NIST AI RMF.
- CLI entrypoint.
