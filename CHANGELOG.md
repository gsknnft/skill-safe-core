# Changelog

All notable changes to `@gsknnft/skill-safe` are documented here.

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
