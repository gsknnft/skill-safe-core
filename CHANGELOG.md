# Changelog

All notable changes to `@gsknnft/skill-safe` are documented here.

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
- Composite "Lethal Trifecta" escalation.
- Trust-level normalization for verified, managed, workspace, community, and
  unknown sources.
- Structured `SkillScanReport` output.
- CLI entrypoint.
