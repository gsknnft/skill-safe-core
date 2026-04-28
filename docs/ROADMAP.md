## v0.3.x Shipped

- Policy presets and CLI flag (`--preset strict|marketplace|workspace`)
- Rule quality fixtures (benign, malicious, obfuscated, source-policy)
- More source-policy checks (npm maintainer age, repo archive status, etc.)
- More static rules:
  - credential file reads
  - SSH key reads
  - `.env` exfiltration
  - clipboard exfiltration
  - recursive delete
  - shell profile modification
  - remote prompt loading
  - `curl | bash` and PowerShell remote execution chains
- Suppression audit mode and CLI flag (`--audit-suppressions`)
- SARIF coverage with stable rule IDs, locations, fingerprints, and governance mappings
- Mapping registry and validation
- Tests for every new rule and every source-level policy
- `pnpm validate:mappings` and `pnpm pack --dry-run` as release gates
- Remote resolving is fetch-injected and testable

## v0.4 Next

- `--audit-suppressions` should emit both the audit and the scan report (not just audit)
- `--preset` should print in the report header so CI logs are self-documenting
- Config-file support (`skill-safe.config.json`) if deterministic and explicit
- More governance mapping coverage and validation
- More static rule coverage as new threats emerge
  - `.env` exfiltration
  - clipboard exfiltration
  - recursive delete
  - shell profile modification
  - remote prompt loading
  - `curl | bash` and PowerShell remote execution chains

## v1.0 Readiness Bar

- Stable public API and package exports.
- Stable report schema with additive-only changes.
- Stable `SS###` rule IDs.
- Complete rules reference with examples.
- CI verifies:
  - install
  - typecheck/build
  - tests
  - mapping validation
  - example smoke
  - pack dry-run
- Clear contribution guide for rules, mappings, tests, and report changes.
- Security policy with responsible disclosure contact and supported versions.

## Adjacent Packages

These should stay separate from the deterministic core:

- `@gsknnft/skill-safe-judge`: optional LLM semantic review.
- `@gsknnft/skill-safe-runtime`: runtime tool-call and trace enforcement.
- `@gsknnft/skill-ledger`: installation, manifesting, sync, and inventory.

The core scanner should produce evidence. Host applications decide whether to
install, warn, quarantine, require review, or block.
