# skill-safe Roadmap

`@gsknnft/skill-safe` should stay the deterministic, zero-runtime-dependency
gate for agent skill markdown. The core package should remain small,
auditable, and embeddable in CLIs, marketplaces, local apps, and CI.

## v0.3.x Hardening

- Keep suppressions report-only by default.
- Add tests for every new rule and every source-level policy.
- Keep `pnpm validate:mappings` green before release.
- Keep `pnpm pack --dry-run` clean and free of generated report artifacts.
- Expand SARIF coverage with stable rule IDs, locations, fingerprints, and
  governance mappings.
- Add config-file support only if it stays deterministic and explicit.
- Keep remote resolving optional and fetch-injected for testability.

## v0.4 Candidates

- Policy presets:
  - `strict`
  - `marketplace`
  - `workspace`
  - `permissive`
- `skill-safe.config.json` for CI and marketplace use.
- Suppression audit mode:
  - invalid suppressions
  - unused suppressions
  - expired suppressions
- Rule quality fixtures:
  - benign
  - malicious
  - obfuscated
  - source-policy
- More source-policy checks:
  - npm maintainer age
  - repository archive status
  - default branch protection signal when available
  - package/license mismatch warnings
- More static rules:
  - credential file reads
  - SSH key reads
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
