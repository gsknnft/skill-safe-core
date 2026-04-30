# Contributing

`skill-safe` is intentionally small: zero runtime dependencies, deterministic
results, and auditable TypeScript.

## Local Checks

Run these before opening a PR:

```sh
pnpm install
pnpm build
pnpm test
pnpm validate:mappings
pnpm validate:rules
pnpm example:batch
pnpm pack --dry-run
```

## Adding Rules

1. Add the rule to `src/rules.ts`.
2. Assign the next stable `SS###` ID. Never reuse or rename an existing ID.
3. Add or verify governance mappings in `src/mappings.ts`.
4. Add tests covering:
   - malicious match
   - at least one benign non-match when false positives are plausible
   - obfuscated form when relevant
5. Add a representative sample to `tests/ruleFixtures.test.ts`.
6. Update `docs/RULES_REFERENCE.md` if the rule creates a new range/category.

## Suppressions

Suppressions must include a reason:

```md
<!-- skill-safe-ignore SS001: documented false positive for local fixture -->
```

Do not make suppressions honored by default. Untrusted skills must not be able to
silence their own findings.

## Report Schema

Report schema changes should be additive. Do not remove existing fields from:

- `SkillScanReport`
- `SkillSafeFullReport`
- SARIF output

Update `docs/REPORT_SCHEMA.md` and tests when adding report fields.

## Dependencies

Do not add runtime dependencies to the core package. Dev dependencies for tests
or build tooling are acceptable when they are justified and pinned in
`package.json`.
