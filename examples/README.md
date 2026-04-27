# skill-safe Examples

These examples exercise the built package the same way a downstream app,
marketplace, or CI workflow would consume it.

Run from `packages/skill-safe`:

```sh
pnpm example:smoke
pnpm example:json
pnpm example:markdown
node dist/cli.js examples/skills --json --fail-on never
```

`example:smoke` scans:

- a safe local skill fixture
- a malicious local skill fixture
- a mocked `github:` source through the resolver
- a custom `hermes:` resolver hook

The full batch report is expected to fail because it intentionally includes the
malicious fixture. The safe fixture should still show `safeToInstall: true`,
`recommendedAction: "allow"`, and `riskScore: 0` inside its own document entry.

It writes full report artifacts to `examples/reports/`:

- `skill-safe-batch-report.json`
- `skill-safe-batch-report.md`
- `skill-safe-safe-only-report.json`
- `skill-safe-safe-only-report.md`
- `skill-safe-source-descriptors.json`

Generated reports are ignored by git so local smoke runs do not create package
churn.
