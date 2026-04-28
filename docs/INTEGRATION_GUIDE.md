# Integration Guide

How to integrate `@gsknnft/skill-safe` into marketplaces, loaders, agent
harnesses, and CI.

`skill-safe` is the deterministic static gate. It does not run skills, call
LLMs, sandbox tools, or approve transactions. Use it before install, then let
host policy decide whether to allow, review, quarantine, or block.

## Layers

| Layer | Package | Purpose |
| --- | --- | --- |
| Static | `@gsknnft/skill-safe` | Zero-dependency scan, reports, SARIF, policy presets |
| Ledger | `@gsknnft/skill-ledger` | Manifest, inventory, doctor, skill library state |
| UI | `@gsknnft/skill-ui` | Review workbench and manager surface |
| Semantic | `@gsknnft/skill-safe-judge` | Optional LLM intent analysis |
| Runtime | `@gsknnft/skill-safe-runtime` | Tool-call, taint, trace, and allowlist enforcement |

## Minimal Static Integration

```ts
import {
  requiresSanitization,
  resolveSkillTrustLevel,
  sanitizeSkillMarkdown,
} from "@gsknnft/skill-safe";

export function scanSkill({ markdown, source, bundled = false }) {
  const trust = resolveSkillTrustLevel(source, bundled);

  if (!requiresSanitization(trust)) {
    return {
      safeToInstall: true,
      recommendedAction: "allow",
      reason: "trusted-source",
    };
  }

  const result = sanitizeSkillMarkdown(markdown);

  return {
    trust,
    safeToInstall: result.safeToInstall,
    recommendedAction: result.report.recommendedAction,
    report: result.report,
    flags: result.flags,
  };
}
```

## Directory / Marketplace Scan

Use batch scanning when ingesting a directory or marketplace submission set.

```ts
import { scanSkillDirectory } from "@gsknnft/skill-safe";

const { report, files } = await scanSkillDirectory("./skills", {
  failOn: "review",
  suppressionMode: "report-only",
  resolveSource(file) {
    if (file.relativePath.startsWith("internal/")) return "workspace";
    return "community";
  },
});

if (!report.ok) {
  // Store report, open review queue, block installs, or upload SARIF.
}
```

Per-file source override is useful when a workspace mixes verified internal
skills, community imports, and temporary local experiments in one tree.

## Config-Driven CLI

For repeatable CI or monorepos, add `skill-safe.config.json`:

```json
{
  "preset": "marketplace",
  "failOn": "review",
  "suppressionMode": "report-only",
  "npmPolicy": {
    "minAgeDays": 7,
    "requireProvenance": false
  },
  "scan": {
    "include": ["skills", "examples/skills"],
    "exclude": ["node_modules", "dist"],
    "maxDepth": 12
  }
}
```

Then run:

```sh
skill-safe --json --coverage --audit-suppressions
```

With no explicit target, the CLI scans configured `scan.include` paths.

## Policy Presets

| Preset | Intended use |
| --- | --- |
| `strict` | Security review and high-assurance marketplaces |
| `marketplace` | Public/community skill ingestion |
| `workspace` | Local trusted workspaces |
| `permissive` | Local exploration without CI failure |

Example:

```sh
skill-safe ./skills --preset strict --sarif --out skill-safe.sarif
skill-safe ./skills --preset permissive --coverage --fail-on never
```

## Suppression Audit

Suppressions are report-only by default. Audit them regularly:

```sh
skill-safe ./skills --audit-suppressions --json --fail-on never
```

Suppression syntax:

```md
<!-- skill-safe-ignore SS001: tracked false positive -- expires: 2026-06-01 -->
```

The audit reports:

- invalid rule IDs
- unused suppressions
- expired suppressions

## Marketplace Flow

1. Discover or import candidates with `skill-ledger`.
2. Scan with `skill-safe` using `marketplace` or `strict`.
3. Store the full JSON report and SARIF artifact.
4. Display:
   - recommended action
   - risk score
   - findings
   - governance mappings
   - suppression audit state
5. Require review for `review`.
6. Quarantine or block `block`.

## Wallet / NFT Host Flow

`skill-safe` is not a wallet security layer. Wallet-aware hosts should use it as
the first gate only:

1. Scan candidate skill markdown.
2. Block dangerous static findings.
3. Require human review for caution/review findings.
4. Apply host runtime policy, wallet scopes, Safe{Core}, multisig, or approval
   gates only when a skill attempts asset-moving actions.

## CI Flow

Recommended strict ingestion:

```sh
skill-safe ./skills \
  --preset strict \
  --audit-suppressions \
  --coverage \
  --sarif \
  --out skill-safe.sarif
```

Upload SARIF to GitHub Code Scanning or your CI security dashboard.

## Versioning

Report envelopes are versioned:

- `skill-safe.report.v1`
- `skill-safe.full-report.v1`
- `skill-safe.suppression-audit.v1`
- `skill-safe.coverage.v1`

Future additions should be additive where practical.

## Related Docs

- [Report schema](REPORT_SCHEMA.md)
- [Rules reference](RULES_REFERENCE.md)
- [SARIF output](SARIF_OUTPUT.md)
- [Risk scoring](RISK_SCORING.md)
- [Supply-chain hardening](SUPPLY_CHAIN.md)
- [Skill suite boundaries](SKILL_SUITE.md)
