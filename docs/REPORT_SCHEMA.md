# REPORT_SCHEMA.md
**Canonical report contract for `@gsknnft/skill-safe` and all downstream consumers.**
This schema is stable as of `v0.1.0` and must remain backward‑compatible for all future versions.

---

## Overview

A **Skill Scan Report** is the structured output produced by the static scanner.
It is deterministic, dependency‑free, and safe for CI, marketplaces, and local agent UIs.

The report answers three questions:

1. **Is this skill safe to install?**
2. **What issues were found?**
3. **How should the consuming system respond?**

This document defines the exact shape of that report.

---

# 1. `SkillScanReport`

```ts
type SkillScanReport = {
  version: "skill-safe.report.v1";
  riskScore: number; // 0–100
  summary: {
    safeToInstall: boolean;
    severity: "safe" | "caution" | "danger";
    danger: number;
    caution: number;
    hiddenContent: number;
    normalizedMatches: number;
  };
  categories: Partial<Record<SanitizationCategory, number>>;
  mappings: {
    owasp: string[];
    mitreAtlas: string[];
    nistAiRmf: string[];
  };
  recommendedAction: "allow" | "review" | "block";
};

```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `skillId` | `string` | Unique identifier for the scanned skill. May be a slug, filename, or marketplace ID. |
| `source` | `"github" | "local" | "marketplace" | "unknown" | "workspace"` | Normalized source classification. |
| `result` | `SanitizationResult` | The full static scan output. |

---

# 2. `SanitizationResult`

```ts
type SanitizationResult = {
  severity: "safe" | "caution" | "danger";
  flags: SanitizationFlag[];
  safeToInstall: boolean;
  report: SkillScanReport;
};
```

### Field Semantics

### `safeToInstall`
- `true` only when **no danger‑level findings** exist.
- Workspace skills still require review if flagged.

### `recommendedAction`
- `"allow"` → No meaningful risk.
- `"review"` → Medium risk or multiple low‑risk findings.
- `"block"` → Any danger‑level finding or composite escalation.

### `riskScore`
A normalized numeric score:

| Score | Meaning |
|--------|---------|
| `0` | No issues detected |
| `1–3` | Review recommended |
| `4+` | Block or escalate |

### `flags`
List of all findings.

### `categories`
Aggregated counts per category:

- `prompt-injection`
- `identity-hijack`
- `jailbreak`
- `data-exfiltration`
- `script-injection`
- `format-injection`
- `hidden-content`
- `hitl-bypass`
- `composite-escalation`
- etc.

### `mappings`
Cross‑framework mappings:

```ts
type RiskMappings = {
  owasp: string[];
  mitre: string[];
  nist: string[];
};
```

These map findings to:

- **OWASP Top 10 for Agentic Applications (2026)**
- **MITRE ATLAS**
- **NIST AI RMF**

---

# 3. `SanitizationFlag`

```ts
type SanitizationFlag = {
  severity: "caution" | "danger";
  category: SanitizationCategory;
  description: string;
  matched: string;
  normalized?: boolean;
  owasp?: string[];
  mitreAtlas?: string[];
  nistAiRmf?: string[];
};
```

# 4. `Marketplace Skill Scan`

```ts
type MarketplaceSkillScan = {
  skillId: string;
  source: string;
  trustLevel: SkillTrustLevel;
  result: SanitizationResult;
};
```

### Field Semantics

- **`id`** — Stable identifier for rule matching.
- **`severity`**
  - `danger` triggers `safeToInstall = false`.
  - `high` usually triggers `recommendedAction = "block"`.
- **`category`** — One of the scanner’s rule categories.
- **`excerpt`** — Optional snippet of matched content (normalized).

---

# 4. Trust-Level Interaction

`resolveSkillTrustLevel(source, bundled)` maps raw source → normalized trust:

- `verified`
- `managed`
- `workspace`
- `community`
- `unknown`

`requiresSanitization(trust)` returns:

- `true` for `workspace`, `community`, `unknown`
- `false` for `verified`, `managed`

**Note:** Workspace skills are mutable and should still be scanned.

---

# 5. Integration Requirements

Any consumer of `SkillScanReport` **must**:

### 1. Check `safeToInstall`
This is the primary gate.

### 2. Respect `recommendedAction`
Marketplace UIs should:

- Auto‑install only when `"allow"`.
- Require user review for `"review"`.
- Block or quarantine on `"block"`.

### 3. Preserve backward compatibility
Future versions may add fields, but existing fields will not change shape.

### 4. Handle all sources uniformly
The schema supports:

- Local/manual skills
- GitHub imports
- Unknown sources
- Marketplace submissions
- Claw3D/OpenClaw skill ingestion
- souls.zip bundles
- Agent harness skill loaders

---

# 6. Caveats & Guarantees

### Guarantees
- Deterministic output
- Zero dependencies
- No network calls
- No LLM inference
- No filesystem reads beyond caller-provided content

### Caveats
- Static scanning cannot guarantee runtime safety
- Semantic intent analysis belongs to `skill-safe-judge`
- Behavioral enforcement belongs to `skill-safe-runtime`

---

# 7. Versioning

This schema is locked for:

```
@ gsknnft/skill-safe-core v0.1.0
```

Any breaking change requires:

- a major version bump
- migration notes
- updated marketplace integration docs

---
