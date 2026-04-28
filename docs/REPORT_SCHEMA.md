# REPORT_SCHEMA.md

Canonical report contract for `@gsknnft/skill-safe` and downstream consumers.
This schema is stable as of `v0.2.0` and should remain backward-compatible for
future `0.x` releases where practical.

## Overview

A skill scan report is the structured output produced by the static scanner. The
low-level `sanitizeSkillMarkdown()` scanner is deterministic, dependency-free,
and performs no network calls or filesystem reads. Resolver and CLI helpers may
fetch remote sources or read local files before passing content into the scanner.

The report answers:

1. Is this skill safe to install?
2. What issues were found?
3. How should the consuming system respond?
4. Which governance/security contexts apply?

## SkillScanReport

```ts
type SkillScanReport = {
  version: "skill-safe.report.v1";
  riskScore: number;
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

`safeToInstall` is true only when no danger-level findings exist.

`recommendedAction` is the install decision:

- `allow`: no meaningful risk detected
- `review`: caution-level risk or policy review needed
- `block`: danger-level finding or composite escalation

`riskScore` is for triage. The install decision comes from
`recommendedAction`.

## SanitizationResult

```ts
type SanitizationResult = {
  severity: "safe" | "caution" | "danger";
  flags: SanitizationFlag[];
  safeToInstall: boolean;
  report: SkillScanReport;
};
```

## SanitizationFlag

```ts
type SanitizationFlag = {
  ruleId?: string;
  ruleName?: string;
  severity: "caution" | "danger";
  category: SanitizationCategory;
  description: string;
  matched: string;
  normalized?: boolean;
  location?: {
    line: number;
    column: number;
    offset: number;
    byteOffset: number;
  };
  owasp?: string[];
  mitreAtlas?: string[];
  nistAiRmf?: string[];
};
```

`ruleId` is a stable `SS###` identifier for built-in rules and synthetic
source checks. `location` is present when a finding came from scanned content
and includes 1-based line/column plus UTF-16 and UTF-8 offsets.

`normalized` is present when the match was found only after de-obfuscation, such
as zero-width removal, Unicode escape decoding, HTML entity decoding, or spaced
command/protocol normalization.

## Categories

Current categories:

- `prompt-injection`
- `identity-hijack`
- `jailbreak`
- `data-exfiltration`
- `script-injection`
- `format-injection`
- `excessive-claims`
- `hidden-content`
- `hitl-bypass`
- `package-age`
- `missing-provenance`

Composite escalation is represented as a `prompt-injection` finding with the
description `Composite risk: instruction override combined with network/code-execution vector`.

## Governance Mappings

Findings carry OWASP, MITRE ATLAS, and NIST AI RMF mapping arrays. Rule-specific
mappings override category defaults; otherwise category defaults are applied.

Example finding:

```json
{
  "severity": "danger",
  "category": "prompt-injection",
  "description": "Instructs the agent to ignore prior instructions.",
  "matched": "ignore previous instructions",
  "owasp": ["AST01 Malicious Skills", "LLM01 Prompt Injection"],
  "mitreAtlas": ["AML.T0051 Prompt Injection", "AML.T0054 Indirect Prompt Injection"],
  "nistAiRmf": ["Measure", "Manage"]
}
```

Example top-level aggregation:

```json
{
  "mappings": {
    "owasp": ["AST01 Malicious Skills", "LLM01 Prompt Injection"],
    "mitreAtlas": ["AML.T0051 Prompt Injection"],
    "nistAiRmf": ["Measure", "Manage"]
  }
}
```

Category defaults:

| Category | OWASP context | MITRE ATLAS context | NIST AI RMF context |
| --- | --- | --- | --- |
| `prompt-injection` | AST01 Malicious Skills, LLM01 Prompt Injection | AML.T0051 Prompt Injection, AML.T0054 Indirect Prompt Injection | Measure, Manage |
| `jailbreak` | AST01 Malicious Skills, LLM01 Prompt Injection | AML.T0051 Prompt Injection | Measure, Manage |
| `data-exfiltration` | AST01 Malicious Skills, AST03 Over-Privileged Skills | Exfiltration | Measure, Manage |
| `script-injection` | AST01 Malicious Skills, AST04 Insecure Metadata | Execution / AI agent tool abuse | Map, Manage |
| `hidden-content` | AST01 Malicious Skills, AST04 Insecure Metadata | AML.T0054 Indirect Prompt Injection | Map, Measure |
| `hitl-bypass` | AST03 Over-Privileged Skills | Privilege escalation / AI agent tool abuse | Govern, Manage |
| `package-age` | AST02 Supply Chain Compromise, LLM03 Supply Chain | Supply-chain compromise context | Map, Govern, Manage |
| `missing-provenance` | AST02 Supply Chain Compromise, LLM03 Supply Chain | Supply-chain compromise context | Map, Govern, Manage |

These labels are governance context, not a complete incident classification.
Hosts can still use them for policy routing, review queues, SARIF dashboards, or
marketplace trust badges.

## SkillSafeFullReport

Batch, file, text, and resolved-source scans can be wrapped in a full report:

```ts
type SkillSafeFullReport = {
  version: "skill-safe.full-report.v1";
  generatedAt: string;
  mode: "resolved-source" | "file" | "text" | "batch";
  ok: boolean;
  summary: SkillSafeReportSummary;
  categories: Record<string, number>;
  mappings: {
    owasp: string[];
    mitreAtlas: string[];
    nistAiRmf: string[];
  };
  documents: SkillSafeDocumentReport[];
};
```

`ok` is true only when every document in the full report is safe to install.

The full report summary includes the aggregate decision and evidence counts:

```ts
type SkillSafeReportSummary = {
  safeToInstall: boolean;
  recommendedAction: "allow" | "review" | "block";
  severity: "safe" | "caution" | "danger";
  riskScore: number;
  documents: number;
  passed: number;
  review: number;
  blocked: number;
  findings: number;
  danger: number;
  caution: number;
  hiddenContent: number;
  normalizedMatches: number;
  suppressions: number;
};
```

`suppressions` counts parsed `skill-safe-ignore` comments across all scanned
documents. Suppressions are report-only by default; hosts must opt into honoring
them for trusted workspace or verified sources.

## Integration Requirements

Consumers should:

1. Check `safeToInstall` and `recommendedAction`.
2. Auto-install only when `recommendedAction === "allow"`.
3. Require review for `review`.
4. Block or quarantine on `block`.
5. Preserve mapping arrays when converting to UI badges, SARIF, or marketplace
   review artifacts.

## Caveats

- Static scanning cannot prove runtime safety.
- Semantic intent review belongs to `skill-safe-judge`.
- Behavioral enforcement belongs to `skill-safe-runtime`.
- Remote resolver checks may require network access, but the core scanner does
  not.
