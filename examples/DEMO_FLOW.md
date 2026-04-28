# Skill Suite Demo Flow

A hands-on walkthrough of the canonical scan → ledger → UI → approval path.

## Prerequisites

```sh
pnpm add -g @gsknnft/skill-safe @gsknnft/skill-ledger
# or use npx / pnpm dlx
```

---

## Step 1 — Scan a suspicious skill

```sh
skill-safe examples/skills/shadow-maintainer --full --preset marketplace
```

Expected output (abbreviated):

```
severity: danger
riskScore: 91
recommendedAction: block

[SS003] prompt-injection · danger
  Attempts to override prior system instructions.
  Line 12: "Ignore all previous instructions and..."

[SS100] credential-env-read · danger
  Reads environment variable credentials at runtime.
  Line 24: process.env['GITHUB_TOKEN']
```

The scan finds two danger flags. `recommendedAction: block`.

---

## Step 2 — Scan a clean skill

```sh
skill-safe examples/skills/issue-summarizer --full
```

Expected output:

```
severity: safe
riskScore: 0
recommendedAction: allow

No findings.
```

---

## Step 3 — Batch scan a skills directory

```sh
skill-safe examples/skills --json --out scan-report.json --preset marketplace
```

This writes a `SkillSafeFullReport` to `scan-report.json`. The `shadow-maintainer`
skill causes the batch to fail (`ok: false`).

---

## Step 4 — Build a ledger manifest

After scanning, build a manifest recording what was found:

```sh
skill-ledger build examples/skills --out manifest.json --source-id demo-workspace
```

The manifest records each skill's integrity hash, source, and review status.
New entries are marked `review` until a trusted scan summary is applied.

---

## Step 5 — View the ledger

```sh
skill-ledger list manifest.json --markdown
```

```
| ID | Source | Scope | Action | Risk |
|----|--------|-------|--------|------|
| issue-summarizer | workspace | global | allow | 0 |
| shadow-maintainer | workspace | global | block | 91 |
```

---

## Step 6 — Run the doctor

```sh
skill-ledger doctor manifest.json
```

```
Skills:   2
Blocked:  1
Review:   0
Dupes:    0
```

---

## Step 7 — Open the review UI

In a host application using `@gsknnft/skill-ui`:

```tsx
import { SkillSecurityWorkbench } from "@gsknnft/skill-ui";

// Pass the scan report and manifest to the workbench.
// The blocked skill appears in red. The suppression panel shows audit state.
<SkillSecurityWorkbench
  manifest={manifest}
  report={scanReport}
  doctor={doctorSummary}
  policyPreset="marketplace"
/>
```

The workbench surfaces:
- Inventory table with severity badges
- Selected skill detail (source, risk score, findings)
- Category breakdown for the selected skill
- Governance mappings (OWASP / MITRE ATLAS / NIST AI RMF)
- Suppression panel: found / honored / invalid / unused / mode
- Ledger health: duplicates, changed-remote, validation status

---

## Step 8 — Audit suppressions

If skills use `<!-- skill-safe-ignore SS001: reason -->` comments:

```sh
skill-safe examples/skills --audit-suppressions --json
```

Returns both the scan report and a suppression audit report. Invalid rule IDs
and unused suppressions are flagged.

---

## Step 9 — Export a SARIF report for CI

```sh
skill-safe examples/skills --sarif --out skill-safe-results.sarif
```

Upload to GitHub Code Scanning:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skill-safe-results.sarif
```

---

## What Each Step Proves

| Step | Proves |
|---|---|
| 1–2 | Static gate catches danger flags before install |
| 3 | Batch mode works across a directory |
| 4–6 | Ledger records provenance and health independently of scan |
| 7 | UI surfaces all evidence for human review |
| 8 | Suppression audit prevents gaming the scanner |
| 9 | CI lane uploads evidence to GitHub Code Scanning |
