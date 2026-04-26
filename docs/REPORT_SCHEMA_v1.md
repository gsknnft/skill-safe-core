# TODO: Add a minimal REPORT_SCHEMA.md


Core, this is the right instinct — **the report contract *is* the product**.
Skill scanners live or die by the stability of their output shape, and you’re about to lock the first public version. That means `REPORT_SCHEMA.md` becomes the canonical truth for:

- Claw3D / OpenClaw
- souls.zip marketplace
- local WorkLab loaders
- Campus multi-agent ingestion
- GitHub skill imports
- unknown / community sources
- your own agent harnesses

So let’s turn your draft into a **proper, production‑ready schema doc** — crisp, explicit, and aligned with the v1/v2/v3 roadmap.

Below is a refined version that fits the tone and rigor of the rest of `skill-safe-core`.

Core, this is the schema you want to ship before `0.1.0`.
It’s stable, explicit, and future‑proof — and it gives every downstream consumer a contract they can rely on.

If you want, I can also generate:

- `INTEGRATION_GUIDE.md`
- `RULES_REFERENCE.md`
- `RISK_SCORING.md`
- `SARIF_OUTPUT.md`
- or a full `docs/` folder structure

Just tell me which one you want next.


This should be included before 0.1.0 because the biggest value is the report contract.

Add:

packages/skill-safe/docs/REPORT_SCHEMA.md

Cover:

SanitizationResult
SanitizationFlag
SkillScanReport
recommendedAction
riskScore semantics
mappings
safeToInstall caveat

This matters for adding from;
Directly (own local agent, own GPT, own hand)
Github
Unknown sources
Other agent harnesses
Claw3D/OpenClaw/souls.zip marketplace integration because the consuming pipeline needs a stable report shape.

---

# REPORT_SCHEMA.md

This schema defines the contract for skill sanitization reports. It ensures a stable, predictable structure for consuming pipelines, including Claw3D/OpenClaw/souls.zip marketplace integration, agent harnesses, and direct/manual additions.

## Objects

### `SanitizationResult`
- **flags**: `SanitizationFlag[]` — List of detected issues or warnings.
- **riskScore**: `number` — Numeric risk score (0 = safe, higher = more risk).
- **recommendedAction**: `string` — Suggested action (e.g., "allow", "review", "block").
- **safeToInstall**: `boolean` — True if the skill is considered safe for installation.
- **mappings**: `object` — Optional, maps detected issues to their descriptions or categories.

### `SanitizationFlag`
- **id**: `string` — Unique identifier for the flag.
- **severity**: `string` — Severity level (e.g., "low", "medium", "high").
- **description**: `string` — Human-readable explanation of the issue.

### `SkillScanReport`
- **skillId**: `string` — Unique identifier for the scanned skill.
- **result**: `SanitizationResult` — The result object as above.
- **source**: `string` — Where the skill was sourced (e.g., "github", "local", "marketplace", "unknown").

## Field Semantics

- **riskScore**: 0 = safe, 1–3 = review, 4+ = block or escalate.
- **recommendedAction**: Should be one of "allow", "review", "block".
- **safeToInstall**: Always false if any high-severity flag is present.

## Integration Caveats

- All consumers must check `safeToInstall` before installation.
- Reports must be stable and forward-compatible for all sources (local, GitHub, unknown, agent harnesses, marketplace).

---

Let me know if you want this added to the file or need further details for any field.
