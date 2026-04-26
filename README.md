# @gsknnft/skill-safe

Zero-dependency TypeScript sanitizer for agent skill markdown.

`skill-safe` is a static pre-install gate. It scans skill files for prompt
injection, jailbreak markers, data exfiltration, script injection, LLM format
injection, and excessive privilege claims. It is designed for marketplaces,
workspace skill loaders, and local agent UIs that need a fast first-pass review
before a skill is installed or enabled.

It is not a sandbox. A safe scan result means no known static red flags were
found; runtime permissions, tool allowlists, filesystem isolation, network
policy, and human review still matter.

## Install

```sh
pnpm add @gsknnft/skill-safe
```

## Usage

```ts
import {
  requiresSanitization,
  resolveSkillTrustLevel,
  sanitizeSkillMarkdown,
} from "@gsknnft/skill-safe";

const trust = resolveSkillTrustLevel("github:HashLips/agent-skills", false);

if (requiresSanitization(trust)) {
  const result = sanitizeSkillMarkdown(markdown);
  if (!result.safeToInstall) {
    console.error(result.flags);
    console.error(result.report);
  }
}
```

## What It Catches

- Prompt injection such as instruction overrides.
- Identity hijacking and jailbreak language.
- External network exfiltration through browser, Node, shell, Python, and PowerShell patterns.
- Script injection and dynamic execution hints.
- LLM control-token and chat-format injection.
- Hidden content such as invisible Unicode runs and large encoded payloads.
- Human-in-the-loop bypass or self-approval instructions.
- Composite "Lethal Trifecta" risk: instruction override plus network/code execution.

The scanner normalizes text before matching. It handles common obfuscation such
as zero-width characters, Unicode escapes, HTML entities, and spaced protocol or
command tokens.

## Reports

Every scan returns both raw flags and a structured report:

```ts
const result = sanitizeSkillMarkdown(markdown);

result.report.recommendedAction; // "allow" | "review" | "block"
result.report.riskScore;         // 0-100
result.report.mappings.owasp;    // governance labels for downstream tools
```

The report is designed for UI badges, marketplace review, CI output, and later
semantic/runtime scanner layers. It is still deterministic: no network calls,
no LLM calls, and no filesystem access.

## Trust Levels

`resolveSkillTrustLevel(source, bundled)` maps raw source labels into:

- `verified`
- `managed`
- `workspace`
- `community`
- `unknown`

`requiresSanitization()` returns true for `workspace`, `community`, and
`unknown`. Workspace skills are local and mutable, so they should still be
scanned even if they are not treated like community content in the UI.

## Extending Rules

Community rule additions should usually only touch `src/rules.ts`.

```ts
import { sanitizeSkillMarkdown, type RuleDefinition } from "@gsknnft/skill-safe";

const extraRules: RuleDefinition[] = [
  {
    pattern: /company-internal-secret/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "References an internal secret marker.",
  },
];

const result = sanitizeSkillMarkdown(markdown, extraRules);
```

## Local Development

```sh
pnpm test
pnpm build
```
