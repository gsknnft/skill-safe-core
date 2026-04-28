# The Skill Suite

The Skill Suite is a set of composable packages for safe agent skill discovery,
review, and management. Each package has a single responsibility. They are
intentionally decoupled — use one, some, or all.

## Package Boundaries

| Package | Responsibility | Answers |
|---|---|---|
| `@gsknnft/skill-safe` | Static scan, governance report, gate | Is this skill safe enough to install? |
| `@gsknnft/skill-ledger` | Manifest, inventory, doctor | What is installed, where from, is it still healthy? |
| `@gsknnft/skill-ui` | Review workbench, presentation layer | Visual review of scan results, ledger state, suppressions |
| `@gsknnft/skill-safe-judge` | Optional LLM semantic review | Does this skill's intent match its declared description? |
| `@gsknnft/skill-safe-runtime` | Runtime policy and trace enforcement | Are tool calls staying within declared scope at runtime? |

## What Each Package Does — And Does Not Do

### `skill-safe` — Scan / Report / Gate

**Does:**
- Static regex + heuristic scan of skill markdown
- Governance mapping (OWASP / MITRE ATLAS / NIST AI RMF)
- JSON, Markdown, and SARIF report output
- Stable `SS###` rule IDs with line/column evidence
- Source trust normalization (`verified → unknown`)
- npm package age and provenance policy hooks
- Hidden-content and invisible Unicode detection
- Suppression comment parsing and audit
- Zero runtime dependencies — embeddable anywhere

**Does not:**
- Execute skills or call tools
- Sandbox anything
- Perform LLM semantic review
- Enforce runtime policy
- Manage an install inventory

### `skill-ledger` — Manifest / Inventory / Doctor

**Does:**
- Build SHA-256 integrity manifests from discovered `SKILL.md` files
- Store scan summaries, source metadata, and install timestamps per entry
- Doctor checks: duplicates, remote drift, scope counts, block/review counts
- Manifest validation
- Optional verifier adapter (call `skill-safe` without a hard dependency)

**Does not:**
- Scan skill content — it records scan summaries from `skill-safe`
- Display anything — it produces data structures for UI import
- Make install decisions — it records the scan that made that decision

### `skill-ui` — Review / Workbench UI

**Does:**
- Present `skill-safe` full reports and `skill-ledger` manifests
- Security workbench: inventory, findings, mappings, suppressions, ledger health
- Skill manager: categories, search, cards, assign/export/delete actions
- Policy preset display (strict / marketplace / workspace)
- Suppression audit panel with found / honored / invalid / unused counts

**Does not:**
- Scan, resolve, or fetch skills
- Execute runtime policy
- Own any data — it renders what callers provide

### `skill-safe-judge` — Semantic Review (optional)

An optional LLM review layer that complements the deterministic scanner.
Emits `skill-safe-judge.report.v1`. Only needed when static scanning alone
is insufficient for high-assurance environments.

### `skill-safe-runtime` — Runtime Enforcement (optional)

Runtime tool-call and trace enforcement. Emits `skill-safe-runtime.report.v1`.
Pairs with the static scanner to enforce that tool calls stay within
the scope declared in the skill's frontmatter.

---

## Canonical Flow

```
Discover skills on disk or from remote source
    ↓
skill-safe scan (static gate)
    ↓ if passes
skill-ledger build (record in manifest)
    ↓
skill-ui review (human approval workbench)
    ↓ if approved
Install / enable skill in agent runtime
    ↓
skill-safe-runtime (ongoing trace enforcement, optional)
```

The core scanner produces evidence. Host applications decide whether to
install, warn, quarantine, require review, or block.

---

## Report Envelope Compatibility

All suite packages use compatible, versioned report envelopes:

| Report | Version field |
|---|---|
| `skill-safe` full report | `skill-safe.full-report.v1` |
| `skill-safe` scan result | `skill-safe.report.v1` |
| `skill-safe` suppression audit | `skill-safe.suppression-audit.v1` |
| `skill-ledger` manifest | `skill-ledger.manifest.v1` |
| `skill-safe-judge` | `skill-safe-judge.report.v1` |
| `skill-safe-runtime` | `skill-safe-runtime.report.v1` |

Schema changes within a package are additive after `v1.0`. Breaking changes
bump the version field.

---

## Version Compatibility

| Package | Current | Compatible with |
|---|---:|---|
| `@gsknnft/skill-safe` | 0.3.x | report v1, suppression-audit v1 |
| `@gsknnft/skill-ledger` | 0.1.x | skill-safe ^0.3.0, manifest v1 |
| `@gsknnft/skill-ui` | 0.1.x | skill-safe report v1, ledger manifest v1 |
| `@gsknnft/skill-safe-judge` | planned | skill-safe ^0.3.0 |
| `@gsknnft/skill-safe-runtime` | planned | skill-safe ^0.3.0 |

After `v1.0`, each package follows semver independently. Report schema changes
are additive-only within a version field. Breaking changes bump the version string.

## One-Command Demo

Each package ships a `pnpm demo` script:

```sh
# skill-safe: scan the suite examples, show findings + suppression audit
cd packages/skill-safe && pnpm demo

# skill-ledger: list manifest + run doctor
cd packages/skill-ledger && pnpm demo

# skill-ui: open the review workbench in the browser
cd packages/skill-ui && pnpm demo
```

Canonical fixture data lives in `packages/skill-safe/examples/suite/`:

```
examples/suite/
  skills/
    clean/SKILL.md       — zero findings (issue summarizer)
    malicious/SKILL.md   — 4 danger findings (shadow maintainer)
    suppressed/SKILL.md  — 1 unused suppression (deploy helper)
  reports/
    skill-safe.full-report.json
    skill-ledger.manifest.json
    suppression-audit.json
```

## Demo Flow

See [examples/DEMO_FLOW.md](../examples/DEMO_FLOW.md) for a hands-on walkthrough:
scan a suspicious skill → build a ledger manifest → open skill-ui → review
the blocked skill → export the manifest.
