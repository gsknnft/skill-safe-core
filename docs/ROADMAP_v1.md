# skill-safe Roadmap

`@gsknnft/skill-safe` is the static pre-install gate for agent skills. It is
meant to catch obvious and obfuscated risk before a skill reaches an agent,
marketplace, workspace loader, or local UI.

The package should stay fast, deterministic, and dependency-light. Heavier
semantic or runtime checks should be optional layers built on top of the core
scanner.

## Current v1 Scope

v1 is a static scanner for markdown-like skill content.

Implemented:

- Prompt injection and instruction override detection.
- Identity hijack and persona override detection.
- Jailbreak and unsafe capability claim detection.
- Data exfiltration patterns across browser, Node, shell, Python, PowerShell,
  webhook, and netcat-style instructions.
- Script injection and dynamic execution hints.
- LLM format injection markers such as raw role/control tokens.
- Hidden content detection:
  - zero-width and invisible Unicode characters
  - long invisible-character runs
  - Unicode escapes
  - HTML entities
  - spaced protocol/command words
  - large base64-like payloads
- Composite "Lethal Trifecta" escalation when instruction override combines
  with network or code execution.
- HITL bypass and self-approval rules.
- Source trust normalization for verified, managed, workspace, community, and
  unknown skill sources.
- Structured `SkillScanReport` output with:
  - risk score
  - recommended action: `allow`, `review`, or `block`
  - category counts
  - normalized-match count
  - OWASP / MITRE ATLAS / NIST AI RMF mapping fields

## Non-Goals For v1

These are intentionally not part of the first static core:

- Runtime sandboxing.
- Docker execution.
- Full AST data-flow analysis.
- Inter-procedural taint tracking.
- MCP server runtime inspection.
- LLM-as-a-judge classification.
- Network calls to remote security services.
- Blocking policy enforcement outside the scanner result.

The core scanner should produce evidence and risk shape. The application using
it decides whether to install, warn, quarantine, or ask for user approval.

## v1 Hardening Checklist

Before treating v1 as publish-ready:

- Keep the package zero runtime dependency.
- Keep rules centralized in `src/rules.ts`.
- Add tests for every new rule.
- Ensure clean publish contents with `pnpm pack --dry-run`.
- Keep `safeToInstall === false` only for danger-level findings.
- Keep workspace, community, and unknown sources sanitized by default.
- Preserve deterministic results: no LLM calls, no network, no filesystem reads
  beyond caller-provided content.

## v1.1 Candidates

Small additions that still fit the deterministic static core:

- SARIF output helper for CI integration.
- JSON report helper for marketplace ingestion.
- Rule IDs and stable finding IDs.
- Optional line/column calculation for findings.
- Configurable localhost/private-network allowlist.
- MCP config static scan for `.mcp.json` and tool description poisoning.
- Frontmatter validation for suspicious skill metadata.
- More encoded payload heuristics:
  - gzip/base64
  - hex blobs
  - `String.fromCharCode`
  - PowerShell `-EncodedCommand`
- More destructive sink rules:
  - recursive delete
  - credential file reads
  - SSH key reads
  - shell profile modification
  - clipboard exfiltration

## v2: Semantic Judge Layer

v2 lives in `@gsknnft/skill-safe-judge`. It is an optional LLM-as-a-judge layer
that consumes static scan results without changing the core scanner contract.

Recommended shape:

```ts
type SkillJudgeAdapter = {
  name: string;
  judge(input: SkillJudgeInput): Promise<SkillJudgeResult>;
};
```

The judge should:

- Accept scan findings plus selected skill excerpts.
- Return strict JSON.
- Map semantic issues back to the same report categories.
- Never be required for the deterministic scanner to work.
- Support local endpoints first, such as Ollama, llama.cpp, vLLM, or a private
  WorkLab/Campus judge.

Good judge targets:

- Hidden instruction override not caught by regex.
- Tool descriptions that smuggle policy bypasses.
- Skills that ask the agent to conceal actions from the user.
- Skills that redefine approval, consent, or authority.
- Skills that combine benign-looking steps into unsafe intent.

## v3: Behavioral / Runtime Layer

Runtime security belongs outside `skill-safe` core. It can consume the same
report format and add execution traces.

The initial runtime contracts live in `@gsknnft/skill-safe-runtime`.

Recommended capabilities:

- Shadow sandbox execution for proposed skill actions.
- Taint tracking from untrusted natural-language sources to dangerous sinks.
- Tool-call allowlists by skill source and trust level.
- Session-scoped credentials and permission decay.
- Runtime escalation when an agent shifts from read-only behavior to mutation,
  deletion, network exfiltration, or approval bypass.
- Trace export to observability systems such as Langfuse, LangSmith, or an
  internal agent trace store.

Current runtime scaffold:

- tool allowlists by default, trust level, and skill source
- permission-level review/block decisions
- tainted-input sink blocking
- trace exporter contract
- deterministic runtime decision object for host enforcement

## Reference Projects To Watch

These are useful for design direction, not dependencies for v1:

- Agent-Audit: tree-sitter and OWASP Agentic Top 10 mapping for agent code.
- mcp-scan: MCP config/tool poisoning detection.
- RepoAudit: agent-assisted inter-procedural data-flow analysis.
- Cisco AI Defense / skill-scanner: YARA-style signatures and SARIF ideas.
- Skillguard: practical static malicious-skill patterns.
- Guardrails AI: schema/RAIL-style validation ideas.
- Giskard: agent/RAG security evaluation patterns.

## Product Positioning

`skill-safe` should be the first gate, not the whole security system.

Use it when:

- Installing a community skill.
- Loading workspace skills.
- Displaying marketplace trust badges.
- Importing skills from GitHub, Hermes, OpenClaw, souls.zip, or custom sources.
- Deciding whether a skill needs user review before enabling.

Pair it with:

- Tool allowlists.
- Filesystem and network sandboxing.
- Human approval for destructive actions.
- Runtime telemetry for actual agent behavior.
- Source signing or marketplace review for verified skills.
