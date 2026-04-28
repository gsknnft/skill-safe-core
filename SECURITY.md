# Security Policy

`@gsknnft/skill-safe` is a static pre-install scanner for agent skill markdown.
It is not a sandbox and does not prove runtime safety.

## Supported Versions

| Version | Security fixes |
|---------|---------------|
| 0.3.x   | Yes — current |
| < 0.3   | No            |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security reports.**

Report privately via GitHub Security Advisories:
> Repository → Security → Advisories → "Report a vulnerability"

Or email: **gsknnft@gmail.com** with subject `[skill-safe] Security Report`.

Include:
- Package version (`npm list @gsknnft/skill-safe`)
- Reproduction input (skill markdown or source string)
- Expected vs. actual result
- Whether the issue is: false negative, false positive, resolver behavior,
  SARIF output, or supply-chain concern

Expect acknowledgment within **72 hours** and a fix or advisory within **14 days**
for confirmed vulnerabilities.

## Security Model

The core package:

- Has **zero runtime dependencies** — verified by CI on every push.
- Performs **deterministic static scanning** — same input always produces same output.
- Does **not** call LLMs, execute skills, or evaluate code.
- Does **not** perform filesystem reads except when caller uses the Node scanner
  helpers (`scanSkillFiles`, `scanSkillDirectory`).
- Performs **remote fetches only through explicit, injected resolver APIs** —
  `resolveSkillMarkdown` and `resolveMarkdownFile` accept a `fetcher` parameter
  and do not touch the network unless called.
- **Suppression defaults to `"report-only"`** — skills cannot silence their own
  findings without the host explicitly opting into `"honor"` mode.

## What skill-safe Does NOT Do

- It does not sandbox or execute agent tool calls at runtime.
- It does not guarantee that a "safe" skill is free of all risk — it flags
  known patterns; novel attacks may evade detection.
- It does not verify the integrity of the calling host application.

Runtime enforcement belongs in host applications or companion packages such as
`@gsknnft/skill-safe-runtime`.

## CI Security Lane

Every push and weekly schedule runs:
- `pnpm audit --prod` — dependency CVE check
- Self-scan of example skills with SARIF upload to GitHub Code Scanning
- Zero-runtime-dependency assertion
- Tarball contents inspection (no test file leakage)

See [.github/workflows/security.yml](.github/workflows/security.yml).
