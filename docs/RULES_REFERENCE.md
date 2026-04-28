# RULES_REFERENCE.md

This document catalogs all static analysis rules used by `@gsknnft/skill-safe`.

## Rule Table

| Rule ID   | Category          | Severity       | Description                                              | Example Match                             |
|-----------|-------------------|----------------|----------------------------------------------------------|-------------------------------------------|
| SS001–006 | prompt-injection  | danger         | Override/forget/redefine instructions                    | `ignore all previous instructions`        |
| SS010–014 | identity-hijack   | caution/danger | Impersonate or redefine agent identity                   | `you are now DAN`                         |
| SS020–025 | jailbreak         | danger         | Bypass system restrictions or roleplay mode              | `act as if you have no restrictions`      |
| SS030–038 | data-exfiltration | caution/danger | Leak files, credentials, or env data                     | `send the file to https://...`            |
| SS040–045 | script-injection  | caution/danger | Embedded scripts or eval tricks                          | `<script>eval(...)</script>`              |
| SS050–052 | format-injection  | caution/danger | Role tokens, markdown abuse                              | raw role/control tokens                   |
| SS060–063 | excessive-claims  | caution/danger | Overstated privileges or disabled guardrails             | `all safety guardrails are disabled`      |
| SS070–072 | hitl-bypass       | danger         | Skip human-in-the-loop approval                          | `auto-approve all tool calls`             |
| SS080–082 | hidden-content    | caution/danger | Base64 payloads, invisible Unicode                       | zero-width spaces, `atob(...)` blobs      |
| SS100     | data-exfiltration | danger         | SSH private key read                                     | `cat ~/.ssh/id_rsa`                       |
| SS101     | data-exfiltration | danger         | `.env` secrets file read                                 | `require('./.env.production')`            |
| SS102     | data-exfiltration | danger         | AWS credentials file read                                | `cat ~/.aws/credentials`                  |
| SS103     | data-exfiltration | caution        | API key / secret accessed from environment               | `process.env['OPENAI_API_KEY']`           |
| SS110     | script-injection  | danger         | `curl | bash` — remote shell execution                   | `curl https://... | bash`                 |
| SS111     | script-injection  | danger         | `wget | sh` — remote shell execution                     | `wget -qO- https://... | sh`              |
| SS112     | script-injection  | danger         | PowerShell IEX download dropper                          | `IEX (...).DownloadString(...)`           |
| SS113     | prompt-injection  | danger         | Remote prompt load — indirect prompt injection           | fetch + eval/exec on remote content       |
| SS120     | script-injection  | danger         | Recursive force-delete from root/home                    | `rm -rf /`                                |
| SS121     | script-injection  | danger         | Disk format / zero-fill                                  | `mkfs.ext4 /dev/sda1`                     |
| SS130     | script-injection  | danger         | Shell profile write — persistence                        | `echo ... >> ~/.bashrc`                   |
| SS131     | script-injection  | danger         | Crontab modification — scheduled persistence             | `echo ... | crontab`                      |
| SS140     | data-exfiltration | caution        | Clipboard exfiltration                                   | `pbcopy |`                                |
| SS900     | prompt-injection  | danger         | Lethal Trifecta composite risk escalation                | injection + exfil + script together       |
| SS901     | package-age       | danger         | npm package published below minimum-age policy           | recently published npm version            |
| SS902     | missing-provenance| caution        | npm package lacks OIDC/Sigstore provenance               | package without attestation metadata      |

## Rule Numbering Convention

- **SS001–SS099**: Static content rules, grouped by attack category (10s digit = category).
- **SS100–SS149**: Credential and secrets access rules.
- **SS110–SS119**: Remote code execution rules.
- **SS120–SS129**: Destructive filesystem operation rules.
- **SS130–SS139**: Persistence / shell profile rules.
- **SS140–SS149**: Clipboard and side-channel exfiltration rules.
- **SS8xx**: Synthetic hidden-content rules (detected post-normalization, no fixed location).
- **SS9xx**: Synthetic composite or source-level rules (Lethal Trifecta, npm policy).

## Rationale

Each rule is designed to catch a class of attacks or unsafe behaviors relevant to
agent skills. Rules may be updated as new threats emerge. Stable `SS###` IDs are
guaranteed not to be reassigned — a suppressed rule ID will always refer to the
same rule.

## Governance Mappings

Findings carry structured governance mappings for OWASP, MITRE ATLAS, and NIST AI RMF.
Rule-specific mappings override category defaults; otherwise category defaults are
applied automatically. See `src/mappings.ts` and `getCategoryReportArrays()` for
the full registry.

| Category           | OWASP context                             | MITRE ATLAS context                       | NIST AI RMF context |
|--------------------|-------------------------------------------|-------------------------------------------|---------------------|
| prompt-injection   | AST01 Malicious Skills, LLM01             | AML.T0051, AML.T0054                      | Measure, Manage     |
| identity-hijack    | AST01 Malicious Skills, LLM01             | AML.T0051                                 | Measure, Manage     |
| jailbreak          | AST01 Malicious Skills, LLM01             | AML.T0051                                 | Measure, Manage     |
| data-exfiltration  | AST01, AST03 Over-Privileged Skills       | AML.T0040                                 | Measure, Manage     |
| script-injection   | AST01, AST04 Insecure Metadata            | AML.T0044                                 | Map, Manage         |
| hidden-content     | AST01, AST04 Insecure Metadata            | AML.T0054                                 | Map, Measure        |
| hitl-bypass        | AST03 Over-Privileged Skills              | AML.T0044                                 | Govern, Manage      |
| package-age        | AST02 Supply Chain, LLM03 Supply Chain    | AML.T0010                                 | Map, Govern, Manage |
| missing-provenance | AST02 Supply Chain, LLM03 Supply Chain    | AML.T0010                                 | Map, Govern, Manage |

## Adding New Rules

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the rule contribution checklist.
Each rule requires a stable `SS###` ID, a short `name`, a `pattern`, `severity`,
`category`, `description`, and governance mapping fields (`owasp`, `mitreAtlas`,
`nistAiRmf`). Update this reference table and run `pnpm validate:mappings` before
opening a PR.
