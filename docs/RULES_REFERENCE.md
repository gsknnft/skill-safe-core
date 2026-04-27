# RULES_REFERENCE.md

This document catalogs all static analysis rules used by `@gsknnft/skill-safe`.

## Rule Table

| Rule ID                | Category             | Severity   | Description                                      | Example Match/Excerpt         |
|------------------------|---------------------|------------|--------------------------------------------------|-------------------------------|
| SS001-SS006            | prompt-injection    | danger     | Detects prompt injection attempts                | "Ignore previous instructions"|
| SS010-SS014            | identity-hijack     | caution/danger | Attempts to impersonate or override agent ID | "You are now..."             |
| SS020-SS025            | jailbreak           | danger     | Attempts to bypass system restrictions           | "Disregard all prior rules"   |
| SS030-SS038            | data-exfiltration   | caution/danger | Attempts to leak or export sensitive data    | "Send the file to..."         |
| SS040-SS045            | script-injection    | caution/danger | Embeds or executes scripts/code              | "<script>...</script>"        |
| SS050-SS052            | format-injection    | caution/danger | Malicious formatting or encoding tricks      | raw role/control tokens        |
| SS060-SS063            | excessive-claims    | caution/danger | Overstates privileges or disables guardrails | "unrestricted access"         |
| SS070-SS072            | hitl-bypass         | danger     | Attempts to bypass human-in-the-loop controls    | "self-approve all tool calls" |
| SS080-SS082            | hidden-content      | caution/danger | Invisible or obfuscated content              | "\u200B" (zero-width space)   |
| SS900                  | prompt-injection    | danger     | Multiple findings that together escalate risk    | Lethal Trifecta composite      |
| SS901                  | package-age         | danger     | npm package version is newer than the minimum age policy | recently published npm version |
| SS902                  | missing-provenance  | caution    | npm package lacks required provenance attestation | package metadata without attestation |

## Rationale
Each rule is designed to catch a class of attacks or unsafe behaviors relevant to agent skills. Rules may be updated as new threats emerge.

## Governance Mappings

Findings carry governance mappings for OWASP, MITRE ATLAS, and NIST AI RMF.
Rule-specific mappings override category defaults; otherwise category defaults
are applied automatically.

| Category | OWASP context | MITRE ATLAS context | NIST AI RMF context |
| --- | --- | --- | --- |
| prompt-injection | AST01 Malicious Skills, LLM01 Prompt Injection | AML.T0051 Prompt Injection, AML.T0054 Indirect Prompt Injection | Measure, Manage |
| jailbreak | AST01 Malicious Skills, LLM01 Prompt Injection | AML.T0051 Prompt Injection | Measure, Manage |
| data-exfiltration | AST01 Malicious Skills, AST03 Over-Privileged Skills | Exfiltration | Measure, Manage |
| script-injection | AST01 Malicious Skills, AST04 Insecure Metadata | Execution / AI agent tool abuse | Map, Manage |
| hidden-content | AST01 Malicious Skills, AST04 Insecure Metadata | AML.T0054 Indirect Prompt Injection | Map, Measure |
| hitl-bypass | AST03 Over-Privileged Skills | Privilege escalation / AI agent tool abuse | Govern, Manage |
| package-age | AST02 Supply Chain Compromise, LLM03 Supply Chain | Supply-chain compromise context | Map, Govern, Manage |
| missing-provenance | AST02 Supply Chain Compromise, LLM03 Supply Chain | Supply-chain compromise context | Map, Govern, Manage |
