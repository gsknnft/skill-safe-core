# RULES_REFERENCE.md

This document catalogs all static analysis rules used by `@gsknnft/skill-safe`.

## Rule Table

| Rule ID                | Category             | Severity   | Description                                      | Example Match/Excerpt         |
|------------------------|---------------------|------------|--------------------------------------------------|-------------------------------|
| prompt-injection       | prompt-injection    | danger     | Detects prompt injection attempts                | "Ignore previous instructions"|
| identity-hijack        | identity-hijack     | high       | Attempts to impersonate or override agent ID     | "You are now..."             |
| jailbreak              | jailbreak           | high       | Attempts to bypass system restrictions           | "Disregard all prior rules"   |
| data-exfiltration      | data-exfiltration   | high       | Attempts to leak or export sensitive data        | "Send the file to..."         |
| script-injection       | script-injection    | danger     | Embeds or executes scripts/code                  | "<script>...</script>"        |
| format-injection       | format-injection    | medium     | Malicious formatting or encoding tricks          | "\u202E" (RTL override)       |
| hidden-content         | hidden-content      | medium     | Invisible or obfuscated content                  | "\u200B" (zero-width space)   |
| hitl-bypass            | hitl-bypass         | high       | Attempts to bypass human-in-the-loop controls    | "Do not show this to a human"  |
| package-age            | package-age         | danger     | npm package version is newer than the minimum age policy | recently published npm version |
| missing-provenance     | missing-provenance  | caution    | npm package lacks required provenance attestation | package metadata without attestation |
| composite-escalation   | composite-escalation| danger     | Multiple findings that together escalate risk    | N/A                           |

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
