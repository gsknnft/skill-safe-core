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
| composite-escalation   | composite-escalation| danger     | Multiple findings that together escalate risk    | N/A                           |

## Rationale
Each rule is designed to catch a class of attacks or unsafe behaviors relevant to agent skills. Rules may be updated as new threats emerge.
