# Security Policy

`@gsknnft/skill-safe` is a static pre-install scanner for agent skill markdown.
It is not a sandbox and does not prove runtime safety.

## Supported Versions

Security fixes are expected to target the latest published minor version.

## Reporting Vulnerabilities

Please report suspected vulnerabilities privately before public disclosure.
Include:

- package version
- reproduction input
- expected result
- actual result
- whether the issue is false negative, false positive, resolver behavior, or
  report/SARIF output

## Security Model

The core package:

- has zero runtime dependencies
- performs deterministic static scanning
- does not call LLMs
- does not execute skills
- does not perform filesystem reads except when caller uses Node scanner helpers
- performs remote fetches only through explicit resolver APIs

Runtime enforcement belongs in host applications or companion packages such as
`@gsknnft/skill-safe-runtime`.
