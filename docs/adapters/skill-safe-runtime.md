# skill-safe-runtime Adapter Guide

This guide describes the intended boundary between `@gsknnft/skill-safe` and
`@gsknnft/skill-safe-runtime`.

`skill-safe` owns deterministic static evidence before install. Runtime
enforcement belongs to the host runtime or the optional runtime package.

## Expected Flow

1. Scan skill markdown with `@gsknnft/skill-safe`.
2. Install or enable only if host policy allows the static result.
3. At execution time, apply runtime policy:
   - tool allowlists by source trust
   - filesystem/network constraints
   - human approval for destructive actions
   - trace capture for tool calls and side effects

## Host Wrapper Sketch

```ts
import { sanitizeSkillMarkdown } from "@gsknnft/skill-safe";

const staticResult = sanitizeSkillMarkdown(skillMarkdown);

if (staticResult.report.recommendedAction === "block") {
  throw new Error("Skill blocked before runtime");
}

// Host/runtime package owns actual execution controls.
const runtimeResult = await runtimeMonitor.run({
  skillId,
  trust,
  allowedTools: trust === "community" ? ["read_file"] : ["read_file", "fetch"],
});
```

## Runtime Should Catch

- tool calls outside the source trust policy
- HITL bypass attempts during execution
- unexpected write/delete/network escalation
- tainted user or web content reaching dangerous sinks
- concealed side effects

The runtime report should reference the static report ID when possible so hosts
can display one combined review record.
