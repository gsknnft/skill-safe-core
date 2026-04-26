# skill-safe-runtime Sandbox Guide

This guide explains how to use the runtime sandbox for shadow execution and behavioral checks.

## Usage
- Run the skill in the sandbox to observe tool calls and side effects.
- The sandbox simulates execution and captures any dangerous or unexpected behavior.

## Example
```js
import { runSkillInSandbox } from '@gsknnft/skill-safe-runtime';

const result = await runSkillInSandbox(skillMarkdown);
// result includes observed tool calls, side effects, and a runtime risk assessment
```

## Blocking on Behavior
- If the sandbox detects forbidden actions, escalate the report and block installation.
- Use in CI or as a pre-install gate for high-trust environments.
