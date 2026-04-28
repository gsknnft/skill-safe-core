# skill-safe-judge Adapter Guide

This guide explains how to integrate semantic/LLM-based judging into the skill-safe pipeline.

## Usage

- Run the static scan first to get a `SkillScanReport`.
- Pass the skill and report to the judge adapter.
- The judge will analyze for semantic/intent-based issues and return an upgraded report.

## Example

```js
import { sanitizeSkillMarkdown } from "@gsknnft/skill-safe";
import { judgeSkill } from "@gsknnft/skill-safe-judge";

const staticReport = sanitizeSkillMarkdown(skillMarkdown);
const judgedReport = await judgeSkill(skillMarkdown, staticReport);
// judgedReport includes semantic flags and may escalate riskScore or recommendedAction
```

## Merging Results

- The judge adapter merges new flags and updates risk scoring as needed.
- Downstream consumers should always use the final, merged report.
