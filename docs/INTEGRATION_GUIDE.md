# INTEGRATION_GUIDE.md
**How to integrate `@gsknnft/skill-safe` into marketplaces, loaders, and agent harnesses.**

This guide explains how to use the static scanner (`skill-safe-core`), the semantic judge (`skill-safe-judge`), and the runtime monitor (`skill-safe-runtime`) in real systems.

---

# 1. Overview

Skill-safe provides **three layers** of protection:

| Layer | Package | Purpose |
|-------|---------|---------|
| **v1 Static** | `@gsknnft/skill-safe-core` | Deterministic, zero-dependency scan |
| **v2 Semantic** | `@gsknnft/skill-safe-judge` | Optional LLM-based intent analysis |
| **v3 Runtime** | `@gsknnft/skill-safe-runtime` | Behavioral enforcement during execution |

Most integrations only need **v1**.
Marketplaces and agent harnesses may add **v2**.
High-security environments add **v3**.

---

# 2. Minimal Integration (Static Only)

```ts
import {
  sanitizeSkillMarkdown,
  resolveSkillTrustLevel,
  requiresSanitization,
} from "@gsknnft/skill-safe-core";

export function scanSkill({ markdown, source, bundled }) {
  const trust = resolveSkillTrustLevel(source, bundled);

  if (!requiresSanitization(trust)) {
    return { safeToInstall: true, reason: "trusted-source" };
  }

  const report = sanitizeSkillMarkdown(markdown);

  if (!report.safeToInstall) {
    throw new Error("Skill blocked: " + JSON.stringify(report.flags, null, 2));
  }

  return report;
}
```

### When to use this:
- Local agent UIs
- Workspace skill loaders
- GitHub imports
- CLI tools

---

# 3. Marketplace Integration (Claw3D / OpenClaw / souls.zip)

Marketplaces must:

1. **Always run the static scanner**
2. **Store the full `SkillScanReport`**
3. **Display trust badges**
4. **Block or quarantine on `recommendedAction = "block"`**
5. **Require user review for `"review"`**

### Example ingestion pipeline:

```ts
const report = sanitizeSkillMarkdown(markdown);

db.skills.insert({
  id: skillId,
  source,
  report,
  trust: resolveSkillTrustLevel(source, false),
  createdAt: Date.now(),
});
```

### Marketplace UI rules:

| recommendedAction | UI Behavior |
|-------------------|-------------|
| `"allow"` | Install button enabled |
| `"review"` | Yellow badge + “Review Required” |
| `"block"` | Red badge + Install disabled |

---

# 4. Adding the Semantic Judge (Optional v2)

```ts
import { sanitizeSkillMarkdown } from "@gsknnft/skill-safe-core";
import { llamaCppJudge } from "@gsknnft/skill-safe-judge";

async function scanWithJudge(markdown) {
  const staticReport = sanitizeSkillMarkdown(markdown);

  const semantic = await llamaCppJudge.judge({
    markdown,
    excerpts: staticReport.flags.map(f => f.excerpt).filter(Boolean),
    findings: staticReport.flags,
  });

  return {
    static: staticReport,
    semantic,
  };
}
```

### When to use this:
- Marketplace submissions
- Enterprise agent deployments
- High-risk community skills

---

# 5. Runtime Enforcement (v3)

```ts
import { createRuntimeMonitor } from "@gsknnft/skill-safe-runtime";

const monitor = createRuntimeMonitor({
  allowlist: {
    "verified": ["read_file", "fetch"],
    "community": ["read_file"],
    "unknown": [],
  },
  permissionDecay: true,
  traceExporter: new LangfuseExporter(),
});

// Wrap agent execution
const result = await monitor.run(agent, userInput);
```

### What runtime catches:
- HITL bypass
- Self-approval
- Concealed actions
- Network exfiltration
- Privilege escalation
- Dangerous tool-call sequences

---

# 6. Integration Patterns by Source

### **Local / Workspace**
- Always scan
- Allow `"review"` installs
- Block `"block"`

### **GitHub**
- Treat as `community`
- Always scan
- `"review"` → warn
- `"block"` → reject

### **Unknown ZIP / souls.zip**
- Treat as `unknown`
- Always scan
- `"review"` → quarantine
- `"block"` → reject

### **Marketplace**
- Store report
- Display trust badge
- Enforce recommendedAction

---

# 7. Example: Claw3D Skill Loader

```ts
const report = sanitizeSkillMarkdown(markdown);

if (!report.safeToInstall) {
  return ui.showBlockScreen(report);
}

if (report.recommendedAction === "review") {
  return ui.showReviewScreen(report);
}

return installSkill(skillId, markdown);
```

---

# 8. Versioning & Stability

The report schema is **locked** for:

```
@ gsknnft/skill-safe-core v0.1.0
```

Future versions may add fields but **never break existing ones**.

---

# 9. Testing

```sh
pnpm test
pnpm build
pnpm pack --dry-run
```

---

# 10. Related Docs

- `REPORT_SCHEMA.md`
- `RULES_REFERENCE.md`
- `RISK_SCORING.md`
- `SARIF_OUTPUT.md`
- `skill-safe-judge` adapter docs
- `skill-safe-runtime` sandbox docs
