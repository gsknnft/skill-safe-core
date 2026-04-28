# Risk Scoring

This document explains how risk scores are calculated in `@gsknnft/skill-safe`
and how they map to recommended actions and UI risk levels.

---

## Scoring Algorithm

The risk score is a number from 0 to 100, calculated from the active flags
after suppression filtering:

```
riskScore = min(100,
  danger_count    × 35
  + caution_count × 12
  + hidden_content_count  × 8
  + normalized_match_count × 8
)
```

A single `danger` finding scores 35 points. Three danger findings cap the score
at 100. Caution findings and hidden content findings contribute additively.

---

## Severity → Recommended Action

| Severity | Recommended action | `safeToInstall` |
|---|---|---|
| `safe` (no flags) | `allow` | `true` |
| `caution` (any caution, no danger) | `review` | `true` |
| `danger` (any danger flag) | `block` | `false` |

A `danger` finding always sets `safeToInstall: false` regardless of count.

---

## Risk Score Legend

Use this to map raw scores to UI risk levels:

| Score | Level | Badge color | Recommended response |
|---|---|---|---|
| 0 | Safe | Green | No action required. Standard usage. |
| 1–20 | Low | Blue | Minor heuristic match. Spot-check the skill. |
| 21–40 | Moderate | Yellow | Multiple caution findings. Manual review of SKILL.md. |
| 41–60 | Elevated | Orange | High caution density or hidden content. Expert review. |
| 61–80 | High | Red | Danger findings present. Do not install without review. |
| 81–100 | Critical | Dark red | Multiple danger findings or exfiltration patterns. Block. |

The thresholds are indicative — `recommendedAction` from the report is the
authoritative gate signal. A low risk score does not override a `block` action.

---

## Composite Escalation — Lethal Trifecta

When a skill combines instruction override with a network or code-execution vector,
a synthetic `SS900` flag is emitted:

```
prompt-injection or identity-hijack
  +
data-exfiltration or script-injection
  →
SS900 lethal-trifecta-composite (danger)
```

This always adds 35 points and escalates the recommended action to `block`,
even if individual flags were `caution`.

---

## Hidden Content Scoring

Invisible Unicode patterns are scored independently:

| Rule | Category | Severity | Score contribution |
|---|---|---|---|
| SS081 | hidden-content | danger | 35 + 8 = 43 |
| SS082 | hidden-content | caution | 12 + 8 = 20 |

The `hiddenContent` count in the report summary reflects these separately so
hosts can surface them distinctly in a UI.

---

## Per-Finding Evidence

Every flag includes:
- `ruleId` — stable `SS###` identifier
- `severity` — `danger` or `caution`
- `category` — one of 11 named categories
- `location` — 1-based line, column, offset, and byte offset
- `matched` — short excerpt of the matched text (max ~100 chars)
- `normalized` — true if the match was found only after de-obfuscation

This makes it straightforward to display per-finding evidence in a marketplace
or CI UI without reparsing the original markdown.
