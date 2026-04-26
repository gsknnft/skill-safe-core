# RISK_SCORING.md

This document explains how risk scores are calculated in `@gsknnft/skill-safe` and how they map to recommended actions.

## Scoring Algorithm
- Each `SanitizationFlag` has a severity: info (0), low (1), medium (2), high (3), danger (4).
- The risk score is the sum of all flag severities, with composite escalation rules able to boost the score.

## Thresholds
| Score | Action         |
|-------|---------------|
| 0     | allow         |
| 1–3   | review        |
| 4+    | block         |

- Any `danger` flag triggers `block`.
- Multiple `medium` or `high` flags may escalate to `block`.

## Composite Escalation
If multiple lower-severity findings are present, a composite rule may escalate the risk score and recommended action.
