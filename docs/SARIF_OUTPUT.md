# SARIF_OUTPUT.md

This document describes the SARIF output format for `@gsknnft/skill-safe`.

## SARIF Version
- Uses SARIF v2.1.0

## Mapping
- Each `SanitizationFlag` is mapped to a SARIF `result`.
- Rule metadata is mapped to SARIF `rules`.
- The overall `SkillScanReport` is mapped to a SARIF `run`.

## Example Output
```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "skill-safe-core" } },
      "results": [
        {
          "ruleId": "prompt-injection",
          "level": "error",
          "message": { "text": "Prompt injection detected: 'Ignore previous instructions'" },
          "locations": [ { "physicalLocation": { "artifactLocation": { "uri": "skill.md" } } } ]
        }
      ]
    }
  ]
}
```

## Enabling SARIF Output
- Use the CLI flag `--sarif` or set `outputFormat: 'sarif'` in the API.
