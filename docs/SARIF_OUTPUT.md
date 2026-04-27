# SARIF_OUTPUT.md

This document describes the SARIF output format for `@gsknnft/skill-safe`.

## SARIF Version
- Uses SARIF v2.1.0

## Mapping
- Each `SanitizationFlag` is mapped to a SARIF `result`.
- Built-in findings use stable `SS###` rule IDs when available.
- Category fallback metadata is still emitted for custom rules without IDs.
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
          "ruleId": "SS001",
          "level": "error",
          "message": { "text": "[SS001] Instructs the agent to ignore prior instructions. - matched: Ignore previous instructions" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "skill.md" },
                "region": {
                  "startLine": 12,
                  "startColumn": 1,
                  "charOffset": 186,
                  "byteOffset": 186
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## Enabling SARIF Output

Use the CLI flag `--sarif` or call `toSarifReport()` /
`stringifySkillSafeSarifJson()` from the library API.
