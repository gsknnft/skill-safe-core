




export const HELP = `skill-safe

Static pre-install scanner for agent skill markdown.

Usage:
  skill-safe [source]
  skill-safe ./skills
  skill-safe --file ./SKILL.md
  skill-safe --dir ./skills
  skill-safe --text "ignore previous instructions"

Sources:
  github:owner/repo[@branch][/path]
  # hashlips: is now universal: use github:HashLips/repo or hashlips:repo
  npm:package[/path]
  registry:https://example.com/SKILL.md
  https://example.com/SKILL.md

 Recognizes:
    - openclaw-bundled          → verified
    - openclaw-managed          → managed
    - openclaw-workspace        → workspace
    - agents-skills-*           → workspace
    - openclaw-extra            → community
    - github:<owner>/<repo>     → community
    - registry:<name>           → community
    - souls:<id>                → community
    - hermes:<id>               → community
    - anything else             → unknown

Options:
  --json              Print the complete JSON report.
  --sarif             Print a SARIF v2.1.0 report for GitHub Code Scanning.
  --markdown          Print the complete Markdown report.
  --full              Include full finding mappings/evidence in human output.
  --dir <path>        Recursively scan SKILL.md/skill.md files under a directory.
  --out <path>        Write the report to a file (JSON, SARIF, or Markdown).
  --preset <name>     strict | marketplace | workspace. Default: workspace.
  --fail-on <mode>    never | review | block. Default: block.
  --honor-suppressions  Apply skill-safe-ignore comments. Use only for trusted sources.
  --no-suppressions     Disable suppression parsing.
  --audit-suppressions  Report invalid or unused skill-safe-ignore comments.
  --help              Show this help.

Exit codes:
  0  scan completed and did not meet --fail-on threshold
  1  scan completed and met --fail-on threshold, or failed to scan
`;
