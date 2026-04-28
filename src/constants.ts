import type {
  SkillSafePolicyPreset,
  SkillSafePolicy,
  SanitizationCategory,
  SarifRuleMeta,
} from "./types.js";

export const ORDERED_CATEGORIES: SanitizationCategory[] = [
  "prompt-injection",
  "identity-hijack",
  "jailbreak",
  "data-exfiltration",
  "script-injection",
  "format-injection",
  "excessive-claims",
  "hidden-content",
  "hitl-bypass",
  "package-age",
  "missing-provenance",
];

export const PREFERRED_MARKDOWN_FILES = [
  "SKILL.md",
  "skill.md",
  "README.md",
  "readme.md",
  "index.md",
];

export const DEFAULT_MARKDOWN_CANDIDATES = [
  "SKILL.md",
  "skill.md",
  "README.md",
  "readme.md",
];

export const HTML_ENTITIES: Record<string, string> = {
  amp: "&",
  apos: "'",
  colon: ":",
  gt: ">",
  lt: "<",
  nbsp: " ",
  quot: '"',
  sol: "/",
};

export const ZERO_WIDTH_RE = /[\u200B-\u200D\u2060\uFEFF]/g;
export const INVISIBLE_RE =
  /[\u200B-\u200D\u2060\uFEFF\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u2800\u3164\uFFA0]/g;
export const INVISIBLE_RUN_RE =
  /[\u200B-\u200D\u2060\uFEFF\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u2800\u3164\uFFA0]{10,}/g;


export const POLICY_PRESETS: Record<SkillSafePolicyPreset, SkillSafePolicy> = {
  strict: {
    preset: "strict",
    failOn: "review",
    suppressionMode: "disabled",
    npmPolicy: { minAgeDays: 14, requireProvenance: true },
  },
  marketplace: {
    preset: "marketplace",
    failOn: "review",
    suppressionMode: "report-only",
    npmPolicy: { minAgeDays: 7, requireProvenance: false },
  },
  workspace: {
    preset: "workspace",
    failOn: "block",
    suppressionMode: "report-only",
    npmPolicy: { minAgeDays: 2, requireProvenance: false },
  },
};

export const CATEGORY_RULE_META: Record<SanitizationCategory, SarifRuleMeta> = {
  "prompt-injection": {
    id: "SS/prompt-injection",
    name: "PromptInjection",
    short: "Prompt injection instruction detected.",
    full: "The skill attempts to override the agent's existing system instructions, change its behavior, or plant a new directive mid-skill. This can cause the agent to perform unauthorized actions.",
    securitySeverity: "8.5",
    precision: "high",
  },
  "identity-hijack": {
    id: "SS/identity-hijack",
    name: "IdentityHijack",
    short: "Identity or persona hijack detected.",
    full: "The skill instructs the agent to assume a different identity, persona, or role that bypasses its safety guidelines.",
    securitySeverity: "8.0",
    precision: "high",
  },
  jailbreak: {
    id: "SS/jailbreak",
    name: "Jailbreak",
    short: "Jailbreak pattern detected.",
    full: "The skill contains patterns commonly used to bypass AI safety constraints, such as DAN-style prompts or developer-mode unlocks.",
    securitySeverity: "9.0",
    precision: "high",
  },
  "data-exfiltration": {
    id: "SS/data-exfiltration",
    name: "DataExfiltration",
    short: "Data exfiltration vector detected.",
    full: "The skill contains network requests, webhook calls, or other mechanisms that could leak conversation data, credentials, or workspace files to an external endpoint.",
    securitySeverity: "9.5",
    precision: "very-high",
  },
  "script-injection": {
    id: "SS/script-injection",
    name: "ScriptInjection",
    short: "Script or code injection pattern detected.",
    full: "The skill embeds shell commands, eval() calls, or other execution vectors that could run arbitrary code on the host system.",
    securitySeverity: "9.0",
    precision: "high",
  },
  "format-injection": {
    id: "SS/format-injection",
    name: "FormatInjection",
    short: "Format injection pattern detected.",
    full: "The skill uses special tokens (e.g., <|system|>, [INST]) that exploit prompt-format boundaries in template-based LLM deployments.",
    securitySeverity: "7.5",
    precision: "high",
  },
  "excessive-claims": {
    id: "SS/excessive-claims",
    name: "ExcessiveClaims",
    short: "Excessive or deceptive capability claims detected.",
    full: "The skill claims capabilities that could mislead the agent or user into granting unwarranted trust or permissions.",
    securitySeverity: "4.0",
    precision: "medium",
  },
  "hidden-content": {
    id: "SS/hidden-content",
    name: "HiddenContent",
    short: "Hidden or invisible content detected.",
    full: "The skill contains invisible Unicode characters, zero-width joiners, or HTML-encoded text that may hide instructions from human reviewers.",
    securitySeverity: "7.0",
    precision: "very-high",
  },
  "hitl-bypass": {
    id: "SS/hitl-bypass",
    name: "HitlBypass",
    short: "Human-in-the-loop bypass attempt detected.",
    full: "The skill instructs the agent to skip, suppress, or automatically approve human approval steps.",
    securitySeverity: "8.5",
    precision: "high",
  },
  "package-age": {
    id: "SS/package-age",
    name: "PackageAge",
    short: "New package version detected.",
    full: "The resolved package version was published inside the configured minimum-age window. Newly published packages are higher risk for typosquatting, account takeover, or malicious rapid ingestion.",
    securitySeverity: "7.0",
    precision: "high",
  },
  "missing-provenance": {
    id: "SS/missing-provenance",
    name: "MissingProvenance",
    short: "Package provenance is missing.",
    full: "The resolved package has no registry provenance attestation. The package may still be legitimate, but build origin could not be verified from registry metadata.",
    securitySeverity: "4.0",
    precision: "medium",
  },
};

export const SYNTHETIC_RULE_META: Record<string, SarifRuleMeta> = {
  SS081: {
    id: "SS081",
    name: "InvisibleUnicodeRun",
    short: "Long invisible Unicode run detected.",
    full: "The skill contains a long run of invisible Unicode characters that may hide instructions from reviewers while remaining visible to an LLM.",
    securitySeverity: "8.0",
    precision: "very-high",
    category: "hidden-content",
  },
  SS082: {
    id: "SS082",
    name: "InvisibleUnicodeCharacter",
    short: "Invisible Unicode character detected.",
    full: "The skill contains invisible Unicode characters that may hide or split operational instructions.",
    securitySeverity: "6.0",
    precision: "very-high",
    category: "hidden-content",
  },
  SS900: {
    id: "SS900",
    name: "LethalTrifectaComposite",
    short: "Instruction override combined with execution or exfiltration.",
    full: "The skill combines an instruction override with a network or code execution vector. This composite pattern is significantly higher risk than either finding alone.",
    securitySeverity: "9.8",
    precision: "high",
    category: "prompt-injection",
  },
  SS901: {
    id: "SS901",
    name: "NpmPackageAgeGate",
    short: "npm package version is inside the minimum-age window.",
    full: "The resolved npm package version was published too recently to satisfy the configured source policy.",
    securitySeverity: "7.0",
    precision: "high",
    category: "package-age",
  },
  SS902: {
    id: "SS902",
    name: "NpmMissingProvenance",
    short: "npm package provenance attestation is missing.",
    full: "The resolved npm package has no registry provenance attestation. Build origin could not be verified from registry metadata.",
    securitySeverity: "4.0",
    precision: "medium",
    category: "missing-provenance",
  },
};


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
