export type SkillTrustLevel =
  | "verified" // bundled with the app, reviewed and signed
  | "managed" // installed via official marketplace
  | "workspace" // from an agent's local workspace
  | "community" // external source (GitHub, registry, etc.)
  | "unknown"; // unrecognized — treat as untrusted

export type SkillSafePolicyPreset =
  | "strict"
  | "marketplace"
  | "workspace"
  | "permissive";

// ---------------------------------------------------------------------------
// Risk Level — maps a 0-100 risk score to a named severity tier for UI display.
// Aligned with the RISK_SCORING.md legend.
// ---------------------------------------------------------------------------

export type SkillRiskLevel =
  | "safe"      // 0
  | "low"       // 1–20
  | "moderate"  // 21–40
  | "elevated"  // 41–60
  | "high"      // 61–80
  | "critical"; // 81–100

// ---------------------------------------------------------------------------
// Skill Frontmatter — typed representation of SKILL.md YAML header.
//
// Field names are chosen to be compatible with:
//   - OpenAI Agent SDK tool definitions (name, description, inputSchema)
//   - MCP tool definitions (name, description, inputSchema)
//   - Claude Code skill commands (name, description, tools)
//   - Common SKILL.md conventions (source, permissions, version, author)
// ---------------------------------------------------------------------------

export type SkillFrontmatter = {
  /** Display name for the skill. Required. */
  name: string;
  /** One-sentence description of what the skill does. Required. */
  description: string;
  /** Semantic version string. */
  version?: string;
  /** Author name or org handle. */
  author?: string;
  /** SPDX license identifier. */
  license?: string;
  /**
   * Canonical source URI for this skill.
   * Formats: `github:owner/repo`, `npm:package@version`, `url:https://...`
   */
  source?: string;
  /**
   * Tool names or tool specifiers the skill is allowed to use.
   * Compatible with OpenAI tool_choice and MCP tool list.
   */
  tools?: string[];
  /**
   * Permission scopes the skill declares it needs.
   * E.g. `read:files`, `write:github`, `execute:shell`
   */
  permissions?: string[];
  /**
   * Preferred or required model for this skill.
   * E.g. `claude-opus-4-7`, `gpt-4o`
   */
  model?: string;
  /** Taxonomy category for marketplace grouping. */
  category?: string;
  /** Freeform tags for search and filtering. */
  tags?: string[];
  /**
   * JSON Schema string describing expected input.
   * Compatible with OpenAI function calling and MCP inputSchema.
   */
  inputSchema?: string;
  /** JSON Schema string describing expected output. */
  outputSchema?: string;
  /** Pass-through for custom or future standard fields. */
  [key: string]: string | string[] | undefined;
};

export type SanitizationLocation = {
  /** 1-based line number in the scanned content. */
  line: number;
  /** 1-based column number in the scanned content. */
  column: number;
  /** UTF-16 string offset used by JavaScript RegExp matches. */
  offset: number;
  /** UTF-8 byte offset for scanners/reporters that need byte coordinates. */
  byteOffset: number;
};

export type SanitizationFlag = {
  /** Stable rule identifier for built-in rules and synthetic source checks. */
  ruleId?: SkillRuleId;
  /** Stable short rule name for reports and future suppressions. */
  ruleName?: string;
  severity: SanitizationSeverity;
  category: SanitizationCategory;
  description: string;
  /** Short excerpt of the matched text for display */
  matched: string;
  /** True when matched only after normalization/de-obfuscation. */
  normalized?: boolean;
  /** External framework mapping for governance/reporting. */
  owasp?: string[];
  mitreAtlas?: string[];
  nistAiRmf?: string[];
  /** Best-effort evidence location for content-backed findings. */
  location?: SanitizationLocation;
};

export type SkillScanReport = {
  version: "skill-safe.report.v1";
  riskScore: number;
  summary: {
    safeToInstall: boolean;
    severity: "safe" | "caution" | "danger";
    danger: number;
    caution: number;
    hiddenContent: number;
    normalizedMatches: number;
  };
  categories: Partial<Record<SanitizationCategory, number>>;
  mappings: {
    owasp: string[];
    mitreAtlas: string[];
    nistAiRmf: string[];
  };
  recommendedAction: "allow" | "review" | "block";
};

/**
 * Controls how `<!-- skill-safe-ignore SS001: reason -->` comments are treated.
 *
 * - `"disabled"`     — suppression comments are not parsed at all.
 * - `"report-only"`  — comments are parsed and surfaced on the result, but all
 *                      flags are still reported. Safe default for untrusted content.
 * - `"honor"`        — matching rule IDs are filtered from the flag list. Only
 *                      use for workspace/verified sources where the author is trusted.
 */
export type SuppressionMode = "disabled" | "report-only" | "honor";

export type SanitizationOptions = {
  /** Additional rules appended to the built-in set. */
  extraRules?: RuleDefinition[];
  /**
   * Controls suppression comment behavior.
   * Defaults to `"report-only"` — suppressions are parsed and surfaced but
   * never applied when scanning untrusted content.
   */
  suppressionMode?: SuppressionMode;
};

export type SkillSafePolicy = {
  preset: SkillSafePolicyPreset;
  failOn: "never" | "review" | "block";
  suppressionMode: SuppressionMode;
  npmPolicy: NpmSourcePolicy;
};

export type SkillSafeReportMode = "resolved-source" | "file" | "text" | "batch";

export type SourceIntegrity = {
  /** SHA-256 hex digest of the raw markdown bytes. */
  contentHash: string;
  /** SHA-256 hex digest of the resolved URL string, or null if no URL. */
  urlHash: string | null;
  /** Resolved URL at scan time, or null. */
  resolvedUrl: string | null;
  /** ISO 8601 timestamp of when the integrity record was created. */
  scannedAt: string;
  /** Byte length of the content (UTF-8). */
  bytes: number;
  /** Algorithm used. Always "SHA-256" for now. */
  algorithm: "SHA-256";
};

export type GitHubSkillShorthand = {
  owner: string;
  repo: string;
  branch: string;
  path: string;
};
export type SanitizationCategory =
  | "prompt-injection"
  | "identity-hijack"
  | "jailbreak"
  | "data-exfiltration"
  | "script-injection"
  | "format-injection"
  | "excessive-claims"
  | "hidden-content"
  | "hitl-bypass"
  | "package-age"
  | "missing-provenance";

export type SanitizationSeverity = "caution" | "danger";

export type SkillSourceKind =
  | "github"
  | "npm"
  | "registry"
  | "souls"
  | "hermes"
  | "openclaw"
  | "workspace"
  | "url"
  | "unknown";

export type SkillRuleId = `SS${string}`;

export type RuleDefinition = {
  /** Stable rule identifier. Built-in rules use SS001-style IDs. */
  id?: SkillRuleId;
  /** Stable short name for reports, SARIF, docs, and future suppressions. */
  name?: string;
  pattern: RegExp;
  severity: SanitizationSeverity;
  category: SanitizationCategory;
  description: string;
  /** Structured governance mappings. When present, overrides category-level defaults in reports. */
  governance?: GovernanceMapping[];
};

export type GovernanceMappings = {
  owasp: GovernanceMapping[];
  mitreAtlas: GovernanceMapping[];
  nistAiRmf: GovernanceMapping[];
};

export type GovernanceFramework =
  | "owasp-agentic"
  | "owasp-llm"
  | "mitre-atlas"
  | "nist-ai-rmf";

export type MappingConfidence = "direct" | "related" | "inferred";

export type GovernanceMapping = {
  framework: GovernanceFramework;
  id: string;
  label: string;
  url?: string;
  sourceVersion?: string;
  confidence: MappingConfidence;
};

export type CategoryGovernanceMapping = {
  category: SanitizationCategory;
  mappings: GovernanceMapping[];
};

export type SkillSourceDescriptor = {
  source: string;
  kind: SkillSourceKind;
  trust: SkillTrustLevel;
  bundled: boolean;
  value: string;
  directlyResolvable: boolean;
};

export type ResolvedSkillMarkdown = SkillSourceDescriptor & {
  resolvedUrl: string | null;
  markdown: string;
  /**
   * Source-level flags injected before content analysis — e.g. age-gate or
   * missing provenance. Empty array when not applicable.
   */
  sourceFlags: SanitizationFlag[];
};

export type ResolvedSkillScanReport = ResolvedSkillMarkdown & {
  scan: SanitizationResult | null;
};

export type SkillSourceResolver = (
  descriptor: SkillSourceDescriptor,
) => Promise<string | { markdown: string; resolvedUrl?: string | null }>;

export type NpmSourcePolicy = {
  /**
   * Minimum age in days a package version must have before it is trusted.
   * Mitigates package-takeover and typosquatting attacks where a malicious
   * version is published and immediately consumed by automated agents.
   * Defaults to 2.
   */
  minAgeDays?: number;
  /**
   * When true, a `missing-provenance` flag is emitted if the registry has no
   * OIDC/Sigstore attestation for the resolved version.
   * Defaults to false (provenance check is a best-effort stub today).
   */
  requireProvenance?: boolean;
};

export type SkillResolverOptions = {
  bundled?: boolean;
  /** Required for built-in network resolvers. Custom resolvers may ignore it. */
  fetcher?: typeof fetch;
  resolvers?: Partial<Record<SkillSourceKind, SkillSourceResolver>>;
  /** Policy applied when resolving npm: sources. */
  npmPolicy?: NpmSourcePolicy;
};

export type SanitizationSuppression = {
  ruleId: string;
  reason: string;
  /** 1-based line number of the suppression comment. */
  line: number;
  /** Optional ISO date from "-- expires: YYYY-MM-DD". */
  expiresAt?: string;
};

export type SanitizationResult = {
  /** Worst severity across all flags, or "safe" if none. */
  severity: "safe" | "caution" | "danger";
  flags: SanitizationFlag[];
  /** false only when at least one "danger" flag is present */
  safeToInstall: boolean;
  /** Suppressions parsed from skill-safe-ignore comments in the content. */
  suppressions: SanitizationSuppression[];
  report: SkillScanReport;
};

export type SuppressionAuditFinding = {
  documentId: string;
  ruleId: string;
  line: number;
  reason: string;
  issue: "invalid-rule" | "unused-suppression" | "expired-suppression";
};

export type SuppressionAuditReport = {
  version: "skill-safe.suppression-audit.v1";
  ok: boolean;
  invalid: number;
  unused: number;
  expired: number;
  findings: SuppressionAuditFinding[];
};

export type RuleCoverageEntry = {
  ruleId: SkillRuleId;
  ruleName: string;
  category: SanitizationCategory;
  severity: SanitizationSeverity;
  fired: number;
};

export type SkillSafeCoverageReport = {
  version: "skill-safe.coverage.v1";
  totalRules: number;
  firedRules: number;
  neverFiredRules: number;
  rules: RuleCoverageEntry[];
  categories: Record<string, { total: number; fired: number }>;
};

export type SkillSafeDocumentReport = {
  id: string;
  source: string;
  resolvedUrl: string | null;
  sourceKind: SkillSourceKind | "file" | "text";
  trust: SkillTrustLevel | "unknown";
  directlyResolvable: boolean;
  sanitized: boolean;
  bytes: number;
  lines: number;
  scan: SanitizationResult;
};

export type SkillSafeReportSummary = {
  safeToInstall: boolean;
  recommendedAction: SkillScanReport["recommendedAction"];
  severity: SanitizationResult["severity"];
  riskScore: number;
  documents: number;
  passed: number;
  review: number;
  blocked: number;
  findings: number;
  danger: number;
  caution: number;
  hiddenContent: number;
  normalizedMatches: number;
  /** Suppression comments parsed across all documents. */
  suppressions: number;
};

export type SkillSafeFullReport = {
  version: "skill-safe.full-report.v1";
  generatedAt: string;
  mode: SkillSafeReportMode;
  ok: boolean;
  summary: SkillSafeReportSummary;
  categories: Record<string, number>;
  mappings: {
    owasp: string[];
    mitreAtlas: string[];
    nistAiRmf: string[];
  };
  documents: SkillSafeDocumentReport[];
};

export type CreateSkillSafeReportOptions = {
  mode: SkillSafeReportMode;
  documents: SkillSafeDocumentReport[];
  generatedAt?: string;
};

export type ScanSkillFilesOptions = {
  /**
   * Root directory used to compute relative document IDs in the report.
   * Defaults to process.cwd().
   */
  root?: string;
  /**
   * Treat every file as a specific trust source, such as "openclaw-workspace".
   * Defaults to "workspace".
   */
  source?: string;
  /**
   * Whether the files are bundled/verified. When true, static sanitization is
   * skipped and files are reported as allowed.
   */
  bundled?: boolean;
  /** Additional rules appended to the built-in set. */
  extraRules?: RuleDefinition[];
  /**
   * Compute source integrity for each file. Defaults to true.
   */
  computeIntegrity?: boolean;
  /**
   * Per-file source string override. Called with the absolute file path.
   * Return null to use the default source.
   */
  resolveSource?: (filePath: string) => string | null;
  /**
   * Controls how `<!-- skill-safe-ignore SS001: reason -->` comments are
   * treated during scanning. Defaults to `"report-only"`.
   */
  suppressionMode?: SuppressionMode;
};

export type ScanSkillDirectoryOptions = ScanSkillFilesOptions & {
  /**
   * File extensions to include when includeFileNames is null. Defaults to [".md"].
   */
  extensions?: string[];
  /**
   * Exact entrypoint file names to scan. Defaults to ["SKILL.md", "skill.md"].
   * Set to null to scan by extension instead.
   */
  includeFileNames?: string[] | null;
  /**
   * Directory basenames to skip.
   */
  ignoreDirs?: string[];
  /**
   * Maximum recursion depth. 0 = only top-level files. Defaults to 10.
   */
  maxDepth?: number;
};

export type ScannedSkillFile = {
  absolutePath: string;
  relativePath: string;
  source: string;
  document: SkillSafeDocumentReport;
  integrity: SourceIntegrity | null;
};

export type ScanSkillBatchResult = {
  report: SkillSafeFullReport;
  files: ScannedSkillFile[];
};

// ---------------------------------------------------------------------------
// SARIF types (minimal subset for GitHub Code Scanning)
// ---------------------------------------------------------------------------

export type ToSarifOptions = {
  /** Tool version to embed. Defaults to the current package version. */
  version?: string;
};

export type SarifLog = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
  version: "2.1.0";
  runs: SarifRun[];
};

export type SarifRule = {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  defaultConfiguration: { level: "error" | "warning" | "note" | "none" };
  properties: {
    tags: string[];
    /** CVSS-like score string, 0.0–10.0, used by GitHub Advanced Security. */
    "security-severity": string;
    precision: "very-high" | "high" | "medium" | "low";
    "problem.severity": "error" | "warning" | "recommendation";
  };
};

export type SarifLocation = {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId: "%SRCROOT%";
    };
    region: {
      startLine: number;
      startColumn?: number;
      charOffset?: number;
      byteOffset?: number;
    };
  };
};

export type SarifResult = {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations: SarifLocation[];
  partialFingerprints?: Record<string, string>;
  properties?: {
    ruleName?: string;
    matched?: string;
    normalized?: boolean;
    owasp?: string[];
    mitreAtlas?: string[];
    nistAiRmf?: string[];
  };
};

export type SarifArtifact = {
  location: { uri: string; uriBaseId: "%SRCROOT%" };
  length: number;
  mimeType: "text/markdown";
  properties: { trustLevel: string; sourceKind: string };
};

export type SarifRun = {
  tool: {
    driver: {
      name: "skill-safe";
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  artifacts: SarifArtifact[];
  properties: {
    "skill-safe:report": {
      mode: string;
      riskScore: number;
      recommendedAction: string;
    };
  };
};

// ---------------------------------------------------------------------------
// Category → SARIF rule mapping
// ---------------------------------------------------------------------------

export type SarifRuleMeta = {
  id: string;
  name: string;
  short: string;
  full: string;
  securitySeverity: string;
  precision: SarifRule["properties"]["precision"];
  category?: SanitizationCategory;
};

export type MarkdownFileSource =
  | "github"
  | "registry"
  | "souls"
  | "hermes"
  | "marketplace"
  | "gitlab"
  | "huggingface"
  | "url"
  | "unknown";

// ---------------------------------------------------------------------------
// Project-level config — skill-safe.config.json
// ---------------------------------------------------------------------------

/**
 * Serializable rule definition for skill-safe.config.json.
 * The pattern is a string (compiled to RegExp on load).
 */
export type SkillSafeConfigRule = {
  /** RegExp source string. Flags default to "i" unless overridden. */
  pattern: string;
  /** RegExp flags. Defaults to "i". */
  flags?: string;
  severity: SanitizationSeverity;
  category: SanitizationCategory;
  description: string;
  /** Optional stable rule ID (SS-prefixed). */
  id?: SkillRuleId;
  /** Optional short rule name for reports. */
  name?: string;
};

/**
 * skill-safe.config.json schema.
 *
 * All fields are optional — omitted fields fall back to the chosen preset
 * (or "workspace" if preset is also omitted).
 *
 * CLI flags always override config file values.
 */
export type SkillSafeConfig = {
  /**
   * Base policy preset. Individual fields (failOn, suppressionMode, npmPolicy)
   * override the preset after it is applied.
   */
  preset?: SkillSafePolicyPreset;
  /** Override the fail threshold from the preset. */
  failOn?: "never" | "review" | "block";
  /** Override suppression handling from the preset. */
  suppressionMode?: SuppressionMode;
  /** Override npm source policy from the preset. */
  npmPolicy?: NpmSourcePolicy;
  /**
   * Additional rules appended to the built-in set.
   * Patterns are strings and compiled to RegExp on load.
   */
  extraRules?: SkillSafeConfigRule[];
  /** Scan target configuration for directory scans. */
  scan?: {
    /** Glob patterns or directory paths to include. Defaults to current directory. */
    include?: string[];
    /** Directory basenames to exclude. */
    exclude?: string[];
    /** Max recursion depth. Defaults to 10. */
    maxDepth?: number;
  };
};

export type ResolveMarkdownFileOptions = {
  owner?: string;
  repo?: string;
  branch?: string;
  path?: string;
  source?: MarkdownFileSource;
  /**
   * Optional API endpoint for source hosts with GitHub-compatible contents
   * responses. If provided, it is used directly.
   */
  apiUrl?: string;
  /** Injected fetch implementation for tests, workers, or custom runtimes. */
  fetcher?: typeof fetch;
  /** Optional auth token for private or higher-rate GitHub API requests. */
  token?: string;
  /** Preferred markdown entrypoints, in order. */
  preferredFileNames?: string[];
  /** Whether to inspect one level of subdirectories for SKILL.md. Defaults true. */
  scanSubdirectories?: boolean;
};

export type ResolvedMarkdownFile = {
  resolvedUrl: string;
  source: MarkdownFileSource;
  owner?: string;
  repo?: string;
  branch?: string;
  path?: string;
};

export type GitHubContentFile = {
  type: "file";
  name: string;
  path: string;
  download_url?: string | null;
};

export type GitHubContentDirectory = {
  type: "dir";
  name: string;
  path: string;
  url?: string;
};

export type GitHubContentResponse =
  | GitHubContentFile
  | GitHubContentDirectory
  | Array<GitHubContentFile | GitHubContentDirectory>;
