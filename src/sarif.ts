/**
 * SARIF v2.1.0 output for GitHub Code Scanning integration.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 * GitHub schema: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-github-code-scanning
 */

import type { RuleDefinition, SanitizationCategory, SanitizationFlag } from "./sanitize.js";
import { RULES } from "./rules.js";
import type {
  SarifResult,
  SkillSafeDocumentReport,
  SarifRule,
  SarifLocation,
  SkillSafeFullReport,
  SarifLog,
  SarifArtifact,
  SarifRuleMeta,
} from "./types.js";


const CATEGORY_RULE_META: Record<SanitizationCategory, SarifRuleMeta> = {
  "prompt-injection": {
    id:   "SS/prompt-injection",
    name: "PromptInjection",
    short: "Prompt injection instruction detected.",
    full:  "The skill attempts to override the agent's existing system instructions, change its behavior, or plant a new directive mid-skill. This can cause the agent to perform unauthorized actions.",
    securitySeverity: "8.5",
    precision: "high",
  },
  "identity-hijack": {
    id:   "SS/identity-hijack",
    name: "IdentityHijack",
    short: "Identity or persona hijack detected.",
    full:  "The skill instructs the agent to assume a different identity, persona, or role that bypasses its safety guidelines.",
    securitySeverity: "8.0",
    precision: "high",
  },
  "jailbreak": {
    id:   "SS/jailbreak",
    name: "Jailbreak",
    short: "Jailbreak pattern detected.",
    full:  "The skill contains patterns commonly used to bypass AI safety constraints, such as DAN-style prompts or developer-mode unlocks.",
    securitySeverity: "9.0",
    precision: "high",
  },
  "data-exfiltration": {
    id:   "SS/data-exfiltration",
    name: "DataExfiltration",
    short: "Data exfiltration vector detected.",
    full:  "The skill contains network requests, webhook calls, or other mechanisms that could leak conversation data, credentials, or workspace files to an external endpoint.",
    securitySeverity: "9.5",
    precision: "very-high",
  },
  "script-injection": {
    id:   "SS/script-injection",
    name: "ScriptInjection",
    short: "Script or code injection pattern detected.",
    full:  "The skill embeds shell commands, eval() calls, or other execution vectors that could run arbitrary code on the host system.",
    securitySeverity: "9.0",
    precision: "high",
  },
  "format-injection": {
    id:   "SS/format-injection",
    name: "FormatInjection",
    short: "Format injection pattern detected.",
    full:  "The skill uses special tokens (e.g., <|system|>, [INST]) that exploit prompt-format boundaries in template-based LLM deployments.",
    securitySeverity: "7.5",
    precision: "high",
  },
  "excessive-claims": {
    id:   "SS/excessive-claims",
    name: "ExcessiveClaims",
    short: "Excessive or deceptive capability claims detected.",
    full:  "The skill claims capabilities that could mislead the agent or user into granting unwarranted trust or permissions.",
    securitySeverity: "4.0",
    precision: "medium",
  },
  "hidden-content": {
    id:   "SS/hidden-content",
    name: "HiddenContent",
    short: "Hidden or invisible content detected.",
    full:  "The skill contains invisible Unicode characters, zero-width joiners, or HTML-encoded text that may hide instructions from human reviewers.",
    securitySeverity: "7.0",
    precision: "very-high",
  },
  "hitl-bypass": {
    id:   "SS/hitl-bypass",
    name: "HitlBypass",
    short: "Human-in-the-loop bypass attempt detected.",
    full:  "The skill instructs the agent to skip, suppress, or automatically approve human approval steps.",
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

const SYNTHETIC_RULE_META: Record<string, SarifRuleMeta> = {
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

const ORDERED_CATEGORIES: SanitizationCategory[] = [
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

const severityToLevel = (severity: SanitizationFlag["severity"]): SarifResult["level"] =>
  severity === "danger" ? "error" : "warning";

const buildArtifactUri = (doc: SkillSafeDocumentReport): string => {
  const resolved = doc.resolvedUrl;
  if (resolved) return resolved;
  // For file/text sources, use the source string as a relative URI
  const src = doc.source.replace(/\\/g, "/");
  return src.startsWith("/") || src.includes("://") ? src : `./${src}`;
};

const ruleMetaToSarifRule = (meta: SarifRuleMeta): SarifRule => ({
  id: meta.id,
  name: meta.name,
  shortDescription: { text: meta.short },
  fullDescription: { text: meta.full },
  helpUri: `https://github.com/gsknnft/skill-safe-core#${meta.category ?? meta.id.toLowerCase()}`,
  defaultConfiguration: {
    level: Number(meta.securitySeverity) >= 7 ? "error" : "warning",
  },
  properties: {
    tags: ["security", "ai-safety", meta.category ?? meta.id],
    "security-severity": meta.securitySeverity,
    precision: meta.precision,
    "problem.severity":
      Number(meta.securitySeverity) >= 7
        ? "error"
        : Number(meta.securitySeverity) >= 4
          ? "warning"
          : "recommendation",
  },
});

const ruleDefinitionToMeta = (rule: RuleDefinition): SarifRuleMeta | null => {
  if (!rule.id) return null;
  const categoryMeta = CATEGORY_RULE_META[rule.category];
  return {
    id: rule.id,
    name: rule.name ?? rule.id,
    short: rule.description,
    full: rule.description,
    securitySeverity: categoryMeta.securitySeverity,
    precision: categoryMeta.precision,
    category: rule.category,
  };
};

const buildRules = (): SarifRule[] => {
  const categoryRules = ORDERED_CATEGORIES.map((cat) =>
    ruleMetaToSarifRule(CATEGORY_RULE_META[cat]),
  );
  const builtInRules = RULES
    .map(ruleDefinitionToMeta)
    .filter((meta): meta is SarifRuleMeta => meta !== null)
    .map(ruleMetaToSarifRule);
  const syntheticRules = Object.values(SYNTHETIC_RULE_META).map(ruleMetaToSarifRule);

  return [...categoryRules, ...builtInRules, ...syntheticRules];
};

const buildRegion = (flag: SanitizationFlag): SarifLocation["physicalLocation"]["region"] => {
  if (!flag.location) return { startLine: 1 };
  return {
    startLine: flag.location.line,
    startColumn: flag.location.column,
    charOffset: flag.location.offset,
    byteOffset: flag.location.byteOffset,
  };
};

const buildResultsForDocument = (
  doc: SkillSafeDocumentReport,
  ruleIndexById: Map<string, number>,
): SarifResult[] => {
  const uri = buildArtifactUri(doc);

  return doc.scan.flags.map((flag) => {
    const meta = CATEGORY_RULE_META[flag.category as SanitizationCategory];
    const fallbackRuleId = meta?.id ?? `SS/${flag.category}`;
    const ruleId = flag.ruleId ?? fallbackRuleId;
    const ruleIndex = ruleIndexById.get(ruleId) ?? ruleIndexById.get(fallbackRuleId) ?? 0;
    return {
      ruleId,
      ruleIndex,
      level: severityToLevel(flag.severity),
      message: {
        text: `[${flag.ruleId ?? flag.category}] ${flag.description} - matched: ${flag.matched.slice(0, 200)}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
            region: buildRegion(flag),
          },
        },
      ],
      partialFingerprints: {
        "skill-safe/category/v1": flag.category,
        "skill-safe/rule/v1": ruleId,
        "skill-safe/document/v1": doc.id,
      },
      properties: {
        ruleName: flag.ruleName,
        matched: flag.matched.slice(0, 500),
        normalized: flag.normalized ?? false,
        owasp: flag.owasp ?? [],
        mitreAtlas: flag.mitreAtlas ?? [],
        nistAiRmf: flag.nistAiRmf ?? [],
      },
    };
  });
};

export type ToSarifOptions = {
  /** Tool version to embed. Defaults to the current package version. */
  version?: string;
};

/**
 * Convert a SkillSafeFullReport into a SARIF v2.1.0 log suitable for
 * GitHub Code Scanning upload.
 */
export const toSarifReport = (
  report: SkillSafeFullReport,
  options: ToSarifOptions = {},
): SarifLog => {
  const version = options.version ?? "0.2.1";
  const rules = buildRules();
  const ruleIndexById = new Map(rules.map((rule, index) => [rule.id, index]));

  const artifacts: SarifArtifact[] = report.documents.map((doc) => ({
    location: { uri: buildArtifactUri(doc), uriBaseId: "%SRCROOT%" },
    length: doc.bytes,
    mimeType: "text/markdown",
    properties: {
      trustLevel: doc.trust,
      sourceKind: doc.sourceKind,
    },
  }));

  const results: SarifResult[] = report.documents.flatMap((doc) =>
    buildResultsForDocument(doc, ruleIndexById),
  );

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "skill-safe",
            version,
            informationUri: "https://github.com/gsknnft/skill-safe-core",
            rules,
          },
        },
        results,
        artifacts,
        properties: {
          "skill-safe:report": {
            mode: report.mode,
            riskScore: report.summary.riskScore,
            recommendedAction: report.summary.recommendedAction,
          },
        },
      },
    ],
  };
};

/** Serialize a SARIF log to a JSON string (with trailing newline). */
export const stringifySkillSafeSarifJson = (
  report: SkillSafeFullReport,
  options: ToSarifOptions = {},
): string => `${JSON.stringify(toSarifReport(report, options), null, 2)}\n`;
