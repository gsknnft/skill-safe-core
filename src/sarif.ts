/**
 * SARIF v2.1.0 output for GitHub Code Scanning integration.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 * GitHub schema: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-github-code-scanning
 */

import type { SkillSafeFullReport, SkillSafeDocumentReport } from "./reporter.js";
import type { SanitizationFlag } from "./sanitize.js";
import type { SanitizationCategory } from "./rules.js";

// ---------------------------------------------------------------------------
// SARIF types (minimal subset for GitHub Code Scanning)
// ---------------------------------------------------------------------------

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
    region: { startLine: number };
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

const CATEGORY_RULE_META: Record<
  SanitizationCategory,
  { id: string; name: string; short: string; full: string; securitySeverity: string; precision: SarifRule["properties"]["precision"] }
> = {
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

const CATEGORY_INDEX = new Map<SanitizationCategory, number>(
  ORDERED_CATEGORIES.map((cat, i) => [cat, i]),
);

const severityToLevel = (severity: SanitizationFlag["severity"]): SarifResult["level"] =>
  severity === "danger" ? "error" : "warning";

const buildArtifactUri = (doc: SkillSafeDocumentReport): string => {
  const resolved = doc.resolvedUrl;
  if (resolved) return resolved;
  // For file/text sources, use the source string as a relative URI
  const src = doc.source.replace(/\\/g, "/");
  return src.startsWith("/") || src.includes("://") ? src : `./${src}`;
};

const buildRules = (): SarifRule[] =>
  ORDERED_CATEGORIES.map((cat) => {
    const meta = CATEGORY_RULE_META[cat];
    return {
      id: meta.id,
      name: meta.name,
      shortDescription: { text: meta.short },
      fullDescription: { text: meta.full },
      helpUri: `https://github.com/gsknnft/skill-safe-core#${cat}`,
      defaultConfiguration: {
        level: Number(meta.securitySeverity) >= 7 ? "error" : "warning",
      },
      properties: {
        tags: ["security", "ai-safety", cat],
        "security-severity": meta.securitySeverity,
        precision: meta.precision,
        "problem.severity":
          Number(meta.securitySeverity) >= 7
            ? "error"
            : Number(meta.securitySeverity) >= 4
              ? "warning"
              : "recommendation",
      },
    };
  });

const buildResultsForDocument = (
  doc: SkillSafeDocumentReport,
  artifactIndex: number,
): SarifResult[] => {
  const uri = buildArtifactUri(doc);

  return doc.scan.flags.map((flag) => {
    const meta = CATEGORY_RULE_META[flag.category as SanitizationCategory];
    const ruleIndex = CATEGORY_INDEX.get(flag.category as SanitizationCategory) ?? 0;
    return {
      ruleId: meta?.id ?? `SS/${flag.category}`,
      ruleIndex,
      level: severityToLevel(flag.severity),
      message: {
        text: `[${flag.category}] ${flag.description} — matched: ${flag.matched.slice(0, 200)}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
            region: { startLine: 1 },
          },
        },
      ],
      partialFingerprints: {
        "skill-safe/category/v1": flag.category,
        "skill-safe/document/v1": doc.id,
      },
      properties: {
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
  /** Tool version to embed. Defaults to "0.1.0". */
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
  const version = options.version ?? "0.1.0";
  const rules = buildRules();

  const artifacts: SarifArtifact[] = report.documents.map((doc) => ({
    location: { uri: buildArtifactUri(doc), uriBaseId: "%SRCROOT%" },
    length: doc.bytes,
    mimeType: "text/markdown",
    properties: {
      trustLevel: doc.trust,
      sourceKind: doc.sourceKind,
    },
  }));

  const results: SarifResult[] = report.documents.flatMap((doc, artifactIndex) =>
    buildResultsForDocument(doc, artifactIndex),
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
