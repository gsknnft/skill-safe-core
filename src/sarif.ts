/**
 * SARIF v2.1.0 output for GitHub Code Scanning integration.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 * GitHub schema: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-github-code-scanning
 */

import { CATEGORY_RULE_META, ORDERED_CATEGORIES, SYNTHETIC_RULE_META } from "./constants.js";
import { RULES } from "./rules.js";
import type {
  RuleDefinition,
  SarifResult,
  SkillSafeDocumentReport,
  SarifRule,
  SarifLocation,
  SkillSafeFullReport,
  SarifLog,
  SarifArtifact,
  SanitizationFlag,
  SarifRuleMeta,
  SanitizationCategory,
  ToSarifOptions,
} from "./types.js";


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
