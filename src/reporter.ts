import type {
  SanitizationFlag,
  SanitizationResult,
  SkillScanReport,
} from "./sanitize.js";
import type { SkillSourceKind } from "./resolver.js";
import type { SkillTrustLevel } from "./trust.js";

export type SkillSafeReportMode = "resolved-source" | "file" | "text" | "batch";

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

const actionRank: Record<SkillScanReport["recommendedAction"], number> = {
  allow: 0,
  review: 1,
  block: 2,
};

const severityRank: Record<SanitizationResult["severity"], number> = {
  safe: 0,
  caution: 1,
  danger: 2,
};

const uniqueSorted = (values: string[]): string[] =>
  Array.from(new Set(values)).sort();

const countLines = (content: string): number =>
  content.length === 0 ? 0 : content.split(/\r?\n/).length;

export const createSkillSafeDocumentReport = ({
  id,
  source,
  resolvedUrl,
  sourceKind,
  trust,
  directlyResolvable,
  sanitized,
  content,
  scan,
}: {
  id: string;
  source: string;
  resolvedUrl: string | null;
  sourceKind: SkillSafeDocumentReport["sourceKind"];
  trust: SkillSafeDocumentReport["trust"];
  directlyResolvable: boolean;
  sanitized: boolean;
  content: string;
  scan: SanitizationResult;
}): SkillSafeDocumentReport => ({
  id,
  source,
  resolvedUrl,
  sourceKind,
  trust,
  directlyResolvable,
  sanitized,
  bytes: new TextEncoder().encode(content).length,
  lines: countLines(content),
  scan,
});

export const createSkillSafeReport = ({
  mode,
  documents,
  generatedAt = new Date().toISOString(),
}: CreateSkillSafeReportOptions): SkillSafeFullReport => {
  if (documents.length === 0) {
    throw new Error("At least one document is required to create a skill-safe report.");
  }

  const categories: Record<string, number> = {};
  for (const document of documents) {
    for (const [category, count] of Object.entries(document.scan.report.categories)) {
      categories[category] = (categories[category] ?? 0) + (count ?? 0);
    }
  }

  const recommendedAction = documents.reduce<SkillScanReport["recommendedAction"]>(
    (highest, document) =>
      actionRank[document.scan.report.recommendedAction] > actionRank[highest]
        ? document.scan.report.recommendedAction
        : highest,
    "allow",
  );

  const severity = documents.reduce<SanitizationResult["severity"]>(
    (highest, document) =>
      severityRank[document.scan.severity] > severityRank[highest]
        ? document.scan.severity
        : highest,
    "safe",
  );

  const summary: SkillSafeReportSummary = {
    safeToInstall: documents.every((document) => document.scan.safeToInstall),
    recommendedAction,
    severity,
    riskScore: Math.max(...documents.map((document) => document.scan.report.riskScore)),
    documents: documents.length,
    passed: documents.filter((document) => document.scan.report.recommendedAction === "allow").length,
    review: documents.filter((document) => document.scan.report.recommendedAction === "review").length,
    blocked: documents.filter((document) => document.scan.report.recommendedAction === "block").length,
    findings: documents.reduce((sum, document) => sum + document.scan.flags.length, 0),
    danger: documents.reduce((sum, document) => sum + document.scan.report.summary.danger, 0),
    caution: documents.reduce((sum, document) => sum + document.scan.report.summary.caution, 0),
    hiddenContent: documents.reduce(
      (sum, document) => sum + document.scan.report.summary.hiddenContent,
      0,
    ),
    normalizedMatches: documents.reduce(
      (sum, document) => sum + document.scan.report.summary.normalizedMatches,
      0,
    ),
  };

  return {
    version: "skill-safe.full-report.v1",
    generatedAt,
    mode,
    ok: summary.safeToInstall,
    summary,
    categories,
    mappings: {
      owasp: uniqueSorted(
        documents.flatMap((document) => document.scan.report.mappings.owasp),
      ),
      mitreAtlas: uniqueSorted(
        documents.flatMap((document) => document.scan.report.mappings.mitreAtlas),
      ),
      nistAiRmf: uniqueSorted(
        documents.flatMap((document) => document.scan.report.mappings.nistAiRmf),
      ),
    },
    documents,
  };
};

export const stringifySkillSafeReportJson = (
  report: SkillSafeFullReport,
  space = 2,
): string => `${JSON.stringify(report, null, space)}\n`;

const formatList = (values: string[]): string =>
  values.length > 0 ? values.join(", ") : "none";

const truncate = (value: string, max = 160): string => {
  const normalized = value.replace(/\s+/g, " ").trim();
  if (normalized.length <= max) return normalized;
  return `${normalized.slice(0, max - 1)}...`;
};

const formatFindingMarkdown = (
  flag: SanitizationFlag,
  index: number,
  full: boolean,
): string => {
  const lines = [
    `${index + 1}. **[${flag.severity}] ${flag.ruleId ?? flag.category} ${flag.category}**`,
    `   - ${flag.description}`,
    `   - Match: \`${truncate(flag.matched, full ? 500 : 120)}\``,
  ];
  if (flag.ruleName) lines.push(`   - Rule: ${flag.ruleName}`);
  if (flag.location) {
    lines.push(`   - Location: line ${flag.location.line}, column ${flag.location.column}`);
  }
  if (flag.normalized) lines.push("   - Normalized match: yes");
  if (full) {
    lines.push(`   - OWASP: ${formatList(flag.owasp ?? [])}`);
    lines.push(`   - MITRE ATLAS: ${formatList(flag.mitreAtlas ?? [])}`);
    lines.push(`   - NIST AI RMF: ${formatList(flag.nistAiRmf ?? [])}`);
  }
  return lines.join("\n");
};

export const formatSkillSafeReportMarkdown = (
  report: SkillSafeFullReport,
  options: { full?: boolean } = {},
): string => {
  const full = options.full ?? false;
  const lines = [
    "# skill-safe Report",
    "",
    `Generated: ${report.generatedAt}`,
    `Mode: ${report.mode}`,
    `Verdict: ${report.ok ? "PASS" : "FAIL"}`,
    `Recommended action: ${report.summary.recommendedAction}`,
    `Severity: ${report.summary.severity}`,
    `Risk score: ${report.summary.riskScore}/100`,
    "",
    "## Summary",
    "",
    `- Documents: ${report.summary.documents}`,
    `- Passed: ${report.summary.passed}`,
    `- Review: ${report.summary.review}`,
    `- Blocked: ${report.summary.blocked}`,
    `- Findings: ${report.summary.findings}`,
    `- Danger: ${report.summary.danger}`,
    `- Caution: ${report.summary.caution}`,
    `- Hidden content: ${report.summary.hiddenContent}`,
    `- Normalized matches: ${report.summary.normalizedMatches}`,
    "",
    "## Categories",
    "",
  ];

  const categories = Object.entries(report.categories);
  if (categories.length === 0) {
    lines.push("- none");
  } else {
    for (const [category, count] of categories) {
      lines.push(`- ${category}: ${count}`);
    }
  }

  lines.push(
    "",
    "## Governance Mappings",
    "",
    `- OWASP: ${formatList(report.mappings.owasp)}`,
    `- MITRE ATLAS: ${formatList(report.mappings.mitreAtlas)}`,
    `- NIST AI RMF: ${formatList(report.mappings.nistAiRmf)}`,
    "",
    "## Documents",
    "",
  );

  for (const document of report.documents) {
    lines.push(
      `### ${document.id}`,
      "",
      `- Source: ${document.source}`,
      `- Resolved: ${document.resolvedUrl ?? "n/a"}`,
      `- Source kind: ${document.sourceKind}`,
      `- Trust: ${document.trust}`,
      `- Sanitized: ${document.sanitized ? "yes" : "no"}`,
      `- Lines: ${document.lines}`,
      `- Bytes: ${document.bytes}`,
      `- Safe to install: ${document.scan.safeToInstall ? "yes" : "no"}`,
      `- Recommended action: ${document.scan.report.recommendedAction}`,
      `- Risk score: ${document.scan.report.riskScore}/100`,
      "",
      "#### Findings",
      "",
    );
    if (document.scan.flags.length === 0) {
      lines.push("- none", "");
    } else {
      lines.push(
        ...document.scan.flags.map((flag, index) =>
          formatFindingMarkdown(flag, index, full),
        ),
        "",
      );
    }
  }

  return `${lines.join("\n")}\n`;
};
