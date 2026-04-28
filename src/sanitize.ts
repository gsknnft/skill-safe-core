import { ZERO_WIDTH_RE, HTML_ENTITIES, INVISIBLE_RUN_RE, INVISIBLE_RE } from "./constants.js";
import { getCategoryReportArrays, toReportArrays } from "./mappings.js";
import { RULES } from "./rules.js";
import type {
  RuleDefinition,
  SanitizationCategory,
  SanitizationFlag,
  SanitizationLocation,
  SanitizationOptions,
  SanitizationResult,
  SanitizationSuppression,
  SkillScanReport,
  SuppressionMode,
} from "./types.js";

// ---------------------------------------------------------------------------
// Core scanner
// ---------------------------------------------------------------------------


export const normalizeSkillText = (content: string): string => {
  let normalized = content
    .normalize("NFKC")
    .replace(ZERO_WIDTH_RE, "")
    .replace(/\\u\{?([0-9a-fA-F]{2,6})\}?/g, (_match, hex: string) => {
      const code = Number.parseInt(hex, 16);
      if (!Number.isFinite(code)) return _match;
      try {
        return String.fromCodePoint(code);
      } catch {
        return _match;
      }
    })
    .replace(/&#x([0-9a-fA-F]+);?/g, (_match, hex: string) => {
      const code = Number.parseInt(hex, 16);
      if (!Number.isFinite(code)) return _match;
      try {
        return String.fromCodePoint(code);
      } catch {
        return _match;
      }
    })
    .replace(/&#(\d+);?/g, (_match, dec: string) => {
      const code = Number.parseInt(dec, 10);
      if (!Number.isFinite(code)) return _match;
      try {
        return String.fromCodePoint(code);
      } catch {
        return _match;
      }
    })
    .replace(
      /&([a-zA-Z]+);?/g,
      (match, name: string) => HTML_ENTITIES[name.toLowerCase()] ?? match,
    );

  // De-obfuscate common spaced command/protocol words without collapsing normal prose.
  const spacedTokens = [
    "curl",
    "wget",
    "fetch",
    "javascript",
    "ignore",
    "disregard",
    "override",
    "exfiltrate",
  ];
  for (const token of spacedTokens) {
    const pattern = new RegExp(`\\b${token.split("").join("\\s*")}\\b`, "gi");
    normalized = normalized.replace(pattern, token);
  }

  return normalized;
};

const excerptMatch = (
  content: string,
  index: number,
  matchLength: number,
): string => {
  const CONTEXT = 40;
  const start = Math.max(0, index - 20);
  const end = Math.min(content.length, index + matchLength + CONTEXT);
  const raw = content.slice(start, end).replace(/\s+/g, " ").trim();
  return end < content.length ? `${raw}...` : raw;
};

const getLocation = (content: string, offset: number): SanitizationLocation => {
  const safeOffset = Math.max(0, Math.min(offset, content.length));
  let line = 1;
  let lineStart = 0;

  for (let i = 0; i < safeOffset; i += 1) {
    const char = content.charCodeAt(i);
    if (char === 10) {
      line += 1;
      lineStart = i + 1;
    }
  }

  return {
    line,
    column: safeOffset - lineStart + 1,
    offset: safeOffset,
    byteOffset: new TextEncoder().encode(content.slice(0, safeOffset)).length,
  };
};

const uniqueSorted = (values: Array<string | undefined>): string[] =>
  [
    ...new Set(values.filter((value): value is string => Boolean(value))),
  ].sort();

const withDefaultMappings = (flag: SanitizationFlag): SanitizationFlag => {
  const defaults = getCategoryReportArrays(flag.category);
  return {
    ...flag,
    owasp: flag.owasp ?? defaults.owasp,
    mitreAtlas: flag.mitreAtlas ?? defaults.mitreAtlas,
    nistAiRmf: flag.nistAiRmf ?? defaults.nistAiRmf,
  };
};

const buildReport = (
  severity: "safe" | "caution" | "danger",
  safeToInstall: boolean,
  flags: SanitizationFlag[],
): SkillScanReport => {
  const danger = flags.filter((flag) => flag.severity === "danger").length;
  const caution = flags.filter((flag) => flag.severity === "caution").length;
  const hiddenContent = flags.filter(
    (flag) => flag.category === "hidden-content",
  ).length;
  const normalizedMatches = flags.filter((flag) => flag.normalized).length;
  const categories: Partial<Record<SanitizationCategory, number>> = {};
  for (const flag of flags) {
    categories[flag.category] = (categories[flag.category] ?? 0) + 1;
  }

  const riskScore = Math.min(
    100,
    danger * 35 + caution * 12 + hiddenContent * 8 + normalizedMatches * 8,
  );

  return {
    version: "skill-safe.report.v1",
    riskScore,
    summary: {
      safeToInstall,
      severity,
      danger,
      caution,
      hiddenContent,
      normalizedMatches,
    },
    categories,
    mappings: {
      owasp: uniqueSorted(flags.flatMap((flag) => flag.owasp ?? [])),
      mitreAtlas: uniqueSorted(flags.flatMap((flag) => flag.mitreAtlas ?? [])),
      nistAiRmf: uniqueSorted(flags.flatMap((flag) => flag.nistAiRmf ?? [])),
    },
    recommendedAction:
      severity === "danger"
        ? "block"
        : severity === "caution"
          ? "review"
          : "allow",
  };
};

// ---------------------------------------------------------------------------
// Suppression
// ---------------------------------------------------------------------------

/**
 * Parse `<!-- skill-safe-ignore SS001: reason text -->` comments from content.
 * Reason text is required — bare `<!-- skill-safe-ignore SS001 -->` is rejected.
 */
export const parseSuppressions = (
  content: string,
): SanitizationSuppression[] => {
  const suppressions: SanitizationSuppression[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const lineRe = /<!--\s*skill-safe-ignore\s+(SS\w+)\s*:\s*(.+?)\s*-->/gi;
    let match: RegExpExecArray | null;
    while ((match = lineRe.exec(lines[i]!)) !== null) {
      suppressions.push({
        ruleId: match[1]!,
        reason: match[2]!.trim(),
        line: i + 1,
      });
    }
  }
  return suppressions;
};

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/**
 * Scan skill markdown content for red flags.
 * Parses suppressions and reports them, but DOES NOT apply them -
 * Caller is responsible for filtering flags based on suppressions and suppressionMode
 *
 * @param content - Raw markdown string (YAML frontmatter + body)
 * @param extraRulesOrOptions - Additional rules (legacy positional) or options object
 *
 */
/**
 * Scan skill markdown content for red flags.
 * Parses suppressions and reports them, but DOES NOT apply them unless suppressionMode is 'honor'.
 * By default, suppressionMode is 'report-only' (safe for untrusted content).
 *
 * @param content - Raw markdown string (YAML frontmatter + body)
 * @param extraRulesOrOptions - Additional rules (legacy positional) or options object
 * @param honorSuppressions - (DEPRECATED) Use options.suppressionMode instead. If set, overrides suppressionMode for backward compatibility.
 */
export const sanitizeSkillMarkdown = (
  content: string,
  extraRulesOrOptions: RuleDefinition[] | SanitizationOptions = [],
  honorSuppressions?: boolean, // deprecated, use options.suppressionMode
): SanitizationResult => {
  const options: SanitizationOptions = Array.isArray(extraRulesOrOptions)
    ? { extraRules: extraRulesOrOptions }
    : extraRulesOrOptions;
  const extraRules = options.extraRules ?? [];
  let suppressionMode: SuppressionMode = "report-only";
  if (typeof options.suppressionMode === "string") {
    suppressionMode = options.suppressionMode;
  } else if (typeof honorSuppressions === "boolean") {
    suppressionMode = honorSuppressions ? "honor" : "report-only";
  }

  const suppressions =
    suppressionMode !== "disabled" ? parseSuppressions(content) : [];
  const suppressedIds =
    suppressionMode === "honor"
      ? new Set(suppressions.map((s) => s.ruleId))
      : new Set<string>();

  const flags: SanitizationFlag[] = [];
  const seenPatterns = new Set<string>();
  const allRules = [...RULES, ...extraRules];
  const normalizedContent = normalizeSkillText(content);

  const invisibleRuns = [...content.matchAll(INVISIBLE_RUN_RE)];
  for (const match of invisibleRuns) {
    flags.push({
      ruleId: "SS081",
      ruleName: "invisible-unicode-run",
      severity: "danger",
      category: "hidden-content",
      description: "Contains a long run of invisible Unicode characters.",
      matched: excerptMatch(content, match.index ?? 0, match[0].length),
      location: getLocation(content, match.index ?? 0),
      owasp: ["Agentic Instruction and Tool Manipulation"],
      nistAiRmf: ["Map", "Measure"],
    });
  }

  const invisibleCount = (content.match(INVISIBLE_RE) ?? []).length;
  if (invisibleCount > 0 && invisibleRuns.length === 0) {
    const firstInvisibleIndex = Math.max(0, content.search(INVISIBLE_RE));
    flags.push({
      ruleId: "SS082",
      ruleName: "invisible-unicode-character",
      severity: "caution",
      category: "hidden-content",
      description:
        "Contains invisible Unicode characters that may hide instructions from reviewers.",
      matched: `${invisibleCount} invisible character${invisibleCount === 1 ? "" : "s"}`,
      location: getLocation(content, firstInvisibleIndex),
      owasp: ["Agentic Instruction and Tool Manipulation"],
      nistAiRmf: ["Map", "Measure"],
    });
  }

  for (const rule of allRules) {
    const key = `${rule.pattern.source}/${rule.pattern.flags}`;
    if (seenPatterns.has(key)) continue;

    // Reset lastIndex so the regex is safe to reuse across calls
    rule.pattern.lastIndex = 0;
    let match = rule.pattern.exec(content);
    let matchedNormalized = false;
    if (!match && normalizedContent !== content) {
      rule.pattern.lastIndex = 0;
      match = rule.pattern.exec(normalizedContent);
      matchedNormalized = Boolean(match);
    }
    if (!match) continue;

    seenPatterns.add(key);
    const matchContent = matchedNormalized ? normalizedContent : content;
    flags.push({
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      category: rule.category,
      description: rule.description,
      matched: matchedNormalized
        ? excerptMatch(normalizedContent, match.index, match[0].length)
        : excerptMatch(content, match.index, match[0].length),
      normalized: matchedNormalized || undefined,
      location: getLocation(matchContent, match.index),
      ...(rule.governance ? toReportArrays(rule.governance) : {}),
    });
  }

  // Composite risk: prompt-injection + (data-exfiltration or script-injection) = lethal trifecta
  // Inspired by Skillguard / OWASP Agentic Skills Top 10.
  // When an instruction override is combined with a network or code execution vector,
  // escalate the combined flag to danger even if individual flags were caution.
  const categories = new Set(flags.map((f) => f.category));
  const hasInjection =
    categories.has("prompt-injection") || categories.has("identity-hijack");
  const hasExecution =
    categories.has("data-exfiltration") || categories.has("script-injection");
  if (hasInjection && hasExecution) {
    flags.push({
      ruleId: "SS900",
      ruleName: "lethal-trifecta-composite",
      severity: "danger",
      category: "prompt-injection",
      description:
        "Composite risk: instruction override combined with network/code-execution vector (Lethal Trifecta).",
      matched: "(multiple patterns)",
      owasp: [
        "Agentic Instruction and Tool Manipulation",
        "Data and Resource Exfiltration",
      ],
      mitreAtlas: ["Exfiltration"],
      nistAiRmf: ["Measure", "Manage"],
    });
  }

  // Only filter out suppressed flags in 'honor' mode. In 'report-only', all flags are present.
  const activeFlags =
    suppressionMode === "honor" && suppressedIds.size > 0
      ? flags.filter((f) => !f.ruleId || !suppressedIds.has(f.ruleId))
      : flags;

  const hasDanger = activeFlags.some((f) => f.severity === "danger");
  const hasCaution = activeFlags.some((f) => f.severity === "caution");

  const severity = hasDanger ? "danger" : hasCaution ? "caution" : "safe";
  const safeToInstall = !hasDanger;

  const mappedFlags = activeFlags.map(withDefaultMappings);

  return {
    severity,
    flags: mappedFlags,
    safeToInstall,
    suppressions,
    report: buildReport(severity, safeToInstall, mappedFlags),
  };
};

/**
 * Return a new scan result with additional synthetic/source-level flags merged
 * into the normal content findings. This is used for resolver findings such as
 * npm package age or missing provenance without making callers special-case
 * source security checks.
 */
export const appendSanitizationFlags = (
  result: SanitizationResult,
  additionalFlags: SanitizationFlag[],
): SanitizationResult => {
  if (additionalFlags.length === 0) return result;

  const flags = [...additionalFlags, ...result.flags].map(withDefaultMappings);
  const hasDanger = flags.some((flag) => flag.severity === "danger");
  const hasCaution = flags.some((flag) => flag.severity === "caution");
  const severity = hasDanger ? "danger" : hasCaution ? "caution" : "safe";
  const safeToInstall = !hasDanger;

  return {
    severity,
    flags,
    safeToInstall,
    suppressions: result.suppressions,
    report: buildReport(severity, safeToInstall, flags),
  };
};

/**
 * Extract YAML frontmatter from a skill markdown file.
 * Returns null if no frontmatter block is present.
 */
export const extractSkillFrontmatter = (
  content: string,
): Record<string, string> | null => {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/m.exec(content.trimStart());
  if (!match) return null;
  const result: Record<string, string> = {};
  for (const line of match[1]!.split(/\r?\n/)) {
    const colonIndex = line.indexOf(":");
    if (colonIndex === -1) continue;
    const key = line.slice(0, colonIndex).trim();
    const value = line
      .slice(colonIndex + 1)
      .trim()
      .replace(/^['"]|['"]$/g, "");
    if (key) result[key] = value;
  }
  return result;
};

/**
 * Convenience: scan both frontmatter and body of a skill file.
 * Returns a combined result treating them as a single document.
 */
export const sanitizeSkillFile = (
  content: string,
  extraRules: RuleDefinition[] = [],
): SanitizationResult => sanitizeSkillMarkdown(content, extraRules);
