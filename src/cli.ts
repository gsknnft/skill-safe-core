#!/usr/bin/env node
import { stat, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import
    {
        createSkillSafeDocumentReport,
        createSkillSafeReport,
        formatSkillSafeReportMarkdown,
        stringifySkillSafeReportJson,
    } from "./reporter.js";
import
    {
        describeSkillSource,
        resolveAndScanSkillMarkdown,
    } from "./resolver.js";
import { sanitizeSkillMarkdown, type SuppressionMode } from "./sanitize.js";
import { stringifySkillSafeSarifJson } from "./sarif.js";
import { scanSkillDirectory, scanSkillFiles } from "./scanner.js";
import { requiresSanitization } from "./trust.js";
import type { SkillSafeFullReport } from "./types.js";

type Args = {
  source: string | null;
  file: string | null;
  dir: string | null;
  text: string | null;
  json: boolean;
  sarif: boolean;
  markdown: boolean;
  full: boolean;
  out: string | null;
  failOn: "never" | "review" | "block";
  suppressionMode: SuppressionMode;
  help: boolean;
};

const DEFAULT_SOURCE = "github:HashLips/agent-skills";
/**
 * Resolve a trust level from a raw skill source string.
 *
 * Recognizes:
 *   - openclaw-bundled          → verified
 *   - openclaw-managed          → managed
 *   - openclaw-workspace        → workspace
 *   - agents-skills-*           → workspace
 *   - openclaw-extra            → community
 *   - github:<owner>/<repo>     → community
 *   - registry:<name>           → community
 *   - souls:<id>                → community
 *   - hermes:<id>               → community
 *   - anything else             → unknown
 */

const HELP = `skill-safe

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
  --fail-on <mode>    never | review | block. Default: block.
  --honor-suppressions  Apply skill-safe-ignore comments. Use only for trusted sources.
  --no-suppressions     Disable suppression parsing.
  --help              Show this help.

Exit codes:
  0  scan completed and did not meet --fail-on threshold
  1  scan completed and met --fail-on threshold, or failed to scan
`;

const parseArgs = (argv: string[]): Args => {
  const args: Args = {
    source: null,
    file: null,
    dir: null,
    text: null,
    json: false,
    sarif: false,
    markdown: false,
    full: false,
    out: null,
    failOn: "block",
    suppressionMode: "report-only",
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const value = argv[i];
    if (value === "--help" || value === "-h") {
      args.help = true;
    } else if (value === "--json") {
      args.json = true;
    } else if (value === "--sarif") {
      args.sarif = true;
    } else if (value === "--markdown" || value === "--md") {
      args.markdown = true;
    } else if (value === "--full") {
      args.full = true;
    } else if (value === "--file") {
      args.file = argv[++i] ?? "";
    } else if (value === "--dir" || value === "--directory") {
      args.dir = argv[++i] ?? "";
    } else if (value === "--text") {
      args.text = argv[++i] ?? "";
    } else if (value === "--out") {
      args.out = argv[++i] ?? "";
    } else if (value === "--fail-on") {
      const mode = argv[++i] ?? "";
      if (mode !== "never" && mode !== "review" && mode !== "block") {
        throw new Error("--fail-on must be one of: never, review, block");
      }
      args.failOn = mode;
    } else if (value === "--honor-suppressions") {
      args.suppressionMode = "honor";
    } else if (value === "--no-suppressions") {
      args.suppressionMode = "disabled";
    } else if (value.startsWith("--")) {
      throw new Error(`Unknown option: ${value}`);
    } else if (!args.source) {
      args.source = value;
    } else {
      throw new Error(`Unexpected argument: ${value}`);
    }
  }

  const formatFlags = [args.json, args.sarif, args.markdown].filter(Boolean).length;
  if (formatFlags > 1) {
    throw new Error("Use only one output format: --json, --sarif, or --markdown");
  }

  return args;
};

const severityRank = {
  allow: 0,
  review: 1,
  block: 2,
} as const;

const shouldFail = (report: SkillSafeFullReport, failOn: Args["failOn"]): boolean => {
  if (failOn === "never") return false;
  return severityRank[report.summary.recommendedAction] >= severityRank[failOn];
};

const scanFile = async (filePath: string, args: Args): Promise<SkillSafeFullReport> => {
  const absolutePath = resolve(filePath);
  const { report } = await scanSkillFiles([absolutePath], {
    root: dirname(absolutePath),
    source: pathToFileURL(absolutePath).toString(),
    suppressionMode: args.suppressionMode,
  });
  return report;
};

const scanDirectory = async (dirPath: string, args: Args): Promise<SkillSafeFullReport> => {
  const { report } = await scanSkillDirectory(resolve(dirPath), {
    suppressionMode: args.suppressionMode,
  });
  return report;
};

const scanText = (text: string, args: Args): SkillSafeFullReport => {
  const scan = sanitizeSkillMarkdown(text, { suppressionMode: args.suppressionMode });
  return createSkillSafeReport({
    mode: "text",
    documents: [
      createSkillSafeDocumentReport({
        id: "inline text",
        source: "inline text",
        resolvedUrl: null,
        sourceKind: "text",
        trust: "unknown",
        directlyResolvable: true,
        sanitized: true,
        content: text,
        scan,
      }),
    ],
  });
};

const scanSource = async (source: string, args: Args): Promise<SkillSafeFullReport> => {
  const descriptor = describeSkillSource(source);
  const resolved = await resolveAndScanSkillMarkdown(source);
  const scan = resolved.scan ?? sanitizeSkillMarkdown(resolved.markdown, { suppressionMode: args.suppressionMode });

  return createSkillSafeReport({
    mode: "resolved-source",
    documents: [
      createSkillSafeDocumentReport({
        id: resolved.source,
        source: resolved.source,
        resolvedUrl: resolved.resolvedUrl,
        sourceKind: resolved.kind,
        trust: resolved.trust,
        directlyResolvable: descriptor.directlyResolvable,
        sanitized: requiresSanitization(resolved.trust),
        content: resolved.markdown,
        scan,
      }),
    ],
  });
};

const renderReport = (report: SkillSafeFullReport, args: Args): string => {
  if (args.json) return stringifySkillSafeReportJson(report);
  if (args.sarif) return stringifySkillSafeSarifJson(report);
  return formatSkillSafeReportMarkdown(report, { full: args.full });
};

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(HELP);
    return;
  }

  const selectedModes = [args.file, args.dir, args.text, args.source].filter(
    (value) => value !== null,
  ).length;
  if (selectedModes > 1) {
    throw new Error("Use only one input mode: source, --file, --dir, or --text");
  }

  let report: SkillSafeFullReport;
  if (args.file) {
    report = await scanFile(args.file, args);
  } else if (args.dir) {
    report = await scanDirectory(args.dir, args);
  } else if (args.text !== null) {
    report = scanText(args.text, args);
  } else if (args.source) {
    const possiblePath = resolve(args.source);
    try {
      const pathStat = await stat(possiblePath);
      report = pathStat.isDirectory()
        ? await scanDirectory(possiblePath, args)
        : pathStat.isFile()
          ? await scanFile(possiblePath, args)
          : await scanSource(args.source, args);
    } catch {
      report = await scanSource(args.source, args);
    }
  } else {
    report = await scanSource(DEFAULT_SOURCE, args);
  }

  const output = renderReport(report, args);
  if (args.out) {
    await writeFile(args.out, output, "utf8");
  }
  process.stdout.write(output);

  process.exitCode = shouldFail(report, args.failOn) ? 1 : 0;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`${basename(process.argv[1] ?? "skill-safe")}: ${message}`);
  process.exitCode = 1;
});
