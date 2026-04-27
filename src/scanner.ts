/**
 * Batch skill scanner - scan a directory or explicit file list.
 *
 * Node.js only because it uses node:fs/node:path. Import from
 * "@gsknnft/skill-safe/scanner" or the root package export.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import {
  basename,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
} from "node:path";
import { computeContentIntegrity, type SourceIntegrity } from "./integrity.js";
import {
  createSkillSafeDocumentReport,
  createSkillSafeReport,
  type SkillSafeDocumentReport,
  type SkillSafeFullReport,
} from "./reporter.js";
import type { RuleDefinition } from "./rules.js";
import { sanitizeSkillMarkdown } from "./sanitize.js";
import { requiresSanitization, resolveSkillTrustLevel } from "./trust.js";

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

const DEFAULT_IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  ".next",
  "coverage",
  ".turbo",
  "out",
]);

async function collectSkillFiles(
  dir: string,
  extensions: Set<string>,
  includeFileNames: Set<string> | null,
  ignoreDirs: Set<string>,
  maxDepth: number,
  depth = 0,
): Promise<string[]> {
  if (depth > maxDepth) return [];

  const entries = await readdir(dir, { withFileTypes: true });
  const results: string[] = [];

  for (const entry of entries) {
    const absoluteEntry = join(dir, entry.name);

    if (entry.isDirectory()) {
      if (ignoreDirs.has(entry.name)) continue;
      results.push(
        ...(await collectSkillFiles(
          absoluteEntry,
          extensions,
          includeFileNames,
          ignoreDirs,
          maxDepth,
          depth + 1,
        )),
      );
      continue;
    }

    if (!entry.isFile()) continue;

    const matchesName = includeFileNames?.has(entry.name.toLowerCase()) ?? false;
    const matchesExtension =
      includeFileNames === null && extensions.has(extname(entry.name).toLowerCase());

    if (matchesName || matchesExtension) {
      results.push(absoluteEntry);
    }
  }

  return results.sort((a, b) => a.localeCompare(b));
}

async function scanSingleFile(
  absolutePath: string,
  root: string,
  source: string,
  bundled: boolean,
  extraRules: RuleDefinition[],
  withIntegrity: boolean,
): Promise<ScannedSkillFile> {
  const relativePath = relative(root, absolutePath).replace(/\\/g, "/");
  const content = await readFile(absolutePath, "utf8");
  const trust = resolveSkillTrustLevel(source, bundled);
  const shouldSanitize = !bundled && requiresSanitization(trust);
  const scan = shouldSanitize
    ? sanitizeSkillMarkdown(content, extraRules)
    : sanitizeSkillMarkdown("", extraRules);

  const document = createSkillSafeDocumentReport({
    id: relativePath || basename(absolutePath),
    source,
    resolvedUrl: null,
    sourceKind: "file",
    trust,
    directlyResolvable: false,
    sanitized: shouldSanitize,
    content,
    scan,
  });

  const integrity = withIntegrity
    ? await computeContentIntegrity(content, null)
    : null;

  return { absolutePath, relativePath, source, document, integrity };
}

/**
 * Scan an explicit list of skill markdown files and return one full report.
 */
export const scanSkillFiles = async (
  files: string[],
  options: ScanSkillFilesOptions = {},
): Promise<ScanSkillBatchResult> => {
  const root = resolve(options.root ?? process.cwd());
  const source = options.source ?? "workspace";
  const bundled = options.bundled ?? false;
  const extraRules = options.extraRules ?? [];
  const withIntegrity = options.computeIntegrity ?? true;

  if (files.length === 0) {
    throw new Error("scanSkillFiles: no files provided.");
  }

  const scanned = await Promise.all(
    files.map((filePath) => {
      const absolutePath = isAbsolute(filePath)
        ? filePath
        : resolve(root, filePath);
      const resolvedSource = options.resolveSource?.(absolutePath) ?? source;
      return scanSingleFile(
        absolutePath,
        root,
        resolvedSource,
        bundled,
        extraRules,
        withIntegrity,
      );
    }),
  );

  return {
    report: createSkillSafeReport({
      mode: "batch",
      documents: scanned.map((scannedFile) => scannedFile.document),
    }),
    files: scanned,
  };
};

/**
 * Recursively scan a directory for skill entrypoint files and return one full report.
 *
 * By default this only scans SKILL.md/skill.md files. Set includeFileNames to
 * null to scan all files matching extensions instead.
 */
export const scanSkillDirectory = async (
  dir: string,
  options: ScanSkillDirectoryOptions = {},
): Promise<ScanSkillBatchResult> => {
  const absoluteDir = resolve(dir);
  const root = resolve(options.root ?? absoluteDir);
  const extensions = new Set(
    (options.extensions ?? [".md"]).map((extension) => extension.toLowerCase()),
  );
  const includeFileNames =
    options.includeFileNames === null
      ? null
      : new Set(
          (options.includeFileNames ?? ["SKILL.md", "skill.md"]).map((name) =>
            name.toLowerCase(),
          ),
        );
  const ignoreDirs = new Set([...DEFAULT_IGNORE_DIRS, ...(options.ignoreDirs ?? [])]);
  const maxDepth = options.maxDepth ?? 10;

  const dirStat = await stat(absoluteDir);
  if (!dirStat.isDirectory()) {
    throw new Error(`scanSkillDirectory: "${absoluteDir}" is not a directory.`);
  }

  const paths = await collectSkillFiles(
    absoluteDir,
    extensions,
    includeFileNames,
    ignoreDirs,
    maxDepth,
  );

  if (paths.length === 0) {
    const target = includeFileNames
      ? [...includeFileNames].join("/")
      : [...extensions].join("/");
    throw new Error(`scanSkillDirectory: no ${target} files found in "${absoluteDir}".`);
  }

  return scanSkillFiles(paths, {
    ...options,
    root,
    computeIntegrity: options.computeIntegrity ?? true,
  });
};
