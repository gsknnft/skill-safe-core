import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { getPolicyPreset, isPolicyPreset } from "./policy.js";
import type {
  NpmSourcePolicy,
  RuleDefinition,
  SkillSafeConfig,
  SkillSafeConfigRule,
  SkillSafePolicyPreset,
  SkillSafePolicy,
  SuppressionMode,
} from "./types.js";

const CONFIG_FILE_NAMES = [
  "skill-safe.config.json",
  ".skillsaferc.json",
  ".skillsaferc",
];

/** Resolved, fully-merged effective config ready for use. */
export type ResolvedSkillSafeConfig = {
  preset: SkillSafePolicyPreset;
  failOn: "never" | "review" | "block";
  suppressionMode: SuppressionMode;
  npmPolicy: NpmSourcePolicy;
  extraRules: RuleDefinition[];
  scan: {
    include: string[];
    exclude: string[];
    maxDepth: number;
  };
};

function compileRule(raw: SkillSafeConfigRule): RuleDefinition {
  return {
    id: raw.id,
    name: raw.name,
    pattern: new RegExp(raw.pattern, raw.flags ?? "i"),
    severity: raw.severity,
    category: raw.category,
    description: raw.description,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseConfig(raw: unknown, filePath: string): SkillSafeConfig {
  if (!isPlainObject(raw)) {
    throw new Error(`${filePath}: config must be a JSON object`);
  }

  const config: SkillSafeConfig = {};

  if ("preset" in raw) {
    if (!isPolicyPreset(raw.preset as string)) {
      throw new Error(
        `${filePath}: "preset" must be one of: strict, marketplace, workspace`,
      );
    }
    config.preset = raw.preset as SkillSafePolicyPreset;
  }

  if ("failOn" in raw) {
    const v = raw.failOn;
    if (v !== "never" && v !== "review" && v !== "block") {
      throw new Error(
        `${filePath}: "failOn" must be one of: never, review, block`,
      );
    }
    config.failOn = v;
  }

  if ("suppressionMode" in raw) {
    const v = raw.suppressionMode;
    if (v !== "disabled" && v !== "report-only" && v !== "honor") {
      throw new Error(
        `${filePath}: "suppressionMode" must be one of: disabled, report-only, honor`,
      );
    }
    config.suppressionMode = v;
  }

  if ("npmPolicy" in raw && isPlainObject(raw.npmPolicy)) {
    config.npmPolicy = {};
    const np = raw.npmPolicy;
    if ("minAgeDays" in np && typeof np.minAgeDays === "number") {
      config.npmPolicy.minAgeDays = np.minAgeDays;
    }
    if ("requireProvenance" in np && typeof np.requireProvenance === "boolean") {
      config.npmPolicy.requireProvenance = np.requireProvenance;
    }
  }

  if ("extraRules" in raw && Array.isArray(raw.extraRules)) {
    config.extraRules = [];
    for (const [i, rule] of raw.extraRules.entries()) {
      if (!isPlainObject(rule)) {
        throw new Error(`${filePath}: extraRules[${i}] must be an object`);
      }
      if (typeof rule.pattern !== "string") {
        throw new Error(`${filePath}: extraRules[${i}].pattern must be a string`);
      }
      if (rule.severity !== "caution" && rule.severity !== "danger") {
        throw new Error(
          `${filePath}: extraRules[${i}].severity must be "caution" or "danger"`,
        );
      }
      if (typeof rule.category !== "string") {
        throw new Error(`${filePath}: extraRules[${i}].category must be a string`);
      }
      if (typeof rule.description !== "string") {
        throw new Error(`${filePath}: extraRules[${i}].description must be a string`);
      }
      config.extraRules.push(rule as SkillSafeConfigRule);
    }
  }

  if ("scan" in raw && isPlainObject(raw.scan)) {
    const s = raw.scan;
    config.scan = {};
    if ("include" in s && Array.isArray(s.include)) {
      config.scan.include = s.include.filter((v): v is string => typeof v === "string");
    }
    if ("exclude" in s && Array.isArray(s.exclude)) {
      config.scan.exclude = s.exclude.filter((v): v is string => typeof v === "string");
    }
    if ("maxDepth" in s && typeof s.maxDepth === "number") {
      config.scan.maxDepth = s.maxDepth;
    }
  }

  return config;
}

/**
 * Load skill-safe.config.json (or .skillsaferc.json / .skillsaferc) from
 * `cwd` (defaults to process.cwd()). Returns null when no config file is found.
 * Throws on parse errors or invalid field values.
 */
export async function loadConfig(cwd?: string): Promise<SkillSafeConfig | null> {
  const dir = cwd ?? process.cwd();
  for (const name of CONFIG_FILE_NAMES) {
    const filePath = resolve(dir, name);
    try {
      const text = await readFile(filePath, "utf8");
      const raw: unknown = JSON.parse(text);
      return parseConfig(raw, filePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
  }
  return null;
}

/**
 * Merge a loaded config into a fully-resolved effective config.
 *
 * Precedence (highest to lowest):
 *   CLI args (applied by caller after this function) > config individual fields
 *   > config preset > workspace preset defaults.
 */
export function resolveConfig(config: SkillSafeConfig | null): ResolvedSkillSafeConfig {
  const basePreset: SkillSafePolicy = getPolicyPreset(config?.preset ?? "workspace");

  const failOn = config?.failOn ?? basePreset.failOn;
  const suppressionMode = config?.suppressionMode ?? basePreset.suppressionMode;
  const npmPolicy: NpmSourcePolicy = {
    ...basePreset.npmPolicy,
    ...config?.npmPolicy,
  };
  const extraRules: RuleDefinition[] = (config?.extraRules ?? []).map(compileRule);

  return {
    preset: config?.preset ?? "workspace",
    failOn,
    suppressionMode,
    npmPolicy,
    extraRules,
    scan: {
      include: config?.scan?.include ?? [],
      exclude: config?.scan?.exclude ?? [],
      maxDepth: config?.scan?.maxDepth ?? 10,
    },
  };
}
