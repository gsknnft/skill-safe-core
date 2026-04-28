import { writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it, afterEach } from "vitest";
import { loadConfig, resolveConfig } from "../src/config.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string | undefined;

async function makeTmpDir(): Promise<string> {
  const dir = join(tmpdir(), `skill-safe-config-test-${Date.now()}`);
  await mkdir(dir, { recursive: true });
  tmpDir = dir;
  return dir;
}

afterEach(async () => {
  if (tmpDir) {
    await rm(tmpDir, { recursive: true, force: true });
    tmpDir = undefined;
  }
});

async function writeConfigFile(dir: string, content: unknown, name = "skill-safe.config.json"): Promise<void> {
  await writeFile(join(dir, name), JSON.stringify(content), "utf8");
}

// ---------------------------------------------------------------------------
// loadConfig
// ---------------------------------------------------------------------------

describe("loadConfig", () => {
  it("returns null when no config file exists", async () => {
    const dir = await makeTmpDir();
    expect(await loadConfig(dir)).toBeNull();
  });

  it("loads skill-safe.config.json", async () => {
    const dir = await makeTmpDir();
    await writeConfigFile(dir, { preset: "strict" });
    const config = await loadConfig(dir);
    expect(config).not.toBeNull();
    expect(config?.preset).toBe("strict");
  });

  it("loads .skillsaferc.json as fallback", async () => {
    const dir = await makeTmpDir();
    await writeConfigFile(dir, { failOn: "never" }, ".skillsaferc.json");
    const config = await loadConfig(dir);
    expect(config?.failOn).toBe("never");
  });

  it("skill-safe.config.json takes priority over .skillsaferc.json", async () => {
    const dir = await makeTmpDir();
    await writeConfigFile(dir, { preset: "strict" });
    await writeConfigFile(dir, { preset: "marketplace" }, ".skillsaferc.json");
    const config = await loadConfig(dir);
    expect(config?.preset).toBe("strict");
  });

  it("loads full config with all fields", async () => {
    const dir = await makeTmpDir();
    await writeConfigFile(dir, {
      preset: "marketplace",
      failOn: "review",
      suppressionMode: "disabled",
      npmPolicy: { minAgeDays: 7, requireProvenance: true },
      extraRules: [
        {
          pattern: "steal your soul",
          severity: "danger",
          category: "data-exfiltration",
          description: "Soul theft detected.",
        },
      ],
      scan: {
        include: ["./skills"],
        exclude: ["node_modules"],
        maxDepth: 5,
      },
    });
    const config = await loadConfig(dir);
    expect(config?.preset).toBe("marketplace");
    expect(config?.failOn).toBe("review");
    expect(config?.suppressionMode).toBe("disabled");
    expect(config?.npmPolicy?.minAgeDays).toBe(7);
    expect(config?.npmPolicy?.requireProvenance).toBe(true);
    expect(config?.extraRules).toHaveLength(1);
    expect(config?.extraRules?.[0].pattern).toBe("steal your soul");
    expect(config?.scan?.maxDepth).toBe(5);
  });

  it("throws on invalid preset value", async () => {
    const dir = await makeTmpDir();
    await writeConfigFile(dir, { preset: "permissive" });
    await expect(loadConfig(dir)).rejects.toThrow(/preset/);
  });

  it("throws on invalid failOn value", async () => {
    const dir = await makeTmpDir();
    await writeConfigFile(dir, { failOn: "always" });
    await expect(loadConfig(dir)).rejects.toThrow(/failOn/);
  });

  it("throws on invalid suppressionMode value", async () => {
    const dir = await makeTmpDir();
    await writeConfigFile(dir, { suppressionMode: "allow-all" });
    await expect(loadConfig(dir)).rejects.toThrow(/suppressionMode/);
  });

  it("throws when config is not an object", async () => {
    const dir = await makeTmpDir();
    await writeFile(join(dir, "skill-safe.config.json"), '"a string"', "utf8");
    await expect(loadConfig(dir)).rejects.toThrow(/JSON object/);
  });

  it("throws when extraRules entry has non-string pattern", async () => {
    const dir = await makeTmpDir();
    await writeConfigFile(dir, {
      extraRules: [{ pattern: 42, severity: "caution", category: "jailbreak", description: "x" }],
    });
    await expect(loadConfig(dir)).rejects.toThrow(/pattern/);
  });
});

// ---------------------------------------------------------------------------
// resolveConfig
// ---------------------------------------------------------------------------

describe("resolveConfig", () => {
  it("returns workspace defaults when config is null", () => {
    const resolved = resolveConfig(null);
    expect(resolved.preset).toBe("workspace");
    expect(resolved.failOn).toBe("block");
    expect(resolved.suppressionMode).toBe("report-only");
    expect(resolved.extraRules).toEqual([]);
    expect(resolved.scan.maxDepth).toBe(10);
  });

  it("applies preset baseline", () => {
    const resolved = resolveConfig({ preset: "strict" });
    expect(resolved.failOn).toBe("review");
    expect(resolved.suppressionMode).toBe("disabled");
    expect(resolved.npmPolicy.minAgeDays).toBe(14);
  });

  it("config individual fields override the preset", () => {
    const resolved = resolveConfig({ preset: "strict", failOn: "never" });
    expect(resolved.failOn).toBe("never");
    // Other strict fields still apply
    expect(resolved.suppressionMode).toBe("disabled");
  });

  it("compiles extraRules patterns to RegExp", () => {
    const resolved = resolveConfig({
      extraRules: [
        {
          pattern: "steal your soul",
          severity: "danger",
          category: "data-exfiltration",
          description: "Soul theft",
        },
      ],
    });
    expect(resolved.extraRules).toHaveLength(1);
    expect(resolved.extraRules[0].pattern).toBeInstanceOf(RegExp);
    expect(resolved.extraRules[0].pattern.test("STEAL YOUR SOUL")).toBe(true);
  });

  it("respects custom regex flags", () => {
    const resolved = resolveConfig({
      extraRules: [
        {
          pattern: "^steal",
          flags: "",
          severity: "caution",
          category: "jailbreak",
          description: "Steal at start",
        },
      ],
    });
    // Case-sensitive since flags="" (no "i")
    expect(resolved.extraRules[0].pattern.test("STEAL your soul")).toBe(false);
    expect(resolved.extraRules[0].pattern.test("steal your soul")).toBe(true);
  });

  it("merges npmPolicy from preset and config", () => {
    const resolved = resolveConfig({
      preset: "marketplace",
      npmPolicy: { requireProvenance: true },
    });
    // marketplace minAgeDays is 7
    expect(resolved.npmPolicy.minAgeDays).toBe(7);
    // config override
    expect(resolved.npmPolicy.requireProvenance).toBe(true);
  });

  it("scan defaults to empty arrays and depth 10", () => {
    const resolved = resolveConfig({});
    expect(resolved.scan.include).toEqual([]);
    expect(resolved.scan.exclude).toEqual([]);
    expect(resolved.scan.maxDepth).toBe(10);
  });

  it("passes scan config through", () => {
    const resolved = resolveConfig({
      scan: { include: ["./skills"], exclude: ["node_modules"], maxDepth: 3 },
    });
    expect(resolved.scan.include).toEqual(["./skills"]);
    expect(resolved.scan.maxDepth).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Integration: loadConfig → resolveConfig
// ---------------------------------------------------------------------------

describe("loadConfig → resolveConfig integration", () => {
  it("applies file config as effective defaults", async () => {
    const dir = await makeTmpDir();
    await writeConfigFile(dir, {
      preset: "marketplace",
      extraRules: [
        {
          pattern: "exfil-me",
          severity: "danger",
          category: "data-exfiltration",
          description: "Custom rule",
        },
      ],
    });
    const config = await loadConfig(dir);
    const resolved = resolveConfig(config);
    expect(resolved.preset).toBe("marketplace");
    expect(resolved.failOn).toBe("review");
    expect(resolved.extraRules[0].pattern.test("exfil-me")).toBe(true);
  });
});
