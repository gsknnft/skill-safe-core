#!/usr/bin/env node
/**
 * skill-safe suite demo
 * Scans the three suite example skills and prints a human summary.
 * Run: pnpm demo
 */

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const dir = dirname(fileURLToPath(import.meta.url));
const cli = join(dir, "..", "dist", "cli.js");
const suiteSkills = join(dir, "suite", "skills");

console.log("─────────────────────────────────────────");
console.log("  skill-safe · suite demo");
console.log("─────────────────────────────────────────");
console.log("Scanning: examples/suite/skills/\n");

const scan = spawnSync(
  process.execPath,
  [cli, suiteSkills, "--full", "--fail-on", "never"],
  { stdio: "inherit", encoding: "utf8" },
);

console.log("\n─────────────────────────────────────────");
console.log("Suppression audit:");
console.log("─────────────────────────────────────────\n");

const audit = spawnSync(
  process.execPath,
  [cli, suiteSkills, "--audit-suppressions", "--fail-on", "never"],
  { stdio: "inherit", encoding: "utf8" },
);

process.exit(0);
