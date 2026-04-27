#!/usr/bin/env node
/**
 * Validate the governance mapping registry at build/CI time.
 *
 * Checks:
 *   - Every SanitizationCategory has at least one mapping per framework
 *   - No unknown category keys
 *   - Every mapping has required fields (framework, id, label, confidence)
 *   - Every built-in rule's category resolves to mappings
 *   - Supply-chain categories include AML.T0010
 *
 * Run: npx tsx scripts/validate-mappings.ts
 *      pnpm validate:mappings
 */

import { RULES } from "../src/rules.js";
import { CATEGORY_MAPPINGS, getMappingsForCategory } from "../src/mappings.js";
import type { SanitizationCategory } from "../src/types.js";

const ALL_CATEGORIES: SanitizationCategory[] = [
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

const FRAMEWORKS = ["owasp-agentic", "owasp-llm", "mitre-atlas", "nist-ai-rmf"] as const;

const CONTENT_CATEGORIES = ALL_CATEGORIES.filter(
  (c) => c !== "package-age" && c !== "missing-provenance",
);

let errors = 0;
let warnings = 0;

const fail = (msg: string) => { console.error(`  ✗ ${msg}`); errors++; };
const warn = (msg: string) => { console.warn(`  ⚠ ${msg}`); warnings++; };
const pass = (msg: string) => console.log(`  ✓ ${msg}`);

console.log("\nskill-safe governance mapping validation\n");

// 1. Every category is represented
console.log("1. Category coverage");
for (const cat of ALL_CATEGORIES) {
  const mappings = CATEGORY_MAPPINGS[cat];
  if (!mappings || mappings.length === 0) {
    fail(`"${cat}" has no mappings`);
  } else {
    pass(`"${cat}" — ${mappings.length} mapping(s)`);
  }
}

// 2. Content categories cover all frameworks
console.log("\n2. Framework coverage (content categories)");
for (const cat of CONTENT_CATEGORIES) {
  const frameworks = new Set(getMappingsForCategory(cat).map((m) => m.framework));
  for (const fw of FRAMEWORKS) {
    if (!frameworks.has(fw)) {
      fail(`"${cat}" missing "${fw}" mapping`);
    }
  }
  if (FRAMEWORKS.every((fw) => frameworks.has(fw))) {
    pass(`"${cat}" covers all 4 frameworks`);
  }
}

// 3. Required fields on every mapping
console.log("\n3. Required mapping fields");
let fieldErrors = 0;
for (const [cat, mappings] of Object.entries(CATEGORY_MAPPINGS)) {
  for (const m of mappings) {
    if (!m.framework) { fail(`${cat}: mapping missing "framework"`); fieldErrors++; }
    if (!m.id)        { fail(`${cat}: mapping missing "id"`);        fieldErrors++; }
    if (!m.label)     { fail(`${cat}: mapping missing "label"`);     fieldErrors++; }
    if (!m.confidence){ fail(`${cat}: mapping missing "confidence"`); fieldErrors++; }
    if (m.url && !m.url.startsWith("https://")) {
      warn(`${cat} ${m.id}: url does not use https`);
    }
  }
}
if (fieldErrors === 0) pass("all mapping entries have required fields");

// 4. No unknown category keys
console.log("\n4. No unknown categories in registry");
const knownSet = new Set<string>(ALL_CATEGORIES);
let unknownFound = false;
for (const key of Object.keys(CATEGORY_MAPPINGS)) {
  if (!knownSet.has(key)) {
    fail(`unknown category key "${key}" in CATEGORY_MAPPINGS`);
    unknownFound = true;
  }
}
if (!unknownFound) pass("all registry keys are known categories");

// 5. Every built-in rule category resolves
console.log("\n5. Built-in rule category coverage");
let uncovered = 0;
for (const rule of RULES) {
  const mappings = getMappingsForCategory(rule.category);
  if (mappings.length === 0) {
    fail(`rule "${rule.id ?? "(no id)"}" category "${rule.category}" has no mappings`);
    uncovered++;
  }
}
if (uncovered === 0) pass(`all ${RULES.length} built-in rules resolve to mappings`);

// 6. Supply-chain categories include AML.T0010
console.log("\n6. Supply-chain MITRE coverage");
for (const cat of ["package-age", "missing-provenance"] as const) {
  const ids = getMappingsForCategory(cat).map((m) => m.id);
  if (ids.includes("AML.T0010")) {
    pass(`"${cat}" includes AML.T0010`);
  } else {
    fail(`"${cat}" is missing AML.T0010`);
  }
}

// Summary
console.log(`\n${"─".repeat(48)}`);
if (errors > 0) {
  console.error(`\nFAILED — ${errors} error(s), ${warnings} warning(s)\n`);
  process.exit(1);
} else {
  if (warnings > 0) console.warn(`\nPASSED with ${warnings} warning(s)\n`);
  else console.log("\nAll checks passed.\n");
}
