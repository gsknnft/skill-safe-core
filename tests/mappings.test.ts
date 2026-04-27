import { describe, expect, it } from "vitest";
import { RULES } from "../src/rules.js";
import type { SanitizationCategory } from "../src/types.js";
import {
  CATEGORY_MAPPINGS,
  getCategoryReportArrays,
  getMappingsForCategory,
  toReportArrays,
} from "../src/mappings.js";

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

describe("governance mapping registry", () => {
  it("covers every SanitizationCategory", () => {
    for (const cat of ALL_CATEGORIES) {
      expect(
        CATEGORY_MAPPINGS[cat],
        `missing registry entry for category "${cat}"`,
      ).toBeDefined();
      expect(
        CATEGORY_MAPPINGS[cat].length,
        `no mappings for category "${cat}"`,
      ).toBeGreaterThan(0);
    }
  });

  it("has at least one mapping per framework per content category", () => {
    const contentCategories = ALL_CATEGORIES.filter(
      (cat) => cat !== "package-age" && cat !== "missing-provenance",
    );
    for (const cat of contentCategories) {
      const frameworks = new Set(getMappingsForCategory(cat).map((m) => m.framework));
      for (const fw of FRAMEWORKS) {
        expect(
          frameworks.has(fw),
          `category "${cat}" is missing a "${fw}" mapping`,
        ).toBe(true);
      }
    }
  });

  it("has no unknown category keys in the registry", () => {
    const knownSet = new Set<string>(ALL_CATEGORIES);
    for (const key of Object.keys(CATEGORY_MAPPINGS)) {
      expect(knownSet.has(key), `unknown category key "${key}" in CATEGORY_MAPPINGS`).toBe(true);
    }
  });

  it("every built-in rule category has mappings", () => {
    for (const rule of RULES) {
      const mappings = getMappingsForCategory(rule.category);
      expect(
        mappings.length,
        `rule "${rule.id ?? rule.description}" category "${rule.category}" has no mappings`,
      ).toBeGreaterThan(0);
    }
  });

  it("all mappings have required fields", () => {
    for (const [cat, mappings] of Object.entries(CATEGORY_MAPPINGS)) {
      for (const m of mappings) {
        expect(m.framework, `${cat}: missing framework`).toBeTruthy();
        expect(m.id, `${cat}: missing id`).toBeTruthy();
        expect(m.label, `${cat}: missing label`).toBeTruthy();
        expect(m.confidence, `${cat}: missing confidence`).toBeTruthy();
      }
    }
  });

  it("toReportArrays produces backward-compatible flat string arrays", () => {
    const mappings = getMappingsForCategory("prompt-injection");
    const arrays = toReportArrays(mappings);
    expect(Array.isArray(arrays.owasp)).toBe(true);
    expect(Array.isArray(arrays.mitreAtlas)).toBe(true);
    expect(Array.isArray(arrays.nistAiRmf)).toBe(true);
    expect(arrays.owasp.length).toBeGreaterThan(0);
    expect(arrays.mitreAtlas.length).toBeGreaterThan(0);
    expect(arrays.nistAiRmf.length).toBeGreaterThan(0);
    // each entry is a non-empty string
    for (const entry of [...arrays.owasp, ...arrays.mitreAtlas, ...arrays.nistAiRmf]) {
      expect(typeof entry).toBe("string");
      expect(entry.length).toBeGreaterThan(0);
    }
  });

  it("getCategoryReportArrays is equivalent to toReportArrays(getMappingsForCategory(cat))", () => {
    for (const cat of ALL_CATEGORIES) {
      const direct = getCategoryReportArrays(cat);
      const composed = toReportArrays(getMappingsForCategory(cat));
      expect(direct).toEqual(composed);
    }
  });

  it("supply-chain categories map to AML.T0010", () => {
    for (const cat of ["package-age", "missing-provenance"] as const) {
      const ids = getMappingsForCategory(cat).map((m) => m.id);
      expect(ids).toContain("AML.T0010");
    }
  });
});
