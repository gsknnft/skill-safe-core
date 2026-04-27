/**
 * Governance mapping registry for skill-safe categories.
 *
 * Each entry carries structured, versioned metadata for OWASP Agentic AI,
 * OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF. The helpers at the bottom
 * produce the backward-compatible flat arrays used in scan reports.
 */

import type { SanitizationCategory } from "./types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type GovernanceFramework =
  | "owasp-agentic"
  | "owasp-llm"
  | "mitre-atlas"
  | "nist-ai-rmf";

export type MappingConfidence = "direct" | "related" | "inferred";

export type GovernanceMapping = {
  framework: GovernanceFramework;
  /** Framework-specific identifier (e.g. "LLM01", "AML.T0051"). */
  id: string;
  /** Human-readable label. */
  label: string;
  /** Canonical URL for this control, if available. */
  url?: string;
  /** Framework version this ID was drawn from. */
  sourceVersion?: string;
  confidence: MappingConfidence;
};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const CATEGORY_MAPPINGS: Record<SanitizationCategory, GovernanceMapping[]> = {
  "prompt-injection": [
    {
      framework: "owasp-agentic",
      id: "AST01",
      label: "Malicious Skills / Plugins",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast01-malicious-skills-plugins/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-llm",
      id: "LLM01",
      label: "Prompt Injection",
      url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0051",
      label: "LLM Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0051",
      sourceVersion: "2024",
      confidence: "direct",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0054",
      label: "Indirect Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0054",
      sourceVersion: "2024",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MEASURE",
      label: "Measure",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MANAGE",
      label: "Manage",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
  ],

  "identity-hijack": [
    {
      framework: "owasp-agentic",
      id: "AST01",
      label: "Malicious Skills / Plugins",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast01-malicious-skills-plugins/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-agentic",
      id: "AST04",
      label: "Insecure Skill Metadata",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast04-insecure-skill-metadata/",
      sourceVersion: "2025",
      confidence: "related",
    },
    {
      framework: "owasp-llm",
      id: "LLM01",
      label: "Prompt Injection",
      url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      sourceVersion: "2025",
      confidence: "related",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0051",
      label: "LLM Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0051",
      sourceVersion: "2024",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MAP",
      label: "Map",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "related",
    },
    {
      framework: "nist-ai-rmf",
      id: "MEASURE",
      label: "Measure",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
  ],

  "jailbreak": [
    {
      framework: "owasp-agentic",
      id: "AST01",
      label: "Malicious Skills / Plugins",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast01-malicious-skills-plugins/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-llm",
      id: "LLM01",
      label: "Prompt Injection",
      url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0051",
      label: "LLM Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0051",
      sourceVersion: "2024",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MEASURE",
      label: "Measure",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MANAGE",
      label: "Manage",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
  ],

  "data-exfiltration": [
    {
      framework: "owasp-agentic",
      id: "AST01",
      label: "Malicious Skills / Plugins",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast01-malicious-skills-plugins/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-agentic",
      id: "AST03",
      label: "Over-Privileged Skills",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast03-over-privileged-skills/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-llm",
      id: "LLM02",
      label: "Sensitive Information Disclosure",
      url: "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
      sourceVersion: "2025",
      confidence: "related",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0024",
      label: "Exfiltration via ML Inference API",
      url: "https://atlas.mitre.org/techniques/AML.T0024",
      sourceVersion: "2024",
      confidence: "related",
    },
    {
      framework: "nist-ai-rmf",
      id: "MEASURE",
      label: "Measure",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MANAGE",
      label: "Manage",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
  ],

  "script-injection": [
    {
      framework: "owasp-agentic",
      id: "AST01",
      label: "Malicious Skills / Plugins",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast01-malicious-skills-plugins/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-agentic",
      id: "AST04",
      label: "Insecure Skill Metadata",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast04-insecure-skill-metadata/",
      sourceVersion: "2025",
      confidence: "related",
    },
    {
      framework: "owasp-llm",
      id: "LLM07",
      label: "System Prompt Leakage",
      url: "https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
      sourceVersion: "2025",
      confidence: "inferred",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0017",
      label: "Develop Capabilities",
      url: "https://atlas.mitre.org/techniques/AML.T0017",
      sourceVersion: "2024",
      confidence: "related",
    },
    {
      framework: "nist-ai-rmf",
      id: "MAP",
      label: "Map",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MANAGE",
      label: "Manage",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
  ],

  "format-injection": [
    {
      framework: "owasp-agentic",
      id: "AST04",
      label: "Insecure Skill Metadata",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast04-insecure-skill-metadata/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-llm",
      id: "LLM01",
      label: "Prompt Injection",
      url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0051",
      label: "LLM Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0051",
      sourceVersion: "2024",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MAP",
      label: "Map",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MEASURE",
      label: "Measure",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
  ],

  "excessive-claims": [
    {
      framework: "owasp-agentic",
      id: "AST03",
      label: "Over-Privileged Skills",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast03-over-privileged-skills/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-llm",
      id: "LLM09",
      label: "Misinformation",
      url: "https://genai.owasp.org/llmrisk/llm09-misinformation/",
      sourceVersion: "2025",
      confidence: "related",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0048",
      label: "Socially Engineered Instructions",
      url: "https://atlas.mitre.org/techniques/AML.T0048",
      sourceVersion: "2024",
      confidence: "related",
    },
    {
      framework: "nist-ai-rmf",
      id: "GOVERN",
      label: "Govern",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MANAGE",
      label: "Manage",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
  ],

  "hidden-content": [
    {
      framework: "owasp-agentic",
      id: "AST01",
      label: "Malicious Skills / Plugins",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast01-malicious-skills-plugins/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-agentic",
      id: "AST04",
      label: "Insecure Skill Metadata",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast04-insecure-skill-metadata/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-llm",
      id: "LLM01",
      label: "Prompt Injection",
      url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      sourceVersion: "2025",
      confidence: "related",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0054",
      label: "Indirect Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0054",
      sourceVersion: "2024",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MAP",
      label: "Map",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MEASURE",
      label: "Measure",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
  ],

  "hitl-bypass": [
    {
      framework: "owasp-agentic",
      id: "AST03",
      label: "Over-Privileged Skills",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast03-over-privileged-skills/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-agentic",
      id: "AST06",
      label: "Inadequate Human-in-the-Loop Controls",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast06-inadequate-hitl-controls/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-llm",
      id: "LLM06",
      label: "Excessive Agency",
      url: "https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0065",
      label: "Bypass ML Model",
      url: "https://atlas.mitre.org/techniques/AML.T0065",
      sourceVersion: "2024",
      confidence: "related",
    },
    {
      framework: "nist-ai-rmf",
      id: "GOVERN",
      label: "Govern",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MANAGE",
      label: "Manage",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
  ],

  "package-age": [
    {
      framework: "owasp-agentic",
      id: "AST02",
      label: "Supply Chain Compromise",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast02-supply-chain-compromise/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-llm",
      id: "LLM03",
      label: "Supply Chain",
      url: "https://genai.owasp.org/llmrisk/llm03-supply-chain/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0010",
      label: "ML Supply Chain Compromise",
      url: "https://atlas.mitre.org/techniques/AML.T0010",
      sourceVersion: "2024",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MAP",
      label: "Map",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "GOVERN",
      label: "Govern",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MANAGE",
      label: "Manage",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
  ],

  "missing-provenance": [
    {
      framework: "owasp-agentic",
      id: "AST02",
      label: "Supply Chain Compromise",
      url: "https://genai.owasp.org/llmrisk/llmagentsecurity2025/ast02-supply-chain-compromise/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "owasp-llm",
      id: "LLM03",
      label: "Supply Chain",
      url: "https://genai.owasp.org/llmrisk/llm03-supply-chain/",
      sourceVersion: "2025",
      confidence: "direct",
    },
    {
      framework: "mitre-atlas",
      id: "AML.T0010",
      label: "ML Supply Chain Compromise",
      url: "https://atlas.mitre.org/techniques/AML.T0010",
      sourceVersion: "2024",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MAP",
      label: "Map",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "GOVERN",
      label: "Govern",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
    {
      framework: "nist-ai-rmf",
      id: "MANAGE",
      label: "Manage",
      url: "https://airc.nist.gov/RMF/",
      sourceVersion: "1.0",
      confidence: "direct",
    },
  ],
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export const getMappingsForCategory = (
  category: SanitizationCategory,
): GovernanceMapping[] => CATEGORY_MAPPINGS[category] ?? [];

/**
 * Convert structured GovernanceMapping[] to the flat string arrays used in
 * scan reports — backward-compatible with all existing report consumers.
 */
export const toReportArrays = (
  mappings: GovernanceMapping[],
): { owasp: string[]; mitreAtlas: string[]; nistAiRmf: string[] } => {
  const owasp: string[] = [];
  const mitreAtlas: string[] = [];
  const nistAiRmf: string[] = [];

  for (const m of mappings) {
    const label = `${m.id} ${m.label}`;
    if (m.framework === "owasp-agentic" || m.framework === "owasp-llm") {
      owasp.push(label);
    } else if (m.framework === "mitre-atlas") {
      mitreAtlas.push(label);
    } else if (m.framework === "nist-ai-rmf") {
      nistAiRmf.push(label);
    }
  }

  return { owasp, mitreAtlas, nistAiRmf };
};

/**
 * Returns the flat report arrays for a category directly.
 * Convenience wrapper for the common case in sanitize.ts.
 */
export const getCategoryReportArrays = (
  category: SanitizationCategory,
): { owasp: string[]; mitreAtlas: string[]; nistAiRmf: string[] } =>
  toReportArrays(getMappingsForCategory(category));
