import type { SkillSafePolicyPreset, SkillSafePolicy } from "./types.js";


export const POLICY_PRESETS: Record<SkillSafePolicyPreset, SkillSafePolicy> = {
  strict: {
    preset: "strict",
    failOn: "review",
    suppressionMode: "disabled",
    npmPolicy: { minAgeDays: 14, requireProvenance: true },
  },
  marketplace: {
    preset: "marketplace",
    failOn: "review",
    suppressionMode: "report-only",
    npmPolicy: { minAgeDays: 7, requireProvenance: false },
  },
  workspace: {
    preset: "workspace",
    failOn: "block",
    suppressionMode: "report-only",
    npmPolicy: { minAgeDays: 2, requireProvenance: false },
  },
};

export function getPolicyPreset(preset: SkillSafePolicyPreset): SkillSafePolicy {
  return POLICY_PRESETS[preset];
}

export function isPolicyPreset(value: string): value is SkillSafePolicyPreset {
  return value === "strict" || value === "marketplace" || value === "workspace";
}
