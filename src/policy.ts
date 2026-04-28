import { POLICY_PRESETS } from "./constants.js";
import type { SkillSafePolicyPreset, SkillSafePolicy } from "./types.js";

export { POLICY_PRESETS };


export function getPolicyPreset(preset: SkillSafePolicyPreset): SkillSafePolicy {
  return POLICY_PRESETS[preset];
}

export function isPolicyPreset(value: string): value is SkillSafePolicyPreset {
  return (
    value === "strict" ||
    value === "marketplace" ||
    value === "workspace" ||
    value === "permissive"
  );
}
