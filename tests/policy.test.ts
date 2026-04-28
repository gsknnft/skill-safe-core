import { describe, expect, it } from "vitest";
import { getPolicyPreset, isPolicyPreset, POLICY_PRESETS } from "../src/policy.js";

describe("policy presets", () => {
  it("exposes stable CI policy presets", () => {
    expect(Object.keys(POLICY_PRESETS).sort()).toEqual([
      "marketplace",
      "permissive",
      "strict",
      "workspace",
    ]);
  });

  it("maps marketplace to review failure and a stricter npm age gate", () => {
    expect(getPolicyPreset("marketplace")).toMatchObject({
      failOn: "review",
      suppressionMode: "report-only",
      npmPolicy: { minAgeDays: 7 },
    });
  });

  it("validates preset names", () => {
    expect(isPolicyPreset("strict")).toBe(true);
    expect(isPolicyPreset("permissive")).toBe(true);
    expect(isPolicyPreset("unknown")).toBe(false);
  });
});
