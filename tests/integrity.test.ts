import { describe, expect, it } from "vitest";
import { computeContentIntegrity, toSriString } from "../src/index.js";

describe("source integrity", () => {
  it("computes stable SHA-256 integrity metadata and SRI strings", async () => {
    const integrity = await computeContentIntegrity(
      "hello skill-safe",
      "https://example.com/SKILL.md",
    );

    expect(integrity).toMatchObject({
      contentHash:
        "99d1b382fb761b4f41d80b348c0f6faef68b65a4b832c1c079f79fd3d2ccd7d6",
      resolvedUrl: "https://example.com/SKILL.md",
      bytes: 16,
      algorithm: "SHA-256",
    });
    expect(integrity.urlHash).toBe(
      "8be319708bfba6dc01953609378ba2dedbdd2568010bac2905734e12b37f6282",
    );
    expect(Date.parse(integrity.scannedAt)).not.toBeNaN();
    expect(toSriString(integrity)).toBe(
      "sha256-mdGzgvt2G09B2As0jA9vrvaLZaS4MsHAefef09LM19Y",
    );
  });

  it("omits the URL hash for local content", async () => {
    const integrity = await computeContentIntegrity("local only");

    expect(integrity.resolvedUrl).toBeNull();
    expect(integrity.urlHash).toBeNull();
  });
});
