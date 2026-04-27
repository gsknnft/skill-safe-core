import { describe, expect, it } from "vitest";
import
    {
        describeSkillSource,
        parseGithubShorthand,
        resolveAndScanSkillMarkdown,
        resolveGithubRawUrl,
        resolveSkillMarkdown,
    } from "../src/resolver";

describe("GitHub resolver", () => {
  it("parses owner and repo with default branch and no path", () => {
    expect(parseGithubShorthand("github:HashLips/agent-skills")).toEqual({
      owner: "HashLips",
      repo: "agent-skills",
      branch: "main",
      path: "",
    });
  });

  it("parses owner, repo, branch, and explicit path", () => {
    expect(parseGithubShorthand("github:gsknnft/skill-safe@next/docs/ROADMAP_v1.md")).toEqual({
      owner: "gsknnft",
      repo: "skill-safe",
      branch: "next",
      path: "docs/ROADMAP_v1.md",
    });
  });

  it("builds the default raw markdown URL", () => {
    expect(resolveGithubRawUrl("github:HashLips/agent-skills")).toBe(
      "https://raw.githubusercontent.com/HashLips/agent-skills/main/SKILL.md",
    );
  });

  it("rejects malformed shorthand", () => {
    expect(() => parseGithubShorthand("github:HashLips")).toThrow(
      "expected github:owner/repo",
    );
  });
});

describe("source descriptors", () => {
  it.each([
    ["openclaw-bundled", "openclaw", "verified", false],
    ["openclaw-managed", "openclaw", "managed", false],
    ["openclaw-workspace", "workspace", "workspace", false],
    ["agents-skills-local", "workspace", "workspace", false],
    ["openclaw-extra", "openclaw", "community", false],
    ["github:HashLips/agent-skills", "github", "community", true],
    ["hashlips:agent-skills", "github", "community", true],
    ["npm:@gsknnft/skill-safe", "npm", "community", true],
    ["registry:https://example.com/SKILL.md", "registry", "community", true],
    ["souls:abc123", "souls", "community", false],
    ["hermes:skill-id", "hermes", "community", false],
    ["https://example.com/SKILL.md", "url", "unknown", true],
    ["custom-source", "unknown", "unknown", false],
  ] as const)(
    "describes %s",
    (source, kind, trust, directlyResolvable) => {
      expect(describeSkillSource(source)).toMatchObject({
        kind,
        trust,
        directlyResolvable,
      });
    },
  );

  it("parses hashlips: shorthand as github:HashLips/", () => {
    expect(parseGithubShorthand("github:HashLips/agent-skills@dev/docs/SKILL.md")).toEqual({
      owner: "HashLips",
      repo: "agent-skills",
      branch: "dev",
      path: "docs/SKILL.md",
    });
    // Universal: hashlips: is mapped to github:HashLips/
    const desc = describeSkillSource("hashlips:agent-skills@dev/docs/SKILL.md");
    expect(parseGithubShorthand(desc.source)).toEqual({
      owner: "HashLips",
      repo: "agent-skills",
      branch: "dev",
      path: "docs/SKILL.md",
    });
  });
});

describe("markdown resolution", () => {
  const fetcher: typeof fetch = async (input) => {
    const url = String(input);
    if (url.endsWith("/SKILL.md")) {
      return new Response("# Skill\n\nUse tools normally.", { status: 200 });
    }
    return new Response("missing", { status: 404 });
  };

  it("resolves direct GitHub markdown with an injected fetcher", async () => {
    const resolved = await resolveSkillMarkdown("github:HashLips/agent-skills", {
      fetcher,
    });

    expect(resolved).toMatchObject({
      kind: "github",
      trust: "community",
      resolvedUrl: "https://raw.githubusercontent.com/HashLips/agent-skills/main/SKILL.md",
      markdown: "# Skill\n\nUse tools normally.",
    });
  });

  it("uses custom resolvers for runtime-owned source kinds", async () => {
    const resolved = await resolveSkillMarkdown("hermes:daily-brief", {
      resolvers: {
        hermes: async (descriptor) => ({
          resolvedUrl: `hermes://${descriptor.value}`,
          markdown: "# Hermes Skill",
        }),
      },
    });

    expect(resolved).toMatchObject({
      kind: "hermes",
      trust: "community",
      resolvedUrl: "hermes://daily-brief",
      markdown: "# Hermes Skill",
    });
  });

  it("scans resolved community markdown", async () => {
    const result = await resolveAndScanSkillMarkdown("github:HashLips/agent-skills", {
      fetcher,
    });

    expect(result.scan?.safeToInstall).toBe(true);
  });

  it("adds source flags for npm packages inside the age gate", async () => {
    const now = Date.now();
    const fetcher: typeof fetch = async (input) => {
      const url = String(input);
      if (url === "https://registry.npmjs.org/@example%2Ffresh-skill") {
        return new Response(
          JSON.stringify({
            "dist-tags": { latest: "1.0.0" },
            time: {
              "1.0.0": new Date(now - 6 * 60 * 60 * 1000).toISOString(),
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url === "https://unpkg.com/@example/fresh-skill/SKILL.md") {
        return new Response("# Fresh Skill\n\nSummarize issues.", { status: 200 });
      }
      return new Response("missing", { status: 404 });
    };

    const result = await resolveAndScanSkillMarkdown("npm:@example/fresh-skill", {
      fetcher,
      npmPolicy: { minAgeDays: 2 },
    });

    expect(result.sourceFlags).toHaveLength(1);
    expect(result.sourceFlags[0]?.category).toBe("package-age");
    expect(result.scan?.safeToInstall).toBe(false);
    expect(result.scan?.report.categories["package-age"]).toBe(1);
  });

  it("can require npm provenance as a caution source flag", async () => {
    const fetcher: typeof fetch = async (input) => {
      const url = String(input);
      if (url === "https://registry.npmjs.org/example-skill") {
        return new Response(
          JSON.stringify({
            "dist-tags": { latest: "1.0.0" },
            time: {
              "1.0.0": "2020-01-01T00:00:00.000Z",
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url === "https://unpkg.com/example-skill/SKILL.md") {
        return new Response("# Old Skill\n\nSummarize issues.", { status: 200 });
      }
      return new Response("missing", { status: 404 });
    };

    const result = await resolveAndScanSkillMarkdown("npm:example-skill", {
      fetcher,
      npmPolicy: { minAgeDays: 2, requireProvenance: true },
    });

    expect(result.sourceFlags).toHaveLength(1);
    expect(result.sourceFlags[0]?.category).toBe("missing-provenance");
    expect(result.scan?.safeToInstall).toBe(true);
    expect(result.scan?.report.recommendedAction).toBe("review");
  });
});
