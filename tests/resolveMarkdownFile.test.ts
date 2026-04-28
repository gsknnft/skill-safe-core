import { describe, expect, it } from "vitest";
import {
  resolveGitHubMarkdownFile,
  resolveMarkdownFile,
} from "../src/resolveMarkdownFile.js";

const jsonResponse = (body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

describe("resolveMarkdownFile", () => {
  it("resolves the preferred SKILL.md from a GitHub contents listing", async () => {
    const fetcher: typeof fetch = async (input) => {
      expect(String(input)).toBe(
        "https://api.github.com/repos/HashLips/agent-skills/contents?ref=main",
      );
      return jsonResponse([
        {
          type: "file",
          name: "README.md",
          path: "README.md",
          download_url: "https://raw.example/README.md",
        },
        {
          type: "file",
          name: "SKILL.md",
          path: "SKILL.md",
          download_url: "https://raw.example/SKILL.md",
        },
      ]);
    };

    await expect(
      resolveMarkdownFile({
        owner: "HashLips",
        repo: "agent-skills",
        branch: "main",
        fetcher,
      }),
    ).resolves.toMatchObject({
      resolvedUrl: "https://raw.example/SKILL.md",
      source: "github",
      path: "SKILL.md",
    });
  });

  it("checks one directory level for SKILL.md when root has no markdown entrypoint", async () => {
    const fetcher: typeof fetch = async (input) => {
      const url = String(input);
      if (url.endsWith("/contents?ref=main")) {
        return jsonResponse([
          {
            type: "dir",
            name: "summarizer",
            path: "summarizer",
            url: "https://api.example/repos/x/y/contents/summarizer?ref=main",
          },
        ]);
      }
      if (url === "https://api.example/repos/x/y/contents/summarizer?ref=main") {
        return jsonResponse([
          {
            type: "file",
            name: "SKILL.md",
            path: "summarizer/SKILL.md",
            download_url: "https://raw.example/summarizer/SKILL.md",
          },
        ]);
      }
      return new Response("missing", { status: 404 });
    };

    const resolved = await resolveMarkdownFile({
      owner: "x",
      repo: "y",
      fetcher,
    });

    expect(resolved.resolvedUrl).toBe("https://raw.example/summarizer/SKILL.md");
    expect(resolved.path).toBe("summarizer/SKILL.md");
  });

  it("keeps the legacy helper returning just the resolved URL", async () => {
    const fetcher: typeof fetch = async () =>
      jsonResponse({
        type: "file",
        name: "README.md",
        path: "docs/README.md",
        download_url: "https://raw.example/docs/README.md",
      });

    await expect(
      resolveGitHubMarkdownFile("gsknnft", "skill-safe", "main", "docs/README.md", {
        fetcher,
      }),
    ).resolves.toBe("https://raw.example/docs/README.md");
  });

  it("supports GitHub-compatible custom API URLs for non-GitHub sources", async () => {
    const fetcher: typeof fetch = async (input) => {
      expect(String(input)).toBe("https://registry.example/skills/abc/files");
      return jsonResponse([
        {
          type: "file",
          name: "index.md",
          path: "index.md",
          download_url: "https://registry.example/skills/abc/index.md",
        },
      ]);
    };

    const resolved = await resolveMarkdownFile({
      source: "registry",
      apiUrl: "https://registry.example/skills/abc/files",
      fetcher,
    });

    expect(resolved).toMatchObject({
      source: "registry",
      resolvedUrl: "https://registry.example/skills/abc/index.md",
    });
  });
});
