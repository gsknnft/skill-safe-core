import {
  createSkillSafeDocumentReport,
  createSkillSafeReport,
  describeSkillSource,
  formatSkillSafeReportMarkdown,
  requiresSanitization,
  resolveAndScanSkillMarkdown,
  sanitizeSkillMarkdown,
  stringifySkillSafeReportJson,
} from "../dist/index.js";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = (name) => join(here, "fixtures", name);
const reportPath = (name) => join(here, "reports", name);

const safeMarkdown = await readFile(fixturePath("safe-skill.md"), "utf8");
const maliciousMarkdown = await readFile(
  fixturePath("malicious-skill.md"),
  "utf8",
);

const safeScan = sanitizeSkillMarkdown(safeMarkdown);
const maliciousScan = sanitizeSkillMarkdown(maliciousMarkdown);

const mockedGithubFetch = async (url) => {
  const requested = String(url);
  const body = requested.endsWith("/SKILL.md") ? safeMarkdown : "not found";
  return new Response(body, {
    status: requested.endsWith("/SKILL.md") ? 200 : 404,
    headers: { "content-type": "text/markdown" },
  });
};

const resolvedGithub = await resolveAndScanSkillMarkdown(
  "github:ExampleOrg/issue-summarizer",
  { fetcher: mockedGithubFetch },
);

const resolvedHermes = await resolveAndScanSkillMarkdown("hermes:daily-brief", {
  resolvers: {
    hermes: async () => ({
      resolvedUrl: "hermes://daily-brief/SKILL.md",
      markdown: safeMarkdown,
    }),
  },
});

const githubScan =
  resolvedGithub.scan ?? sanitizeSkillMarkdown(resolvedGithub.markdown);
const hermesScan =
  resolvedHermes.scan ?? sanitizeSkillMarkdown(resolvedHermes.markdown);

const report = createSkillSafeReport({
  mode: "batch",
  documents: [
    createSkillSafeDocumentReport({
      id: "fixture:safe-skill",
      source: "examples/fixtures/safe-skill.md",
      resolvedUrl: null,
      sourceKind: "file",
      trust: "workspace",
      directlyResolvable: true,
      sanitized: true,
      content: safeMarkdown,
      scan: safeScan,
    }),
    createSkillSafeDocumentReport({
      id: "fixture:malicious-skill",
      source: "examples/fixtures/malicious-skill.md",
      resolvedUrl: null,
      sourceKind: "file",
      trust: "workspace",
      directlyResolvable: true,
      sanitized: true,
      content: maliciousMarkdown,
      scan: maliciousScan,
    }),
    createSkillSafeDocumentReport({
      id: "resolver:mocked-github",
      source: resolvedGithub.source,
      resolvedUrl: resolvedGithub.resolvedUrl,
      sourceKind: resolvedGithub.kind,
      trust: resolvedGithub.trust,
      directlyResolvable: resolvedGithub.directlyResolvable,
      sanitized: requiresSanitization(resolvedGithub.trust),
      content: resolvedGithub.markdown,
      scan: githubScan,
    }),
    createSkillSafeDocumentReport({
      id: "resolver:custom-hermes",
      source: resolvedHermes.source,
      resolvedUrl: resolvedHermes.resolvedUrl,
      sourceKind: resolvedHermes.kind,
      trust: resolvedHermes.trust,
      directlyResolvable: resolvedHermes.directlyResolvable,
      sanitized: requiresSanitization(resolvedHermes.trust),
      content: resolvedHermes.markdown,
      scan: hermesScan,
    }),
  ],
});

const safeOnlyReport = createSkillSafeReport({
  mode: "file",
  documents: [
    createSkillSafeDocumentReport({
      id: "fixture:safe-skill",
      source: "examples/fixtures/safe-skill.md",
      resolvedUrl: null,
      sourceKind: "file",
      trust: "workspace",
      directlyResolvable: true,
      sanitized: true,
      content: safeMarkdown,
      scan: safeScan,
    }),
  ],
});

const descriptors = [
  describeSkillSource("github:ExampleOrg/issue-summarizer"),
  describeSkillSource("hashlips:agent-skills"),
  describeSkillSource("npm:@gsknnft/example-skill"),
  describeSkillSource("hermes:daily-brief"),
  describeSkillSource("openclaw-managed"),
  describeSkillSource("workspace"),
  describeSkillSource("https://example.com/SKILL.md"),
];

const json = stringifySkillSafeReportJson(report);
const markdown = formatSkillSafeReportMarkdown(report, { full: true });
const safeOnlyJson = stringifySkillSafeReportJson(safeOnlyReport);
const safeOnlyMarkdown = formatSkillSafeReportMarkdown(safeOnlyReport, {
  full: true,
});

await mkdir(reportPath("."), { recursive: true });
await writeFile(reportPath("skill-safe-batch-report.json"), json);
await writeFile(reportPath("skill-safe-batch-report.md"), markdown);
await writeFile(reportPath("skill-safe-safe-only-report.json"), safeOnlyJson);
await writeFile(reportPath("skill-safe-safe-only-report.md"), safeOnlyMarkdown);
await writeFile(
  reportPath("skill-safe-source-descriptors.json"),
  `${JSON.stringify(descriptors, null, 2)}\n`,
);

console.log(markdown);
console.log("Wrote examples/reports/skill-safe-batch-report.json");
console.log("Wrote examples/reports/skill-safe-batch-report.md");
console.log("Wrote examples/reports/skill-safe-safe-only-report.json");
console.log("Wrote examples/reports/skill-safe-safe-only-report.md");
console.log("Wrote examples/reports/skill-safe-source-descriptors.json");

if (!report.ok) {
  console.log("Smoke result: expected failure because malicious-skill.md is blocked.");
}
