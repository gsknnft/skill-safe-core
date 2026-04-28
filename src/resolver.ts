import { DEFAULT_MARKDOWN_CANDIDATES } from "./constants.js";
import
  {
    appendSanitizationFlags,
    sanitizeSkillMarkdown,
  } from "./sanitize.js";
import
  {
    requiresSanitization,
    resolveSkillTrustLevel,
  } from "./trust.js";

import type {
  SanitizationFlag,
  GitHubSkillShorthand,
  NpmSourcePolicy,
  ResolvedSkillMarkdown,
  ResolvedSkillScanReport,
  SkillResolverOptions,
  SkillSourceDescriptor,
} from "./types.js";


const assertNonEmpty = (value: string, label: string): string => {
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`Invalid source: missing ${label}`);
  return trimmed;
};

const stripPrefix = (source: string, prefix: string): string =>
  source.slice(prefix.length).trim();

// parseGithubShorthand.ts
export function parseGithubShorthand(input: string) {
  if (!input.startsWith("github:")) throw new Error("Not a github: source");
  const cleaned = input.slice("github:".length);
  const firstSlash = cleaned.indexOf("/");
  if (firstSlash === -1) throw new Error("Invalid github shorthand, expected github:owner/repo");

  const owner = cleaned.slice(0, firstSlash);
  const rest = cleaned.slice(firstSlash + 1); // repo[@branch][/path]

  let repo = rest;
  let branch = "main";
  let path = "";

  const slashAfterRepo = rest.indexOf("/");
  const atIndex = rest.indexOf("@");

  if (atIndex !== -1 && (slashAfterRepo === -1 || atIndex < slashAfterRepo)) {
    repo = rest.slice(0, atIndex);
    const afterAt = rest.slice(atIndex + 1);
    const nextSlash = afterAt.indexOf("/");
    if (nextSlash === -1) branch = afterAt;
    else {
      branch = afterAt.slice(0, nextSlash);
      path = afterAt.slice(nextSlash + 1);
    }
  } else if (slashAfterRepo !== -1) {
    repo = rest.slice(0, slashAfterRepo);
    path = rest.slice(slashAfterRepo + 1);
  }

  return { owner, repo, branch, path };
}


export function parseShorthand(input: string): GitHubSkillShorthand {
  if (!input.includes(":")) {
    throw new Error("Not a valid shorthand");
  }
  // Accepts "github:owner/repo[@branch][/path]"
  if (input.startsWith("github:")) {
    return parseGithubShorthand(input);
  }
  // Optionally, handle other prefixes or throw for unsupported ones
  throw new Error("Unsupported shorthand prefix");
}

export function resolveGithubRawUrl(input: string): string {
  const { owner, repo, branch, path } = parseGithubShorthand(input);
  const markdownPath = path || DEFAULT_MARKDOWN_CANDIDATES[0];
  return `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(branch)}/${markdownPath}`;
}

export const resolveGithubUrl = resolveGithubRawUrl;

export function resolveUserRawUrl(input: string): string {
  const { owner, repo, branch, path } = parseShorthand(input);
  const markdownPath = path || DEFAULT_MARKDOWN_CANDIDATES[0];
  return `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(branch)}/${markdownPath}`;
}

const isHttpUrl = (value: string): boolean => {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
};

export function describeSkillSource(
  source: string,
  options: Pick<SkillResolverOptions, "bundled"> = {},
): SkillSourceDescriptor {
  const trimmed = assertNonEmpty(source, "source");
  const lower = trimmed.toLowerCase();
  const bundled = options.bundled ?? false;
  const trust = resolveSkillTrustLevel(trimmed, bundled);

  if (lower.startsWith("github:")) {
    return {
      source: trimmed,
      kind: "github",
      trust,
      bundled,
      value: stripPrefix(trimmed, "github:"),
      directlyResolvable: true,
    };
  }
  // Treat hashlips:repo as github:HashLips/repo
  if (lower.startsWith("hashlips:")) {
    const githubSource = `github:HashLips/${stripPrefix(trimmed, "hashlips:")}`;
    return {
      source: githubSource,
      kind: "github",
      trust: resolveSkillTrustLevel(githubSource, bundled),
      bundled,
      value: `HashLips/${stripPrefix(trimmed, "hashlips:")}`,
      directlyResolvable: true,
    };
  }
  if (lower.startsWith("npm:")) {
    return {
      source: trimmed,
      kind: "npm",
      trust,
      bundled,
      value: stripPrefix(trimmed, "npm:"),
      directlyResolvable: true,
    };
  }
  if (lower.startsWith("registry:")) {
    const value = stripPrefix(trimmed, "registry:");
    return {
      source: trimmed,
      kind: "registry",
      trust,
      bundled,
      value,
      directlyResolvable: isHttpUrl(value),
    };
  }
  if (lower.startsWith("souls:")) {
    return {
      source: trimmed,
      kind: "souls",
      trust,
      bundled,
      value: stripPrefix(trimmed, "souls:"),
      directlyResolvable: false,
    };
  }
  if (lower.startsWith("hermes:")) {
    return {
      source: trimmed,
      kind: "hermes",
      trust,
      bundled,
      value: stripPrefix(trimmed, "hermes:"),
      directlyResolvable: false,
    };
  }
  if (
    lower === "openclaw-bundled" ||
    lower === "openclaw-managed" ||
    lower === "openclaw-extra"
  ) {
    return {
      source: trimmed,
      kind: "openclaw",
      trust,
      bundled,
      value: trimmed,
      directlyResolvable: false,
    };
  }
  if (
    lower === "openclaw-workspace" ||
    lower === "workspace" ||
    lower.startsWith("agents-skills-")
  ) {
    return {
      source: trimmed,
      kind: "workspace",
      trust,
      bundled,
      value: trimmed,
      directlyResolvable: false,
    };
  }
  if (isHttpUrl(trimmed)) {
    return {
      source: trimmed,
      kind: "url",
      trust,
      bundled,
      value: trimmed,
      directlyResolvable: true,
    };
  }
  return {
    source: trimmed,
    kind: "unknown",
    trust,
    bundled,
    value: trimmed,
    directlyResolvable: false,
  };
}

const fetchText = async (
  url: string,
  fetcher: typeof fetch,
): Promise<string | null> => {
  const response = await fetcher(url, {
    headers: { "User-Agent": "skill-safe" },
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: HTTP ${response.status}`);
  }
  return response.text();
};

const requireFetcher = (
  fetcher: typeof fetch | undefined,
  source: string,
): typeof fetch => {
  if (fetcher) return fetcher;
  throw new Error(
    `Source ${source} requires an explicit fetcher. Pass { fetcher: globalThis.fetch } in network-enabled hosts.`,
  );
};

const githubCandidateUrls = (parsed: GitHubSkillShorthand): string[] => {
  const candidates = parsed.path ? [parsed.path] : DEFAULT_MARKDOWN_CANDIDATES;
  return candidates.map(
    (candidate) =>
      `https://raw.githubusercontent.com/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/${encodeURIComponent(parsed.branch)}/${candidate}`,
  );
};

const splitNpmPackageSpec = (
  packageSpec: string,
): { packageWithVersion: string; path: string } => {
  const value = assertNonEmpty(packageSpec, "npm package");
  if (value.startsWith("@")) {
    const parts = value.split("/");
    if (parts.length < 2 || !parts[0] || !parts[1]) {
      throw new Error("Invalid scoped npm package: expected @scope/name");
    }
    return {
      packageWithVersion: `${parts[0]}/${parts[1]}`,
      path: parts.slice(2).join("/"),
    };
  }

  const slashIndex = value.indexOf("/");
  if (slashIndex === -1) {
    return { packageWithVersion: value, path: "" };
  }
  return {
    packageWithVersion: value.slice(0, slashIndex),
    path: value.slice(slashIndex + 1),
  };
};

const npmCandidateUrls = (packageSpec: string): string[] => {
  const { packageWithVersion, path } = splitNpmPackageSpec(packageSpec);
  if (path) {
    return [`https://unpkg.com/${packageWithVersion}/${path}`];
  }
  return DEFAULT_MARKDOWN_CANDIDATES.map(
    (candidate) => `https://unpkg.com/${packageWithVersion}/${candidate}`,
  );
};

type NpmRegistryMeta = {
  /** ISO 8601 publish time for the resolved version, or null if unknown. */
  publishedAt: string | null;
  /** True when the registry response includes an attestations field. */
  hasAttestation: boolean;
};

const noSourceFlags: SanitizationFlag[] = [];

const parseNpmPackageName = (packageSpec: string): { name: string; version: string } => {
  // e.g. "lodash", "lodash@4.17.21", "@scope/pkg", "@scope/pkg@1.0.0"
  const { packageWithVersion } = splitNpmPackageSpec(packageSpec);
  const scoped = packageWithVersion.startsWith("@");
  const base = scoped ? packageWithVersion.slice(1) : packageWithVersion;
  const atIndex = base.indexOf("@");
  if (atIndex === -1) {
    return { name: packageSpec, version: "latest" };
  }
  const name = scoped ? `@${base.slice(0, atIndex)}` : base.slice(0, atIndex);
  const version = base.slice(atIndex + 1) || "latest";
  return { name, version };
};

async function fetchNpmRegistryMeta(
  packageSpec: string,
  fetcher: typeof fetch,
): Promise<NpmRegistryMeta> {
  const { name, version } = parseNpmPackageName(packageSpec);
  const registryUrl = `https://registry.npmjs.org/${encodeURIComponent(name).replace("%40", "@")}`;
  let data: Record<string, unknown>;
  try {
    const response = await fetcher(registryUrl, {
      headers: { "User-Agent": "skill-safe", Accept: "application/json" },
    });
    if (!response.ok) return { publishedAt: null, hasAttestation: false };
    data = await response.json() as Record<string, unknown>;
  } catch {
    return { publishedAt: null, hasAttestation: false };
  }

  // Resolve concrete version when "latest" is specified
  const resolvedVersion =
    version === "latest"
      ? ((data["dist-tags"] as Record<string, string> | undefined)?.["latest"] ?? version)
      : version;

  const timeMap = data["time"] as Record<string, string> | undefined;
  const publishedAt = timeMap?.[resolvedVersion] ?? null;
  const hasAttestation =
    Array.isArray((data as Record<string, unknown>)["attestations"]) ||
    typeof (data as Record<string, unknown>)["attestations"] === "object";

  return { publishedAt, hasAttestation };
}

function buildNpmSourceFlags(
  packageSpec: string,
  meta: NpmRegistryMeta,
  policy: NpmSourcePolicy,
): SanitizationFlag[] {
  const flags: SanitizationFlag[] = [];
  const minAgeDays = policy.minAgeDays ?? 2;

  if (meta.publishedAt !== null) {
    const ageMs = Date.now() - new Date(meta.publishedAt).getTime();
    const ageDays = ageMs / 86_400_000;
    if (ageDays < minAgeDays) {
      flags.push({
        ruleId: "SS901",
        ruleName: "npm-package-age-gate",
        severity: "danger",
        category: "package-age",
        description: `npm package "${packageSpec}" was published ${ageDays.toFixed(1)} day(s) ago — below the ${minAgeDays}-day minimum. This is a high-risk window for supply-chain attacks.`,
        matched: `published: ${meta.publishedAt}`,
        owasp: ["A08:2021 – Software and Data Integrity Failures"],
        mitreAtlas: ["AML.T0010"],
      });
    }
  }

  if (policy.requireProvenance && !meta.hasAttestation) {
    flags.push({
      ruleId: "SS902",
      ruleName: "npm-missing-provenance",
      severity: "caution",
      category: "missing-provenance",
      description: `npm package "${packageSpec}" has no OIDC/Sigstore provenance attestation in the registry. Build origin cannot be verified.`,
      matched: `package: ${packageSpec}`,
      owasp: ["A08:2021 – Software and Data Integrity Failures"],
    });
  }

  return flags;
}

async function fetchFirstMarkdown(
  urls: string[],
  fetcher: typeof fetch,
): Promise<{ resolvedUrl: string; markdown: string }> {
  for (const url of urls) {
    const markdown = await fetchText(url, fetcher);
    if (markdown !== null) return { resolvedUrl: url, markdown };
  }
  throw new Error(`No markdown entrypoint found at: ${urls.join(", ")}`);
}

async function resolveDirectMarkdown(
  descriptor: SkillSourceDescriptor,
  fetcher: typeof fetch,
): Promise<{ resolvedUrl: string; markdown: string }> {
  switch (descriptor.kind) {
    case "github":
      return fetchFirstMarkdown(
        githubCandidateUrls(parseGithubShorthand(descriptor.source)),
        fetcher,
      );
    case "npm":
      return fetchFirstMarkdown(npmCandidateUrls(descriptor.value), fetcher);
    case "registry":
    case "url": {
      const url = descriptor.kind === "registry" ? descriptor.value : descriptor.source;
      if (!isHttpUrl(url)) {
        throw new Error(`Source ${descriptor.source} requires a registry resolver.`);
      }
      const markdown = await fetchText(url, fetcher);
      if (markdown === null) throw new Error(`No markdown found at ${url}`);
      return { resolvedUrl: url, markdown };
    }
    default:
      throw new Error(`Source ${descriptor.source} requires a ${descriptor.kind} resolver.`);
  }
}

export async function resolveSkillMarkdown(
  source: string,
  options: SkillResolverOptions = {},
): Promise<ResolvedSkillMarkdown> {
  const descriptor = describeSkillSource(source, options);
  const customResolver = options.resolvers?.[descriptor.kind];
  const fetcher = options.fetcher;
  const sourceFlags =
    descriptor.kind === "npm" && fetcher
      ? buildNpmSourceFlags(
          descriptor.value,
          await fetchNpmRegistryMeta(descriptor.value, fetcher),
          options.npmPolicy ?? {},
        )
      : noSourceFlags;

  if (customResolver) {
    const resolved = await customResolver(descriptor);
    if (typeof resolved === "string") {
      return {
        ...descriptor,
        resolvedUrl: null,
        markdown: resolved,
        sourceFlags,
      };
    }
    return {
      ...descriptor,
      resolvedUrl: resolved.resolvedUrl ?? null,
      markdown: resolved.markdown,
      sourceFlags,
    };
  }

  const { resolvedUrl, markdown } = await resolveDirectMarkdown(
    descriptor,
    requireFetcher(fetcher, source),
  );

  return {
    ...descriptor,
    resolvedUrl,
    markdown,
    sourceFlags,
  };
}

export async function resolveAndScanSkillMarkdown(
  source = "github:HashLips/agent-skills",
  options: SkillResolverOptions = {},
): Promise<ResolvedSkillScanReport> {
  const resolved = await resolveSkillMarkdown(source, options);
  const scan = requiresSanitization(resolved.trust)
    ? appendSanitizationFlags(
        sanitizeSkillMarkdown(resolved.markdown),
        resolved.sourceFlags,
      )
    : null;

  return {
    ...resolved,
    scan,
  };
}
