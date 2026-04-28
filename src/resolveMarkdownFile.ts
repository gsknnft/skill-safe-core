const PREFERRED_MARKDOWN_FILES = ["SKILL.md", "skill.md", "README.md", "readme.md", "index.md"];

export type MarkdownFileSource =
  | "github"
  | "registry"
  | "souls"
  | "hermes"
  | "marketplace"
  | "gitlab"
  | "huggingface"
  | "url"
  | "unknown";

export type ResolveMarkdownFileOptions = {
  owner?: string;
  repo?: string;
  branch?: string;
  path?: string;
  source?: MarkdownFileSource;
  /**
   * Optional API endpoint for source hosts with GitHub-compatible contents
   * responses. If provided, it is used directly.
   */
  apiUrl?: string;
  /** Injected fetch implementation for tests, workers, or custom runtimes. */
  fetcher?: typeof fetch;
  /** Optional auth token. Defaults to GITHUB_TOKEN for GitHub sources in Node. */
  token?: string;
  /** Preferred markdown entrypoints, in order. */
  preferredFileNames?: string[];
  /** Whether to inspect one level of subdirectories for SKILL.md. Defaults true. */
  scanSubdirectories?: boolean;
};

export type ResolvedMarkdownFile = {
  resolvedUrl: string;
  source: MarkdownFileSource;
  owner?: string;
  repo?: string;
  branch?: string;
  path?: string;
};

type GitHubContentFile = {
  type: "file";
  name: string;
  path: string;
  download_url?: string | null;
};

type GitHubContentDirectory = {
  type: "dir";
  name: string;
  path: string;
  url?: string;
};

type GitHubContentResponse = GitHubContentFile | GitHubContentDirectory | Array<GitHubContentFile | GitHubContentDirectory>;

const getProcessEnv = (key: string): string | undefined => {
  if (typeof process === "undefined") return undefined;
  return process.env?.[key];
};

const assertFetchOk = async (response: Response, url: string): Promise<void> => {
  if (response.ok) return;
  throw new Error(`resolveMarkdownFile: ${url} returned HTTP ${response.status}`);
};

const jsonFetch = async (
  url: string,
  fetcher: typeof fetch,
  headers: Record<string, string>,
): Promise<GitHubContentResponse> => {
  const response = await fetcher(url, { headers });
  await assertFetchOk(response, url);
  return await response.json() as GitHubContentResponse;
};

const buildGithubContentsUrl = (
  owner: string,
  repo: string,
  branch: string,
  path: string,
): string => {
  const cleanPath = path.replace(/^\/+/, "");
  const encodedPath = cleanPath
    .split("/")
    .filter(Boolean)
    .map(encodeURIComponent)
    .join("/");
  const suffix = encodedPath ? `/${encodedPath}` : "";
  return `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents${suffix}?ref=${encodeURIComponent(branch)}`;
};

const fileDownloadUrl = (file: GitHubContentFile): string | null =>
  typeof file.download_url === "string" && file.download_url.length > 0
    ? file.download_url
    : null;

const chooseMarkdownFile = (
  entries: Array<GitHubContentFile | GitHubContentDirectory>,
  preferredFileNames: string[],
): GitHubContentFile | null => {
  for (const preferred of preferredFileNames) {
    const found = entries.find(
      (entry): entry is GitHubContentFile =>
        entry.type === "file" && entry.name.toLowerCase() === preferred.toLowerCase(),
    );
    if (found) return found;
  }

  return entries.find(
    (entry): entry is GitHubContentFile =>
      entry.type === "file" && entry.name.toLowerCase().endsWith(".md"),
  ) ?? null;
};

const required = (value: string | undefined, label: string): string => {
  const trimmed = value?.trim();
  if (!trimmed) throw new Error(`resolveMarkdownFile: missing ${label}`);
  return trimmed;
};

export const resolveMarkdownFile = async (
  options: ResolveMarkdownFileOptions,
): Promise<ResolvedMarkdownFile> => {
  const source = options.source ?? "github";
  const fetcher = options.fetcher ?? fetch;
  const preferredFileNames = options.preferredFileNames ?? PREFERRED_MARKDOWN_FILES;
  const scanSubdirectories = options.scanSubdirectories ?? true;

  if (source !== "github" && !options.apiUrl) {
    throw new Error(`resolveMarkdownFile: source "${source}" requires apiUrl`);
  }

  const owner = options.owner;
  const repo = options.repo;
  const branch = options.branch ?? "main";
  const path = options.path ?? "";

  const apiUrl = options.apiUrl ?? buildGithubContentsUrl(
    required(owner, "owner"),
    required(repo, "repo"),
    branch,
    path,
  );

  const token = options.token ?? (source === "github" ? getProcessEnv("GITHUB_TOKEN") : undefined);
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "skill-safe",
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const data = await jsonFetch(apiUrl, fetcher, headers);

  if (!Array.isArray(data)) {
    if (data.type === "file") {
      const resolvedUrl = fileDownloadUrl(data);
      if (resolvedUrl) return { resolvedUrl, source, owner, repo, branch, path: data.path };
    }
    throw new Error("resolveMarkdownFile: expected a markdown file or directory listing");
  }

  const direct = chooseMarkdownFile(data, preferredFileNames);
  if (direct) {
    const directUrl = fileDownloadUrl(direct);
    if (directUrl) {
      return { resolvedUrl: directUrl, source, owner, repo, branch, path: direct.path };
    }
  }

  if (scanSubdirectories) {
    const directories = data.filter((entry): entry is GitHubContentDirectory => entry.type === "dir");
    for (const directory of directories) {
      const subApiUrl = directory.url ?? (
        source === "github" && owner && repo
          ? buildGithubContentsUrl(owner, repo, branch, directory.path)
          : null
      );
      if (!subApiUrl) continue;

      const subData = await jsonFetch(subApiUrl, fetcher, headers);
      if (!Array.isArray(subData)) continue;

      const found = subData.find(
        (entry): entry is GitHubContentFile =>
          entry.type === "file" && /^skill\.md$/i.test(entry.name),
      );
      if (found) {
        const resolvedUrl = fileDownloadUrl(found);
        if (resolvedUrl) {
          return { resolvedUrl, source, owner, repo, branch, path: found.path };
        }
      }
    }
  }

  throw new Error(
    `resolveMarkdownFile: no markdown skill file found in ${path || "/"}${owner && repo ? ` of ${owner}/${repo}@${branch}` : ""}`,
  );
};

export const resolveGitHubMarkdownFile = async (
  owner: string,
  repo: string,
  branch = "main",
  path = "",
  options: Omit<ResolveMarkdownFileOptions, "owner" | "repo" | "branch" | "path" | "source"> = {},
): Promise<string> => {
  const resolved = await resolveMarkdownFile({
    ...options,
    owner,
    repo,
    branch,
    path,
    source: "github",
  });
  return resolved.resolvedUrl;
};
