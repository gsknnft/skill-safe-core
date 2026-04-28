import type { GitHubContentResponse, GitHubContentFile, GitHubContentDirectory, ResolvedMarkdownFile, ResolveMarkdownFileOptions } from "./types.js";
import { PREFERRED_MARKDOWN_FILES } from "./constants.js";

/**
 * Resolve a markdown file URL from a GitHub repository, using the GitHub
 * Contents API. Handles both direct file references and directory listings,
 * with optional recursive scanning of subdirectories.
 *
 * Recognizes:
 *   - github:<owner>/<repo>[@branch][/path]
 *
 * If the path points directly to a markdown file, that file is returned.
 * If the path points to a directory, that directory is scanned for markdown
 * files, prioritizing those in PREFERRED_MARKDOWN_FILES. Optionally, one
 * level of subdirectories can also be scanned.
 *
 * Returns the resolved download URL of the markdown file, or throws an error
 * if no suitable file is found or if any fetch operation fails.
 * Note: GitHub API rate limits apply. Providing an explicit token with
 * appropriate scopes can increase limits and access private repositories.
 *
 * @param options - Configuration for resolving the markdown file, including
 *   repository details, API URL, authentication token, and scanning preferences.
 * @returns An object containing the resolved markdown file URL and related metadata.
 * @throws Error if resolution fails due to missing parameters, fetch errors, or
 *   if no markdown file is found in the specified location.
 * @see GitHub Contents API: https://docs.github.com/en/rest/repos/contents
 * @see GitHub API Authentication: https://docs.github.com/en/rest/overview/authenticating-to-the-rest-api
 * @see GitHub API Rate Limiting: https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting
 * @see PREFERRED_MARKDOWN_FILES for default file prioritization.
 * @remarks This function is designed for use within the skill-safe framework to locate
 * markdown files that define agent skills. It abstracts away the details of
 * interacting with the GitHub API and provides a consistent interface for
 * retrieving skill definitions from repositories.
 * @example
 * // Resolve a markdown file from a GitHub repository
 * const resolved = await resolveMarkdownFile({
 *   source: "github",
 *   owner: "HashLips",
 *   repo: "agent-skills",
 *   branch: "main",
 *   path: "README.md"
 * });
 * console.log(resolved.resolvedUrl); // URL to the raw markdown file
 *
 * // Resolve a markdown file from a directory, prioritizing PREFERRED_MARKDOWN_FILES
 * const resolved = await resolveMarkdownFile({
 *   source: "github",
 *   owner: "HashLips",
 *   repo: "agent-skills",
 *   branch: "main",
 *   path: "docs"
 * });
 * console.log(resolved.resolvedUrl); // URL to the raw markdown file
 *
 * // Resolve a markdown file with recursive subdirectory scanning
 * const resolved = await resolveMarkdownFile({
 *   source: "github",
 *   owner: "HashLips",
 *   repo: "agent-skills",
 *   branch: "main",
 *   path: "docs",
 *   scanSubdirectories: true
 * });
 * console.log(resolved.resolvedUrl); // URL to the raw markdown file
 * 
 */

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

const requireFetcher = (
  fetcher: typeof fetch | undefined,
): typeof fetch => {
  if (fetcher) return fetcher;
  throw new Error(
    "resolveMarkdownFile: network resolution requires an explicit fetcher",
  );
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
  const fetcher = requireFetcher(options.fetcher);
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

  const token = options.token;
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
