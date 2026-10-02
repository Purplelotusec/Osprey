import { fetchText } from "./http.js";

export interface GitHubRepoInfo {
  owner: string;
  repo: string;
  branch?: string;
  path?: string;
}

export function parseGitHubUrl(url: string): GitHubRepoInfo {
  // Support various GitHub URL formats:
  // - https://github.com/owner/repo
  // - https://github.com/owner/repo/tree/branch
  // - https://github.com/owner/repo/tree/branch/path/to/dir
  // - github.com/owner/repo
  // - owner/repo

  let cleanUrl = url.trim();

  // Remove protocol if present
  cleanUrl = cleanUrl.replace(/^https?:\/\//, "");

  // Remove github.com if present
  cleanUrl = cleanUrl.replace(/^github\.com\//, "");

  // Remove trailing slash
  cleanUrl = cleanUrl.replace(/\/$/, "");

  const parts = cleanUrl.split("/");

  if (parts.length < 2) {
    throw new Error(`Invalid GitHub URL format: ${url}. Expected format: owner/repo or https://github.com/owner/repo`);
  }

  const [owner, repo, ...rest] = parts;

  if (!owner || !repo) {
    throw new Error(`Invalid GitHub URL: could not extract owner and repo from ${url}`);
  }

  let branch: string | undefined;
  let path: string | undefined;

  // Parse tree/branch/path format
  if (rest.length > 0 && rest[0] === "tree") {
    branch = rest[1];
    if (rest.length > 2) {
      path = rest.slice(2).join("/");
    }
  }

  return { owner, repo, branch, path };
}

export async function fetchGitHubFile(
  owner: string,
  repo: string,
  filePath: string,
  options?: { branch?: string; token?: string }
): Promise<string> {
  // "HEAD" resolves to the repository's default branch. Guessing main/master
  // instead can silently audit a stale branch (e.g. a repo whose default is "dev").
  const ref = options?.branch ?? "HEAD";
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${filePath}`;

  const headers: Record<string, string> = {
    "User-Agent": "osprey-sbom-audit",
  };

  if (options?.token) {
    headers["Authorization"] = `Bearer ${options.token}`;
  }

  return fetchText(url, { headers }, {});
}

/** Fetches a file if it exists, or returns undefined (any fetch failure counts as absent). */
export async function fetchOptionalGitHubFile(
  repoInfo: GitHubRepoInfo,
  fileName: string,
  options?: { token?: string }
): Promise<string | undefined> {
  const { owner, repo, branch, path } = repoInfo;
  try {
    return await fetchGitHubFile(owner, repo, path ? `${path}/${fileName}` : fileName, { branch, token: options?.token });
  } catch {
    return undefined;
  }
}

/**
 * Manifests looked for in a remote repository, most precise first: lockfiles
 * pin every package at its resolved version; package.json only has ranges.
 * Python order mirrors local detection (src/sbom/generate/python.ts). Named
 * PEP 751 variants (pylock.<name>.toml) can't be discovered without listing
 * the directory, so only pylock.toml is looked for.
 */
const REMOTE_MANIFESTS: Array<{ fileName: string; ecosystem: "npm" | "python" }> = [
  { fileName: "package-lock.json", ecosystem: "npm" },
  { fileName: "uv.lock", ecosystem: "python" },
  { fileName: "poetry.lock", ecosystem: "python" },
  { fileName: "pdm.lock", ecosystem: "python" },
  { fileName: "pylock.toml", ecosystem: "python" },
  { fileName: "Pipfile.lock", ecosystem: "python" },
  { fileName: "requirements.lock", ecosystem: "python" },
  { fileName: "requirements-dev.lock", ecosystem: "python" },
  { fileName: "requirements.txt", ecosystem: "python" },
  { fileName: "package.json", ecosystem: "npm" },
];

export async function detectAndFetchPackageFile(
  repoInfo: GitHubRepoInfo,
  options?: { token?: string }
): Promise<{ ecosystem: "npm" | "python"; content: string; fileName: string }> {
  const { owner, repo, path } = repoInfo;

  for (const { fileName, ecosystem } of REMOTE_MANIFESTS) {
    const content = await fetchOptionalGitHubFile(repoInfo, fileName, options);
    if (content === undefined) continue;
    if (fileName === "package.json") {
      console.warn("⚠ Using package.json (no lock file found). Version ranges may be imprecise.");
    }
    return { ecosystem, content, fileName };
  }

  throw new Error(
    `No supported package file found in ${owner}/${repo}${path ? `/${path}` : ""}. ` +
    `Supported files: ${REMOTE_MANIFESTS.map((manifest) => manifest.fileName).join(", ")}`
  );
}

export interface GitHubPackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export async function fetchPackageJson(
  owner: string,
  repo: string,
  options?: { branch?: string; path?: string; token?: string }
): Promise<GitHubPackageJson> {
  const basePath = options?.path ?? "";
  const filePath = basePath ? `${basePath}/package.json` : "package.json";

  try {
    const content = await fetchGitHubFile(owner, repo, filePath, { branch: options?.branch, token: options?.token });
    return JSON.parse(content);
  } catch (error) {
    throw new Error(`Failed to fetch package.json: ${error instanceof Error ? error.message : String(error)}`);
  }
}
