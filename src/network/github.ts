import { fetchText, HttpError } from "./http.js";

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

/** Fetches a file if it exists: undefined on 404, throws on any other failure. */
export async function fetchOptionalGitHubFile(
  repoInfo: GitHubRepoInfo,
  fileName: string,
  options?: { token?: string }
): Promise<string | undefined> {
  const { owner, repo, branch, path } = repoInfo;
  const filePath = path ? `${path}/${fileName}` : fileName;
  try {
    return await fetchGitHubFile(owner, repo, filePath, { branch, token: options?.token });
  } catch (err) {
    // Only "not found" means absent. A rate limit, bad token or outage must fail the
    // audit: treating it as absent could silently drop a whole ecosystem from it.
    if (err instanceof HttpError && err.status === 404) return undefined;
    throw new Error(`Could not fetch ${filePath} from ${owner}/${repo}: ${(err as Error).message}`);
  }
}

export type RemoteEcosystem = "npm" | "python";

export interface RemotePackageFile {
  ecosystem: RemoteEcosystem;
  fileName: string;
  content: string;
}

/**
 * Manifests looked for in a remote repository, per ecosystem, most precise
 * first. Python order mirrors local detection (src/sbom/generate/python.ts).
 * Named PEP 751 variants (pylock.<name>.toml) can't be discovered without
 * listing the directory, so only pylock.toml is looked for.
 */
const REMOTE_MANIFESTS: Record<RemoteEcosystem, string[]> = {
  npm: ["package-lock.json"],
  python: [
    "uv.lock",
    "poetry.lock",
    "pdm.lock",
    "pylock.toml",
    "Pipfile.lock",
    "requirements.lock",
    "requirements-dev.lock",
    "requirements.txt",
  ],
};

/**
 * Finds the preferred manifest of every ecosystem in the repository, so a mixed
 * repo (e.g. a Python backend with an npm frontend) is audited in full.
 * package.json is a last resort, used only when nothing else is found: it holds
 * version ranges, and in a Python repo it is often just front-end tooling.
 */
export async function detectAndFetchPackageFiles(
  repoInfo: GitHubRepoInfo,
  options?: { token?: string }
): Promise<RemotePackageFile[]> {
  const { owner, repo, path } = repoInfo;

  // Ecosystems are searched concurrently; within one, candidates go in preference order.
  const found = await Promise.all(
    (Object.entries(REMOTE_MANIFESTS) as Array<[RemoteEcosystem, string[]]>).map(async ([ecosystem, fileNames]) => {
      for (const fileName of fileNames) {
        const content = await fetchOptionalGitHubFile(repoInfo, fileName, options);
        if (content !== undefined) return { ecosystem, fileName, content };
      }
      return undefined;
    })
  );
  const files = found.filter((file): file is RemotePackageFile => file !== undefined);
  if (files.length > 0) return files;

  const packageJson = await fetchOptionalGitHubFile(repoInfo, "package.json", options);
  if (packageJson !== undefined) {
    // The npm generator reports the imprecision (and any skipped specs) as SBOM warnings.
    return [{ ecosystem: "npm", fileName: "package.json", content: packageJson }];
  }

  const supported = [...Object.values(REMOTE_MANIFESTS).flat(), "package.json"];
  throw new Error(
    `No supported package file found in ${owner}/${repo}${path ? `/${path}` : ""}. ` +
    `Supported files: ${supported.join(", ")}`
  );
}
