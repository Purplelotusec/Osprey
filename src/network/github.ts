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
  const branch = options?.branch ?? "main";
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`;

  const headers: Record<string, string> = {
    "User-Agent": "osprey-sbom-audit",
  };

  if (options?.token) {
    headers["Authorization"] = `Bearer ${options.token}`;
  }

  try {
    return await fetchText(url, { headers }, {});
  } catch (error) {
    // Try 'master' branch if 'main' fails and no explicit branch was specified
    if (!options?.branch && branch === "main") {
      const masterUrl = `https://raw.githubusercontent.com/${owner}/${repo}/master/${filePath}`;
      try {
        return await fetchText(masterUrl, { headers }, {});
      } catch {
        // Rethrow original error
        throw error;
      }
    }
    throw error;
  }
}

export async function detectAndFetchPackageFile(
  repoInfo: GitHubRepoInfo,
  options?: { token?: string }
): Promise<{ ecosystem: "npm" | "python"; content: string; fileName: string }> {
  const { owner, repo, branch, path } = repoInfo;
  const basePath = path ?? "";

  // Try npm first (package-lock.json)
  try {
    const lockFile = await fetchGitHubFile(
      owner,
      repo,
      basePath ? `${basePath}/package-lock.json` : "package-lock.json",
      { branch, token: options?.token }
    );
    return { ecosystem: "npm", content: lockFile, fileName: "package-lock.json" };
  } catch {
    // npm not found, continue
  }

  // Try Python (requirements.txt)
  try {
    const reqFile = await fetchGitHubFile(
      owner,
      repo,
      basePath ? `${basePath}/requirements.txt` : "requirements.txt",
      { branch, token: options?.token }
    );
    return { ecosystem: "python", content: reqFile, fileName: "requirements.txt" };
  } catch {
    // Python not found, continue
  }

  // Fallback to package.json (less precise than lock files, but better than nothing)
  try {
    const pkgJson = await fetchGitHubFile(
      owner,
      repo,
      basePath ? `${basePath}/package.json` : "package.json",
      { branch, token: options?.token }
    );
    console.warn("⚠ Using package.json (no lock file found). Version ranges may be imprecise.");
    return { ecosystem: "npm", content: pkgJson, fileName: "package.json" };
  } catch {
    // package.json not found either
  }

  // No supported package file found
  throw new Error(
    `No supported package file found in ${owner}/${repo}${basePath ? `/${basePath}` : ""}. ` +
    `Supported files: package-lock.json, package.json (npm), requirements.txt (Python)`
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
