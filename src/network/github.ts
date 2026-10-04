import { fetchText, HttpError } from "./http.js";
import { GRADLE_SETTINGS_FILES, parseSettingsIncludes } from "../sbom/generate/gradle.js";

export interface GitHubRepoInfo {
  owner: string;
  repo: string;
  branch?: string;
  path?: string;
}

/**
 * Accepts the forms people paste: `owner/repo`, `github.com/owner/repo`,
 * `https://github.com/owner/repo(.git)`, and `…/tree/<branch>[/sub/dir]` to
 * pick a branch and a subdirectory. (A branch name containing "/" can't be told
 * apart from a subdirectory in this form.)
 */
export function parseGitHubUrl(url: string): GitHubRepoInfo {
  const cleanUrl = url
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/^(www\.)?github\.com\//, "")
    .replace(/\/+$/, "");

  const parts = cleanUrl.split("/");
  if (parts[1]) parts[1] = parts[1].replace(/\.git$/, ""); // clone URLs end in .git

  if (parts.length < 2) {
    throw new Error(`Invalid GitHub URL format: ${url}. Expected format: owner/repo or https://github.com/owner/repo`);
  }

  const [owner, repo, ...rest] = parts;

  if (!owner || !repo) {
    throw new Error(`Invalid GitHub URL: could not extract owner and repo from ${url}`);
  }

  let branch: string | undefined;
  let path: string | undefined;

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

export type RemoteEcosystem = "npm" | "python" | "maven";

export interface RemotePackageFile {
  ecosystem: RemoteEcosystem;
  fileName: string;
  content: string;
  /** Other files read together with this one (e.g. the rest of requirements/), fetched by the caller. */
  relatedFiles?: string[];
  /** Files already fetched during detection (path -> content), written alongside the manifest. */
  extraFiles?: Record<string, string>;
}

/**
 * Names of the files directly inside `dir` of the repository (no subdirectories),
 * via the GitHub contents API — raw.githubusercontent.com can only fetch files by
 * name. Returns [] when the directory doesn't exist.
 */
export async function listGitHubDirectory(repoInfo: GitHubRepoInfo, dir: string, options?: { token?: string }): Promise<string[]> {
  const { owner, repo, branch, path } = repoInfo;
  const dirPath = path ? `${path}/${dir}` : dir;
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${dirPath.split("/").map(encodeURIComponent).join("/")}${branch ? `?ref=${encodeURIComponent(branch)}` : ""}`;
  const headers: Record<string, string> = { "User-Agent": "osprey-sbom-audit", Accept: "application/vnd.github+json" };
  if (options?.token) headers["Authorization"] = `Bearer ${options.token}`;

  let body: string;
  try {
    body = await fetchText(url, { headers });
  } catch (err) {
    if (err instanceof HttpError && err.status === 404) return [];
    throw new Error(`Could not list ${dirPath} in ${owner}/${repo}: ${(err as Error).message}`);
  }
  const entries: unknown = JSON.parse(body);
  if (!Array.isArray(entries)) return []; // a file, not a directory
  return entries
    .filter((entry): entry is { name: string; type: string } => typeof entry?.name === "string" && entry.type === "file")
    .map((entry) => entry.name);
}

/**
 * Manifests looked for in a remote repository, per ecosystem, most precise
 * first. Python order mirrors local detection (src/sbom/generate/python.ts).
 * Named PEP 751 variants (pylock.<name>.toml) can't be discovered without
 * listing the directory, so only pylock.toml is looked for.
 */
const REMOTE_MANIFESTS: Record<RemoteEcosystem, string[]> = {
  // Same order as local detection (src/sbom/generate/npm.ts NPM_LOCKFILES).
  npm: ["npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"],
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
  // Gradle lockfiles live per module; findGradleLockfilesRemote discovers them via settings.gradle(.kts).
  maven: ["gradle.lockfile"],
};

/** Cap on module lockfiles fetched for one repository. */
const MAX_GRADLE_MODULES = 50;

/**
 * Gradle dependency locking writes one lockfile per module, so the root may have
 * none. Modules are read from settings.gradle(.kts) — the same rule as local
 * detection — and each module's gradle.lockfile is fetched.
 */
async function findGradleLockfilesRemote(repoInfo: GitHubRepoInfo, options?: { token?: string }): Promise<RemotePackageFile | undefined> {
  let settingsFile: string | undefined;
  let settings: string | undefined;
  for (const name of GRADLE_SETTINGS_FILES) {
    settings = await fetchOptionalGitHubFile(repoInfo, name, options);
    if (settings !== undefined) {
      settingsFile = name;
      break;
    }
  }
  const candidates = ["gradle.lockfile", ...parseSettingsIncludes(settings ?? "").slice(0, MAX_GRADLE_MODULES).map((module) => `${module}/gradle.lockfile`)];

  const found: Record<string, string> = {};
  for (let i = 0; i < candidates.length; i += 8) {
    const batch = candidates.slice(i, i + 8);
    const contents = await Promise.all(batch.map((path) => fetchOptionalGitHubFile(repoInfo, path, options)));
    batch.forEach((path, index) => {
      if (contents[index] !== undefined) found[path] = contents[index]!;
    });
  }
  const [first, ...rest] = Object.keys(found);
  if (!first) return undefined;
  const extraFiles = Object.fromEntries(rest.map((path) => [path, found[path]]));
  if (settingsFile && settings !== undefined) extraFiles[settingsFile] = settings;
  return { ecosystem: "maven", fileName: first, content: found[first], extraFiles };
}

/** Same rule as local detection: pinned requirements/*.txt files, used when there's no root manifest. */
async function findRequirementsDirectory(repoInfo: GitHubRepoInfo, options?: { token?: string }): Promise<RemotePackageFile | undefined> {
  const files = (await listGitHubDirectory(repoInfo, "requirements", options))
    .filter((name) => name.endsWith(".txt"))
    .sort()
    .map((name) => `requirements/${name}`);
  if (files.length === 0) return undefined;
  const [first, ...rest] = files;
  const content = await fetchOptionalGitHubFile(repoInfo, first, options);
  return content === undefined ? undefined : { ecosystem: "python", fileName: first, content, relatedFiles: rest };
}

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
      if (ecosystem === "maven") return findGradleLockfilesRemote(repoInfo, options);
      for (const fileName of fileNames) {
        const content = await fetchOptionalGitHubFile(repoInfo, fileName, options);
        if (content !== undefined) return { ecosystem, fileName, content };
      }
      return ecosystem === "python" ? findRequirementsDirectory(repoInfo, options) : undefined;
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
