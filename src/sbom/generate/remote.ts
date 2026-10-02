import { writeFileSync, mkdirSync, mkdtempSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { tmpdir } from "node:os";
import { generateSbom, type GenerateResult } from "./index.js";
import { findRequirementIncludes } from "./requirements.js";
import type { GitHubRepoInfo } from "../../network/github.js";
import { detectAndFetchPackageFiles, fetchOptionalGitHubFile } from "../../network/github.js";

export interface RemoteGenerationOptions {
  repoInfo: GitHubRepoInfo;
  token?: string;
}

export async function generateSbomFromGitHub(options: RemoteGenerationOptions): Promise<GenerateResult> {
  const { repoInfo, token } = options;
  const { owner, repo, path } = repoInfo;

  // One preferred manifest per ecosystem present (npm and/or Python).
  const packageFiles = await detectAndFetchPackageFiles(repoInfo, { token });

  const tempDir = mkdtempSync(join(tmpdir(), "osprey-"));

  try {
    for (const packageFile of packageFiles) {
      writeFileSync(join(tempDir, packageFile.fileName), packageFile.content, "utf-8");

      // npm lockfiles are read together with package.json (project name/version).
      // A missing one surfaces from the npm generator; a failed fetch throws here.
      if (packageFile.fileName === "package-lock.json") {
        const pkgJson = await fetchOptionalGitHubFile(repoInfo, "package.json", { token });
        if (pkgJson !== undefined) writeFileSync(join(tempDir, "package.json"), pkgJson, "utf-8");
      }

      if (packageFile.ecosystem === "python") {
        await fetchPythonCompanions(repoInfo, packageFile, tempDir, token);
      }
    }

    // Generate exactly the ecosystems that were fetched — a package.json fetched
    // only as a companion must not turn into an npm audit of its ranges.
    const result = generateSbom({
      projectDir: tempDir,
      ecosystems: [...new Set(packageFiles.map((file) => file.ecosystem))],
    });

    // Update subject name to reflect the GitHub repo
    const subjectName = path
      ? `${owner}/${repo}/${path}`
      : `${owner}/${repo}`;

    return {
      ...result,
      sbom: {
        ...result.sbom,
        subjectName,
      },
    };
  } finally {
    // Clean up temp directory (best effort)
    try {
      const { rmSync } = await import("node:fs");
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }
}

/** Pip-format files whose `-r` includes must be fetched too. */
const PIP_FORMAT_FILES = new Set(["requirements.txt", "requirements.lock", "requirements-dev.lock"]);
/** Cap on files fetched through `-r` include chains, so a hostile repo can't make us crawl it. */
const MAX_INCLUDED_FILES = 25;

/**
 * Fetches the files a Python manifest is read together with. All are optional:
 * without them the SBOM is still complete, just less labelled — or, for a
 * missing -r include, the parser reports the gap as a warning.
 */
async function fetchPythonCompanions(
  repoInfo: GitHubRepoInfo,
  manifest: { fileName: string; content: string },
  tempDir: string,
  token: string | undefined
): Promise<void> {
  const save = async (fileName: string) => {
    const content = await fetchOptionalGitHubFile(repoInfo, fileName, { token });
    if (content !== undefined) writeFileSync(join(tempDir, fileName), content, "utf-8");
    return content;
  };

  // Project name and declared (direct) dependencies.
  await save("pyproject.toml");
  if (manifest.fileName === "Pipfile.lock") await save("Pipfile");

  const pipFiles = [{ fileName: manifest.fileName, content: manifest.content }];
  if (manifest.fileName === "requirements.lock") {
    const devLock = await save("requirements-dev.lock");
    if (devLock !== undefined) pipFiles.push({ fileName: "requirements-dev.lock", content: devLock });
  }
  if (!PIP_FORMAT_FILES.has(manifest.fileName)) return;

  const fetched = new Set(pipFiles.map((file) => file.fileName));
  const queue = [...pipFiles];
  while (queue.length > 0) {
    const { fileName, content } = queue.shift()!;
    for (const include of findRequirementIncludes(content)) {
      // Resolve relative to the including file, and never outside the audited directory.
      const target = posix.normalize(posix.join(posix.dirname(fileName), include));
      if (target.startsWith("../") || target === ".." || posix.isAbsolute(target) || /^[a-z][a-z0-9+.-]*:/i.test(include)) continue;
      if (fetched.has(target) || fetched.size >= MAX_INCLUDED_FILES) continue;
      fetched.add(target);

      const included = await fetchOptionalGitHubFile(repoInfo, target, { token });
      if (included === undefined) continue;
      const destination = join(tempDir, ...target.split("/"));
      mkdirSync(dirname(destination), { recursive: true });
      writeFileSync(destination, included, "utf-8");
      queue.push({ fileName: target, content: included });
    }
  }
}
