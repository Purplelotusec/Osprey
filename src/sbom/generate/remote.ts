import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { generateSbom, type GenerateResult } from "./index.js";
import type { GitHubRepoInfo } from "../../network/github.js";
import { detectAndFetchPackageFile, fetchOptionalGitHubFile, fetchPackageJson } from "../../network/github.js";

export interface RemoteGenerationOptions {
  repoInfo: GitHubRepoInfo;
  token?: string;
}

export async function generateSbomFromGitHub(options: RemoteGenerationOptions): Promise<GenerateResult> {
  const { repoInfo, token } = options;
  const { owner, repo, branch, path } = repoInfo;

  // Detect and fetch package files
  const packageFile = await detectAndFetchPackageFile(repoInfo, { token });

  // Create temporary directory for files
  const tempDir = join(tmpdir(), `osprey-${Date.now()}`);
  mkdirSync(tempDir, { recursive: true });

  try {
    // Write package file to temp directory
    const packageFilePath = join(tempDir, packageFile.fileName);
    writeFileSync(packageFilePath, packageFile.content, "utf-8");

    // For npm, also fetch package.json if available
    if (packageFile.ecosystem === "npm") {
      try {
        const pkgJson = await fetchPackageJson(owner, repo, { branch, path, token });
        const pkgJsonPath = join(tempDir, "package.json");
        writeFileSync(pkgJsonPath, JSON.stringify(pkgJson, null, 2), "utf-8");
      } catch {
        // package.json is optional for our purposes
      }
    }

    // Python lockfiles take the project name and direct dependencies from
    // pyproject.toml; without it the SBOM is still complete, just less labelled.
    if (packageFile.fileName === "uv.lock" || packageFile.fileName === "poetry.lock") {
      const pyproject = await fetchOptionalGitHubFile(repoInfo, "pyproject.toml", { token });
      if (pyproject !== undefined) writeFileSync(join(tempDir, "pyproject.toml"), pyproject, "utf-8");
    }

    // Generate SBOM from temp directory
    const result = generateSbom({
      projectDir: tempDir,
      ecosystem: packageFile.ecosystem,
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
