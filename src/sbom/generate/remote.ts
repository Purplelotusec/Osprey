import { writeFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { tmpdir } from "node:os";
import { generateSbom, unauditedPackageJsonWarning, UNSUPPORTED_JS_LOCKFILES, type GenerateResult } from "./index.js";
import { findRequirementIncludes } from "./requirements.js";
import { describeUnsupportedEcosystems, unsupportedEcosystemWarnings } from "./unsupported.js";
import type { GitHubRepoInfo } from "../../network/github.js";
import { detectAndFetchPackageFiles, fetchOptionalGitHubFile, listGitHubDirectory, NoSupportedPackageFileError } from "../../network/github.js";

export interface RemoteGenerationOptions {
  repoInfo: GitHubRepoInfo;
  token?: string;
}

export async function generateSbomFromGitHub(options: RemoteGenerationOptions): Promise<GenerateResult> {
  const { repoInfo, token } = options;
  const { owner, repo, path } = repoInfo;

  // The root listing tells which unsupported ecosystems (Rust, Go, ...) are present.
  // It's one GitHub API call, so it is best effort: without it the audit is still
  // complete for what it covers, and the gap is reported instead.
  let rootFiles: string[] | undefined;
  let listingError: string | undefined;
  try {
    rootFiles = await listGitHubDirectory(repoInfo, "", { token });
  } catch (err) {
    listingError = (err as Error).message;
  }

  // One preferred manifest per ecosystem present (npm, Python and/or Gradle).
  let packageFiles;
  try {
    packageFiles = await detectAndFetchPackageFiles(repoInfo, { token });
  } catch (err) {
    const unsupported = err instanceof NoSupportedPackageFileError && rootFiles ? describeUnsupportedEcosystems(rootFiles) : undefined;
    if (unsupported) throw new NoSupportedPackageFileError(`${(err as Error).message}. ${unsupported}`);
    throw err;
  }

  const tempDir = mkdtempSync(join(tmpdir(), "osprey-"));

  try {
    for (const packageFile of packageFiles) {
      const destination = join(tempDir, ...packageFile.fileName.split("/"));
      mkdirSync(dirname(destination), { recursive: true });
      writeFileSync(destination, packageFile.content, "utf-8");

      // JavaScript lockfiles are read together with package.json (project name,
      // direct dependencies). A failed fetch throws; a missing file is tolerated.
      if (packageFile.ecosystem === "npm" && packageFile.fileName !== "package.json") {
        const pkgJson = await fetchOptionalGitHubFile(repoInfo, "package.json", { token });
        if (pkgJson !== undefined) writeFileSync(join(tempDir, "package.json"), pkgJson, "utf-8");
      }

      // Cargo.toml names the project; the lockfile alone is a complete SBOM.
      if (packageFile.ecosystem === "cargo") {
        const manifest = await fetchOptionalGitHubFile(repoInfo, "Cargo.toml", { token });
        if (manifest !== undefined) writeFileSync(join(tempDir, "Cargo.toml"), manifest, "utf-8");
      }

      if (packageFile.ecosystem === "python") {
        await fetchPythonCompanions(repoInfo, packageFile, tempDir, token);
      }

      // e.g. the other modules' gradle.lockfile and settings.gradle(.kts), fetched during detection.
      for (const [extraPath, content] of Object.entries(packageFile.extraFiles ?? {})) {
        const extraDestination = join(tempDir, ...extraPath.split("/"));
        mkdirSync(dirname(extraDestination), { recursive: true });
        writeFileSync(extraDestination, content, "utf-8");
      }
    }

    // Generate exactly the ecosystems that were fetched — a package.json fetched
    // only as a companion must not turn into an npm audit of its ranges.
    const ecosystems = [...new Set(packageFiles.map((file) => file.ecosystem))];
    const result = generateSbom({ projectDir: tempDir, ecosystems });

    // Python found but no npm lockfile: say so if a package.json is being left out,
    // naming the pnpm/Yarn/Bun lockfile in use if there is one.
    if (!ecosystems.includes("npm") && (await fetchOptionalGitHubFile(repoInfo, "package.json", { token })) !== undefined) {
      let otherLockfile: string | undefined;
      for (const file of UNSUPPORTED_JS_LOCKFILES) {
        if ((await fetchOptionalGitHubFile(repoInfo, file, { token })) !== undefined) {
          otherLockfile = file;
          break;
        }
      }
      result.warnings.push(unauditedPackageJsonWarning(otherLockfile));
    }

    if (rootFiles) {
      result.warnings.push(...unsupportedEcosystemWarnings(rootFiles, ecosystems));
    } else {
      result.warnings.push(`Could not list the repository root to check for dependency files Osprey does not read (Rust, Go, Ruby, PHP, .NET, ...), so any such dependencies were NOT audited: ${listingError}`);
    }

    // Label the SBOM with the repository, not the temp directory it was built in.
    const subjectName = path ? `${owner}/${repo}/${path}` : `${owner}/${repo}`;
    return { ...result, sbom: { ...result.sbom, subjectName } };
  } finally {
    // Best effort: a leftover temp directory must not turn a finished audit into a failure.
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* ignored */
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
  manifest: { fileName: string; content: string; relatedFiles?: string[] },
  tempDir: string,
  token: string | undefined
): Promise<void> {
  const save = async (fileName: string) => {
    const content = await fetchOptionalGitHubFile(repoInfo, fileName, { token });
    if (content !== undefined) {
      const destination = join(tempDir, ...fileName.split("/"));
      mkdirSync(dirname(destination), { recursive: true });
      writeFileSync(destination, content, "utf-8");
    }
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
  // The rest of requirements/ (capped like -r includes).
  for (const fileName of (manifest.relatedFiles ?? []).slice(0, MAX_INCLUDED_FILES)) {
    const content = await save(fileName);
    if (content !== undefined) pipFiles.push({ fileName, content });
  }
  if (!PIP_FORMAT_FILES.has(manifest.fileName) && !manifest.fileName.startsWith("requirements/")) return;

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
