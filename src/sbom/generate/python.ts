import { existsSync, readdirSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { generateFromUvLock } from "./uv.js";
import { generateFromPoetryLock } from "./poetry.js";
import { generateFromPdmLock } from "./pdm.js";
import { findPylockFiles, generateFromPylock } from "./pylock.js";
import { generateFromPipfileLock } from "./pipfile.js";
import { generateFromRequirementsFiles, parseRequirementsFile } from "./requirements.js";
import { PypiComponentSet } from "./pypi-components.js";
import type { NormalizedComponent } from "../types.js";

/** What a lockfile parser returns; the subject falls back to the directory name. */
export interface PythonLockfileResult {
  subjectName?: string;
  subjectVersion?: string;
  components: NormalizedComponent[];
  /** Packages left out of the SBOM, each with the reason, so the caller can warn. */
  skipped: string[];
}

export interface PythonProjectResult {
  manifest: PythonManifest;
  subjectName: string;
  subjectVersion?: string;
  components: NormalizedComponent[];
  warnings: string[];
}

interface ManifestHandler {
  /** True when this manifest is present in the project directory. */
  detect: (projectDir: string) => boolean;
  generate: (projectDir: string) => PythonLockfileResult;
}

const fileExists = (fileName: string) => (projectDir: string) => existsSync(join(projectDir, fileName));
const RYE_LOCKS = ["requirements.lock", "requirements-dev.lock"];

/**
 * Python manifests in order of preference. Tool-native lockfiles come first —
 * they pin every package, transitive ones included, and are what the project
 * actually installs from; requirements.txt is only as complete as whoever (or
 * whatever) wrote it, so it is the last resort.
 */
const MANIFESTS = {
  "uv.lock": { detect: fileExists("uv.lock"), generate: generateFromUvLock },
  "poetry.lock": { detect: fileExists("poetry.lock"), generate: generateFromPoetryLock },
  "pdm.lock": { detect: fileExists("pdm.lock"), generate: generateFromPdmLock },
  "pylock.toml": { detect: (dir) => findPylockFiles(dir).length > 0, generate: generateFromPylock },
  "Pipfile.lock": { detect: fileExists("Pipfile.lock"), generate: generateFromPipfileLock },
  // Rye: requirements.lock (runtime) plus requirements-dev.lock (dev), read together.
  "requirements.lock": {
    detect: (dir) => RYE_LOCKS.some((file) => existsSync(join(dir, file))),
    generate: (dir) => generateFromRequirementsFiles(dir, RYE_LOCKS),
  },
  "requirements.txt": {
    detect: fileExists("requirements.txt"),
    generate: (dir) => generateFromRequirementsFiles(dir, ["requirements.txt"]),
  },
  // The requirements/ convention (base.txt, prod.txt, dev.txt, ...), read together.
  "requirements/": {
    detect: (dir) => requirementsDirFiles(dir).length > 0,
    generate: (dir) => generateFromRequirementsFiles(dir, requirementsDirFiles(dir)),
  },
} satisfies Record<string, ManifestHandler>;

/**
 * Pinned requirement files under requirements/, as "requirements/<name>.txt".
 * Only *.txt: the *.in files next to them are pip-compile inputs (ranges), not pins.
 */
export function requirementsDirFiles(projectDir: string): string[] {
  const dir = join(projectDir, "requirements");
  if (!existsSync(dir) || !statSync(dir).isDirectory()) return [];
  return readdirSync(dir)
    .filter((file) => file.endsWith(".txt") && statSync(join(dir, file)).isFile())
    .sort()
    .map((file) => `requirements/${file}`);
}

export type PythonManifest = keyof typeof MANIFESTS;
export const PYTHON_MANIFESTS = Object.keys(MANIFESTS) as PythonManifest[];

export function detectPythonManifest(projectDir: string): PythonManifest | undefined {
  return PYTHON_MANIFESTS.find((manifest) => MANIFESTS[manifest].detect(projectDir));
}

/**
 * The file a Python audit primarily reads, as it exists on disk — which can
 * differ from the manifest kind (a named pylock.dev.toml, or Rye's
 * requirements-dev.lock on its own). Used to point reports at a real file.
 */
export function pythonManifestFile(projectDir: string): string | undefined {
  const manifest = detectPythonManifest(projectDir);
  if (manifest === "pylock.toml") return findPylockFiles(projectDir)[0];
  if (manifest === "requirements.lock") return RYE_LOCKS.find((file) => existsSync(join(projectDir, file)));
  if (manifest === "requirements/") return requirementsDirFiles(projectDir)[0];
  return manifest;
}

export function generateFromPythonProject(projectDir: string): PythonProjectResult {
  const manifest = detectPythonManifest(projectDir);
  if (!manifest) {
    throw new Error(`No Python manifest found in ${projectDir} — looked for ${PYTHON_MANIFESTS.join(", ")}.`);
  }

  const result = MANIFESTS[manifest].generate(projectDir);
  const warnings = result.skipped.length > 0
    ? [
        `Skipped ${result.skipped.length} ${manifest} entr${result.skipped.length === 1 ? "y" : "ies"} that could not be recorded as an exact package-index release: ` +
          result.skipped.slice(0, 5).join(", ") +
          (result.skipped.length > 5 ? ", ..." : ""),
      ]
    : [];

  return {
    manifest,
    subjectName: result.subjectName ?? (basename(resolve(projectDir)) || "unknown-python-project"),
    subjectVersion: result.subjectVersion,
    components: result.components,
    warnings,
  };
}

export interface PythonGenerationResult {
  subjectName: string;
  components: NormalizedComponent[];
  /** Lines that couldn't be recorded at an exact pin, each with the reason —
   * surfaced so the caller can warn rather than silently produce an incomplete SBOM. */
  skippedLines: string[];
}

/**
 * Parses a project's requirements.txt (see requirements.ts for the accepted
 * syntax). Every pin is reported as direct: on its own, a requirements file
 * has no direct/transitive distinction.
 */
export function generateFromRequirementsTxt(projectDir: string): PythonGenerationResult {
  const reqPath = join(projectDir, "requirements.txt");
  if (!existsSync(reqPath)) {
    throw new Error(`No requirements.txt found at ${reqPath}`);
  }

  const parsed = parseRequirementsFile(reqPath);
  const set = new PypiComponentSet();
  for (const entry of parsed.entries) set.add(entry.name, entry.version, true);

  return {
    subjectName: basename(resolve(projectDir)) || "unknown-python-project",
    components: set.components,
    skippedLines: parsed.skipped,
  };
}
