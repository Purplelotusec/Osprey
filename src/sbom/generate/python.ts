import { readFileSync, existsSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { buildPurl } from "../purl.js";
import { generateFromUvLock } from "./uv.js";
import { generateFromPoetryLock } from "./poetry.js";
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

/**
 * Python manifests in order of preference. Lockfiles come first: they pin every
 * package, transitive ones included, whereas requirements.txt is only as
 * complete as whoever wrote it.
 */
export const PYTHON_MANIFESTS = ["uv.lock", "poetry.lock", "requirements.txt"] as const;
export type PythonManifest = (typeof PYTHON_MANIFESTS)[number];

export function detectPythonManifest(projectDir: string): PythonManifest | undefined {
  return PYTHON_MANIFESTS.find((manifest) => existsSync(join(projectDir, manifest)));
}

export function generateFromPythonProject(projectDir: string): PythonProjectResult {
  const manifest = detectPythonManifest(projectDir);
  if (!manifest) {
    throw new Error(`No Python manifest found in ${projectDir} — looked for ${PYTHON_MANIFESTS.join(", ")}.`);
  }
  const fallbackName = basename(resolve(projectDir)) || "unknown-python-project";

  if (manifest === "requirements.txt") {
    const result = generateFromRequirementsTxt(projectDir);
    const warnings = result.skippedLines.length > 0
      ? [
          `Skipped ${result.skippedLines.length} requirements.txt line(s) without an exact pin (==): ` +
            result.skippedLines.slice(0, 5).join(", ") +
            (result.skippedLines.length > 5 ? ", ..." : ""),
        ]
      : [];
    return { manifest, subjectName: result.subjectName, components: result.components, warnings };
  }

  const result = manifest === "uv.lock" ? generateFromUvLock(projectDir) : generateFromPoetryLock(projectDir);
  const warnings = result.skipped.length > 0
    ? [
        `Skipped ${result.skipped.length} ${manifest} package(s) not installed from a package index: ` +
          result.skipped.slice(0, 5).join(", ") +
          (result.skipped.length > 5 ? ", ..." : ""),
      ]
    : [];
  return {
    manifest,
    subjectName: result.subjectName ?? fallbackName,
    subjectVersion: result.subjectVersion,
    components: result.components,
    warnings,
  };
}

export interface PythonGenerationResult {
  subjectName: string;
  components: NormalizedComponent[];
  /** Lines that couldn't be parsed as an exact pin — surfaced so the caller
   * can warn rather than silently produce an incomplete SBOM. */
  skippedLines: string[];
}

const PINNED_LINE = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;#]+)/;

/**
 * Parses a requirements.txt of EXACT pins only (`package==1.2.3`).
 * Deliberately does not attempt to resolve ranges (`>=`, `~=`), VCS
 * requirements, or `-r other.txt` includes — those don't have a single
 * resolved version to record, and guessing one would produce a
 * confidently wrong SBOM rather than an honestly incomplete one.
 * uv and Poetry projects are read from their lockfiles instead (uv.ts,
 * poetry.ts); Pipfile.lock is not yet supported.
 */
export function generateFromRequirementsTxt(projectDir: string): PythonGenerationResult {
  const reqPath = join(projectDir, "requirements.txt");
  if (!existsSync(reqPath)) {
    throw new Error(`No requirements.txt found at ${reqPath}`);
  }

  const lines = readFileSync(reqPath, "utf-8").split("\n");
  const components: NormalizedComponent[] = [];
  const skippedLines: string[] = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;

    const match = line.match(PINNED_LINE);
    if (!match) {
      skippedLines.push(rawLine);
      continue;
    }

    const [, name, version] = match;
    const normalizedName = name.toLowerCase().replace(/_/g, "-"); // PyPI normalization (PEP 503)

    components.push({
      purl: buildPurl({ type: "pypi", name: normalizedName, version }),
      ecosystem: "pypi",
      name: normalizedName,
      version,
      isDirect: true, // requirements.txt has no transitive/direct distinction without a lockfile
    });
  }

  return {
    subjectName: basename(resolve(projectDir)) || "unknown-python-project",
    components,
    skippedLines,
  };
}
