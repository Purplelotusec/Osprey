import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { buildPurl } from "../purl.js";
import type { NormalizedComponent } from "../types.js";

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
 * For projects using Poetry/Pipenv, generate from their lockfile instead
 * (poetry.lock / Pipfile.lock) — not yet implemented here.
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
    subjectName: projectDir.split("/").filter(Boolean).pop() ?? "unknown-python-project",
    components,
    skippedLines,
  };
}
