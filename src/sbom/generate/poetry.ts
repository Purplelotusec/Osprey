import { existsSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { buildPurl } from "../purl.js";
import { normalizePypiName, parseTomlFile, readPyproject } from "./pyproject.js";
import type { NormalizedComponent } from "../types.js";
import type { PythonLockfileResult } from "./python.js";

const poetryLockSchema = z.object({
  package: z.array(z.object({
    name: z.string(),
    version: z.string(),
    // Absent for PyPI; "legacy" for an alternate package index; otherwise git/url/file/directory.
    source: z.object({ type: z.string() }).passthrough().optional(),
  }).passthrough()).default([]),
}).passthrough();

/** Source types that still resolve to a published package release on some index. */
const INDEX_SOURCES = new Set(["legacy"]);

/**
 * Generates components from a poetry.lock. The lockfile records every resolved
 * package but not which ones the project asked for, so direct dependencies are
 * read from pyproject.toml when present (otherwise left undetermined). As with
 * uv.lock, git/URL/local-path packages are skipped and reported rather than
 * labelled as PyPI releases they are not.
 */
export function generateFromPoetryLock(projectDir: string): PythonLockfileResult {
  const lockPath = join(projectDir, "poetry.lock");
  if (!existsSync(lockPath)) throw new Error(`No poetry.lock found at ${lockPath}`);

  const parsed = poetryLockSchema.safeParse(parseTomlFile(lockPath));
  if (!parsed.success) throw new Error(`${lockPath} is not a valid Poetry lockfile: ${parsed.error.issues[0]?.message}`);

  const pyproject = readPyproject(projectDir);
  const components: NormalizedComponent[] = [];
  const skipped: string[] = [];
  const seen = new Set<string>();

  for (const pkg of parsed.data.package) {
    const sourceType = pkg.source?.type;
    if (sourceType && !INDEX_SOURCES.has(sourceType)) {
      skipped.push(`${pkg.name} (${sourceType} source)`);
      continue;
    }

    const name = normalizePypiName(pkg.name);
    const key = `${name}@${pkg.version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    components.push({
      purl: buildPurl({ type: "pypi", name, version: pkg.version }),
      ecosystem: "pypi",
      name,
      version: pkg.version,
      isDirect: pyproject ? pyproject.directDependencies.has(name) : undefined,
    });
  }

  return {
    subjectName: pyproject?.name,
    subjectVersion: pyproject?.version,
    components,
    skipped,
  };
}
