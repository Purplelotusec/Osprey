import { existsSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { parseTomlFile, readPyproject } from "./pyproject.js";
import { PypiComponentSet, directFromPyproject, isProjectItself } from "./pypi-components.js";
import type { PythonLockfileResult } from "./python.js";

const pdmLockSchema = z.object({
  package: z.array(z.object({
    name: z.string(),
    version: z.string().optional(),
    // Present instead of an index release for VCS, direct-URL and local-path packages.
    git: z.string().optional(),
    hg: z.string().optional(),
    svn: z.string().optional(),
    bzr: z.string().optional(),
    url: z.string().optional(),
    path: z.string().optional(),
  }).passthrough()).default([]),
}).passthrough();

const NON_INDEX_SOURCES = ["git", "hg", "svn", "bzr", "url", "path"] as const;

/**
 * Generates components from a pdm.lock (lock_version 4.x). PDM writes one
 * entry per requested extra (`httpx` and `httpx[socks]` at the same version),
 * which collapse to a single component. Direct dependencies come from
 * pyproject.toml; VCS, URL and local-path packages are skipped and reported.
 */
export function generateFromPdmLock(projectDir: string): PythonLockfileResult {
  const lockPath = join(projectDir, "pdm.lock");
  if (!existsSync(lockPath)) throw new Error(`No pdm.lock found at ${lockPath}`);

  const parsed = pdmLockSchema.safeParse(parseTomlFile(lockPath));
  if (!parsed.success) throw new Error(`${lockPath} is not a valid PDM lockfile: ${parsed.error.issues[0]?.message}`);

  const pyproject = readPyproject(projectDir);
  const set = new PypiComponentSet();
  const skipped: string[] = [];

  for (const pkg of parsed.data.package) {
    const source = NON_INDEX_SOURCES.find((key) => pkg[key] !== undefined);
    if (source) {
      if (!isProjectItself(pkg.name, pyproject)) skipped.push(`${pkg.name} (${source} source)`);
      continue;
    }
    if (!pkg.version) {
      skipped.push(`${pkg.name} (no resolved version)`);
      continue;
    }
    set.add(pkg.name, pkg.version, directFromPyproject(pyproject, pkg.name));
  }

  return { subjectName: pyproject?.name, subjectVersion: pyproject?.version, components: set.components, skipped };
}
