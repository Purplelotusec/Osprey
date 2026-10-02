import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { parseTomlFile, readPyproject } from "./pyproject.js";
import { PypiComponentSet, directFromPyproject, isProjectItself } from "./pypi-components.js";
import type { PythonLockfileResult } from "./python.js";

const pylockSchema = z.object({
  "lock-version": z.string(),
  packages: z.array(z.object({
    name: z.string(),
    version: z.string().optional(),
    // Exactly one source per package; index releases have wheels/sdist from `index`.
    vcs: z.unknown().optional(),
    directory: z.unknown().optional(),
    archive: z.unknown().optional(),
  }).passthrough()).default([]),
}).passthrough();

const NON_INDEX_SOURCES = ["vcs", "directory", "archive"] as const;
/** PEP 751: `pylock.toml`, or named variants such as `pylock.dev.toml`. */
const PYLOCK_FILE = /^pylock\.(?:[^.]+\.)?toml$/;

/** Every PEP 751 lockfile in the directory, `pylock.toml` first. */
export function findPylockFiles(projectDir: string): string[] {
  if (!existsSync(projectDir)) return [];
  return readdirSync(projectDir)
    .filter((file) => PYLOCK_FILE.test(file))
    .sort((a, b) => (a === "pylock.toml" ? -1 : b === "pylock.toml" ? 1 : a.localeCompare(b)));
}

/**
 * Generates components from PEP 751 lockfiles (pylock.toml), the standard
 * format written by pip, uv, PDM and Pipenv. Named variants (pylock.dev.toml,
 * ...) lock other environments of the same project, so all of them are read
 * and merged: a vulnerability scan should cover everything that can be
 * installed. Lock versions other than 1.x are rejected, as the PEP requires.
 */
export function generateFromPylock(projectDir: string): PythonLockfileResult {
  const files = findPylockFiles(projectDir);
  if (files.length === 0) throw new Error(`No pylock.toml found in ${projectDir}`);

  const pyproject = readPyproject(projectDir);
  const set = new PypiComponentSet();
  const skipped: string[] = [];

  for (const file of files) {
    const path = join(projectDir, file);
    const parsed = pylockSchema.safeParse(parseTomlFile(path));
    if (!parsed.success) throw new Error(`${path} is not a valid PEP 751 lockfile: ${parsed.error.issues[0]?.message}`);
    if (parsed.data["lock-version"].split(".")[0] !== "1") {
      throw new Error(`${path} uses lock-version ${parsed.data["lock-version"]}; only 1.x is supported.`);
    }

    for (const pkg of parsed.data.packages) {
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
  }

  return { subjectName: pyproject?.name, subjectVersion: pyproject?.version, components: set.components, skipped };
}
