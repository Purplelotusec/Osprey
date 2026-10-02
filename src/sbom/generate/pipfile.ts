import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { normalizePypiName, parseTomlFile } from "./pyproject.js";
import { PypiComponentSet } from "./pypi-components.js";
import type { PythonLockfileResult } from "./python.js";

const lockedPackage = z.object({
  version: z.string().optional(),
  git: z.string().optional(),
  hg: z.string().optional(),
  svn: z.string().optional(),
  bzr: z.string().optional(),
  file: z.string().optional(),
  path: z.string().optional(),
}).passthrough();

const pipfileLockSchema = z.object({
  default: z.record(lockedPackage).default({}),
  develop: z.record(lockedPackage).default({}),
}).passthrough();

const pipfileSchema = z.object({
  packages: z.record(z.unknown()).optional(),
  "dev-packages": z.record(z.unknown()).optional(),
}).passthrough();

const NON_INDEX_SOURCES = ["git", "hg", "svn", "bzr", "file", "path"] as const;
/** Pipfile.lock records index releases as exact pins: "==1.2.3" (or "===1.2.3"). */
const EXACT_PIN = /^===?\s*([^\s,;*]+)$/;

/**
 * Generates components from a Pipfile.lock, covering both the "default" and
 * "develop" sections. Direct dependencies are the ones named in the Pipfile;
 * without a Pipfile they are left undetermined. VCS, file and local-path
 * packages are skipped and reported (a `path = "."` entry is the project itself).
 */
export function generateFromPipfileLock(projectDir: string): PythonLockfileResult {
  const lockPath = join(projectDir, "Pipfile.lock");
  if (!existsSync(lockPath)) throw new Error(`No Pipfile.lock found at ${lockPath}`);

  let json: unknown;
  try {
    json = JSON.parse(readFileSync(lockPath, "utf-8"));
  } catch (err) {
    throw new Error(`Could not parse ${lockPath} as JSON: ${(err as Error).message}`);
  }
  const parsed = pipfileLockSchema.safeParse(json);
  if (!parsed.success) throw new Error(`${lockPath} is not a valid Pipfile.lock: ${parsed.error.issues[0]?.message}`);

  const direct = readPipfileDirectDependencies(projectDir);
  const set = new PypiComponentSet();
  const skipped: string[] = [];

  for (const [name, pkg] of [...Object.entries(parsed.data.default), ...Object.entries(parsed.data.develop)]) {
    const source = NON_INDEX_SOURCES.find((key) => pkg[key] !== undefined);
    if (source) {
      if (!(source === "path" && pkg.path === ".")) skipped.push(`${name} (${source} source)`);
      continue;
    }
    const version = pkg.version?.match(EXACT_PIN)?.[1];
    if (!version) {
      skipped.push(`${name} (${pkg.version ? `non-exact version ${pkg.version}` : "no resolved version"})`);
      continue;
    }
    set.add(name, version, direct ? direct.has(normalizePypiName(name)) : undefined);
  }

  return { components: set.components, skipped };
}

function readPipfileDirectDependencies(projectDir: string): Set<string> | undefined {
  const path = join(projectDir, "Pipfile");
  if (!existsSync(path)) return undefined;
  const parsed = pipfileSchema.safeParse(parseTomlFile(path));
  if (!parsed.success) throw new Error(`${path} has an unexpected structure: ${parsed.error.issues[0]?.message}`);
  const names = [...Object.keys(parsed.data.packages ?? {}), ...Object.keys(parsed.data["dev-packages"] ?? {})];
  return new Set(names.map(normalizePypiName));
}
