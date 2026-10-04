import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import semver from "semver";
import { buildPurl } from "../purl.js";
import { directDependencyNames, parseBunLock, parsePnpmLock, parseYarnLock } from "./js-lockfiles.js";
import type { NormalizedComponent } from "../types.js";

interface PackageLockV2V3 {
  name?: string;
  version?: string;
  lockfileVersion: number;
  packages?: Record<
    string,
    { version?: string; resolved?: string; dev?: boolean; optional?: boolean; peer?: boolean }
  >;
  dependencies?: Record<string, PackageLockV1Dep>;
}

interface PackageLockV1Dep {
  version: string;
  dev?: boolean;
  dependencies?: Record<string, PackageLockV1Dep>;
}

export interface NpmGenerationResult {
  subjectName: string;
  subjectVersion?: string;
  components: NormalizedComponent[];
  warnings: string[];
}

/**
 * JavaScript lockfiles in order of preference. npm-shrinkwrap.json comes first
 * because npm itself gives it precedence over package-lock.json (same format).
 */
export const NPM_LOCKFILES = ["npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"] as const;
export type NpmLockfile = (typeof NPM_LOCKFILES)[number];

export function findNpmLockfile(projectDir: string): NpmLockfile | undefined {
  return NPM_LOCKFILES.find((file) => existsSync(join(projectDir, file)));
}

const JS_LOCKFILE_PARSERS: Record<Exclude<NpmLockfile, "npm-shrinkwrap.json" | "package-lock.json">, typeof parsePnpmLock> = {
  "pnpm-lock.yaml": parsePnpmLock,
  "yarn.lock": parseYarnLock,
  "bun.lock": parseBunLock,
};

/**
 * Generates components for a JavaScript project from whichever lockfile it uses
 * (npm, pnpm, Yarn or Bun). Reads only what's resolved on disk — no install —
 * so it's safe to run in CI without network access. Without a lockfile it falls
 * back to package.json ranges, reported as lower bounds.
 */
export function generateFromNpmProject(projectDir: string): NpmGenerationResult {
  const pkgJsonPath = join(projectDir, "package.json");
  const pkgJson = existsSync(pkgJsonPath) ? JSON.parse(readFileSync(pkgJsonPath, "utf-8")) : undefined;
  const subject = { subjectName: pkgJson?.name ?? "unknown-npm-project", subjectVersion: pkgJson?.version };
  const lockfile = findNpmLockfile(projectDir);

  // The lockfile records what is actually installed; package.json only declares ranges.
  if (lockfile === "package-lock.json" || lockfile === "npm-shrinkwrap.json") {
    const lock: PackageLockV2V3 = JSON.parse(readFileSync(join(projectDir, lockfile), "utf-8"));
    const components = lock.lockfileVersion >= 2 && lock.packages ? parseV2V3(lock) : parseV1(lock);
    return { ...subject, components, warnings: [] };
  }
  if (lockfile) {
    const { components, skipped } = JS_LOCKFILE_PARSERS[lockfile](join(projectDir, lockfile), directDependencyNames(projectDir));
    const warnings = skipped.length > 0
      ? [
          `Skipped ${skipped.length} ${lockfile} entr${skipped.length === 1 ? "y" : "ies"} not installed from the npm registry: ` +
            skipped.slice(0, 5).join(", ") +
            (skipped.length > 5 ? ", ..." : ""),
        ]
      : [];
    return { ...subject, components, warnings };
  }

  if (!pkgJson) throw new Error(`No package.json or JavaScript lockfile found in ${projectDir}`);
  const { components, skipped } = parsePackageJson(pkgJson);
  const warnings = [
    "No package-lock.json: npm versions are the lowest each package.json range allows, not what is installed. Commit a lockfile for exact results.",
  ];
  if (skipped.length > 0) {
    warnings.push(
      `Skipped ${skipped.length} package.json dependenc${skipped.length === 1 ? "y" : "ies"} with no resolvable version: ` +
        skipped.slice(0, 5).join(", ") +
        (skipped.length > 5 ? ", ..." : "")
    );
  }
  return {
    subjectName: pkgJson.name ?? "unknown-npm-project",
    subjectVersion: pkgJson.version,
    components,
    warnings,
  };
}

function parseV2V3(lock: PackageLockV2V3): NormalizedComponent[] {
  const components: NormalizedComponent[] = [];
  for (const [pathKey, entry] of Object.entries(lock.packages ?? {})) {
    if (pathKey === "" || !entry.version) continue;

    const nameMatch = pathKey.match(/node_modules\/((?:@[^/]+\/)?[^/]+)$/);
    if (!nameMatch) continue;
    const fullName = nameMatch[1];
    const isScoped = fullName.startsWith("@");
    const [namespace, name] = isScoped
      ? [fullName.split("/")[0], fullName.split("/")[1]]
      : [undefined, fullName];

    const dedupeKey = `${fullName}@${entry.version}`;
    if (
      components.some(
        (c) => `${c.namespace ? c.namespace + "/" : ""}${c.name}@${c.version}` === dedupeKey
      )
    ) {
      continue;
    }

    // "Direct" heuristic: exactly one "node_modules/" segment in the path
    // means it's installed at the top level (a direct or hoisted dep),
    // not nested under another package's node_modules.
    const nodeModulesOccurrences = pathKey.split("node_modules/").length - 1;

    components.push({
      purl: buildPurl({ type: "npm", namespace, name, version: entry.version }),
      ecosystem: "npm",
      namespace,
      name,
      version: entry.version,
      isDirect: nodeModulesOccurrences === 1,
    });
  }
  return components;
}

function parseV1(lock: PackageLockV2V3): NormalizedComponent[] {
  const components: NormalizedComponent[] = [];
  const seen = new Set<string>();

  function walk(deps: Record<string, PackageLockV1Dep> | undefined, isDirect: boolean) {
    if (!deps) return;
    for (const [fullName, dep] of Object.entries(deps)) {
      const isScoped = fullName.startsWith("@");
      const [namespace, name] = isScoped
        ? [fullName.split("/")[0], fullName.split("/")[1]]
        : [undefined, fullName];

      const key = `${fullName}@${dep.version}`;
      if (!seen.has(key)) {
        seen.add(key);
        components.push({
          purl: buildPurl({ type: "npm", namespace, name, version: dep.version }),
          ecosystem: "npm",
          namespace,
          name,
          version: dep.version,
          isDirect,
        });
      }
      if (dep.dependencies) walk(dep.dependencies, false);
    }
  }

  walk(lock.dependencies, true);
  return components;
}

/**
 * Reads dependencies straight from package.json when there is no lockfile.
 * A range has no single installed version, so each component is recorded at
 * the lowest version its range allows (semver.minVersion: "^1.2.3" → 1.2.3,
 * ">=1.0 <2" → 1.0.0). That is a lower bound, not what is installed. Specs
 * with no meaningful lower bound — "*", "latest", git/file/workspace/alias
 * specs — are skipped and reported rather than guessed.
 */
export function parsePackageJson(pkgJson: {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}): { components: NormalizedComponent[]; skipped: string[] } {
  const components: NormalizedComponent[] = [];
  const skipped: string[] = [];
  const deps = { ...pkgJson.devDependencies, ...pkgJson.dependencies };

  for (const [fullName, spec] of Object.entries(deps)) {
    const isScoped = fullName.startsWith("@");
    const [namespace, name] = isScoped ? [fullName.split("/")[0], fullName.split("/")[1]] : [undefined, fullName];

    const version = lowestVersion(spec);
    if (!version) {
      skipped.push(`${fullName}@${spec}`);
      continue;
    }

    components.push({
      purl: buildPurl({ type: "npm", namespace, name, version }),
      ecosystem: "npm",
      namespace,
      name,
      version,
      isDirect: true,
    });
  }

  return { components, skipped };
}

function lowestVersion(spec: string): string | undefined {
  if (typeof spec !== "string" || semver.validRange(spec) === null) return undefined; // git+, file:, workspace:, npm: aliases, tags
  const min = semver.minVersion(spec);
  // "*", "x", ">=0" bottom out at 0.0.0: no information about what is installed.
  return min && min.version !== "0.0.0" ? min.version : undefined;
}
