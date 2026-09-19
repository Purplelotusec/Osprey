import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { buildPurl } from "../purl.js";
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
}

/**
 * Generates a component list from a project directory containing
 * package.json + package-lock.json. Does not run `npm install` — reads
 * only what's already resolved on disk, so it's safe to run in CI without
 * network access or a fresh install step.
 *
 * If package-lock.json is not found, falls back to package.json dependencies
 * (less precise - uses version ranges instead of exact versions).
 */
export function generateFromNpmProject(projectDir: string): NpmGenerationResult {
  const pkgJsonPath = join(projectDir, "package.json");
  const lockPath = join(projectDir, "package-lock.json");

  if (!existsSync(pkgJsonPath)) {
    throw new Error(`No package.json found at ${pkgJsonPath}`);
  }
  const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf-8"));

  // Try to use lock file first (precise versions)
  if (existsSync(lockPath)) {
    const lock: PackageLockV2V3 = JSON.parse(readFileSync(lockPath, "utf-8"));
    const components: NormalizedComponent[] =
      lock.lockfileVersion >= 2 && lock.packages ? parseV2V3(lock) : parseV1(lock);

    return {
      subjectName: pkgJson.name ?? "unknown-npm-project",
      subjectVersion: pkgJson.version,
      components,
    };
  }

  // Fallback to package.json (version ranges - less precise)
  const components = parsePackageJson(pkgJson);
  return {
    subjectName: pkgJson.name ?? "unknown-npm-project",
    subjectVersion: pkgJson.version,
    components,
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
 * Parse dependencies directly from package.json (when no lock file exists).
 * Note: This uses version ranges (^1.0.0) instead of exact versions (1.0.5),
 * so version status checks may be less accurate.
 */
function parsePackageJson(pkgJson: any): NormalizedComponent[] {
  const components: NormalizedComponent[] = [];
  const deps = {
    ...pkgJson.dependencies,
    ...pkgJson.devDependencies,
  };

  for (const [fullName, versionRange] of Object.entries(deps) as [string, string][]) {
    const isScoped = fullName.startsWith("@");
    const [namespace, name] = isScoped
      ? [fullName.split("/")[0], fullName.split("/")[1]]
      : [undefined, fullName];

    // Clean version range: ^1.0.0 → 1.0.0, ~2.3.4 → 2.3.4
    // Note: This is imprecise! We're taking the base version from the range
    const version = versionRange.replace(/^[\^~>=<]/, "").split(" ")[0];

    components.push({
      purl: buildPurl({ type: "npm", namespace, name, version }),
      ecosystem: "npm",
      namespace,
      name,
      version,
      isDirect: true,
    });
  }

  return components;
}
