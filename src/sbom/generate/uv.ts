import { existsSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { buildPurl } from "../purl.js";
import { normalizePypiName, parseTomlFile, readPyproject } from "./pyproject.js";
import type { NormalizedComponent } from "../types.js";
import type { PythonLockfileResult } from "./python.js";

const dependencyList = z.array(z.object({ name: z.string() }).passthrough());

const uvLockSchema = z.object({
  version: z.number().optional(),
  package: z.array(z.object({
    name: z.string(),
    version: z.string().optional(),
    // Exactly one key naming where the package came from, e.g. { registry = "https://pypi.org/simple" }.
    source: z.record(z.unknown()).optional(),
    dependencies: dependencyList.optional(),
    "optional-dependencies": z.record(dependencyList).optional(),
    "dev-dependencies": z.record(dependencyList).optional(),
  }).passthrough()).default([]),
}).passthrough();

/** Workspace members — the project(s) being locked, not dependencies of it. */
const PROJECT_SOURCES = new Set(["editable", "virtual"]);

/**
 * Generates components from a uv.lock. Every registry package is recorded at
 * its exact resolved version, transitive dependencies included. Packages from
 * git, URL or local-path sources are skipped and reported: they are not the
 * PyPI release a pkg:pypi PURL would claim, so OSV results for that name would
 * describe different code.
 */
export function generateFromUvLock(projectDir: string): PythonLockfileResult {
  const lockPath = join(projectDir, "uv.lock");
  if (!existsSync(lockPath)) throw new Error(`No uv.lock found at ${lockPath}`);

  const parsed = uvLockSchema.safeParse(parseTomlFile(lockPath));
  if (!parsed.success) throw new Error(`${lockPath} is not a valid uv lockfile: ${parsed.error.issues[0]?.message}`);
  const packages = parsed.data.package;

  const sourceKind = (pkg: (typeof packages)[number]) => Object.keys(pkg.source ?? {})[0] ?? "registry";
  const projects = packages.filter((pkg) => PROJECT_SOURCES.has(sourceKind(pkg)));
  const projectNames = new Set(projects.map((pkg) => normalizePypiName(pkg.name)));

  // Direct = anything a workspace member depends on in any group or extra.
  const direct = new Set<string>();
  for (const project of projects) {
    const lists = [
      project.dependencies ?? [],
      ...Object.values(project["optional-dependencies"] ?? {}),
      ...Object.values(project["dev-dependencies"] ?? {}),
    ];
    for (const dep of lists.flat()) direct.add(normalizePypiName(dep.name));
  }

  const components: NormalizedComponent[] = [];
  const skipped: string[] = [];
  const seen = new Set<string>();

  for (const pkg of packages) {
    const name = normalizePypiName(pkg.name);
    if (projectNames.has(name)) continue;

    const kind = sourceKind(pkg);
    if (kind !== "registry" || !pkg.version) {
      skipped.push(`${pkg.name} (${pkg.version ? `${kind} source` : "no resolved version"})`);
      continue;
    }

    // uv may lock several versions of one package for different environment markers.
    const key = `${name}@${pkg.version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    components.push({
      purl: buildPurl({ type: "pypi", name, version: pkg.version }),
      ecosystem: "pypi",
      name,
      version: pkg.version,
      isDirect: projects.length > 0 ? direct.has(name) : undefined,
    });
  }

  const pyproject = readPyproject(projectDir);
  return {
    subjectName: projects[0]?.name ?? pyproject?.name,
    subjectVersion: projects[0]?.version ?? pyproject?.version,
    components,
    skipped,
  };
}
