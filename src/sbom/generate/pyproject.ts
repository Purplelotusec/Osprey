import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parse as parseToml } from "smol-toml";
import { z } from "zod";

/** PyPI names compare case-insensitively with runs of -, _ and . equivalent (PEP 503). */
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

export interface PyprojectInfo {
  name?: string;
  version?: string;
  /** PEP 503-normalized names of every dependency the project declares itself. */
  directDependencies: Set<string>;
}

const PEP508_NAME = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/;

const stringList = z.array(z.unknown()).transform((items) => items.filter((item): item is string => typeof item === "string"));
const poetryDependencyTable = z.record(z.unknown());

const pyprojectSchema = z.object({
  project: z.object({
    name: z.string().optional(),
    version: z.string().optional(),
    dependencies: stringList.optional(),
    "optional-dependencies": z.record(stringList).optional(),
  }).passthrough().optional(),
  // PEP 735; entries may also be { include-group = "..." } tables, which stringList drops.
  "dependency-groups": z.record(stringList).optional(),
  tool: z.object({
    poetry: z.object({
      name: z.string().optional(),
      version: z.string().optional(),
      dependencies: poetryDependencyTable.optional(),
      "dev-dependencies": poetryDependencyTable.optional(),
      group: z.record(z.object({ dependencies: poetryDependencyTable.optional() }).passthrough()).optional(),
    }).passthrough().optional(),
    // Pre-PEP 735 dev dependency tables, still common in PDM and older uv projects.
    pdm: z.object({ "dev-dependencies": z.record(stringList).optional() }).passthrough().optional(),
    uv: z.object({ "dev-dependencies": stringList.optional() }).passthrough().optional(),
    rye: z.object({ "dev-dependencies": stringList.optional() }).passthrough().optional(),
  }).passthrough().optional(),
}).passthrough();

/**
 * Reads the project's own name, version and declared dependencies from
 * pyproject.toml — covering PEP 621 ([project]), PEP 735 ([dependency-groups]),
 * Poetry's [tool.poetry] tables and the PDM/uv/Rye legacy dev-dependency tables. Used only to label the SBOM subject and to
 * mark components as direct; resolved versions always come from the lockfile.
 * Returns undefined when there is no pyproject.toml.
 */
export function readPyproject(projectDir: string): PyprojectInfo | undefined {
  const path = join(projectDir, "pyproject.toml");
  if (!existsSync(path)) return undefined;

  const parsed = pyprojectSchema.safeParse(parseTomlFile(path));
  if (!parsed.success) throw new Error(`${path} has an unexpected structure: ${parsed.error.issues[0]?.message}`);
  const { project, "dependency-groups": dependencyGroups, tool } = parsed.data;
  const poetry = tool?.poetry;

  const requirementStrings = [
    ...(project?.dependencies ?? []),
    ...Object.values(project?.["optional-dependencies"] ?? {}).flat(),
    ...Object.values(dependencyGroups ?? {}).flat(),
    ...Object.values(tool?.pdm?.["dev-dependencies"] ?? {}).flat(),
    ...(tool?.uv?.["dev-dependencies"] ?? []),
    ...(tool?.rye?.["dev-dependencies"] ?? []),
  ];
  const poetryNames = [
    ...Object.keys(poetry?.dependencies ?? {}),
    ...Object.keys(poetry?.["dev-dependencies"] ?? {}),
    ...Object.values(poetry?.group ?? {}).flatMap((group) => Object.keys(group.dependencies ?? {})),
  ].filter((name) => name.toLowerCase() !== "python"); // Poetry lists the interpreter constraint as a dependency

  const directDependencies = new Set<string>();
  for (const requirement of requirementStrings) {
    const name = requirement.match(PEP508_NAME)?.[1];
    if (name) directDependencies.add(normalizePypiName(name));
  }
  for (const name of poetryNames) directDependencies.add(normalizePypiName(name));

  return {
    name: project?.name ?? poetry?.name,
    version: project?.version ?? poetry?.version,
    directDependencies,
  };
}

export function parseTomlFile(path: string): unknown {
  try {
    return parseToml(readFileSync(path, "utf-8"));
  } catch (err) {
    throw new Error(`Could not parse ${path} as TOML: ${(err as Error).message}`);
  }
}
