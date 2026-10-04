import { existsSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { z } from "zod";
import { buildPurl } from "../purl.js";
import { parseTomlFile } from "./pyproject.js";
import type { NormalizedComponent } from "../types.js";

/** Index URLs Cargo records for crates.io: the git index, and the sparse protocol (Cargo 1.68+). */
const CRATES_IO_SOURCES = new Set([
  "registry+https://github.com/rust-lang/crates.io-index",
  "sparse+https://index.crates.io/",
]);

// Cargo.lock lockfile versions 1–4 all list `[[package]]` tables of this shape.
const cargoLockSchema = z.object({
  package: z.array(z.object({
    name: z.string(),
    version: z.string(),
    // Absent for the workspace's own crates and path dependencies.
    source: z.string().optional(),
    // "name", "name version" or "name version (source)".
    dependencies: z.array(z.string()).optional(),
  })).default([]),
});

const cargoManifestSchema = z.object({
  package: z.object({ name: z.string().optional(), version: z.unknown().optional() }).optional(),
}).passthrough();

export interface CargoGenerationResult {
  subjectName: string;
  subjectVersion?: string;
  components: NormalizedComponent[];
  warnings: string[];
}

/**
 * Generates crates.io components from Cargo.lock. Crates without a source are
 * the workspace's own (or path dependencies) and aren't published releases; git
 * and alternate-registry crates aren't crates.io releases either, so they're
 * left out and listed in a warning. Direct dependencies are those the
 * workspace's own crates depend on.
 */
export function generateFromCargoLock(projectDir: string): CargoGenerationResult {
  const lockPath = join(projectDir, "Cargo.lock");
  if (!existsSync(lockPath)) throw new Error(`No Cargo.lock found in ${projectDir}`);
  const parsed = cargoLockSchema.safeParse(parseTomlFile(lockPath));
  if (!parsed.success) {
    throw new Error(`Cargo.lock in ${projectDir} did not match the expected format: ${parsed.error.issues[0]?.path.join(".")}: ${parsed.error.issues[0]?.message}`);
  }
  const packages = parsed.data.package;

  // What the workspace's own crates depend on, by name and by "name version".
  const direct = new Set<string>();
  for (const pkg of packages.filter((p) => p.source === undefined)) {
    for (const dependency of pkg.dependencies ?? []) {
      const [name, version] = dependency.split(" ");
      direct.add(version ? `${name} ${version}` : name);
    }
  }

  const components: NormalizedComponent[] = [];
  const skipped: string[] = [];
  const seen = new Set<string>();
  for (const pkg of packages) {
    if (pkg.source === undefined) continue;
    if (!CRATES_IO_SOURCES.has(pkg.source)) {
      skipped.push(`${pkg.name}@${pkg.version} (${pkg.source.startsWith("git+") ? "git source" : "alternate registry"})`);
      continue;
    }
    const key = `${pkg.name}@${pkg.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    components.push({
      purl: buildPurl({ type: "cargo", name: pkg.name, version: pkg.version }),
      ecosystem: "cargo",
      name: pkg.name,
      version: pkg.version,
      isDirect: direct.has(pkg.name) || direct.has(`${pkg.name} ${pkg.version}`),
    });
  }

  const warnings = skipped.length > 0
    ? [`Skipped ${skipped.length} Cargo.lock ${skipped.length === 1 ? "entry" : "entries"} not installed from crates.io: ${skipped.slice(0, 10).join(", ")}${skipped.length > 10 ? ", ..." : ""}`]
    : [];

  const manifest = readCargoManifest(projectDir);
  const subjectName = manifest?.package?.name ?? (basename(resolve(projectDir)) || "cargo-project");
  // `version.workspace = true` is a table, not a version.
  const subjectVersion = typeof manifest?.package?.version === "string" ? manifest.package.version : undefined;
  return { subjectName, subjectVersion, components, warnings };
}

/** Cargo.toml's [package] table, if the file exists and parses; it only labels the SBOM. */
function readCargoManifest(projectDir: string): z.infer<typeof cargoManifestSchema> | undefined {
  const path = join(projectDir, "Cargo.toml");
  if (!existsSync(path)) return undefined;
  try {
    const parsed = cargoManifestSchema.safeParse(parseTomlFile(path));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}
