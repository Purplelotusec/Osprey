import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { buildPurl } from "../purl.js";
import type { NormalizedComponent } from "../types.js";
import TOML from "@iarna/toml";

export interface RustGenerationResult {
  subjectName: string;
  subjectVersion?: string;
  components: NormalizedComponent[];
  sourceFile: string;
}

interface CargoLock {
  package?: Array<{
    name: string;
    version: string;
    source?: string;
  }>;
}

interface CargoToml {
  package?: {
    name?: string;
    version?: string;
  };
}

/**
 * Generates SBOM from Rust project by parsing Cargo.lock (preferred) or Cargo.toml
 */
export function generateFromRustProject(projectDir: string): RustGenerationResult {
  const lockPath = join(projectDir, "Cargo.lock");
  const tomlPath = join(projectDir, "Cargo.toml");

  // Try Cargo.lock first (has exact versions)
  if (existsSync(lockPath)) {
    const lockContent = readFileSync(lockPath, "utf-8");
    const lock = TOML.parse(lockContent) as CargoLock;

    const components: NormalizedComponent[] = [];

    for (const pkg of lock.package ?? []) {
      // Skip local packages (no source field means it's the current crate or path dependency)
      if (!pkg.source || pkg.source.startsWith("git+")) continue;

      components.push({
        purl: buildPurl({ type: "cargo", name: pkg.name, version: pkg.version }),
        ecosystem: "cargo",
        name: pkg.name,
        version: pkg.version,
        isDirect: false, // Cargo.lock doesn't distinguish direct vs transitive easily
      });
    }

    // Get project name and version from Cargo.toml if available
    let subjectName = "unknown-rust-project";
    let subjectVersion: string | undefined;

    if (existsSync(tomlPath)) {
      const tomlContent = readFileSync(tomlPath, "utf-8");
      const toml = TOML.parse(tomlContent) as CargoToml;
      subjectName = toml.package?.name ?? subjectName;
      subjectVersion = toml.package?.version;
    }

    return {
      subjectName,
      subjectVersion,
      components,
      sourceFile: "Cargo.lock",
    };
  }

  // Fallback to Cargo.toml (less precise - has version requirements, not exact versions)
  if (existsSync(tomlPath)) {
    throw new Error("Cargo.toml found but Cargo.lock is missing. Please run 'cargo build' to generate Cargo.lock first.");
  }

  throw new Error(`No Cargo.lock or Cargo.toml found at ${projectDir}`);
}
