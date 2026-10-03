import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { buildPurl } from "../purl.js";
import type { NormalizedComponent } from "../types.js";

export interface NuGetGenerationResult {
  subjectName: string;
  subjectVersion?: string;
  components: NormalizedComponent[];
  sourceFile: string;
}

/**
 * Generates SBOM from .NET project by parsing packages.lock.json (preferred) or *.csproj
 * packages.lock.json is generated with: dotnet restore --use-lock-file
 */
export function generateFromNuGetProject(projectDir: string): NuGetGenerationResult {
  // Try packages.lock.json first (most accurate)
  const lockPath = join(projectDir, "packages.lock.json");
  if (existsSync(lockPath)) {
    const lockContent = readFileSync(lockPath, "utf-8");
    const lock = JSON.parse(lockContent);

    const components: NormalizedComponent[] = [];

    // packages.lock.json structure: { "dependencies": { "targetFramework": { "packageName": { "resolved": "version", ... } } } }
    for (const targetFramework of Object.values(lock.dependencies ?? {})) {
      for (const [packageName, packageInfo] of Object.entries(targetFramework as Record<string, any>)) {
        const version = packageInfo.resolved;
        if (!version) continue;

        components.push({
          purl: buildPurl({ type: "nuget", name: packageName, version }),
          ecosystem: "nuget",
          name: packageName,
          version,
          isDirect: packageInfo.type === "Direct",
        });
      }
    }

    // Get project name from .csproj if available
    let subjectName = "unknown-dotnet-project";
    const csprojFiles = readdirSync(projectDir).filter(f => f.endsWith(".csproj"));
    if (csprojFiles.length > 0) {
      subjectName = csprojFiles[0].replace(".csproj", "");
    }

    return {
      subjectName,
      components,
      sourceFile: "packages.lock.json",
    };
  }

  // packages.lock.json not found
  const csprojFiles = readdirSync(projectDir).filter(f => f.endsWith(".csproj"));
  if (csprojFiles.length > 0) {
    throw new Error(`Found ${csprojFiles[0]} but no packages.lock.json. Please run 'dotnet restore --use-lock-file' to generate the lock file.`);
  }

  throw new Error(`No packages.lock.json or .csproj files found at ${projectDir}`);
}
