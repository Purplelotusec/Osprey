import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { generateFromNpmProject } from "./npm.js";
import { generateFromRequirementsTxt } from "./python.js";
import { generateFromMavenProject } from "./maven.js";
import { generateFromRustProject } from "./rust.js";
import { generateFromNuGetProject } from "./nuget.js";
import { generateFromRubyGemsProject } from "./rubygems.js";
import type { NormalizedComponent, NormalizedSbom } from "../types.js";

const TOOL_NAME = "osprey-sbom-gen";
const TOOL_VERSION = "0.1.0";

export interface GenerateOptions {
  projectDir: string;
  /** Force a specific generator instead of auto-detecting. */
  ecosystem?: "npm" | "python" | "maven" | "rust" | "nuget" | "rubygems";
}

export interface GenerateResult {
  sbom: NormalizedSbom;
  warnings: string[];
}

export async function generateSbom(opts: GenerateOptions): Promise<GenerateResult> {
  const ecosystem = opts.ecosystem ?? detectEcosystem(opts.projectDir);
  const warnings: string[] = [];

  let subjectName: string;
  let subjectVersion: string | undefined;
  let components: NormalizedComponent[];
  let sourceFile: string | undefined;

  if (ecosystem === "npm") {
    const result = generateFromNpmProject(opts.projectDir);
    subjectName = result.subjectName;
    subjectVersion = result.subjectVersion;
    components = result.components;
    sourceFile = result.sourceFile;
  } else if (ecosystem === "python") {
    const result = generateFromRequirementsTxt(opts.projectDir);
    subjectName = result.subjectName;
    components = result.components;
    sourceFile = "requirements.txt";
    if (result.skippedLines.length > 0) {
      warnings.push(
        `Skipped ${result.skippedLines.length} requirements.txt line(s) without an exact pin (==): ` +
          result.skippedLines.slice(0, 5).join(", ") +
          (result.skippedLines.length > 5 ? ", ..." : "")
      );
    }
  } else if (ecosystem === "maven") {
    const result = await generateFromMavenProject(opts.projectDir);
    subjectName = result.subjectName;
    subjectVersion = result.subjectVersion;
    components = result.components;
    sourceFile = result.sourceFile;
  } else if (ecosystem === "rust") {
    const result = generateFromRustProject(opts.projectDir);
    subjectName = result.subjectName;
    subjectVersion = result.subjectVersion;
    components = result.components;
    sourceFile = result.sourceFile;
  } else if (ecosystem === "nuget") {
    const result = generateFromNuGetProject(opts.projectDir);
    subjectName = result.subjectName;
    subjectVersion = result.subjectVersion;
    components = result.components;
    sourceFile = result.sourceFile;
  } else if (ecosystem === "rubygems") {
    const result = generateFromRubyGemsProject(opts.projectDir);
    subjectName = result.subjectName;
    subjectVersion = result.subjectVersion;
    components = result.components;
    sourceFile = result.sourceFile;
  } else {
    throw new Error(
      `Could not detect a supported project type in ${opts.projectDir}. ` +
      `Supported ecosystems: npm (package-lock.json), Python (requirements.txt), ` +
      `Maven (pom.xml), Rust (Cargo.lock), .NET (packages.lock.json), Ruby (Gemfile.lock). ` +
      `Pass --ecosystem to force one.`
    );
  }

  const sbom: NormalizedSbom = {
    format: "CYCLONEDX_JSON",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    createdAt: new Date().toISOString(),
    toolName: TOOL_NAME,
    toolVersion: TOOL_VERSION,
    subjectName,
    subjectVersion,
    components,
    sourceFile,
  };

  return { sbom, warnings };
}

function detectEcosystem(projectDir: string): "npm" | "python" | "maven" | "rust" | "nuget" | "rubygems" | null {
  // Order matters: prefer lock files over manifest files
  if (existsSync(join(projectDir, "package-lock.json"))) return "npm";
  if (existsSync(join(projectDir, "Cargo.lock"))) return "rust";
  if (existsSync(join(projectDir, "Gemfile.lock"))) return "rubygems";
  if (existsSync(join(projectDir, "packages.lock.json"))) return "nuget";
  if (existsSync(join(projectDir, "pom.xml"))) return "maven";
  if (existsSync(join(projectDir, "requirements.txt"))) return "python";

  // Fallback: check for .csproj files
  try {
    const files = readdirSync(projectDir);
    if (files.some(f => f.endsWith(".csproj"))) return "nuget";
  } catch {
    // Ignore errors
  }

  return null;
}

/**
 * Renders the normalized SBOM as a spec-shaped CycloneDX 1.5 JSON document
 * — this is what actually gets hashed, signed, and stored/uploaded.
 */
export function toCycloneDxJson(sbom: NormalizedSbom): string {
  const doc = {
    bomFormat: "CycloneDX",
    specVersion: sbom.specVersion,
    serialNumber: sbom.serialNumber,
    version: 1,
    metadata: {
      timestamp: sbom.createdAt,
      tools: [{ name: sbom.toolName, version: sbom.toolVersion }],
      component: {
        type: "application",
        name: sbom.subjectName,
        version: sbom.subjectVersion,
      },
    },
    components: sbom.components.map((c) => ({
      type: "library",
      name: c.name,
      version: c.version,
      purl: c.purl,
      cpe: c.cpe,
      group: c.namespace,
      publisher: c.vendor,
      scope: c.isDirect ? "required" : "optional",
    })),
  };
  // Canonical, stable key ordering matters for hashing/signing reproducibility —
  // JSON.stringify preserves insertion order for string keys, which is what we want here.
  return JSON.stringify(doc, null, 2);
}
