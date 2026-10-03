import { existsSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { generateFromNpmProject } from "./npm.js";
import { detectPythonManifest, generateFromPythonProject, PYTHON_MANIFESTS, pythonManifestFile } from "./python.js";
import type { NormalizedComponent, NormalizedSbom } from "../types.js";

const TOOL_NAME = "osprey-sbom-gen";
const TOOL_VERSION = "0.1.0";

export const ECOSYSTEMS = ["npm", "python"] as const;
export type Ecosystem = (typeof ECOSYSTEMS)[number];

export interface GenerateOptions {
  projectDir: string;
  /** Generate only this ecosystem instead of every one detected. */
  ecosystem?: Ecosystem;
  /** Generate exactly these ecosystems (used when the caller already knows what it fetched). */
  ecosystems?: Ecosystem[];
}

export interface GenerateResult {
  sbom: NormalizedSbom;
  warnings: string[];
  /** The ecosystems whose dependencies are in the SBOM, in generation order. */
  ecosystems: Ecosystem[];
}

interface EcosystemResult {
  subjectName: string;
  subjectVersion?: string;
  components: NormalizedComponent[];
  warnings: string[];
}

const GENERATORS: Record<Ecosystem, (projectDir: string) => EcosystemResult> = {
  npm: generateFromNpmProject,
  python: generateFromPythonProject,
};

/**
 * Generates one SBOM covering every ecosystem in the project. Repositories
 * commonly mix them (a Django or Flask backend with an npm-built frontend), and
 * auditing only one would leave the other's dependencies silently unchecked.
 * Components keep their own ecosystem (PURL type), so the merged list never
 * conflates an npm package with a same-named PyPI one.
 */
export function generateSbom(opts: GenerateOptions): GenerateResult {
  if (opts.ecosystem !== undefined && !ECOSYSTEMS.includes(opts.ecosystem)) {
    throw new Error(`Unsupported ecosystem "${opts.ecosystem}" — expected one of: ${ECOSYSTEMS.join(", ")}.`);
  }
  const autoDetected = opts.ecosystems === undefined && opts.ecosystem === undefined;
  const ecosystems = opts.ecosystems ?? (opts.ecosystem ? [opts.ecosystem] : detectEcosystems(opts.projectDir));
  const unlockedPackageJson = existsSync(join(opts.projectDir, "package.json")) && !existsSync(join(opts.projectDir, "package-lock.json"));
  if (ecosystems.length === 0) {
    throw new Error(
      unlockedPackageJson
        ? `Found package.json but no package-lock.json in ${opts.projectDir}, so there are no exact npm versions to audit. Create a lockfile (npm install --package-lock-only) and commit it, or use cra-sbom --ecosystem npm to audit the package.json ranges as lower bounds.`
        : `Could not detect a supported project type in ${opts.projectDir} — looked for package-lock.json (npm) and ${PYTHON_MANIFESTS.join(", ")} (Python). Pass --ecosystem to force one, or generate the SBOM from another tool and use the ingestion path instead.`
    );
  }

  const results = ecosystems.map((ecosystem) => GENERATORS[ecosystem](opts.projectDir));
  const warnings = results.flatMap((result) => result.warnings);
  // A frontend without a lockfile next to a Python backend must not be skipped silently.
  if (autoDetected && !ecosystems.includes("npm") && unlockedPackageJson) {
    warnings.push(unauditedPackageJsonWarning(UNSUPPORTED_JS_LOCKFILES.find((file) => existsSync(join(opts.projectDir, file)))));
  }
  // The subject is the first ecosystem's project, in ECOSYSTEMS order, so it is stable.
  const [primary] = results;

  const sbom: NormalizedSbom = {
    format: "CYCLONEDX_JSON",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    createdAt: new Date().toISOString(),
    toolName: TOOL_NAME,
    toolVersion: TOOL_VERSION,
    subjectName: primary.subjectName,
    subjectVersion: primary.subjectVersion,
    components: results.flatMap((result) => result.components),
  };

  return { sbom, warnings, ecosystems };
}

export const UNLOCKED_PACKAGE_JSON_WARNING =
  "Found package.json without package-lock.json: its npm dependencies were NOT audited. Commit a lockfile (npm install --package-lock-only) to include them.";

/** Lockfiles of other JavaScript package managers, which Osprey doesn't read yet. */
export const UNSUPPORTED_JS_LOCKFILES = ["pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"];

/** The warning for a package.json Osprey isn't auditing, naming the lockfile actually in use if there is one. */
export function unauditedPackageJsonWarning(otherLockfile: string | undefined): string {
  return otherLockfile
    ? `Found package.json locked by ${otherLockfile}, which Osprey can't read yet: its JavaScript dependencies were NOT audited.`
    : UNLOCKED_PACKAGE_JSON_WARNING;
}

/**
 * The dependency file each ecosystem's components come from, keyed by PURL
 * type ("npm", "pypi"), as paths relative to projectDir. Lets reports attach a
 * finding to the file a developer would edit.
 */
export function detectManifestFiles(projectDir: string): Partial<Record<"npm" | "pypi" | "maven", string>> {
  const files: Partial<Record<"npm" | "pypi" | "maven", string>> = {};
  const firstExisting = (candidates: string[]) => candidates.find((file) => existsSync(join(projectDir, file)));
  const npmFile = firstExisting(["package-lock.json", "package.json"]);
  if (npmFile) files.npm = npmFile;
  const pythonFile = pythonManifestFile(projectDir);
  if (pythonFile) files.pypi = pythonFile;
  // JVM components come from a build-generated SBOM; point findings at the build file.
  const jvmFile = firstExisting(["pom.xml", "gradle.lockfile", "build.gradle.kts", "build.gradle"]);
  if (jvmFile) files.maven = jvmFile;
  return files;
}

/** Every ecosystem with a supported manifest in the directory, in ECOSYSTEMS order. */
export function detectEcosystems(projectDir: string): Ecosystem[] {
  const present: Record<Ecosystem, boolean> = {
    npm: existsSync(join(projectDir, "package-lock.json")),
    python: detectPythonManifest(projectDir) !== undefined,
  };
  return ECOSYSTEMS.filter((ecosystem) => present[ecosystem]);
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
  // The signature covers these exact bytes, so key order must be deterministic:
  // JSON.stringify keeps insertion order for string keys, i.e. the order written above.
  return JSON.stringify(doc, null, 2);
}
