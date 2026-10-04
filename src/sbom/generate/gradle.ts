import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { buildPurl } from "../purl.js";
import type { NormalizedComponent } from "../types.js";

export const GRADLE_SETTINGS_FILES = ["settings.gradle.kts", "settings.gradle"];
const LEGACY_LOCK_DIR = "gradle/dependency-locks";

/**
 * Module directories declared in settings.gradle(.kts): `include("app", "lib:core")`
 * or `include ':app', ':lib:core'`, as relative paths ("app", "lib/core").
 */
export function parseSettingsIncludes(settings: string): string[] {
  const modules = new Set<string>();
  for (const statement of settings.matchAll(/\binclude\b\s*\(?([^)\n]*)/g)) {
    for (const quoted of statement[1].matchAll(/["']([^"']+)["']/g)) {
      const path = quoted[1].replace(/^:/, "").replace(/:/g, "/");
      if (path) modules.add(path);
    }
  }
  return [...modules];
}

/** The project's name from `rootProject.name = "..."`, if set. */
export function parseRootProjectName(settings: string): string | undefined {
  return /rootProject\.name\s*=\s*["']([^"']+)["']/.exec(settings)?.[1];
}

function readSettings(projectDir: string): string | undefined {
  const file = GRADLE_SETTINGS_FILES.find((name) => existsSync(join(projectDir, name)));
  return file ? readFileSync(join(projectDir, file), "utf-8") : undefined;
}

/**
 * Every Gradle dependency-locking file in the project, as relative POSIX paths:
 * gradle.lockfile at the root and in each module listed in settings.gradle(.kts),
 * plus the pre-6.8 per-configuration files under gradle/dependency-locks/.
 */
export function findGradleLockfiles(projectDir: string): string[] {
  const modules = ["", ...parseSettingsIncludes(readSettings(projectDir) ?? "")];
  const found: string[] = [];
  for (const module of modules) {
    const prefix = module ? `${module}/` : "";
    if (existsSync(join(projectDir, `${prefix}gradle.lockfile`))) found.push(`${prefix}gradle.lockfile`);
    const legacyDir = join(projectDir, prefix, LEGACY_LOCK_DIR);
    if (existsSync(legacyDir) && statSync(legacyDir).isDirectory()) {
      for (const file of readdirSync(legacyDir).filter((name) => name.endsWith(".lockfile")).sort()) {
        found.push(`${prefix}${LEGACY_LOCK_DIR}/${file}`);
      }
    }
  }
  return found;
}

export interface GradleGenerationResult {
  subjectName: string;
  components: NormalizedComponent[];
  warnings: string[];
}

/**
 * Generates Maven components from Gradle lockfiles. Each line is
 * `group:artifact:version=configuration,...` (legacy files omit the
 * configurations); `empty=` lists configurations without dependencies. Lockfiles
 * don't say which dependencies were declared directly, so directness is unknown.
 */
export function generateFromGradleLockfiles(projectDir: string): GradleGenerationResult {
  const files = findGradleLockfiles(projectDir);
  if (files.length === 0) throw new Error(`No gradle.lockfile found in ${projectDir}`);

  const components: NormalizedComponent[] = [];
  const seen = new Set<string>();
  const malformed: string[] = [];

  for (const file of files) {
    for (const rawLine of readFileSync(join(projectDir, file), "utf-8").split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#") || line.startsWith("empty=")) continue;
      const coordinates = line.split("=")[0].split(":");
      if (coordinates.length !== 3 || coordinates.some((part) => !part)) {
        malformed.push(`${file}: ${line}`);
        continue;
      }
      const [group, artifact, version] = coordinates;
      const key = `${group}:${artifact}@${version}`;
      if (seen.has(key)) continue; // the same dependency appears in every module that uses it
      seen.add(key);
      components.push({
        purl: buildPurl({ type: "maven", namespace: group, name: artifact, version }),
        ecosystem: "maven",
        namespace: group,
        name: artifact,
        version,
      });
    }
  }

  const warnings = malformed.length > 0
    ? [`Skipped ${malformed.length} unrecognized Gradle lockfile line(s): ${malformed.slice(0, 5).join(", ")}${malformed.length > 5 ? ", ..." : ""}`]
    : [];
  const subjectName = parseRootProjectName(readSettings(projectDir) ?? "") ?? (basename(resolve(projectDir)) || "gradle-project");
  return { subjectName, components, warnings };
}
