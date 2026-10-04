import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { readPyproject } from "./pyproject.js";
import { PypiComponentSet, directFromPyproject } from "./pypi-components.js";
import type { PythonLockfileResult } from "./python.js";

/** `name[extras] == version` or `===`, optionally followed by `; markers`. */
const PINNED_REQUIREMENT = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;,*]+)\s*(?:;.*)?$/;
const INCLUDE_OPTION = /^(?:-r|--requirement)(?:\s*=\s*|\s+|(?=\S))(.+)$/;
const EDITABLE_OPTION = /^(?:-e|--editable)(?:\s*=\s*|\s+)(.+)$/;
/** Per-requirement options pip allows after a requirement, e.g. pip-compile's --hash=sha256:… */
const TRAILING_OPTIONS = /\s+--[a-z][a-z-]*(?:=\S+)?/g;
const URL_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
/** Editable installs of the working tree itself (`-e .`, Rye's `-e file:.`). */
const SELF_EDITABLE = /^(?:file:)?\.\/?$/;

export interface RequirementsParseResult {
  entries: Array<{ name: string; version: string }>;
  /** Lines that could not be recorded at an exact version, each with the reason. */
  skipped: string[];
}

/**
 * Parses pip requirements syntax — hand-written requirements.txt, pip-compile /
 * `uv export` / `pip freeze` output, and Rye's requirements*.lock. Only exact
 * pins (`==`, `===`) are recorded: ranges have no single resolved version and a
 * guessed one would make the SBOM confidently wrong rather than honestly
 * incomplete. `-r` includes are followed (relative to the including file, with
 * cycle protection); `-c` constraint files are not, since constraints restrict
 * versions but install nothing.
 */
export function parseRequirementsFile(path: string, visited = new Set<string>()): RequirementsParseResult {
  const result: RequirementsParseResult = { entries: [], skipped: [] };
  const absolute = resolve(path);
  if (visited.has(absolute)) return result;
  visited.add(absolute);

  for (const line of logicalLines(readFileSync(absolute, "utf-8"))) {
    const include = line.match(INCLUDE_OPTION);
    if (include) {
      if (URL_SCHEME.test(include[1].trim())) {
        // pip can fetch includes over HTTP; an SBOM generator should not fetch arbitrary URLs.
        result.skipped.push(`${line} (remote include not followed)`);
        continue;
      }
      const target = resolve(dirname(absolute), include[1].trim());
      if (!existsSync(target)) {
        result.skipped.push(`${line} (included file not found)`);
        continue;
      }
      const nested = parseRequirementsFile(target, visited);
      result.entries.push(...nested.entries);
      result.skipped.push(...nested.skipped);
      continue;
    }

    const editable = line.match(EDITABLE_OPTION);
    if (editable) {
      if (!SELF_EDITABLE.test(editable[1].trim())) result.skipped.push(`${line} (editable install)`);
      continue;
    }
    if (line.startsWith("-")) continue; // global options: -c, -i/--index-url, --extra-index-url, -f, --pre, ...

    const requirement = line.replace(TRAILING_OPTIONS, "").trim();
    const pin = requirement.match(PINNED_REQUIREMENT);
    if (pin) {
      result.entries.push({ name: pin[1], version: pin[2] });
    } else {
      // "name @ https://…" and a bare archive URL both install from a URL, not an index.
      const isUrl = requirement.includes(" @ ") || URL_SCHEME.test(requirement);
      result.skipped.push(`${requirement} (${isUrl ? "direct URL reference" : "no exact == pin"})`);
    }
  }
  return result;
}

/** Joins `\` continuations and strips comments (a `#` at line start or after whitespace). */
function logicalLines(content: string): string[] {
  const lines: string[] = [];
  let pending = "";
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.replace(/(^|\s)#.*$/, "");
    if (/\\\s*$/.test(line)) {
      pending += line.replace(/\\\s*$/, " ");
      continue;
    }
    const logical = (pending + line).trim();
    pending = "";
    if (logical) lines.push(logical);
  }
  if (pending.trim()) lines.push(pending.trim());
  return lines;
}

/** Relative paths of the files a requirements file includes with -r (used to fetch them remotely). */
export function findRequirementIncludes(content: string): string[] {
  return logicalLines(content).flatMap((line) => {
    const include = line.match(INCLUDE_OPTION);
    return include ? [include[1].trim()] : [];
  });
}

/**
 * Builds components from one or more pip-format files. Directness comes from
 * pyproject.toml when it declares dependencies; otherwise every pin is treated
 * as direct, which matches a hand-written requirements.txt.
 */
export function generateFromRequirementsFiles(projectDir: string, fileNames: string[]): PythonLockfileResult {
  const pyproject = readPyproject(projectDir);
  const set = new PypiComponentSet();
  const skipped: string[] = [];
  const visited = new Set<string>();

  for (const fileName of fileNames) {
    const path = join(projectDir, fileName);
    if (!existsSync(path)) continue;
    const parsed = parseRequirementsFile(path, visited);
    for (const entry of parsed.entries) set.add(entry.name, entry.version, directFromPyproject(pyproject, entry.name) ?? true);
    skipped.push(...parsed.skipped);
  }

  return {
    subjectName: pyproject?.name,
    subjectVersion: pyproject?.version,
    components: set.components,
    skipped,
  };
}
