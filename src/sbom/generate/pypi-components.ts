import { buildPurl } from "../purl.js";
import { normalizePypiName, type PyprojectInfo } from "./pyproject.js";
import type { NormalizedComponent } from "../types.js";

/**
 * Accumulates PyPI components for one SBOM, normalizing names (PEP 503) and
 * de-duplicating by name@version — lockfiles repeat a package per extra (PDM)
 * or per environment marker, and an include chain can list it twice.
 */
export class PypiComponentSet {
  readonly components: NormalizedComponent[] = [];
  private readonly seen = new Set<string>();

  add(rawName: string, version: string, isDirect: boolean | undefined): void {
    const name = normalizePypiName(rawName);
    const key = `${name}@${version}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.components.push({
      purl: buildPurl({ type: "pypi", name, version }),
      ecosystem: "pypi",
      name,
      version,
      isDirect,
    });
  }
}

/**
 * Directness from the project's declared dependencies. Undefined — "not known"
 * — when there is no pyproject.toml, or it declares none (e.g. dependencies
 * live in setup.py): marking everything transitive would be a confident lie.
 */
export function directFromPyproject(pyproject: PyprojectInfo | undefined, rawName: string): boolean | undefined {
  if (!pyproject || pyproject.directDependencies.size === 0) return undefined;
  return pyproject.directDependencies.has(normalizePypiName(rawName));
}

/**
 * True for the project's own entry in a lockfile (an editable install of the
 * working tree), which is the SBOM subject rather than one of its dependencies.
 */
export function isProjectItself(rawName: string, pyproject: PyprojectInfo | undefined): boolean {
  return pyproject?.name !== undefined && normalizePypiName(pyproject.name) === normalizePypiName(rawName);
}
