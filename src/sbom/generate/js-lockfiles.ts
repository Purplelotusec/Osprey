import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import semver from "semver";
import { parse as parseYaml, parseAllDocuments } from "yaml";
import { buildPurl } from "../purl.js";
import type { NormalizedComponent } from "../types.js";

/** What a JavaScript lockfile parser returns; npm.ts adds the subject and warnings. */
export interface JsLockfileResult {
  components: NormalizedComponent[];
  /** Packages not recorded at an npm registry version, each with the reason. */
  skipped: string[];
}

/**
 * Accumulates npm components, de-duplicated by name@version (lockfiles list a
 * package once per peer-dependency variant or per requesting range).
 */
class NpmComponentSet {
  readonly components: NormalizedComponent[] = [];
  readonly skipped: string[] = [];
  private readonly seen = new Set<string>();

  constructor(private readonly directNames: Set<string> | undefined) {}

  add(fullName: string, version: string): void {
    const key = `${fullName}@${version}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    const [namespace, name] = fullName.startsWith("@") ? [fullName.split("/")[0], fullName.split("/").slice(1).join("/")] : [undefined, fullName];
    this.components.push({
      purl: buildPurl({ type: "npm", namespace, name, version }),
      ecosystem: "npm",
      namespace,
      name,
      version,
      isDirect: this.directNames ? this.directNames.has(fullName) : undefined,
    });
  }

  skip(entry: string): void {
    if (!this.skipped.includes(entry)) this.skipped.push(entry);
  }

  result(): JsLockfileResult {
    return { components: this.components, skipped: this.skipped };
  }
}

/** Names declared in package.json (all dependency kinds) — the project's direct dependencies. */
export function directDependencyNames(projectDir: string): Set<string> | undefined {
  const path = join(projectDir, "package.json");
  if (!existsSync(path)) return undefined;
  const pkg = JSON.parse(readFileSync(path, "utf-8"));
  return new Set(
    ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"].flatMap((field) => Object.keys(pkg[field] ?? {}))
  );
}

/** Splits "name@version" / "@scope/name@version" at the version separator. */
function splitNameVersion(spec: string): [string, string] | undefined {
  const at = spec.indexOf("@", 1);
  return at === -1 ? undefined : [spec.slice(0, at), spec.slice(at + 1)];
}

/** A registry release has a plain semver version; anything else (URL, git, file, link) doesn't. */
function registryVersion(version: string): string | undefined {
  return semver.valid(version) ?? undefined;
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml (lockfile versions 5.x, 6.x and 9.x)
// ---------------------------------------------------------------------------

/**
 * Reads the `packages` section. Key shapes by lockfile version:
 *   5.x  /name/1.2.3, /@scope/name/1.2.3_peer@4.5.6
 *   6.x  /name@1.2.3, /name@1.2.3(peer@4.5.6)
 *   9.x  name@1.2.3   (peer variants live in `snapshots`)
 * Keys for git, tarball and local packages carry no registry version and are reported.
 *
 * pnpm 10 can write two YAML documents to one file: an "env" lockfile for
 * configDependencies (pnpm's own tooling), then the project lockfile. Both
 * describe installed packages, so every document is read.
 */
export function parsePnpmLock(path: string, directNames: Set<string> | undefined): JsLockfileResult {
  type PnpmDoc = { lockfileVersion?: string | number; packages?: Record<string, unknown> } | null;
  const docs = parseAllDocuments(readFileSync(path, "utf-8")).map((doc) => {
    if (doc.errors.length > 0) throw new Error(`Could not parse ${path}: ${doc.errors[0].message}`);
    return doc.toJS() as PnpmDoc;
  });
  const lockDocs = docs.filter((doc): doc is NonNullable<PnpmDoc> => doc?.lockfileVersion !== undefined);
  if (lockDocs.length === 0) throw new Error(`${path} has no lockfileVersion; it doesn't look like a pnpm lockfile.`);

  const set = new NpmComponentSet(directNames);
  for (const doc of lockDocs) {
    const major = Number.parseInt(String(doc.lockfileVersion), 10);
    if (![5, 6, 7, 9].includes(major)) {
      throw new Error(`${path} has lockfileVersion ${doc.lockfileVersion}; supported pnpm lockfile versions are 5, 6 and 9.`);
    }
    for (const key of Object.keys(doc.packages ?? {})) {
      // v6+ keys may carry peer-dependency suffixes, e.g. /vite@5.0.6(@types/node@20.10.4): still vite 5.0.6.
      const parsed = major === 5 ? parsePnpmV5Key(key) : splitNameVersion(key.replace(/^\//, "").replace(/\(.*$/, ""));
      const version = parsed ? registryVersion(parsed[1]) : undefined;
      if (parsed && version) set.add(parsed[0], version);
      else set.skip(`${key} (not an npm registry release)`);
    }
  }
  return set.result();
}

function parsePnpmV5Key(key: string): [string, string] | undefined {
  if (!key.startsWith("/")) return undefined; // e.g. github.com/owner/repo/<commit>
  const slash = key.lastIndexOf("/");
  const name = key.slice(1, slash);
  const version = key.slice(slash + 1).split("_")[0]; // "1.2.3_peer@4.5.6" -> "1.2.3"
  return name ? [name, version] : undefined;
}

// ---------------------------------------------------------------------------
// yarn.lock: classic (v1) text format and Berry (v2+) YAML
// ---------------------------------------------------------------------------

export function parseYarnLock(path: string, directNames: Set<string> | undefined): JsLockfileResult {
  const text = readFileSync(path, "utf-8");
  return /^__metadata:/m.test(text) ? parseYarnBerry(text, directNames) : parseYarnClassic(text, directNames);
}

/**
 * Classic yarn.lock: entries like
 *   "@babel/core@^7.0.0", "@babel/core@^7.1.0":
 *     version "7.24.0"
 *     resolved "https://registry.yarnpkg.com/..."
 * The package name comes from the first requesting spec; an `npm:` alias
 * ("alias@npm:real@^1") resolves to the real package.
 */
function parseYarnClassic(text: string, directNames: Set<string> | undefined): JsLockfileResult {
  const set = new NpmComponentSet(directNames);
  let header: string | undefined;

  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#")) continue;
    if (!line.startsWith(" ") && line.endsWith(":")) {
      header = line.slice(0, -1);
      continue;
    }
    const versionMatch = /^ {2}version "?([^"\s]+)"?$/.exec(line);
    if (!versionMatch || !header) continue;

    const firstSpec = header.split(",")[0].trim().replace(/^"|"$/g, "");
    const split = splitNameVersion(firstSpec);
    if (!split) continue;
    let [name, range] = split;
    if (range.startsWith("npm:")) {
      const aliased = splitNameVersion(range.slice(4));
      if (aliased) [name, range] = aliased;
      else name = range.slice(4);
    }
    const version = registryVersion(versionMatch[1]);
    if (version && !/^(git|https?:|file:|link:|github:)|#/.test(range)) set.add(name, version);
    else set.skip(`${firstSpec} (not an npm registry release)`);
    header = undefined;
  }
  return set.result();
}

/**
 * Berry (v2+) yarn.lock is YAML. An entry's `resolution` names its source:
 * "react@npm:18.2.0" is a registry release; patch: wrappers around an npm
 * release still install that release; workspace:, link:, portal:, file: and
 * git sources are reported instead.
 */
function parseYarnBerry(text: string, directNames: Set<string> | undefined): JsLockfileResult {
  const doc = parseYaml(text) as Record<string, { version?: string; resolution?: string } | undefined>;
  const set = new NpmComponentSet(directNames);

  for (const [key, entry] of Object.entries(doc ?? {})) {
    if (key === "__metadata" || !entry?.resolution) continue;
    const at = entry.resolution.indexOf("@", 1);
    const name = entry.resolution.slice(0, at);
    const source = entry.resolution.slice(at + 1);
    const fromRegistry = source.startsWith("npm:") || (source.startsWith("patch:") && source.includes("@npm%3A"));
    const version = entry.version ? registryVersion(entry.version) : undefined;
    if (fromRegistry && version) set.add(name, version);
    else if (!source.startsWith("workspace:")) set.skip(`${entry.resolution} (not an npm registry release)`);
  }
  return set.result();
}

// ---------------------------------------------------------------------------
// bun.lock (text lockfile, Bun 1.2+)
// ---------------------------------------------------------------------------

/**
 * bun.lock is JSON with trailing commas. Each `packages` entry is an array whose
 * first element is "name@version" for registry packages, or a non-registry
 * reference such as "name@github:owner/repo#ref" or "name@workspace:packages/x".
 */
export function parseBunLock(path: string, directNames: Set<string> | undefined): JsLockfileResult {
  const text = readFileSync(path, "utf-8").replace(/,(\s*[}\]])/g, "$1");
  let doc: { lockfileVersion?: number; packages?: Record<string, unknown[]> };
  try {
    doc = JSON.parse(text);
  } catch (err) {
    throw new Error(`Could not parse ${path}: ${(err as Error).message}`);
  }
  const set = new NpmComponentSet(directNames);

  for (const [key, entry] of Object.entries(doc.packages ?? {})) {
    const spec = Array.isArray(entry) && typeof entry[0] === "string" ? entry[0] : undefined;
    const split = spec ? splitNameVersion(spec) : undefined;
    const version = split ? registryVersion(split[1]) : undefined;
    if (split && version) set.add(split[0], version);
    else if (!spec?.includes("@workspace:")) set.skip(`${spec ?? key} (not an npm registry release)`);
  }
  return set.result();
}
