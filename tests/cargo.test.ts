import { afterEach, describe, it, expect, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { generateFromCargoLock } from "../src/sbom/generate/cargo.js";
import { detectEcosystems, generateSbom } from "../src/sbom/generate/index.js";
import { generateSbomFromGitHub } from "../src/sbom/generate/remote.js";
import { isSameOsvPackage, osvPackage } from "../src/vulnerability/osv.js";
import { runKevCheck } from "../src/vulnerability/check.js";
import { crossCheckWithAdvisories } from "../src/correlation/matcher.js";
import { osvPackageKey } from "../src/vulnerability/osv.js";

const here = dirname(fileURLToPath(import.meta.url));
const project = join(here, "fixtures", "cargo-project");
const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  vi.unstubAllGlobals();
});

describe("Cargo.lock", () => {
  const { components, warnings, subjectName, subjectVersion } = generateFromCargoLock(project);
  const byKey = new Map(components.map((c) => [`${c.name}@${c.version}`, c]));

  it("records every crates.io crate, from both the git and the sparse index", () => {
    expect([...byKey.keys()].sort()).toEqual(["aho-corasick@0.7.18", "memchr@2.4.1", "regex@1.5.4", "serde@1.0.130", "serde@1.0.219"]);
  });

  it("leaves out the workspace's own crates and lists git crates in a warning", () => {
    expect(byKey.has("cargo-kev-demo@0.3.1")).toBe(false);
    expect(byKey.has("local-util@0.1.0")).toBe(false);
    expect(warnings).toEqual(["Skipped 1 Cargo.lock entry not installed from crates.io: tokio-tungstenite@0.21.0 (git source)"]);
  });

  it("marks what the workspace's crates depend on as direct", () => {
    expect(components.filter((c) => c.isDirect).map((c) => `${c.name}@${c.version}`).sort()).toEqual(["regex@1.5.4", "serde@1.0.130", "serde@1.0.219"]);
  });

  it("names the project from Cargo.toml", () => {
    expect([subjectName, subjectVersion]).toEqual(["cargo-kev-demo", "0.3.1"]);
  });

  it("produces components OSV looks up in the crates.io ecosystem", () => {
    const regex = byKey.get("regex@1.5.4")!;
    expect(regex.purl).toBe("pkg:cargo/regex@1.5.4");
    expect(osvPackage(regex)).toEqual({ ecosystem: "crates.io", name: "regex" });
    expect(osvPackage({ name: "x", purl: "pkg:cargo/tokio@1.0.0" })).toEqual({ ecosystem: "crates.io", name: "tokio" });
  });

  it("matches crate names the way crates.io does (- and _ are the same)", () => {
    expect(isSameOsvPackage({ ecosystem: "crates.io", name: "tokio_util" }, { ecosystem: "crates.io", name: "tokio-util" })).toBe(true);
  });

  it("reads lockfile version 1, which carries dependency sources and a [metadata] table", () => {
    const legacy = generateFromCargoLock(join(here, "fixtures", "cargo-v1"));
    expect(legacy.components.map((c) => [`${c.name}@${c.version}`, c.isDirect])).toEqual([["smallvec@0.6.13", true]]);
  });

  it("is detected and generated as the cargo ecosystem, next to an npm frontend (Tauri-style)", () => {
    const dir = mkdtempSync(join(tmpdir(), "osprey-tauri-"));
    tempDirs.push(dir);
    cpSync(project, dir, { recursive: true });
    cpSync(join(here, "fixtures", "npm-project"), dir, { recursive: true });
    expect(detectEcosystems(dir)).toEqual(["npm", "cargo"]);
    const { sbom, warnings } = generateSbom({ projectDir: dir });
    expect(sbom.components.filter((c) => c.ecosystem === "cargo")).toHaveLength(5);
    expect(warnings.join("\n")).not.toMatch(/Rust dependencies were NOT audited/);
  });

  it("still warns about a Rust crate without a Cargo.lock", () => {
    const dir = mkdtempSync(join(tmpdir(), "osprey-rust-nolock-"));
    tempDirs.push(dir);
    cpSync(join(here, "fixtures", "npm-project"), dir, { recursive: true });
    writeFileSync(join(dir, "Cargo.toml"), '[package]\nname = "lib"\n');
    expect(generateSbom({ projectDir: dir }).warnings).toContainEqual(expect.stringMatching(/^Found Cargo\.toml: its Rust dependencies were NOT audited — there is no Cargo\.lock/));
  });
});

describe("matching crates against KEV", () => {
  it("orders crate versions by SemVer and suggests cargo update", async () => {
    const advisory = {
      id: "RUSTSEC-2099-0001",
      aliases: ["CVE-2099-0001"],
      affected: [{ package: { ecosystem: "crates.io", name: "regex" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.5.5" }] }] }],
    };
    const component = generateFromCargoLock(project).components.find((c) => c.name === "regex")!;
    const result = await runKevCheck({
      subjectName: "s",
      failOnHigh: false,
      generateComponents: () => [component],
      pollKev: async () => ({ count: 1, fetchedAt: "2026-10-04T00:00:00Z", entries: [{ cveId: "CVE-2099-0001", vendorProject: "Rust", product: "regex", vulnerabilityName: "n", dateAdded: "2026-01-01", shortDescription: "s" }] }),
      lookupAdvisories: async () => ({ advisories: new Map([[osvPackageKey({ ecosystem: "crates.io", name: "regex" }), [advisory]]]), warnings: [] }),
      crossCheck: crossCheckWithAdvisories,
      sendAlert: async () => {},
    });
    expect(result.matches.map((m) => [m.versionStatus, m.patchedVersion])).toEqual([["affected", "1.5.5"]]);
  });
});

describe("--url with Cargo.lock", () => {
  it("fetches Cargo.lock with Cargo.toml for the project name", async () => {
    const files: Record<string, string> = {
      "Cargo.lock": readFileSync(join(project, "Cargo.lock"), "utf-8"),
      "Cargo.toml": readFileSync(join(project, "Cargo.toml"), "utf-8"),
    };
    vi.stubGlobal("fetch", async (input: string | URL) => {
      const path = String(input).replace(/^https:\/\/raw\.githubusercontent\.com\/owner\/repo\/HEAD\//, "");
      return path in files ? new Response(files[path]) : new Response("Not Found", { status: 404, statusText: "Not Found" });
    });
    const { ecosystems, sbom } = await generateSbomFromGitHub({ repoInfo: { owner: "owner", repo: "repo" } });
    expect(ecosystems).toEqual(["cargo"]);
    expect(sbom.components).toHaveLength(5);
  });
});
