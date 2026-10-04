import { afterEach, describe, it, expect, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { generateSbom } from "../src/sbom/generate/index.js";
import { generateSbomFromGitHub } from "../src/sbom/generate/remote.js";
import { findUnsupportedEcosystems } from "../src/sbom/generate/unsupported.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => join(here, "fixtures", name);
const tempDirs: string[] = [];

/** A copy of a fixture with extra root files added. */
function project(base: string, extraFiles: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "osprey-unsupported-"));
  tempDirs.push(dir);
  cpSync(fixture(base), dir, { recursive: true });
  for (const [name, content] of Object.entries(extraFiles)) writeFileSync(join(dir, name), content);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  vi.unstubAllGlobals();
});

describe("recognising ecosystems Osprey does not read", () => {
  it("names the lockfile when there is one, the manifest otherwise", () => {
    const found = findUnsupportedEcosystems(["Gemfile", "Gemfile.lock", "go.mod", "App.csproj", "README.md"]);
    expect(found.map(({ ecosystem, file }) => `${ecosystem.label}:${file}`)).toEqual(["Go:go.mod", "Ruby:Gemfile.lock", ".NET:App.csproj"]);
  });

  it("does not report a Gradle build whose lockfiles were audited", () => {
    expect(findUnsupportedEcosystems(["build.gradle.kts"], ["maven"])).toEqual([]);
    expect(findUnsupportedEcosystems(["build.gradle.kts"], ["npm"]).map(({ file }) => file)).toEqual(["build.gradle.kts"]);
  });
});

describe("local projects", () => {
  it("warns that the Go half of a mixed project was not audited", () => {
    const { ecosystems, warnings } = generateSbom({ projectDir: project("npm-project", { "go.mod": "module example.com/app\n", "go.sum": "" }) });
    expect(ecosystems).toEqual(["npm"]);
    expect(warnings).toContainEqual(expect.stringMatching(/^Found go\.sum: its Go dependencies were NOT audited — Osprey does not read Go projects\. /));
  });

  it("stays quiet when the caller chose the ecosystem explicitly", () => {
    const dir = project("npm-project", { "go.mod": "module example.com/app\n" });
    expect(generateSbom({ projectDir: dir, ecosystem: "npm" }).warnings.join("\n")).not.toMatch(/go.mod/);
  });

  it("names what it found when nothing supported is there", () => {
    const dir = mkdtempSync(join(tmpdir(), "osprey-go-only-"));
    tempDirs.push(dir);
    writeFileSync(join(dir, "go.mod"), "module example.com/app\n");
    expect(() => generateSbom({ projectDir: dir })).toThrow(/Found go\.mod \(Go\), but Osprey does not read Go projects./);
  });
});

describe("--url", () => {
  const repo = { owner: "owner", repo: "repo" };
  const npmFiles = {
    "package-lock.json": readFileSync(join(fixture("npm-project"), "package-lock.json"), "utf-8"),
    "package.json": readFileSync(join(fixture("npm-project"), "package.json"), "utf-8"),
  };

  /** Raw file fetches plus the contents API listing of the root (or a failure for it). */
  function stubGitHub(files: Record<string, string>, listing: Response | (() => Response)) {
    vi.stubGlobal("fetch", async (input: string | URL) => {
      const url = String(input);
      if (url === "https://api.github.com/repos/owner/repo/contents/") return typeof listing === "function" ? listing() : listing.clone();
      const path = url.replace(/^https:\/\/raw\.githubusercontent\.com\/owner\/repo\/HEAD\//, "");
      return path in files ? new Response(files[path]) : new Response("Not Found", { status: 404, statusText: "Not Found" });
    });
  }
  const listingOf = (names: string[]) => Response.json(names.map((name) => ({ name, type: "file" })));

  it("finds unsupported ecosystems from one listing of the repository root", async () => {
    stubGitHub(npmFiles, listingOf(["Gemfile", "Gemfile.lock", "package.json", "package-lock.json"]));
    const { ecosystems, warnings } = await generateSbomFromGitHub({ repoInfo: repo });
    expect(ecosystems).toEqual(["npm"]);
    expect(warnings).toContainEqual(expect.stringMatching(/^Found Gemfile\.lock: its Ruby dependencies were NOT audited/));
  });

  it("reports the gap, rather than failing, when the listing is unavailable", async () => {
    stubGitHub(npmFiles, () => new Response("rate limited", { status: 403, statusText: "Forbidden" }));
    const { sbom, warnings } = await generateSbomFromGitHub({ repoInfo: repo });
    expect(sbom.components.length).toBeGreaterThan(0);
    expect(warnings).toContainEqual(expect.stringMatching(/^Could not list the repository root .* NOT audited/));
  });

  it("names the unsupported files when nothing supported is found", async () => {
    stubGitHub({}, listingOf(["go.mod", "go.sum", "main.go"]));
    await expect(generateSbomFromGitHub({ repoInfo: repo })).rejects.toThrow(/No supported package file found .*Found go\.sum \(Go\), but Osprey does not read Go projects./);
  });
});
