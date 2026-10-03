import { afterEach, describe, it, expect, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { detectEcosystems, generateSbom, UNLOCKED_PACKAGE_JSON_WARNING } from "../src/sbom/generate/index.js";
import { generateSbomFromGitHub } from "../src/sbom/generate/remote.js";
import { detectAndFetchPackageFiles } from "../src/network/github.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => join(here, "fixtures", name);

const tempDirs: string[] = [];
/** A Django-style repo: a uv-managed Python backend plus an npm-built frontend. */
function mixedProject(): string {
  const dir = mkdtempSync(join(tmpdir(), "osprey-mixed-"));
  tempDirs.push(dir);
  cpSync(fixture("npm-project"), dir, { recursive: true });
  cpSync(fixture("uv-project"), dir, { recursive: true });
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  vi.unstubAllGlobals();
});

describe("local mixed npm + Python projects", () => {
  it("detects every ecosystem present", () => {
    expect(detectEcosystems(mixedProject())).toEqual(["npm", "python"]);
  });

  it("audits both halves in one SBOM, keeping each component's ecosystem", () => {
    const { sbom, ecosystems, warnings } = generateSbom({ projectDir: mixedProject() });
    expect(ecosystems).toEqual(["npm", "python"]);
    expect(sbom.components.filter((c) => c.ecosystem === "npm")).toHaveLength(3);
    expect(sbom.components.filter((c) => c.ecosystem === "pypi")).toHaveLength(5);
    // The Python half's warnings survive the merge.
    expect(warnings).toEqual([expect.stringContaining("internal-lib (git source)")]);
    // Subject comes from the first ecosystem in a fixed order, so it is stable.
    expect(sbom.subjectName).toBe("example-app");
  });

  it("--ecosystem restricts the SBOM to one ecosystem", () => {
    const { sbom, ecosystems } = generateSbom({ projectDir: mixedProject(), ecosystem: "python" });
    expect(ecosystems).toEqual(["python"]);
    expect(sbom.components.every((c) => c.ecosystem === "pypi")).toBe(true);
  });

  it("rejects an unknown --ecosystem instead of silently auditing nothing", () => {
    expect(() => generateSbom({ projectDir: mixedProject(), ecosystem: "cargo" as never })).toThrow(/Unsupported ecosystem "cargo"/);
  });

  it("single-ecosystem projects are unchanged", () => {
    expect(generateSbom({ projectDir: fixture("npm-project") }).ecosystems).toEqual(["npm"]);
    expect(generateSbom({ projectDir: fixture("uv-project") }).ecosystems).toEqual(["python"]);
  });
});

/** Serves `files` (repo-relative path -> content) as raw.githubusercontent.com; anything else 404s. */
function stubGitHub(files: Record<string, string>): string[] {
  const requested: string[] = [];
  vi.stubGlobal("fetch", async (input: string | URL) => {
    const path = String(input).replace(/^https:\/\/raw\.githubusercontent\.com\/owner\/repo\/HEAD\//, "");
    requested.push(path);
    return path in files ? new Response(files[path]) : new Response("Not Found", { status: 404, statusText: "Not Found" });
  });
  return requested;
}

const read = (name: string, file: string) => readFileSync(join(fixture(name), file), "utf-8");
const repo = { owner: "owner", repo: "repo" };

describe("remote (--url) mixed repositories", () => {
  it("fetches the preferred manifest of each ecosystem", async () => {
    stubGitHub({
      "package-lock.json": read("npm-project", "package-lock.json"),
      "uv.lock": read("uv-project", "uv.lock"),
      "requirements.txt": "django==4.2.0\n", // less preferred than uv.lock, must not be chosen
    });
    const files = await detectAndFetchPackageFiles(repo);
    expect(files.map((file) => `${file.ecosystem}:${file.fileName}`)).toEqual(["npm:package-lock.json", "python:uv.lock"]);
  });

  it("generates one merged SBOM for a mixed repository", async () => {
    stubGitHub({
      "package-lock.json": read("npm-project", "package-lock.json"),
      "package.json": read("npm-project", "package.json"),
      "uv.lock": read("uv-project", "uv.lock"),
      "pyproject.toml": read("uv-project", "pyproject.toml"),
    });
    const { sbom, ecosystems } = await generateSbomFromGitHub({ repoInfo: repo });
    expect(ecosystems).toEqual(["npm", "python"]);
    expect(sbom.components).toHaveLength(8);
    expect(sbom.subjectName).toBe("owner/repo");
  });

  it("does not audit a tooling-only package.json in a Python repository", async () => {
    stubGitHub({
      "package.json": '{"name":"tooling","devDependencies":{"prettier":"^3.0.0"}}',
      "requirements.txt": "django==4.2.0\n",
    });
    const { sbom, ecosystems } = await generateSbomFromGitHub({ repoInfo: repo });
    expect(ecosystems).toEqual(["python"]);
    expect(sbom.components.map((c) => c.name)).toEqual(["django"]);
  });

  it("still falls back to package.json when it is the only manifest", async () => {
    stubGitHub({ "package.json": '{"name":"app","dependencies":{"express":"^4.18.0"}}' });
    const files = await detectAndFetchPackageFiles(repo);
    expect(files.map((file) => file.fileName)).toEqual(["package.json"]);
  });

  it("reports every supported file when nothing is found", async () => {
    stubGitHub({});
    await expect(detectAndFetchPackageFiles(repo)).rejects.toThrow(/package-lock\.json, uv\.lock, .*requirements\.txt, package\.json/);
  });
});

describe("remote fetch errors are not mistaken for missing files (review finding 3)", () => {
  function stubStatuses(statuses: Record<string, number>, files: Record<string, string>): void {
    vi.stubGlobal("fetch", async (input: string | URL) => {
      const path = String(input).replace(/^https:\/\/raw\.githubusercontent\.com\/owner\/repo\/HEAD\//, "");
      if (path in statuses) return new Response("error", { status: statuses[path], statusText: "Error" });
      return path in files ? new Response(files[path]) : new Response("Not Found", { status: 404, statusText: "Not Found" });
    });
  }

  it.each([401, 403, 429, 500])("fails the audit when a manifest fetch returns %i, instead of dropping that ecosystem", async (status) => {
    stubStatuses({ "package-lock.json": status }, { "requirements.txt": "django==4.2.0\n" });
    await expect(detectAndFetchPackageFiles(repo)).rejects.toThrow(`Could not fetch package-lock.json from owner/repo: HTTP ${status}`);
  });

  it("fails when a companion file (pyproject.toml) can't be fetched", async () => {
    stubStatuses({ "pyproject.toml": 503 }, { "uv.lock": read("uv-project", "uv.lock") });
    await expect(generateSbomFromGitHub({ repoInfo: repo })).rejects.toThrow(/Could not fetch pyproject\.toml/);
  });

  it("still treats a 404 as 'not there'", async () => {
    stubStatuses({}, { "requirements.txt": "django==4.2.0\n" });
    expect((await detectAndFetchPackageFiles(repo)).map((f) => f.fileName)).toEqual(["requirements.txt"]);
  });
});

describe("a package.json without a lockfile is never skipped silently (finding C)", () => {
  function pythonWithUnlockedFrontend(): string {
    const dir = mkdtempSync(join(tmpdir(), "osprey-unlocked-"));
    tempDirs.push(dir);
    cpSync(fixture("uv-project"), dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "frontend", dependencies: { jquery: "^3.4.1" } }));
    return dir;
  }

  it("warns locally that the npm dependencies were not audited", () => {
    const { ecosystems, warnings } = generateSbom({ projectDir: pythonWithUnlockedFrontend() });
    expect(ecosystems).toEqual(["python"]);
    expect(warnings).toContain(UNLOCKED_PACKAGE_JSON_WARNING);
  });

  it("does not warn when the caller chose the ecosystems explicitly", () => {
    expect(generateSbom({ projectDir: pythonWithUnlockedFrontend(), ecosystem: "python" }).warnings).not.toContain(UNLOCKED_PACKAGE_JSON_WARNING);
  });

  it("explains how to fix a package.json-only project instead of 'could not detect'", () => {
    const dir = mkdtempSync(join(tmpdir(), "osprey-pkgjson-only-"));
    tempDirs.push(dir);
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "app", dependencies: { express: "^4.18.0" } }));
    expect(() => generateSbom({ projectDir: dir })).toThrow(/Found package\.json but no package-lock\.json .*npm install --package-lock-only/);
  });

  it("warns with --url too, by checking whether the repo has a package.json", async () => {
    stubGitHub({ "package.json": '{"name":"frontend","dependencies":{"jquery":"^3.4.1"}}', "requirements.txt": "django==4.2.0\n" });
    const { ecosystems, warnings } = await generateSbomFromGitHub({ repoInfo: repo });
    expect(ecosystems).toEqual(["python"]);
    expect(warnings).toContain(UNLOCKED_PACKAGE_JSON_WARNING);
  });

  it("a repo with a real npm lockfile gets no such warning", async () => {
    stubGitHub({ "package-lock.json": read("npm-project", "package-lock.json"), "package.json": read("npm-project", "package.json"), "requirements.txt": "django==4.2.0\n" });
    expect((await generateSbomFromGitHub({ repoInfo: repo })).warnings).not.toContain(UNLOCKED_PACKAGE_JSON_WARNING);
  });
});

describe("package.json locked by another package manager (finding C, refined on real repos)", () => {
  it("names the pnpm lockfile instead of advising a package-lock.json", () => {
    const dir = mkdtempSync(join(tmpdir(), "osprey-pnpm-"));
    tempDirs.push(dir);
    cpSync(fixture("uv-project"), dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "frontend" }));
    writeFileSync(join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    const { warnings } = generateSbom({ projectDir: dir });
    expect(warnings).toContain("Found package.json locked by pnpm-lock.yaml, which Osprey can't read yet: its JavaScript dependencies were NOT audited.");
    expect(warnings).not.toContain(UNLOCKED_PACKAGE_JSON_WARNING);
  });

  it("does the same with --url (e.g. a Sentry/Zulip-style repo)", async () => {
    stubGitHub({ "uv.lock": read("uv-project", "uv.lock"), "package.json": '{"name":"frontend"}', "pnpm-lock.yaml": "lockfileVersion: '9.0'\n" });
    const { warnings } = await generateSbomFromGitHub({ repoInfo: repo });
    expect(warnings).toEqual(expect.arrayContaining([expect.stringContaining("locked by pnpm-lock.yaml")]));
  });
});
