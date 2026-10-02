import { afterEach, describe, it, expect, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { detectEcosystems, generateSbom } from "../src/sbom/generate/index.js";
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
    vi.spyOn(console, "warn").mockImplementation(() => {});
    stubGitHub({ "package.json": '{"name":"app","dependencies":{"express":"^4.18.0"}}' });
    const files = await detectAndFetchPackageFiles(repo);
    expect(files.map((file) => file.fileName)).toEqual(["package.json"]);
  });

  it("reports every supported file when nothing is found", async () => {
    stubGitHub({});
    await expect(detectAndFetchPackageFiles(repo)).rejects.toThrow(/package-lock\.json, uv\.lock, .*requirements\.txt, package\.json/);
  });
});
