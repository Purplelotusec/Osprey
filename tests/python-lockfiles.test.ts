import { afterEach, describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { cpSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { generateFromUvLock } from "../src/sbom/generate/uv.js";
import { generateFromPoetryLock } from "../src/sbom/generate/poetry.js";
import { detectPythonManifest } from "../src/sbom/generate/python.js";
import { generateSbom } from "../src/sbom/generate/index.js";
import { readPyproject } from "../src/sbom/generate/pyproject.js";

const here = dirname(fileURLToPath(import.meta.url));
const uvFixture = join(here, "fixtures", "uv-project");
const poetryFixture = join(here, "fixtures", "poetry-project");

const tempDirs: string[] = [];
function copyFixture(fixture: string): string {
  const dir = mkdtempSync(join(tmpdir(), "osprey-test-"));
  tempDirs.push(dir);
  cpSync(fixture, dir, { recursive: true });
  return dir;
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("uv.lock SBOM generation", () => {
  it("records every registry package at its resolved version, excluding the project itself", () => {
    const { components } = generateFromUvLock(uvFixture);
    expect(components.map((c) => `${c.name}@${c.version}`).sort()).toEqual([
      "certifi@2024.8.30",
      "numpy@1.26.4",
      "numpy@2.1.0", // both marker-specific versions are real installs
      "pytest@8.3.3",
      "requests@2.32.3",
    ]);
    expect(components.find((c) => c.name === "requests")?.purl).toBe("pkg:pypi/requests@2.32.3");
  });

  it("marks direct dependencies from the workspace member, including extras and dev groups", () => {
    const { components } = generateFromUvLock(uvFixture);
    const direct = (name: string) => components.find((c) => c.name === name)?.isDirect;
    expect(direct("requests")).toBe(true);
    expect(direct("numpy")).toBe(true); // optional extra
    expect(direct("pytest")).toBe(true); // dev group
    expect(direct("certifi")).toBe(false); // transitive via requests
  });

  it("skips and reports non-registry packages instead of labelling them as PyPI releases", () => {
    const result = generateFromUvLock(uvFixture);
    expect(result.components.some((c) => c.name === "internal-lib")).toBe(false);
    expect(result.skipped).toEqual(["internal-lib (git source)"]);
  });

  it("takes the subject from the workspace member", () => {
    const result = generateFromUvLock(uvFixture);
    expect(result.subjectName).toBe("example-uv-app");
    expect(result.subjectVersion).toBe("0.3.0");
  });

  it("rejects a file that is not a uv lockfile", () => {
    const dir = copyFixture(uvFixture);
    writeFileSync(join(dir, "uv.lock"), "this is = = not toml");
    expect(() => generateFromUvLock(dir)).toThrow(/Could not parse .*uv\.lock as TOML/);
  });
});

describe("poetry.lock SBOM generation", () => {
  it("includes PyPI and alternate-index packages, normalized, and skips VCS ones", () => {
    const result = generateFromPoetryLock(poetryFixture);
    expect(result.components.map((c) => `${c.name}@${c.version}`).sort()).toEqual([
      "corp-utils@3.1.0",
      "django@4.2.0", // "Django" normalized per PEP 503
      "pytest@8.3.3",
      "typing-extensions@4.12.2", // "typing_extensions" normalized per PEP 503
    ]);
    expect(result.skipped).toEqual(["internal-tool (git source)"]);
  });

  it("reads direct dependencies from pyproject.toml, ignoring Poetry's python constraint", () => {
    const { components } = generateFromPoetryLock(poetryFixture);
    const direct = (name: string) => components.find((c) => c.name === name)?.isDirect;
    expect(direct("django")).toBe(true);
    expect(direct("pytest")).toBe(true); // [tool.poetry.group.dev.dependencies]
    expect(direct("typing-extensions")).toBe(false);
  });

  it("leaves directness undetermined rather than guessing when pyproject.toml is missing", () => {
    const dir = copyFixture(poetryFixture);
    unlinkSync(join(dir, "pyproject.toml"));
    const result = generateFromPoetryLock(dir);
    expect(result.components.every((c) => c.isDirect === undefined)).toBe(true);
    expect(result.subjectName).toBeUndefined();
  });

  it("takes the subject from [tool.poetry]", () => {
    const result = generateFromPoetryLock(poetryFixture);
    expect(result.subjectName).toBe("example-poetry-app");
    expect(result.subjectVersion).toBe("1.4.0");
  });
});

describe("pyproject.toml direct dependencies", () => {
  it("collects PEP 621 dependencies, extras and PEP 735 groups by normalized name", () => {
    expect([...readPyproject(uvFixture)!.directDependencies].sort()).toEqual(["internal-lib", "numpy", "pytest", "requests"]);
  });
});

describe("Python manifest detection", () => {
  it("prefers uv.lock, then poetry.lock, then requirements.txt", () => {
    const dir = copyFixture(uvFixture);
    cpSync(join(poetryFixture, "poetry.lock"), join(dir, "poetry.lock"));
    writeFileSync(join(dir, "requirements.txt"), "django==4.2.0\n");
    expect(detectPythonManifest(dir)).toBe("uv.lock");
    unlinkSync(join(dir, "uv.lock"));
    expect(detectPythonManifest(dir)).toBe("poetry.lock");
    unlinkSync(join(dir, "poetry.lock"));
    expect(detectPythonManifest(dir)).toBe("requirements.txt");
  });

  it("generateSbom auto-detects a uv project and surfaces skipped packages as warnings", () => {
    const { sbom, warnings } = generateSbom({ projectDir: uvFixture });
    expect(sbom.subjectName).toBe("example-uv-app");
    expect(sbom.components).toHaveLength(5);
    expect(warnings).toEqual([expect.stringContaining("internal-lib (git source)")]);
  });

  it("generateSbom auto-detects a Poetry project", () => {
    const { sbom } = generateSbom({ projectDir: poetryFixture });
    expect(sbom.subjectName).toBe("example-poetry-app");
    expect(sbom.components).toHaveLength(4);
  });
});
