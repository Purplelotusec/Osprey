import { afterEach, describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { cpSync, mkdtempSync, readdirSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { generateFromPdmLock } from "../src/sbom/generate/pdm.js";
import { generateFromPipfileLock } from "../src/sbom/generate/pipfile.js";
import { generateFromPylock } from "../src/sbom/generate/pylock.js";
import { findRequirementIncludes, generateFromRequirementsFiles, parseRequirementsFile } from "../src/sbom/generate/requirements.js";
import { detectPythonManifest, PYTHON_MANIFESTS } from "../src/sbom/generate/python.js";
import { generateSbom } from "../src/sbom/generate/index.js";
import type { NormalizedComponent } from "../src/sbom/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => join(here, "fixtures", name);

const tempDirs: string[] = [];
function emptyDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "osprey-test-"));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

const pins = (components: NormalizedComponent[]) => components.map((c) => `${c.name}@${c.version}`).sort();
const directness = (components: NormalizedComponent[], name: string) => components.find((c) => c.name === name)?.isDirect;

describe("pdm.lock", () => {
  it("collapses per-extra entries and skips VCS packages", () => {
    const result = generateFromPdmLock(fixture("pdm-project"));
    expect(pins(result.components)).toEqual(["anyio@4.6.0", "httpx@0.28.1", "pytest@8.3.3", "socksio@1.0.0"]);
    expect(result.skipped).toEqual(["internal-sdk (git source)"]);
  });

  it("marks direct dependencies from [project] and [tool.pdm.dev-dependencies]", () => {
    const { components } = generateFromPdmLock(fixture("pdm-project"));
    expect(directness(components, "httpx")).toBe(true);
    expect(directness(components, "pytest")).toBe(true);
    expect(directness(components, "anyio")).toBe(false);
  });
});

describe("Pipfile.lock", () => {
  it("reads default and develop, de-duplicates, and silently drops the project's own path entry", () => {
    const result = generateFromPipfileLock(fixture("pipenv-project"));
    expect(pins(result.components)).toEqual(["certifi@2024.8.30", "pytest@8.3.3", "requests@2.32.3"]);
    expect(result.skipped).toEqual(["vendored-lib (git source)"]);
  });

  it("marks direct dependencies from the Pipfile", () => {
    const { components } = generateFromPipfileLock(fixture("pipenv-project"));
    expect(directness(components, "requests")).toBe(true);
    expect(directness(components, "pytest")).toBe(true);
    expect(directness(components, "certifi")).toBe(false);
  });

  it("leaves directness undetermined without a Pipfile", () => {
    const dir = emptyDir();
    cpSync(join(fixture("pipenv-project"), "Pipfile.lock"), join(dir, "Pipfile.lock"));
    expect(generateFromPipfileLock(dir).components.every((c) => c.isDirect === undefined)).toBe(true);
  });

  it("rejects malformed JSON with a clear error", () => {
    const dir = emptyDir();
    writeFileSync(join(dir, "Pipfile.lock"), "{ not json");
    expect(() => generateFromPipfileLock(dir)).toThrow(/Could not parse .*Pipfile\.lock as JSON/);
  });
});

describe("pylock.toml (PEP 751)", () => {
  it("merges pylock.toml with named variants and skips non-index sources", () => {
    const result = generateFromPylock(fixture("pylock-project"));
    expect(pins(result.components)).toEqual(["attrs@25.1.0", "mkdocs@1.6.1", "pyyaml@6.0.2"]);
    // The project's own `directory` entry is the subject, not a skipped dependency.
    expect(result.skipped).toEqual(["tool-from-git (vcs source)"]);
    expect(result.subjectName).toBe("example-pylock-app");
  });

  it("marks direct dependencies from pyproject.toml, including dependency groups", () => {
    const { components } = generateFromPylock(fixture("pylock-project"));
    expect(directness(components, "attrs")).toBe(true);
    expect(directness(components, "pyyaml")).toBe(true);
    expect(directness(components, "mkdocs")).toBe(false);
  });

  it("refuses an unsupported major lock-version, as PEP 751 requires", () => {
    const dir = emptyDir();
    writeFileSync(join(dir, "pylock.toml"), 'lock-version = "2.0"\n');
    expect(() => generateFromPylock(dir)).toThrow(/lock-version 2\.0; only 1\.x is supported/);
  });
});

describe("Rye requirements*.lock", () => {
  it("reads runtime and dev locks together, ignoring the -e file:. self-install", () => {
    const { sbom, warnings } = generateSbom({ projectDir: fixture("rye-project") });
    expect(pins(sbom.components)).toEqual(["click@8.1.7", "colorama@0.4.6", "iniconfig@2.0.0", "pytest@8.3.3"]);
    expect(warnings).toEqual([]);
    expect(sbom.subjectName).toBe("example-rye-app");
  });

  it("marks direct dependencies from [project] and [tool.rye]", () => {
    const { sbom } = generateSbom({ projectDir: fixture("rye-project") });
    expect(directness(sbom.components, "click")).toBe(true);
    expect(directness(sbom.components, "pytest")).toBe(true);
    expect(directness(sbom.components, "iniconfig")).toBe(false);
  });
});

describe("pip requirements syntax", () => {
  const project = fixture("pip-compile-project");
  const parsed = () => parseRequirementsFile(join(project, "requirements.txt"));

  it("records exact pins through extras, hashes, continuations, markers, === and -r includes", () => {
    expect(parsed().entries.map((e) => `${e.name}@${e.version}`).sort()).toEqual([
      "Certifi@2024.8.30", // from requirements/base.txt
      "PySocks@1.7.1",
      "requests@2.32.3",
      "urllib3@2.2.3",
    ]);
  });

  it("survives an include cycle (base.txt includes requirements.txt back)", () => {
    expect(() => parsed()).not.toThrow();
  });

  it("reports everything it could not record, with the reason", () => {
    expect(parsed().skipped).toEqual([
      "django==4.2.* (no exact == pin)",
      "flask>=3.0 (no exact == pin)",
      "mylib @ https://example.com/mylib-1.0.tar.gz (direct URL reference)",
      "-e git+https://github.com/example/editable.git#egg=editable (editable install)",
      "-r https://example.com/shared-requirements.txt (remote include not followed)",
      "-r requirements/missing.txt (included file not found)",
    ]);
  });

  it("does not follow -c constraint files (they install nothing)", () => {
    expect(parsed().skipped.some((line) => line.includes("constraints"))).toBe(false);
  });

  it("lists -r includes for remote fetching", () => {
    expect(findRequirementIncludes("-r base.txt\n--requirement=dev.txt\nrequests==1.0\n-c c.txt")).toEqual(["base.txt", "dev.txt"]);
  });

  it("produces normalized components through the generic generator", () => {
    const result = generateFromRequirementsFiles(project, ["requirements.txt"]);
    expect(pins(result.components)).toEqual(["certifi@2024.8.30", "pysocks@1.7.1", "requests@2.32.3", "urllib3@2.2.3"]);
  });
});

describe("Python manifest detection order", () => {
  it("covers every supported format, lockfiles before requirements.txt", () => {
    expect(PYTHON_MANIFESTS).toEqual([
      "uv.lock",
      "poetry.lock",
      "pdm.lock",
      "pylock.toml",
      "Pipfile.lock",
      "requirements.lock",
      "requirements.txt",
      "requirements/",
    ]);
  });

  it("picks the most preferred manifest present, one at a time", () => {
    const dir = emptyDir();
    for (const name of ["pdm-project", "pylock-project", "pipenv-project", "rye-project"]) {
      cpSync(fixture(name), dir, { recursive: true });
    }
    writeFileSync(join(dir, "requirements.txt"), "requests==2.32.3\n");

    const order: string[] = [];
    let manifest = detectPythonManifest(dir);
    while (manifest) {
      order.push(manifest);
      for (const file of readdirSync(dir)) {
        const owned =
          manifest === "pylock.toml" ? /^pylock\./.test(file)
          : manifest === "requirements.lock" ? /^requirements(-dev)?\.lock$/.test(file)
          : file === manifest;
        if (owned) unlinkSync(join(dir, file));
      }
      manifest = detectPythonManifest(dir);
    }
    expect(order).toEqual(["pdm.lock", "pylock.toml", "Pipfile.lock", "requirements.lock", "requirements.txt"]);
  });

  it("detects a project with only a named pylock variant", () => {
    const dir = emptyDir();
    cpSync(join(fixture("pylock-project"), "pylock.docs.toml"), join(dir, "pylock.docs.toml"));
    expect(detectPythonManifest(dir)).toBe("pylock.toml");
  });
});

describe("requirements/ directory convention", () => {
  const project = fixture("requirements-dir-project");

  it("reads every pinned requirements/*.txt (not the *.in inputs) when there's no root requirements.txt", () => {
    expect(detectPythonManifest(project)).toBe("requirements/");
    const { sbom, warnings } = generateSbom({ projectDir: project });
    expect(pins(sbom.components)).toEqual(["django@4.2.11", "pytest@8.3.3", "requests@2.31.0"]);
    expect(warnings).toEqual([expect.stringContaining("internal_tool-1.0-py3-none-any.whl (direct URL reference)")]);
  });

  it("prefers a root requirements.txt when both exist", () => {
    const dir = emptyDir();
    cpSync(project, dir, { recursive: true });
    writeFileSync(join(dir, "requirements.txt"), "flask==3.0.3\n");
    expect(detectPythonManifest(dir)).toBe("requirements.txt");
  });
});
