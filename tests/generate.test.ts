import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { generateFromNpmProject } from "../src/sbom/generate/npm.js";
import { generateFromRequirementsTxt } from "../src/sbom/generate/python.js";
import { generateSbom, toCycloneDxJson } from "../src/sbom/generate/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const npmFixture = join(here, "fixtures", "npm-project");
const pyFixture = join(here, "fixtures", "python-project");

describe("npm SBOM generation", () => {
  it("extracts all resolved packages from a v3 lockfile, deduped", () => {
    const result = generateFromNpmProject(npmFixture);
    const names = result.components.map((c) => c.name).sort();
    expect(names).toEqual(["express", "lodash", "qs"]);
  });

  it("produces a valid purl for each component", () => {
    const result = generateFromNpmProject(npmFixture);
    const lodash = result.components.find((c) => c.name === "lodash");
    expect(lodash?.purl).toBe("pkg:npm/lodash@4.17.21");
  });

  it("marks top-level deps as direct and nested ones as not", () => {
    const result = generateFromNpmProject(npmFixture);
    expect(result.components.find((c) => c.name === "express")?.isDirect).toBe(true);
    expect(result.components.find((c) => c.name === "qs")?.isDirect).toBe(false);
  });

  it("reads the subject name/version from package.json", () => {
    const result = generateFromNpmProject(npmFixture);
    expect(result.subjectName).toBe("example-app");
    expect(result.subjectVersion).toBe("1.2.0");
  });
});

describe("python SBOM generation", () => {
  it("parses only exact pins, skipping ranges and VCS lines", () => {
    const result = generateFromRequirementsTxt(pyFixture);
    const names = result.components.map((c) => c.name).sort();
    expect(names).toEqual(["django", "requests"]);
    expect(result.skippedLines.some((l) => l.includes(">="))).toBe(true);
  });

  it("normalizes package names per PEP 503", () => {
    const result = generateFromRequirementsTxt(pyFixture);
    expect(result.components.find((c) => c.name === "django")).toBeDefined(); // Django -> django
  });
});

describe("end-to-end generateSbom + toCycloneDxJson", () => {
  it("auto-detects npm and produces a valid CycloneDX document", () => {
    const { sbom } = generateSbom({ projectDir: npmFixture });
    const json = JSON.parse(toCycloneDxJson(sbom));
    expect(json.bomFormat).toBe("CycloneDX");
    expect(json.specVersion).toBe("1.5");
    expect(json.components).toHaveLength(3);
  });

  it("throws a clear error when no supported manifest is found", () => {
    expect(() => generateSbom({ projectDir: "/tmp/definitely-empty-dir-xyz" })).toThrow(/Could not detect/);
  });
});
