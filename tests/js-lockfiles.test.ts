import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { generateFromNpmProject, findNpmLockfile } from "../src/sbom/generate/npm.js";
import { generateSbom } from "../src/sbom/generate/index.js";
import type { NormalizedComponent } from "../src/sbom/types.js";

// Fixtures follow the formats of real lockfiles (pnpm 5.4/6.0/9.0 from vuejs/core,
// Yarn classic from facebook/react, Yarn Berry from babel/babel, bun.lock from
// elysiajs/elysia). On those real files the parsers agree with OSV-Scanner on
// every registry package.
const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => join(here, "fixtures", "js", name);
const pins = (components: NormalizedComponent[]) =>
  components.map((c) => `${c.namespace ? `${c.namespace}/` : ""}${c.name}@${c.version}`).sort();
const directness = (components: NormalizedComponent[], name: string) => components.find((c) => c.name === name)?.isDirect;

describe("pnpm-lock.yaml", () => {
  it.each([
    ["pnpm-v5", "/name/1.2.3 keys with _peer suffixes"],
    ["pnpm-v6", "/name@1.2.3 keys with (peer) suffixes"],
  ])("%s: reads %s", (name) => {
    const { components } = generateFromNpmProject(fixture(name));
    expect(pins(components)).toEqual(["@types/node@20.10.4", "lodash@4.17.21", "react@18.2.0", "vite@5.0.6"]);
    expect(components.find((c) => c.name === "node")).toMatchObject({ namespace: "@types", purl: "pkg:npm/%40types/node@20.10.4" });
  });

  it("v5: reports a git-sourced package instead of guessing its version", () => {
    expect(generateFromNpmProject(fixture("pnpm-v5")).warnings).toEqual([expect.stringContaining("github.com/example/forked-lib/abc123")]);
  });

  it("v9: reads every YAML document (pnpm 10's env lockfile plus the project lockfile)", () => {
    const { components, warnings } = generateFromNpmProject(fixture("pnpm-v9"));
    expect(pins(components)).toEqual(["@pnpm/exe@10.24.0", "@types/node@20.10.4", "lodash@4.17.21", "react@18.2.0", "vite@5.0.6"]);
    expect(warnings).toEqual([expect.stringContaining("forked-lib@https://codeload.github.com")]);
  });

  it("marks direct dependencies from package.json", () => {
    const { components } = generateFromNpmProject(fixture("pnpm-v6"));
    expect(directness(components, "react")).toBe(true);
    expect(directness(components, "vite")).toBe(true);
    expect(directness(components, "node")).toBe(false);
  });
});

describe("yarn.lock", () => {
  it("classic v1: one component per resolved version, aliases resolved to the real package", () => {
    const { components, warnings } = generateFromNpmProject(fixture("yarn-classic"));
    expect(pins(components)).toEqual(["@types/node@20.10.4", "lodash@4.17.21", "react@18.2.0", "string-width@4.2.3", "vite@5.0.6"]);
    expect(warnings).toEqual([expect.stringContaining("eslint-plugin-internal@link:./scripts/eslint-rules")]);
  });

  it("Berry: npm and patched-npm releases count; workspaces are skipped silently, git sources reported", () => {
    const { components, warnings } = generateFromNpmProject(fixture("yarn-berry"));
    expect(pins(components)).toEqual(["lodash@4.17.21", "react@18.2.0", "resolve@1.22.8", "vite@5.0.6"]);
    expect(warnings).toEqual([expect.stringMatching(/^Skipped 1 yarn\.lock entry .*forked-lib@https:\/\/github\.com/)]);
  });
});

describe("bun.lock", () => {
  it("parses the trailing-comma JSON format; workspace entries skipped silently, git sources reported", () => {
    const { components, warnings } = generateFromNpmProject(fixture("bun"));
    expect(pins(components)).toEqual(["esbuild@0.19.8", "lodash@4.17.21", "react@18.2.0", "vite@5.0.6"]);
    expect(warnings).toEqual([expect.stringContaining("forked-lib@github:example/forked-lib#abc123")]);
    expect(directness(components, "lodash")).toBe(true);
    expect(directness(components, "esbuild")).toBe(false);
  });
});

describe("JavaScript lockfile detection", () => {
  it.each([
    ["pnpm-v9", "pnpm-lock.yaml"],
    ["yarn-classic", "yarn.lock"],
    ["yarn-berry", "yarn.lock"],
    ["bun", "bun.lock"],
    ["shrinkwrap", "npm-shrinkwrap.json"],
  ])("%s is detected as %s and audited as npm", (name, lockfile) => {
    expect(findNpmLockfile(fixture(name))).toBe(lockfile);
    expect(generateSbom({ projectDir: fixture(name) }).ecosystems).toEqual(["npm"]);
  });

  it("npm-shrinkwrap.json is read like package-lock.json", () => {
    expect(pins(generateFromNpmProject(fixture("shrinkwrap")).components)).toEqual(["express@4.19.2", "lodash@4.17.21", "qs@6.11.0"]);
  });
});
