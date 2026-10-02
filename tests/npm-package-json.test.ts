import { afterEach, describe, it, expect } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateFromNpmProject, parsePackageJson } from "../src/sbom/generate/npm.js";

const versionOf = (spec: string) => parsePackageJson({ dependencies: { pkg: spec } }).components[0]?.version;

describe("package.json fallback (no lockfile)", () => {
  it("records the lowest version each range allows", () => {
    expect(versionOf("^1.2.3")).toBe("1.2.3");
    expect(versionOf("~2.3.4")).toBe("2.3.4");
    expect(versionOf("1.2.3")).toBe("1.2.3");
    expect(versionOf("=1.2.3")).toBe("1.2.3");
    expect(versionOf("v1.2.3")).toBe("1.2.3");
  });

  it("handles ranges the old one-character strip got wrong", () => {
    expect(versionOf(">=1.0")).toBe("1.0.0"); // previously "=1.0"
    expect(versionOf(">=1.0 <2")).toBe("1.0.0"); // previously "=1.0"
    expect(versionOf(">1.2.3")).toBe("1.2.4"); // previously "1.2.3", which the range excludes
    expect(versionOf("1.x")).toBe("1.0.0");
    expect(versionOf("1.2.3 - 2.0.0")).toBe("1.2.3");
    expect(versionOf("^2.0.0 || ^3.0.0")).toBe("2.0.0");
  });

  it("skips and reports specs with no meaningful version instead of guessing", () => {
    const { components, skipped } = parsePackageJson({
      dependencies: {
        star: "*",
        latest: "latest",
        git: "git+https://github.com/example/repo.git#v1.0.0",
        local: "file:../local-lib",
        workspace: "workspace:^",
        alias: "npm:other-package@^1.0.0",
        github: "user/repo",
        ok: "^4.17.21",
      },
    });
    expect(components.map((c) => c.name)).toEqual(["ok"]);
    expect(skipped.sort()).toEqual([
      "alias@npm:other-package@^1.0.0",
      "git@git+https://github.com/example/repo.git#v1.0.0",
      "github@user/repo",
      "latest@latest",
      "local@file:../local-lib",
      "star@*",
      "workspace@workspace:^",
    ]);
  });

  it("keeps scoped names and prefers dependencies over devDependencies for the same package", () => {
    const { components } = parsePackageJson({
      dependencies: { "@scope/pkg": "^2.0.0" },
      devDependencies: { "@scope/pkg": "^1.0.0" },
    });
    expect(components).toHaveLength(1);
    expect(components[0]).toMatchObject({ namespace: "@scope", name: "pkg", version: "2.0.0", purl: "pkg:npm/%40scope/pkg@2.0.0" });
  });
});

describe("generateFromNpmProject without a lockfile", () => {
  let dir: string | undefined;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("warns that versions are lower bounds and lists skipped specs", () => {
    dir = mkdtempSync(join(tmpdir(), "osprey-npm-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "app", dependencies: { express: "^4.18.0", tool: "latest" } }));
    const result = generateFromNpmProject(dir);
    expect(result.components.map((c) => `${c.name}@${c.version}`)).toEqual(["express@4.18.0"]);
    expect(result.warnings).toEqual([
      expect.stringContaining("lowest each package.json range allows"),
      expect.stringContaining("tool@latest"),
    ]);
  });

  it("has no warnings when a lockfile is present", () => {
    expect(generateFromNpmProject(join(dirname(fileURLToPath(import.meta.url)), "fixtures", "npm-project")).warnings).toEqual([]);
  });
});
