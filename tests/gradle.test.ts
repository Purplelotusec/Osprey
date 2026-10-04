import { afterEach, describe, it, expect, vi } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { findGradleLockfiles, generateFromGradleLockfiles, parseSettingsIncludes } from "../src/sbom/generate/gradle.js";
import { generateSbom } from "../src/sbom/generate/index.js";
import { generateSbomFromGitHub } from "../src/sbom/generate/remote.js";
import { osvPackage } from "../src/vulnerability/osv.js";

// tests/fixtures/gradle-project holds lockfiles written by Gradle 8.10.2
// (`gradle dependencies --write-locks`) for a two-module build.
const here = dirname(fileURLToPath(import.meta.url));
const project = join(here, "fixtures", "gradle-project");
const legacy = join(here, "fixtures", "gradle-legacy");
const coords = (dir: string) => generateFromGradleLockfiles(dir).components.map((c) => `${c.namespace}:${c.name}@${c.version}`).sort();

afterEach(() => vi.unstubAllGlobals());

describe("settings.gradle(.kts) modules", () => {
  it.each([
    ['include("app", "lib")', ["app", "lib"]],
    ["include ':app', ':lib:core'", ["app", "lib/core"]],
    ['include(":services:api")\ninclude(":services:worker")', ["services/api", "services/worker"]],
    ['rootProject.name = "x"\n// no modules', []],
  ])("%s", (settings, modules) => {
    expect(parseSettingsIncludes(settings)).toEqual(modules);
  });
});

describe("gradle.lockfile", () => {
  it("finds the per-module lockfiles Gradle writes", () => {
    expect(findGradleLockfiles(project)).toEqual(["app/gradle.lockfile", "lib/gradle.lockfile"]);
  });

  it("records every locked dependency once across modules, as Maven components", () => {
    expect(coords(project)).toEqual([
      "com.google.code.findbugs:jsr305@3.0.2",
      "com.google.errorprone:error_prone_annotations@2.11.0",
      "com.google.guava:failureaccess@1.0.1",
      "com.google.guava:guava@31.1-jre",
      "com.google.guava:listenablefuture@9999.0-empty-to-avoid-conflict-with-guava",
      "com.google.j2objc:j2objc-annotations@1.3",
      "junit:junit@4.13.2",
      "org.apache.logging.log4j:log4j-api@2.14.1",
      "org.apache.logging.log4j:log4j-core@2.14.1",
      "org.checkerframework:checker-qual@3.12.0",
      "org.hamcrest:hamcrest-core@1.3",
      "org.springframework:spring-beans@5.3.17",
      "org.springframework:spring-core@5.3.17",
      "org.springframework:spring-jcl@5.3.17",
    ]);
  });

  it("produces components OSV can look up as Maven group:artifact", () => {
    const log4j = generateFromGradleLockfiles(project).components.find((c) => c.name === "log4j-core")!;
    expect(log4j.purl).toBe("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
    expect(osvPackage(log4j)).toEqual({ ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" });
  });

  it("names the project from rootProject.name", () => {
    expect(generateFromGradleLockfiles(project).subjectName).toBe("gradle-kev-demo");
  });

  it("reads legacy gradle/dependency-locks/*.lockfile files (Gradle < 6.8)", () => {
    expect(coords(legacy)).toEqual(["com.fasterxml.jackson.core:jackson-databind@2.9.10.7", "junit:junit@4.12", "org.yaml:snakeyaml@1.26"]);
  });

  it("is detected and generated as the maven ecosystem", () => {
    const { ecosystems, sbom } = generateSbom({ projectDir: project });
    expect(ecosystems).toEqual(["maven"]);
    expect(sbom.components).toHaveLength(14);
  });
});

describe("--url with Gradle module lockfiles", () => {
  it("discovers module lockfiles through settings.gradle.kts", async () => {
    const files: Record<string, string> = {
      "settings.gradle.kts": readFileSync(join(project, "settings.gradle.kts"), "utf-8"),
      "app/gradle.lockfile": readFileSync(join(project, "app", "gradle.lockfile"), "utf-8"),
      "lib/gradle.lockfile": readFileSync(join(project, "lib", "gradle.lockfile"), "utf-8"),
    };
    vi.stubGlobal("fetch", async (input: string | URL) => {
      const path = String(input).replace(/^https:\/\/raw\.githubusercontent\.com\/owner\/repo\/HEAD\//, "");
      return path in files ? new Response(files[path]) : new Response("Not Found", { status: 404, statusText: "Not Found" });
    });
    const { ecosystems, sbom } = await generateSbomFromGitHub({ repoInfo: { owner: "owner", repo: "repo" } });
    expect(ecosystems).toEqual(["maven"]);
    expect(sbom.components).toHaveLength(14);
  });
});
