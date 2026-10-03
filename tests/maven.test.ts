import { describe, it, expect, vi, afterEach } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { osvPackage, osvPackageKey, isSameOsvPackage, type OsvAdvisory } from "../src/vulnerability/osv.js";
import { runKevCheck } from "../src/vulnerability/check.js";
import { crossCheckWithAdvisories } from "../src/correlation/matcher.js";
import { printAuditReport } from "../src/output/audit-report.js";
import type { NormalizedComponent } from "../src/sbom/types.js";

// tests/fixtures/maven-sbom/bom.json is unmodified output of cyclonedx-maven-plugin 2.9.1
// for a project depending on log4j-core 2.14.1, spring-beans 5.3.17 and struts2-core 2.5.10.
const here = dirname(fileURLToPath(import.meta.url));
const pluginBom = JSON.parse(readFileSync(join(here, "fixtures", "maven-sbom", "bom.json"), "utf8"));
/** The same mapping cra-kev --sbom applies (purl, group -> namespace). */
const sbomComponents: NormalizedComponent[] = pluginBom.components.map((c: any) => ({ purl: c.purl, namespace: c.group, name: c.name, version: c.version }));

const LOG4J = "org.apache.logging.log4j:log4j-core";

/** CVE-2021-44228 as OSV publishes it (GHSA-jfh8-c2jp-5v3q), trimmed to the affected ranges. */
const log4shell: OsvAdvisory = {
  id: "GHSA-jfh8-c2jp-5v3q",
  aliases: ["CVE-2021-44228"],
  affected: [{
    package: { ecosystem: "Maven", name: LOG4J },
    ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.13.0" }, { fixed: "2.15.0" }, { introduced: "2.0-beta9" }, { fixed: "2.3.1" }, { introduced: "2.4" }, { fixed: "2.12.2" }] }],
  }],
};

const kevEntry = {
  cveId: "CVE-2021-44228",
  vendorProject: "Apache",
  product: "Log4j2",
  vulnerabilityName: "Apache Log4j2 Remote Code Execution Vulnerability",
  dateAdded: "2021-12-10",
  shortDescription: "Log4Shell",
};

function audit(components: NormalizedComponent[]) {
  return runKevCheck({
    subjectName: "maven-app",
    failOnHigh: true,
    generateComponents: () => components,
    pollKev: async () => ({ count: 1, entries: [kevEntry], fetchedAt: "2026-10-03T00:00:00Z" }),
    lookupAdvisories: async (comps) => ({
      advisories: new Map(comps.flatMap((c) => {
        const pkg = osvPackage(c);
        return pkg ? [[osvPackageKey(pkg), pkg.name === LOG4J ? [log4shell] : []] as [string, OsvAdvisory[]]] : [];
      })),
      warnings: [],
    }),
    crossCheck: crossCheckWithAdvisories,
    sendAlert: async () => {},
  });
}

afterEach(() => vi.restoreAllMocks());

describe("Maven package identity", () => {
  it("maps pkg:maven PURLs (with qualifiers) to OSV's group:artifact name", () => {
    expect(osvPackage({ name: "log4j-core", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar" })).toEqual({ ecosystem: "Maven", name: LOG4J });
    expect(osvPackage({ ecosystem: "maven", namespace: "org.springframework", name: "spring-beans", version: "5.3.17" })).toEqual({ ecosystem: "Maven", name: "org.springframework:spring-beans" });
  });

  it("treats a Maven component without a groupId as uncheckable rather than guessing", () => {
    expect(osvPackage({ name: "log4j-core", purl: "pkg:maven/log4j-core@2.14.1" })).toBeUndefined();
  });

  it("compares Maven coordinates case-sensitively", () => {
    const pkg = { ecosystem: "Maven" as const, name: "com.example:Lib" };
    expect(isSameOsvPackage({ ecosystem: "Maven", name: "com.example:Lib" }, pkg)).toBe(true);
    expect(isSameOsvPackage({ ecosystem: "Maven", name: "com.example:lib" }, pkg)).toBe(false);
  });
});

describe("auditing a real cyclonedx-maven-plugin SBOM", () => {
  it("checks every component and flags Log4Shell with the right fix (not a downgrade)", async () => {
    const result = await audit(sbomComponents);
    expect(result.sbomComponentCount).toBe(12);
    expect(result.checkedComponentCount).toBe(12);
    expect(result.warnings).toEqual([]);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]).toMatchObject({
      component: { namespace: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1" },
      kevEntry: { cveId: "CVE-2021-44228" },
      versionStatus: "affected",
      patchedVersion: "2.15.0",
    });
    expect(result.status).toBe("failed"); // --fail-on-high with an affected install
  });

  it("does not flag the patched version", async () => {
    const patched = sbomComponents.map((c) => (c.name === "log4j-core" ? { ...c, version: "2.17.1", purl: c.purl!.replace("2.14.1", "2.17.1") } : c));
    const result = await audit(patched);
    expect(result.matches.map((m) => m.versionStatus)).toEqual(["not_affected"]);
    expect(result.status).toBe("passed");
  });

  it("tells Maven users where to change the version", async () => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => void lines.push(args.join(" ")));
    printAuditReport(await audit(sbomComponents));
    const output = lines.join("\n").replace(/\x1b\[[0-9;]*m/g, "");
    expect(output).toContain("12 packages checked");
    expect(output).toContain(`Update ${LOG4J} to 2.15.0 in pom.xml`);
    expect(output).not.toContain("npm install");
  });
});
