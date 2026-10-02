import { describe, it, expect } from "vitest";
import { crossCheckWithAdvisories } from "../src/correlation/matcher.js";
import { osvPackageKey, type OsvAdvisory } from "../src/vulnerability/osv.js";
import type { KevEntry } from "../src/vulnerability/types.js";
import type { NormalizedComponent } from "../src/sbom/types.js";

function kevEntry(overrides: Partial<KevEntry> = {}): KevEntry {
  return {
    cveId: "CVE-2026-00001",
    vendorProject: "Acme",
    product: "widget",
    vulnerabilityName: "Acme Widget Remote Code Execution",
    dateAdded: "2026-01-01",
    shortDescription: "test",
    ...overrides,
  };
}

function npmComponent(name: string, version = "1.0.0", namespace?: string): NormalizedComponent {
  const fullName = namespace ? `${encodeURIComponent(namespace)}/${name}` : name;
  return { purl: `pkg:npm/${fullName}@${version}`, ecosystem: "npm", namespace, name, version };
}

function advisory(id: string, aliases: string[] = []): OsvAdvisory {
  return { id, aliases };
}

/** advisoriesByPackage as lookupOsvAdvisories builds it: keyed by ecosystem-qualified package. */
function advisoriesFor(packageName: string, advisories: OsvAdvisory[]): Map<string, OsvAdvisory[]> {
  return new Map([[osvPackageKey({ ecosystem: "npm", name: packageName }), advisories]]);
}

describe("KEV cross-check matcher (CVE-based)", () => {
  it("matches when an OSV advisory's CVE alias is in KEV, with high confidence", () => {
    const matches = crossCheckWithAdvisories(
      [npmComponent("widget")],
      [kevEntry()],
      advisoriesFor("widget", [advisory("GHSA-aaaa-bbbb-cccc", ["CVE-2026-00001"])])
    );
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({ confidence: "high", matchedOn: "cve_from_osv", kevEntry: { cveId: "CVE-2026-00001" } });
    expect(matches[0].component.name).toBe("widget");
  });

  it("matches when the advisory ID itself is the CVE", () => {
    const matches = crossCheckWithAdvisories([npmComponent("widget")], [kevEntry()], advisoriesFor("widget", [advisory("CVE-2026-00001")]));
    expect(matches).toHaveLength(1);
  });

  it("does not match a CVE that is not in KEV (has a CVE, but not known-exploited)", () => {
    const matches = crossCheckWithAdvisories(
      [npmComponent("widget")],
      [kevEntry()],
      advisoriesFor("widget", [advisory("GHSA-aaaa-bbbb-cccc", ["CVE-2026-99999"])])
    );
    expect(matches).toHaveLength(0);
  });

  it("ignores advisories with no CVE identifier", () => {
    const matches = crossCheckWithAdvisories([npmComponent("widget")], [kevEntry()], advisoriesFor("widget", [advisory("GHSA-aaaa-bbbb-cccc")]));
    expect(matches).toHaveLength(0);
  });

  it("compares CVE IDs case-insensitively", () => {
    const matches = crossCheckWithAdvisories(
      [npmComponent("widget")],
      [kevEntry({ cveId: "cve-2026-00001" })],
      advisoriesFor("widget", [advisory("GHSA-aaaa-bbbb-cccc", ["CVE-2026-00001"])])
    );
    expect(matches).toHaveLength(1);
  });

  it("returns one match per distinct KEV CVE affecting a component", () => {
    const matches = crossCheckWithAdvisories(
      [npmComponent("widget")],
      [kevEntry({ cveId: "CVE-2026-00001" }), kevEntry({ cveId: "CVE-2026-00002" })],
      advisoriesFor("widget", [advisory("GHSA-1111-1111-1111", ["CVE-2026-00001"]), advisory("GHSA-2222-2222-2222", ["CVE-2026-00002"])])
    );
    expect(matches.map((m) => m.kevEntry.cveId).sort()).toEqual(["CVE-2026-00001", "CVE-2026-00002"]);
  });

  it("only applies a package's advisories to that package", () => {
    const matches = crossCheckWithAdvisories(
      [npmComponent("widget"), npmComponent("lodash", "4.17.21")],
      [kevEntry()],
      advisoriesFor("widget", [advisory("GHSA-aaaa-bbbb-cccc", ["CVE-2026-00001"])])
    );
    expect(matches.map((m) => m.component.name)).toEqual(["widget"]);
  });

  it("keys scoped npm packages by their full @scope/name", () => {
    const matches = crossCheckWithAdvisories(
      [npmComponent("core", "3.0.0", "@acme")],
      [kevEntry()],
      advisoriesFor("@acme/core", [advisory("GHSA-aaaa-bbbb-cccc", ["CVE-2026-00001"])])
    );
    expect(matches).toHaveLength(1);
  });

  it("matches components known only by PURL (e.g. from a third-party SBOM)", () => {
    const fromSbom: NormalizedComponent = { purl: "pkg:npm/widget@1.0.0", name: "widget", version: "1.0.0" };
    const matches = crossCheckWithAdvisories([fromSbom], [kevEntry()], advisoriesFor("widget", [advisory("CVE-2026-00001")]));
    expect(matches).toHaveLength(1);
  });

  it("skips components in ecosystems without OSV lookup support", () => {
    const crate: NormalizedComponent = { purl: "pkg:cargo/widget@1.0.0", name: "widget", version: "1.0.0" };
    const matches = crossCheckWithAdvisories([crate], [kevEntry()], advisoriesFor("widget", [advisory("CVE-2026-00001")]));
    expect(matches).toHaveLength(0);
  });

  describe("regression: no name-based matching", () => {
    // The removed fuzzy matcher flagged e.g. @aws-sdk/core as KEV's "WordPress Core".
    // Matching now requires an OSV advisory linking the exact package to the CVE.

    it("does not match a component whose name equals a KEV product but has no advisory", () => {
      const matches = crossCheckWithAdvisories([npmComponent("widget")], [kevEntry({ product: "widget" })], new Map());
      expect(matches).toHaveLength(0);
    });

    it("does not match @aws-sdk/core to KEV's WordPress Core", () => {
      const matches = crossCheckWithAdvisories(
        [npmComponent("core", "3.658.0", "@aws-sdk")],
        [kevEntry({ cveId: "CVE-2026-00042", vendorProject: "WordPress", product: "Core" })],
        new Map()
      );
      expect(matches).toHaveLength(0);
    });

    it("does not match on vendor alone", () => {
      const vendorOnly: NormalizedComponent = { name: "some-lib", vendor: "Acme" };
      expect(crossCheckWithAdvisories([vendorOnly], [kevEntry()], new Map())).toHaveLength(0);
    });
  });
});
