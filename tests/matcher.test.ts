import { describe, it, expect } from "vitest";
import { crossCheck } from "../src/correlation/matcher.js";
import type { KevEntry } from "../src/vulnerability/types.js";
import type { NormalizedComponent } from "../src/sbom/types.js";

function kevEntry(overrides: Partial<KevEntry> = {}): KevEntry {
  return {
    cveId: "CVE-2026-00001",
    vendorProject: "Acme",
    product: "openssl",
    vulnerabilityName: "Acme OpenSSL Buffer Overflow",
    dateAdded: "2026-01-01",
    shortDescription: "test",
    ...overrides,
  };
}

describe("KEV cross-check matcher", () => {
  it("marks a PURL-backed exact product-name match as high confidence", () => {
    const component: NormalizedComponent = {
      purl: "pkg:generic/openssl@3.2.1",
      name: "openssl",
      version: "3.2.1",
    };
    const matches = crossCheck([component], [kevEntry()]);
    expect(matches).toHaveLength(1);
    expect(matches[0].confidence).toBe("high");
    expect(matches[0].matchedOn).toBe("purl_ecosystem_name");
  });

  it("marks a vendor-only match without a purl as low confidence", () => {
    const component: NormalizedComponent = {
      name: "some-lib",
      vendor: "Acme",
    };
    const matches = crossCheck([component], [kevEntry()]);
    expect(matches).toHaveLength(1);
    expect(matches[0].confidence).toBe("low");
  });

  it("does not match unrelated components", () => {
    const component: NormalizedComponent = { purl: "pkg:npm/lodash@4.17.21", name: "lodash" };
    const matches = crossCheck([component], [kevEntry()]);
    expect(matches).toHaveLength(0);
  });

  it("matches case-insensitively", () => {
    const component: NormalizedComponent = { purl: "pkg:generic/OpenSSL@3.2.1", name: "OpenSSL" };
    const matches = crossCheck([component], [kevEntry({ product: "openssl" })]);
    expect(matches).toHaveLength(1);
  });

  it("returns one match per (component, KEV entry) pair when multiple entries match", () => {
    const component: NormalizedComponent = { purl: "pkg:generic/openssl@3.2.1", name: "openssl" };
    const matches = crossCheck(
      [component],
      [kevEntry({ cveId: "CVE-2026-00001" }), kevEntry({ cveId: "CVE-2026-00002" })]
    );
    expect(matches).toHaveLength(2);
  });
});
