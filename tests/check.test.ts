import { afterEach, describe, it, expect, vi } from "vitest";
import { runKevCheck, type KevCheckRunOptions } from "../src/vulnerability/check.js";
import { crossCheckWithAdvisories } from "../src/correlation/matcher.js";
import { printAuditReport } from "../src/output/audit-report.js";
import type { KevSnapshot } from "../src/vulnerability/types.js";
import type { NormalizedComponent } from "../src/sbom/types.js";

const component: NormalizedComponent = { purl: "pkg:npm/lodash@4.17.20", ecosystem: "npm", name: "lodash", version: "4.17.20" };

const snapshot: KevSnapshot = {
  count: 1,
  entries: [{
    cveId: "CVE-2026-00001",
    vendorProject: "Example",
    product: "example",
    vulnerabilityName: "Example",
    dateAdded: "2026-01-01",
    shortDescription: "test",
  }],
  fetchedAt: "2026-10-02T00:00:00Z",
};

function options(overrides: Partial<KevCheckRunOptions> = {}): KevCheckRunOptions {
  return {
    subjectName: "subject",
    failOnHigh: false,
    generateComponents: () => [component],
    pollKev: async () => snapshot,
    lookupAdvisories: async () => ({ advisories: new Map(), warnings: [] }),
    crossCheck: crossCheckWithAdvisories,
    sendAlert: async () => {},
    ...overrides,
  };
}

afterEach(() => vi.restoreAllMocks());

describe("OSV advisory lookup failure", () => {
  const failingLookup = async () => {
    throw new Error("HTTP 503 Service Unavailable");
  };

  it("fails the run instead of passing with an empty advisory set", async () => {
    const result = await runKevCheck(options({ lookupAdvisories: failingLookup }));
    expect(result.status).toBe("failed");
    expect(result.stages.crossCheck.status).toBe("failed");
    expect(result.stages.crossCheck.reason).toMatch(/OSV advisory lookup failed.*HTTP 503/);
    expect(result.errors).toEqual([expect.stringMatching(/OSV advisory lookup failed, so no package could be checked against KEV/)]);
  });

  it("fails even without --fail-on-high, because nothing was actually checked", async () => {
    const result = await runKevCheck(options({ failOnHigh: false, lookupAdvisories: failingLookup }));
    expect(result.status).toBe("failed");
  });

  it("keeps the context that did succeed, and sends no alert", async () => {
    const sendAlert = vi.fn(async () => {});
    const result = await runKevCheck(options({ lookupAdvisories: failingLookup, webhookUrl: "https://hooks.example/x", sendAlert }));
    expect(result.sbomComponentCount).toBe(1);
    expect(result.kevSnapshot.entryCount).toBe(1);
    expect(result.stages.pollKev.status).toBe("succeeded");
    expect(result.matches).toEqual([]);
    expect(sendAlert).not.toHaveBeenCalled();
  });

  it("is reported as an incomplete audit, never as clean", async () => {
    const result = await runKevCheck(options({ lookupAdvisories: failingLookup }));
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => void lines.push(args.join(" ")));
    printAuditReport(result);
    const output = lines.join("\n").replace(/\x1b\[[0-9;]*m/g, "");
    expect(output).toContain("Audit incomplete");
    expect(output).toContain("FAILED (audit incomplete)");
    expect(output).not.toContain("No vulnerabilities found");
  });
});

describe("successful lookups are unaffected", () => {
  it("passes when OSV answers and reports no advisories", async () => {
    const result = await runKevCheck(options());
    expect(result.status).toBe("passed");
    expect(result.errors).toEqual([]);
    expect(result.stages.crossCheck.status).toBe("succeeded");
  });
});

describe("components that cannot be checked (finding B)", () => {
  const crate: NormalizedComponent = { name: "openssl", version: "0.10.55", purl: "pkg:cargo/openssl@0.10.55" };
  const goModule: NormalizedComponent = { name: "net", namespace: "golang.org/x", version: "v0.17.0", purl: "pkg:golang/golang.org/x/net@v0.17.0" };
  const unversioned: NormalizedComponent = { name: "lodash", purl: "pkg:npm/lodash" };
  const anonymous: NormalizedComponent = { name: "mystery" };

  it("fails as incomplete when none of the SBOM's components can be checked", async () => {
    const result = await runKevCheck(options({ generateComponents: () => [crate, goModule, unversioned, anonymous] }));
    expect(result.status).toBe("failed");
    expect(result.checkedComponentCount).toBe(0);
    expect(result.stages.crossCheck.status).toBe("failed");
    expect(result.errors[0]).toMatch(/None of the 4 components could be checked against KEV/);
    expect(result.errors[0]).toContain("1 in an unsupported ecosystem (cargo: openssl@0.10.55)");
    expect(result.errors[0]).toContain("1 without a version (lodash)");
  });

  it("warns, naming what isn't covered, when only some components can be checked", async () => {
    const result = await runKevCheck(options({ generateComponents: () => [component, crate, unversioned] }));
    expect(result.status).toBe("passed");
    expect(result.sbomComponentCount).toBe(3);
    expect(result.checkedComponentCount).toBe(1);
    expect(result.warnings).toEqual([
      expect.stringMatching(/^2 of 3 components could not be checked against KEV and are NOT covered by this result: 1 in an unsupported ecosystem \(cargo: openssl@0\.10\.55\); 1 without a version \(lodash\)$/),
    ]);
  });

  it("reports the coverage in the terminal report", async () => {
    const result = await runKevCheck(options({ generateComponents: () => [component, crate] }));
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => void lines.push(args.join(" ")));
    printAuditReport(result);
    expect(lines.join("\n")).toContain("1 of 2 packages checked");
  });

  it("an empty SBOM is not an error (nothing to check)", async () => {
    const result = await runKevCheck(options({ generateComponents: () => [] }));
    expect(result.status).toBe("passed");
    expect(result.warnings).toEqual([]);
  });

  it("a fully checkable SBOM has no coverage warning", async () => {
    const result = await runKevCheck(options());
    expect(result.checkedComponentCount).toBe(1);
    expect(result.warnings).toEqual([]);
  });
});
