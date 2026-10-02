import { describe, it, expect } from "vitest";
import { crossCheckWithAdvisories } from "../src/correlation/matcher.js";
import { runKevCheck } from "../src/vulnerability/check.js";
import { osvPackage, osvPackageKey, type OsvAdvisory, type OsvAffected } from "../src/vulnerability/osv.js";
import { evaluateVersionStatus } from "../src/vulnerability/version.js";
import type { KevEntry } from "../src/vulnerability/types.js";
import type { NormalizedComponent } from "../src/sbom/types.js";

const CVE = "CVE-2026-11111";

function kevEntry(cveId = CVE): KevEntry {
  return {
    cveId,
    vendorProject: "Example",
    product: "example",
    vulnerabilityName: "Example RCE",
    dateAdded: "2026-01-01",
    shortDescription: "test",
  };
}

function advisory(ecosystem: string, name: string, extra: Partial<OsvAffected> = {}): OsvAdvisory {
  return {
    id: "GHSA-test-test-test",
    aliases: [CVE],
    affected: [{ package: { ecosystem, name }, ...extra }],
  };
}

const djangoComponent: NormalizedComponent = {
  purl: "pkg:pypi/django@4.2.0",
  ecosystem: "pypi",
  name: "django",
  version: "4.2.0",
};

describe("osvPackage", () => {
  it("maps generator ecosystems to OSV ecosystem names", () => {
    expect(osvPackage(djangoComponent)).toEqual({ ecosystem: "PyPI", name: "django" });
    expect(osvPackage({ ecosystem: "npm", namespace: "@scope", name: "pkg", version: "1.0.0" })).toEqual({
      ecosystem: "npm",
      name: "@scope/pkg",
    });
  });

  it("falls back to the PURL for components ingested from third-party SBOMs", () => {
    expect(osvPackage({ purl: "pkg:pypi/requests@2.31.0", name: "requests" })).toEqual({ ecosystem: "PyPI", name: "requests" });
    expect(osvPackage({ purl: "pkg:npm/%40scope/pkg@1.0.0", name: "pkg" })).toEqual({ ecosystem: "npm", name: "@scope/pkg" });
  });

  it("returns undefined for ecosystems OSV lookup does not support yet", () => {
    expect(osvPackage({ purl: "pkg:cargo/serde@1.0.0", name: "serde" })).toBeUndefined();
    expect(osvPackage({ name: "no-identity" })).toBeUndefined();
  });

  it("normalizes PyPI keys per PEP 503 and keeps ecosystems apart", () => {
    expect(osvPackageKey({ ecosystem: "PyPI", name: "Typing_Extensions" })).toBe(
      osvPackageKey({ ecosystem: "PyPI", name: "typing.extensions" })
    );
    expect(osvPackageKey({ ecosystem: "PyPI", name: "requests" })).not.toBe(
      osvPackageKey({ ecosystem: "npm", name: "requests" })
    );
  });
});

describe("cross-check across ecosystems", () => {
  it("matches a Python component whose OSV advisory CVE is in KEV", () => {
    const advisories = new Map([[osvPackageKey({ ecosystem: "PyPI", name: "django" }), [advisory("PyPI", "Django")]]]);
    const matches = crossCheckWithAdvisories([djangoComponent], [kevEntry()], advisories);
    expect(matches).toHaveLength(1);
    expect(matches[0].kevEntry.cveId).toBe(CVE);
  });

  it("does not apply an npm package's advisories to a same-named PyPI package", () => {
    const advisories = new Map([[osvPackageKey({ ecosystem: "npm", name: "django" }), [advisory("npm", "django")]]]);
    expect(crossCheckWithAdvisories([djangoComponent], [kevEntry()], advisories)).toHaveLength(0);
  });
});

describe("version status for PyPI findings", () => {
  it("treats an exact hit in OSV's version list as affected even for non-semver versions", () => {
    expect(evaluateVersionStatus("4.2", [{ package: { ecosystem: "PyPI", name: "django" }, versions: ["4.1", "4.2"] }])).toBe("affected");
  });

  it("reports unknown, not not_affected, for a non-semver version missing from the list", () => {
    expect(evaluateVersionStatus("4.2", [{ package: { ecosystem: "PyPI", name: "django" }, versions: ["4.2.0"] }])).toBe("unknown");
  });

  it("enriches a Python match end-to-end with version status and patched version", async () => {
    const pypiAdvisory = advisory("PyPI", "Django", {
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "4.0.0" }, { fixed: "4.2.5" }] }],
    });

    const result = await runKevCheck({
      subjectName: "python-project",
      failOnHigh: true,
      generateComponents: () => [djangoComponent],
      pollKev: async () => ({ count: 1, entries: [kevEntry()], fetchedAt: "2026-10-02T00:00:00Z" }),
      lookupAdvisories: async () => new Map([[osvPackageKey({ ecosystem: "PyPI", name: "django" }), [pypiAdvisory]]]),
      crossCheck: crossCheckWithAdvisories,
      sendAlert: async () => {},
    });

    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].versionStatus).toBe("affected");
    expect(result.matches[0].patchedVersion).toBe("4.2.5");
    expect(result.affectedCount).toBe(1);
    expect(result.status).toBe("failed");
  });
});
