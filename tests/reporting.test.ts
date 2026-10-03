import { describe, expect, it } from "vitest";
import { renderAnnotations, renderSummary, toSarif } from "../src/reporting/report.js";
import { parseSboimResult } from "../src/reporting/input.js";
import type { SecurityFinding, SboimResult } from "../src/vulnerability/types.js";

function result(overrides: Partial<SboimResult> = {}): SboimResult {
  return {
    schemaVersion: "1.0",
    status: "passed",
    subjectName: "demo-project",
    sbomComponentCount: 3,
    kevSnapshot: { entryCount: 2, fetchedAt: "2026-09-14T00:00:00.000Z" },
    matches: [],
    highConfidenceMatchCount: 0,
    lowConfidenceMatchCount: 0,
    affectedCount: 0,
    notAffectedCount: 0,
    unknownCount: 0,
    warnings: [],
    errors: [],
    stages: {
      generate: { status: "succeeded" },
      sign: { status: "skipped", reason: "Signing not configured" },
      store: { status: "skipped", reason: "Storage not configured" },
      pollKev: { status: "succeeded" },
      crossCheck: { status: "succeeded" },
      alert: { status: "skipped", reason: "Webhook not configured" },
    },
    ...overrides,
  };
}

function finding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    component: { name: "demo", version: "1.2.3", ecosystem: "npm", purl: "pkg:npm/demo@1.2.3" },
    kevEntry: {
      cveId: "CVE-2026-0001",
      vendorProject: "Demo vendor",
      product: "demo",
      vulnerabilityName: "Demo issue",
      dateAdded: "2026-01-01",
      shortDescription: "Demo description",
      requiredAction: "Apply updates per vendor instructions.",
    },
    confidence: "high",
    matchedOn: "cve_from_osv",
    identityConfidence: "high",
    versionStatus: "affected",
    exploitationStatus: "known_exploited",
    advisoryIds: ["GHSA-demo"],
    patchedVersion: "1.2.4",
    ...overrides,
  };
}

const manifests = { npm: "package-lock.json", pypi: "uv.lock" };

describe("Markdown summary", () => {
  it("renders counts, pipeline stages and findings from the result", () => {
    const summary = renderSummary(result({
      matches: [
        finding({ versionStatus: "not_affected" }),
        finding({ versionStatus: "affected" }),
        finding({ versionStatus: "unknown", kevEntry: { ...finding().kevEntry, cveId: "" }, advisoryIds: [] }),
      ],
      affectedCount: 1,
      notAffectedCount: 1,
      unknownCount: 1,
    }));

    expect(summary).toContain("# Osprey: known exploited vulnerabilities");
    expect(summary).toContain("| Affected (installed version vulnerable) | 1 |");
    expect(summary).toContain("| Not affected (patched) | 1 |");
    expect(summary).toContain("Signing not configured");
    expect(summary).toContain("KEV entry without CVE");
    // Most urgent first, regardless of input order.
    expect(summary.indexOf("| affected |")).toBeLessThan(summary.indexOf("| not_affected |"));
    expect(summary).toContain("| 1.2.4 |");
  });

  it("reports FAILED when an installed version is affected, even without --fail-on-high", () => {
    // status "passed" is what cra writes when --fail-on-high is not set.
    const summary = renderSummary(result({ status: "passed", matches: [finding()], affectedCount: 1 }));
    expect(summary).toContain("## Overall status: FAILED");
    expect(summary).not.toContain("PASSED");
  });

  it("reports PASSED when every match is patched", () => {
    const summary = renderSummary(result({ matches: [finding({ versionStatus: "not_affected" })], notAffectedCount: 1 }));
    expect(summary).toContain("## Overall status: PASSED");
  });

  it("never presents an incomplete audit as clean", () => {
    const summary = renderSummary(result({
      status: "failed",
      errors: ["OSV advisory lookup failed"],
      stages: { ...result().stages, crossCheck: { status: "failed", reason: "OSV advisory lookup failed" } },
    }));
    expect(summary).toContain("## Overall status: FAILED (audit incomplete)");
    expect(summary).toContain("not a clean result");
    expect(summary).not.toContain("No KEV findings were reported.");
  });

  it("escapes untrusted Markdown, including HTML", () => {
    const unsafe = finding({ component: { name: "bad|name`\\<img src=x>", version: "1.0.0\nnext", ecosystem: "npm" } });
    const summary = renderSummary(result({ matches: [unsafe] }));
    expect(summary).toContain("bad\\|name\\`\\\\&lt;img src=x&gt;");
    expect(summary).not.toContain("<img");
    expect(summary).not.toContain("1.0.0\nnext");
  });
});

describe("SARIF", () => {
  it("attaches each finding to its ecosystem's dependency file", () => {
    const sarif = toSarif(result({
      matches: [finding(), finding({ component: { name: "django", version: "4.2.0", ecosystem: "pypi" } })],
    }), manifests);
    const uris = sarif.runs[0].results.map((r) => r.locations[0].physicalLocation.artifactLocation.uri);
    expect(uris).toEqual(["package-lock.json", "uv.lock"]);
  });

  it("falls back to the PURL type, then any manifest, so no result lacks a location", () => {
    const purlOnly = finding({ component: { name: "django", version: "4.2.0", purl: "pkg:pypi/django@4.2.0" } });
    const unknown = finding({ component: { name: "mystery" } });
    const results = toSarif(result({ matches: [purlOnly, unknown] }), { npm: "package-lock.json" }).runs[0].results;
    expect(results[0].locations[0].physicalLocation.artifactLocation.uri).toBe("package-lock.json");
    expect(toSarif(result({ matches: [unknown] }), {}).runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe(".");
  });

  it("maps version status to level: only an affected install is an error", () => {
    const levels = toSarif(result({
      matches: [finding({ versionStatus: "affected" }), finding({ versionStatus: "unknown" }), finding({ versionStatus: "not_affected" })],
    }), manifests).runs[0].results.map((r) => r.level);
    expect(levels).toEqual(["error", "warning", "note"]);
  });

  it("defines one rule per CVE with KEV details, and omits the rule ID when there is no CVE", () => {
    const sarif = toSarif(result({ matches: [finding(), finding(), finding({ kevEntry: { ...finding().kevEntry, cveId: "" }, advisoryIds: [] })] }), manifests);
    const run = sarif.runs[0];
    expect(sarif.version).toBe("2.1.0");
    expect(run.tool.driver.name).toBe("Osprey");
    expect(run.tool.driver.informationUri).toBe("https://github.com/Purplelotusec/Osprey");
    expect(run.tool.driver.rules).toHaveLength(1);
    expect(run.tool.driver.rules[0]).toMatchObject({
      id: "CVE-2026-0001",
      helpUri: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
      help: { text: "Apply updates per vendor instructions." },
    });
    expect(run.results[0].ruleId).toBe("CVE-2026-0001");
    expect(run.results[2]).not.toHaveProperty("ruleId");
  });

  it("creates an empty result set when there are no findings", () => {
    const run = toSarif(result(), manifests).runs[0];
    expect(run.results).toEqual([]);
    expect(run.tool.driver.rules).toEqual([]);
  });
});

describe("workflow annotations", () => {
  it("flags affected and unknown findings and failed stages, but not patched packages", () => {
    const annotations = renderAnnotations(result({
      matches: [finding({ versionStatus: "not_affected" }), finding({ versionStatus: "unknown" }), finding({ versionStatus: "affected" })],
      stages: { ...result().stages, store: { status: "failed", reason: "Upload failed" } },
    }));
    expect(annotations).toHaveLength(3);
    expect(annotations[0]).toMatch(/^::error title=Exploited vulnerability in installed dependency::/);
    expect(annotations[1]).toMatch(/^::warning title=Exploited vulnerability%2C version status unknown::/);
    expect(annotations[2]).toBe("::error title=Store stage failed::Upload failed");
  });

  it("escapes newlines so untrusted values cannot inject workflow commands", () => {
    const unsafe = finding({ kevEntry: { ...finding().kevEntry, vulnerabilityName: "x\n::set-output name=pwned::1" } });
    const [annotation] = renderAnnotations(result({ matches: [unsafe] }));
    expect(annotation).not.toContain("\n");
    expect(annotation).toContain("%0A::set-output");
  });

  it("keeps ':' readable in message data (only properties need it escaped)", () => {
    const [annotation] = renderAnnotations(result({ matches: [finding()] }));
    expect(annotation).toContain("(Demo vendor demo: Demo issue)");
  });
});

describe("result input validation", () => {
  it("rejects malformed results before rendering, naming the bad field", () => {
    expect(() => parseSboimResult({ status: "passed" })).toThrow(/Invalid Osprey result/);
    expect(() => parseSboimResult({ ...result(), affectedCount: -1 })).toThrow(/affectedCount/);
  });

  it("accepts a current result and one from the earlier name-based matcher", () => {
    expect(parseSboimResult(result({ matches: [finding()] })).matches).toHaveLength(1);
    const legacy = { ...result(), matches: [{ ...finding(), confidence: "low", identityConfidence: "low", matchedOn: "vendor_product_name" }] };
    expect(() => parseSboimResult(legacy)).not.toThrow();
  });
});

describe("Markdown injection (review finding 5)", () => {
  it("renders links, images and emphasis from untrusted values as literal text", () => {
    const summary = renderSummary(result({
      warnings: ["see [docs](https://evil.example) and ![img](https://evil.example/x.png) **now**"],
      matches: [finding({ component: { name: "[click me](https://evil.example)", version: "1.0.0", ecosystem: "npm" } })],
    }));
    expect(summary).not.toContain("| [click me](");
    expect(summary).toContain("\\[click me\\]\\(https://evil.example\\)");
    expect(summary).toContain("\\!\\[img\\]");
    expect(summary).toContain("\\*\\*now\\*\\*");
  });
});

describe("SARIF artifact URIs (finding E)", () => {
  const uriFor = (path: string) => toSarif(result({ matches: [finding()] }), { npm: path }).runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;

  it("percent-encodes path segments, keeping '/' as the separator", () => {
    expect(uriFor("my app/package-lock.json")).toBe("my%20app/package-lock.json");
    expect(uriFor("services/web#1/[legacy]/package-lock.json")).toBe("services/web%231/%5Blegacy%5D/package-lock.json");
    expect(uriFor("frontend/ünïcode/package-lock.json")).toBe("frontend/%C3%BCn%C3%AFcode/package-lock.json");
  });

  it("leaves ordinary paths unchanged", () => {
    expect(uriFor("package-lock.json")).toBe("package-lock.json");
    expect(uriFor("apps/web-ui/package-lock.json")).toBe("apps/web-ui/package-lock.json");
  });
});
