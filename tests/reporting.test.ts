import { describe, expect, it } from "vitest";
import { renderAnnotations, renderSummary, toSarif } from "../src/reporting/report.js";
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
    },
    confidence: "high",
    matchedOn: "purl_ecosystem_name",
    identityConfidence: "high",
    versionStatus: "affected",
    exploitationStatus: "known_exploited",
    advisoryIds: ["GHSA-demo"],
    ...overrides,
  };
}

describe("SBOIM reporting", () => {
  it("renders a readable summary from actual result values", () => {
    const summary = renderSummary(result({
      matches: [
        finding({ versionStatus: "affected" }),
        finding({ versionStatus: "not_affected", confidence: "low", identityConfidence: "low" }),
        finding({ versionStatus: "unknown", kevEntry: { ...finding().kevEntry, cveId: "" }, advisoryIds: [] }),
      ],
      highConfidenceMatchCount: 2,
      lowConfidenceMatchCount: 1,
      warnings: ["Advisory lookup failed"],
      errors: ["Cross-check failed"],
      status: "failed",
    }));

    expect(summary).toContain("# SBOIM Security Scan");
    expect(summary).toContain("| Affected versions | 1 |");
    expect(summary).toContain("| Not affected versions | 1 |");
    expect(summary).toContain("| Unknown versions | 1 |");
    expect(summary).toContain("Signing not configured");
    expect(summary).toContain("KEV entry without CVE");
  });

  it("escapes untrusted Markdown and workflow annotation values", () => {
    const unsafe = finding({
      component: { name: "bad|name`\\", version: "1.0.0\nnext", ecosystem: "npm" },
      kevEntry: { ...finding().kevEntry, vendorProject: "vendor|name", product: "product`", vulnerabilityName: "bad::error\nmessage" },
    });
    const summary = renderSummary(result({ matches: [unsafe] }));
    const annotations = renderAnnotations(result({ matches: [unsafe] }));

    expect(summary).not.toContain("bad|name::warning");
    expect(summary).toContain("bad\\|name\\`\\\\");
    expect(annotations[0]).toContain("%3A");
    expect(annotations[0]).toContain("%0A");
  });

  it("creates valid SARIF for multiple findings and omits a missing CVE rule ID", () => {
    const sarif = toSarif(result({ matches: [finding(), finding({ kevEntry: { ...finding().kevEntry, cveId: "" }, advisoryIds: [] })] }));

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results).toHaveLength(2);
    expect(sarif.runs[0].results[0].ruleId).toBe("CVE-2026-0001");
    expect(sarif.runs[0].results[1]).not.toHaveProperty("ruleId");
    expect(sarif.runs[0].results[0]).not.toHaveProperty("partialFingerprints");
  });

  it("creates an empty SARIF result set when there are no findings", () => {
    expect(toSarif(result()).runs[0].results).toEqual([]);
    expect(renderSummary(result())).toContain("No KEV findings were reported.");
  });

  it("annotates high-confidence findings and failed stages only", () => {
    const scan = result({ matches: [finding({ versionStatus: "not_affected" })], stages: {
      ...result().stages,
      store: { status: "failed", reason: "Upload failed" },
    }});
    const annotations = renderAnnotations(scan);

    expect(annotations).toHaveLength(2);
    expect(annotations[0]).toContain("High-confidence KEV match");
    expect(annotations[1]).toContain("Store stage failed");
  });
});
