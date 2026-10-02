import { afterEach, describe, it, expect, vi } from "vitest";
import { printAuditReport, printAuditSummary } from "../src/output/audit-report.js";
import type { SboimResult } from "../src/vulnerability/types.js";

function captureOutput(print: () => void): string {
  const lines: string[] = [];
  const spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    lines.push(args.join(" "));
  });
  try {
    print();
  } finally {
    spy.mockRestore();
  }
  // Strip ANSI colour codes so assertions read like the terminal does.
  return lines.join("\n").replace(/\x1b\[[0-9;]*m/g, "");
}

function result(overrides: Partial<SboimResult> = {}): SboimResult {
  return {
    schemaVersion: "1.0",
    status: "passed",
    subjectName: "subject",
    sbomComponentCount: 10,
    kevSnapshot: { entryCount: 1, fetchedAt: "2026-10-02T00:00:00Z" },
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
      sign: { status: "skipped" },
      store: { status: "skipped" },
      pollKev: { status: "succeeded" },
      crossCheck: { status: "succeeded" },
      alert: { status: "skipped" },
    },
    ...overrides,
  };
}

const failedGenerate = (): SboimResult =>
  result({
    status: "failed",
    sbomComponentCount: 0,
    errors: ["No supported package file found in owner/repo."],
    stages: { ...result().stages, generate: { status: "failed", reason: "No supported package file found" }, pollKev: { status: "skipped" }, crossCheck: { status: "skipped" } },
  });

describe("audit report for an incomplete run", () => {
  afterEach(() => vi.restoreAllMocks());

  it("never claims a clean result or PASSED when a stage failed", () => {
    const output = captureOutput(() => printAuditReport(failedGenerate()));
    expect(output).not.toContain("No vulnerabilities found");
    expect(output).not.toContain("PASSED");
    expect(output).toContain("Audit incomplete");
    expect(output).toContain("FAILED (audit incomplete)");
    expect(output).toContain("No supported package file found");
  });

  it("summary mode reports the failure and its errors instead of a clean result", () => {
    const output = captureOutput(() => printAuditSummary(failedGenerate()));
    expect(output).not.toContain("No active exploitable vulnerabilities detected");
    expect(output).toContain("Audit incomplete");
    expect(output).toContain("No supported package file found");
  });

  it("summary mode still shows warnings, e.g. that cached data was used", () => {
    const output = captureOutput(() => printAuditSummary(result({ warnings: ["Offline: using cached OSV advisories from 2026-10-01"] })));
    expect(output).toContain("No active exploitable vulnerabilities detected");
    expect(output).toContain("Offline: using cached OSV advisories from 2026-10-01");
  });

  it("still reports a genuinely clean run as clean", () => {
    expect(captureOutput(() => printAuditReport(result(), { verbose: true }))).toContain("PASSED");
    expect(captureOutput(() => printAuditSummary(result()))).toContain("No active exploitable vulnerabilities detected");
  });
});
