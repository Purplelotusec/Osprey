import { afterEach, describe, it, expect, vi } from "vitest";
import { sendCrossCheckAlert } from "../src/alerting/webhook.js";
import type { SecurityFinding, VersionStatus } from "../src/vulnerability/types.js";

function finding(name: string, versionStatus: VersionStatus, namespace?: string): SecurityFinding {
  return {
    component: { ecosystem: "npm", namespace, name, version: "1.0.0" },
    kevEntry: {
      cveId: `CVE-2026-${name.length}`,
      vendorProject: "Example",
      product: name,
      vulnerabilityName: `${name} RCE`,
      dateAdded: "2026-01-01",
      shortDescription: "test",
    },
    confidence: "high",
    matchedOn: "cve_from_osv",
    identityConfidence: "high",
    versionStatus,
    exploitationStatus: "known_exploited",
    advisoryIds: [],
  };
}

function captureWebhook(): () => string {
  let body = "";
  vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
    body = JSON.parse(String(init.body)).text;
    return new Response("ok");
  });
  return () => body;
}

afterEach(() => vi.unstubAllGlobals());

describe("webhook alert", () => {
  it("groups findings by whether the installed version is affected, most urgent first", async () => {
    const sent = captureWebhook();
    await sendCrossCheckAlert(
      [finding("patched-lib", "not_affected"), finding("bad-lib", "affected"), finding("unclear-lib", "unknown")],
      { webhookUrl: "https://hooks.example/x", subjectName: "my-app" }
    );
    const text = sent();
    expect(text).toContain("Osprey — known exploited vulnerabilities: my-app");
    expect(text.indexOf("1 affected")).toBeLessThan(text.indexOf("1 unknown"));
    expect(text.indexOf("1 unknown")).toBeLessThan(text.indexOf("1 patched"));
    expect(text).not.toMatch(/low-confidence|CRA Guard/);
  });

  it("shows scoped npm names in full and summarizes long groups", async () => {
    const sent = captureWebhook();
    const many = Array.from({ length: 12 }, (_, i) => finding(`lib${i}`, "affected"));
    await sendCrossCheckAlert([finding("core", "affected", "@acme"), ...many], { webhookUrl: "https://hooks.example/x", subjectName: "s" });
    expect(sent()).toContain("`@acme/core@1.0.0`");
    expect(sent()).toContain("…and 3 more");
  });

  it("sends nothing when there are no findings", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    await sendCrossCheckAlert([], { webhookUrl: "https://hooks.example/x", subjectName: "s" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
