import { describe, expect, it } from "vitest";
import { sendCrossCheckAlert } from "../src/alerting/webhook.js";
import type { CrossCheckMatch } from "../src/correlation/matcher.js";

const match: CrossCheckMatch = {
  component: { name: "demo", version: "1.0.0" },
  kevEntry: {
    cveId: "CVE-2026-0001",
    vendorProject: "vendor",
    product: "demo",
    vulnerabilityName: "issue",
    dateAdded: "2026-01-01",
    shortDescription: "issue",
  },
  confidence: "high",
  matchedOn: "vendor_product_name",
};

describe("webhook endpoint validation", () => {
  it("rejects non-loopback HTTP before sending an alert", async () => {
    await expect(sendCrossCheckAlert([match], {
      webhookUrl: "http://hooks.example.test/alert",
      subjectName: "demo",
    })).rejects.toThrow(/HTTPS/);
  });

  it("rejects embedded webhook credentials", async () => {
    await expect(sendCrossCheckAlert([match], {
      webhookUrl: "https://user:secret@hooks.example.test/alert",
      subjectName: "demo",
    })).rejects.toThrow(/embedded credentials/);
  });
});
