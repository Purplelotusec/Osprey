import { afterEach, describe, expect, it, vi } from "vitest";
import { lookupOsvAdvisories } from "../src/vulnerability/osv.js";

describe("OSV advisory lookup", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("deduplicates repeated npm package identities in one batch", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ results: [
        { vulns: [{ id: "OSV-1" }] },
        { vulns: [{ id: "OSV-1" }] },
      ] })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: "OSV-1", affected: [] })));
    vi.stubGlobal("fetch", fetchMock);

    const advisories = await lookupOsvAdvisories([
      { purl: "pkg:npm/demo@1.0.0", name: "demo", version: "1.0.0" },
      { purl: "pkg:npm/demo@2.0.0", name: "demo", version: "2.0.0" },
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(advisories.get("demo")?.[0].id).toBe("OSV-1");
  });
});