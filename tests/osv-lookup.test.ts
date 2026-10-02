import { afterEach, describe, it, expect, vi } from "vitest";
import { fetchWithConcurrencyLimit, lookupOsvAdvisories, osvPackageKey } from "../src/vulnerability/osv.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("fetchWithConcurrencyLimit", () => {
  it("returns every result, in input order, even when later calls finish first", async () => {
    const items = Array.from({ length: 50 }, (_, i) => i);
    // Earlier items take longest, so completion order is the reverse of input order.
    const results = await fetchWithConcurrencyLimit(items, async (i) => {
      await sleep(50 - i);
      return i * 2;
    }, 20);
    expect(results).toEqual(items.map((i) => i * 2));
  });

  it("never runs more than the configured number of calls at once", async () => {
    let inFlight = 0;
    let peak = 0;
    await fetchWithConcurrencyLimit(Array.from({ length: 60 }, (_, i) => i), async (i) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await sleep(i % 7);
      inFlight -= 1;
    }, 5);
    expect(peak).toBe(5);
  });

  it("rejects instead of resolving with a partial result set", async () => {
    await expect(
      fetchWithConcurrencyLimit([1, 2, 3, 4], async (i) => {
        await sleep(i);
        if (i === 3) throw new Error("boom");
        return i;
      }, 2)
    ).rejects.toThrow("boom");
  });

  it("handles an empty input", async () => {
    expect(await fetchWithConcurrencyLimit([], async () => 1, 20)).toEqual([]);
  });
});

describe("lookupOsvAdvisories", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("keeps every advisory OSV reports, not just the first concurrency-sized batch", async () => {
    const ids = Array.from({ length: 120 }, (_, i) => `GHSA-test-${String(i).padStart(4, "0")}`);

    vi.stubGlobal("fetch", async (input: string | URL) => {
      const url = String(input);
      if (url.endsWith("/querybatch")) {
        return Response.json({ results: [{ vulns: ids.map((id) => ({ id })) }] });
      }
      const id = decodeURIComponent(url.split("/").pop()!);
      // Variable latency so requests complete out of order, as they do against the real API.
      await sleep(Number(id.slice(-2)) % 9);
      return Response.json({ id, aliases: [`CVE-2026-${id.slice(-4)}`] });
    });

    const result = await lookupOsvAdvisories([{ ecosystem: "pypi", name: "django", version: "3.2.0", purl: "pkg:pypi/django@3.2.0" }]);
    const advisories = result.advisories.get(osvPackageKey({ ecosystem: "PyPI", name: "django" })) ?? [];

    expect(advisories.map((advisory) => advisory.id).sort()).toEqual(ids);
  });
});

describe("OSV batch responses (review findings 1 and 2)", () => {
  afterEach(() => vi.unstubAllGlobals());
  const django = { ecosystem: "pypi", name: "django", version: "3.2.0", purl: "pkg:pypi/django@3.2.0" };
  const lodash = { ecosystem: "npm", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" };

  function stubBatch(respond: (queries: Array<{ package: { name: string }; page_token?: string }>) => unknown): void {
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      if (String(input).endsWith("/querybatch")) return Response.json(respond(JSON.parse(String(init?.body)).queries));
      return Response.json({ id: decodeURIComponent(String(input).split("/").pop()!) });
    });
  }

  it("rejects a response without results instead of reading it as 'no vulnerabilities'", async () => {
    stubBatch(() => ({}));
    await expect(lookupOsvAdvisories([django])).rejects.toThrow(/OSV query response did not match the expected schema: results/);
  });

  it("rejects a response with fewer results than queries", async () => {
    stubBatch(() => ({ results: [{ vulns: [{ id: "GHSA-1" }] }] }));
    await expect(lookupOsvAdvisories([django, lodash])).rejects.toThrow(/OSV returned 1 results for 2 queries/);
  });

  it("accepts an empty per-package result: that package genuinely has no advisories", async () => {
    stubBatch((queries) => ({ results: queries.map(() => ({})) }));
    const { advisories } = await lookupOsvAdvisories([django]);
    expect(advisories.get(osvPackageKey({ ecosystem: "PyPI", name: "django" }))).toEqual([]);
  });

  it("follows next_page_token until every page of advisories is collected", async () => {
    const seenTokens: Array<string | undefined> = [];
    stubBatch((queries) => ({
      results: queries.map((q) => {
        seenTokens.push(q.page_token);
        if (!q.page_token) return { vulns: [{ id: "GHSA-page1" }], next_page_token: "p2" };
        if (q.page_token === "p2") return { vulns: [{ id: "GHSA-page2" }], next_page_token: "p3" };
        return { vulns: [{ id: "GHSA-page3" }] };
      }),
    }));
    const { advisories } = await lookupOsvAdvisories([django]);
    expect(advisories.get(osvPackageKey({ ecosystem: "PyPI", name: "django" }))?.map((a) => a.id)).toEqual(["GHSA-page1", "GHSA-page2", "GHSA-page3"]);
    expect(seenTokens).toEqual([undefined, "p2", "p3"]);
  });

  it("gives up on a server that never stops paginating", async () => {
    let page = 0;
    stubBatch((queries) => ({ results: queries.map(() => ({ vulns: [], next_page_token: `t${++page}` })) }));
    await expect(lookupOsvAdvisories([django])).rejects.toThrow(/more than 50 pages of advisories for django \(PyPI\)/);
  });
});
