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
    const advisories = result.get(osvPackageKey({ ecosystem: "PyPI", name: "django" })) ?? [];

    expect(advisories.map((advisory) => advisory.id).sort()).toEqual(ids);
  });
});
