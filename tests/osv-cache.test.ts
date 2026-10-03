import { afterEach, describe, it, expect, vi } from "vitest";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createOsvAdvisoryFetcher, readOsvCache } from "../src/vulnerability/osv-cache.js";
import { osvPackageKey } from "../src/vulnerability/osv.js";
import { runKevCheck } from "../src/vulnerability/check.js";
import { crossCheckWithAdvisories } from "../src/correlation/matcher.js";
import type { NormalizedComponent } from "../src/sbom/types.js";

const django = (version = "3.2.0"): NormalizedComponent => ({ ecosystem: "pypi", name: "django", version, purl: `pkg:pypi/django@${version}` });
const lodash: NormalizedComponent = { ecosystem: "npm", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" };
const djangoKey = osvPackageKey({ ecosystem: "PyPI", name: "django" });

/** A fake OSV: django has one advisory aliasing a KEV CVE; lodash has none. */
const ADVISORY = {
  id: "GHSA-test-0001",
  aliases: ["CVE-2026-11111"],
  affected: [{ package: { ecosystem: "PyPI", name: "django" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.0.0" }] }] }],
};
function stubOsv(): { calls: () => number } {
  let calls = 0;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    calls += 1;
    const url = String(input);
    if (url.endsWith("/querybatch")) {
      const queries = JSON.parse(String(init?.body)).queries as Array<{ package: { name: string } }>;
      return Response.json({ results: queries.map((q) => (q.package.name === "django" ? { vulns: [{ id: ADVISORY.id }] } : {})) });
    }
    return Response.json(ADVISORY);
  });
  return { calls: () => calls };
}
function stubOsvDown(): void {
  vi.stubGlobal("fetch", async () => new Response("unavailable", { status: 400, statusText: "Bad Request" }));
}

let dir: string;
const cachePath = () => join(dir, "osv-cache.json");
afterEach(() => {
  vi.unstubAllGlobals();
  if (dir) rmSync(dir, { recursive: true, force: true });
});
function freshDir(): void {
  dir = mkdtempSync(join(tmpdir(), "osprey-osv-cache-"));
}

describe("OSV cache: online", () => {
  it("queries OSV and records the results in a valid cache, atomically", async () => {
    freshDir();
    stubOsv();
    const lookup = await createOsvAdvisoryFetcher({ cachePath: cachePath() })([django(), lodash]);
    expect(lookup.advisories.get(djangoKey)?.map((a) => a.id)).toEqual(["GHSA-test-0001"]);
    expect(lookup.warnings).toEqual([]);

    const cache = readOsvCache(cachePath());
    expect(Object.keys(cache.packages).sort()).toEqual([djangoKey, osvPackageKey({ ecosystem: "npm", name: "lodash" })].sort());
    expect(cache.advisories["GHSA-test-0001"].aliases).toEqual(["CVE-2026-11111"]);
    expect(readdirSync(dir)).toEqual(["osv-cache.json"]);
  });

  it("always fetches fresh online, even when the cache already has the package", async () => {
    freshDir();
    const osv = stubOsv();
    const fetcher = createOsvAdvisoryFetcher({ cachePath: cachePath() });
    await fetcher([django()]);
    const first = osv.calls();
    await fetcher([django()]);
    expect(osv.calls()).toBe(first * 2);
  });

  it("falls back to a complete cache when OSV is unreachable, with a warning", async () => {
    freshDir();
    stubOsv();
    await createOsvAdvisoryFetcher({ cachePath: cachePath() })([django()]);
    stubOsvDown();
    const lookup = await createOsvAdvisoryFetcher({ cachePath: cachePath() })([django()]);
    expect(lookup.advisories.get(djangoKey)).toHaveLength(1);
    expect(lookup.warnings).toEqual([expect.stringMatching(/OSV lookup failed \(HTTP 400.*using cached OSV advisories from .*Results may be stale/)]);
  });

  it("does not fall back to a cache that is missing any package", async () => {
    freshDir();
    stubOsv();
    await createOsvAdvisoryFetcher({ cachePath: cachePath() })([django()]);
    stubOsvDown();
    await expect(createOsvAdvisoryFetcher({ cachePath: cachePath() })([django(), lodash])).rejects.toThrow(
      /OSV lookup failed \(HTTP 400.*the OSV cache can't stand in: the OSV cache has no advisories for 1 package\(s\): lodash \(npm\)/
    );
  });

  it("without any cache, an OSV failure propagates (and fails the audit)", async () => {
    freshDir();
    stubOsvDown();
    await expect(createOsvAdvisoryFetcher({ cachePath: cachePath() })([django()])).rejects.toThrow(/HTTP 400/);
  });

  it("rebuilds a corrupt cache from fresh results instead of failing the run", async () => {
    freshDir();
    writeFileSync(cachePath(), "{ truncated");
    stubOsv();
    const lookup = await createOsvAdvisoryFetcher({ cachePath: cachePath() })([django()]);
    expect(lookup.warnings).toEqual([expect.stringMatching(/OSV cache .* is unusable \(not valid JSON.*rebuilt it/)]);
    expect(() => readOsvCache(cachePath())).not.toThrow();
  });
});

describe("OSV cache: offline", () => {
  it("audits from the cache without any network request", async () => {
    freshDir();
    stubOsv();
    await createOsvAdvisoryFetcher({ cachePath: cachePath() })([django()]);
    const network = vi.fn(async () => { throw new Error("network used offline"); });
    vi.stubGlobal("fetch", network);

    const lookup = await createOsvAdvisoryFetcher({ cachePath: cachePath(), offline: true })([django()]);
    expect(lookup.advisories.get(djangoKey)).toHaveLength(1);
    expect(lookup.warnings).toEqual([expect.stringContaining("Offline: using cached OSV advisories from")]);
    expect(network).not.toHaveBeenCalled();
  });

  it("serves any version of a cached package (OSV queries are version-independent)", async () => {
    freshDir();
    stubOsv();
    await createOsvAdvisoryFetcher({ cachePath: cachePath() })([django("3.2.0")]);
    const lookup = await createOsvAdvisoryFetcher({ cachePath: cachePath(), offline: true })([django("4.1.0")]);
    expect(lookup.advisories.get(djangoKey)).toHaveLength(1);
  });

  it("fails, naming the packages, when any package is not cached", async () => {
    freshDir();
    stubOsv();
    await createOsvAdvisoryFetcher({ cachePath: cachePath() })([django()]);
    await expect(createOsvAdvisoryFetcher({ cachePath: cachePath(), offline: true })([django(), lodash])).rejects.toThrow(
      /Offline audit not possible: the OSV cache has no advisories for 1 package\(s\): lodash \(npm\)\. Run once online/
    );
  });

  it("treats a package whose advisories are missing from the cache as not cached", async () => {
    freshDir();
    writeFileSync(cachePath(), JSON.stringify({
      version: 1,
      packages: { [djangoKey]: { vulnIds: ["GHSA-test-0001"], fetchedAt: "2026-10-01T00:00:00.000Z" } },
      advisories: {},
    }));
    await expect(createOsvAdvisoryFetcher({ cachePath: cachePath(), offline: true })([django()])).rejects.toThrow(/no advisories for 1 package/);
  });

  it("requires a cache file, and refuses a corrupt one", async () => {
    freshDir();
    await expect(createOsvAdvisoryFetcher({ cachePath: cachePath(), offline: true })([django()])).rejects.toThrow(/--offline requires an OSV cache/);
    writeFileSync(cachePath(), JSON.stringify({ version: 2 }));
    await expect(createOsvAdvisoryFetcher({ cachePath: cachePath(), offline: true })([django()])).rejects.toThrow(/OSV cache .* is unusable/);
  });

  it("end to end: an offline audit finds the exploited CVE and reports that it used the cache", async () => {
    freshDir();
    stubOsv();
    await createOsvAdvisoryFetcher({ cachePath: cachePath() })([django()]);
    vi.stubGlobal("fetch", async () => { throw new Error("offline"); });

    const result = await runKevCheck({
      subjectName: "app",
      failOnHigh: true,
      generateComponents: () => [django()],
      pollKev: async () => ({
        count: 1,
        fetchedAt: "2026-10-01T00:00:00.000Z",
        entries: [{ cveId: "CVE-2026-11111", vendorProject: "Django", product: "Django", vulnerabilityName: "RCE", dateAdded: "2026-01-01", shortDescription: "t" }],
      }),
      lookupAdvisories: createOsvAdvisoryFetcher({ cachePath: cachePath(), offline: true }),
      crossCheck: crossCheckWithAdvisories,
      sendAlert: async () => {},
    });
    expect(result.matches.map((m) => `${m.component.name}@${m.component.version} ${m.kevEntry.cveId} ${m.versionStatus}`)).toEqual([
      "django@3.2.0 CVE-2026-11111 affected",
    ]);
    expect(result.status).toBe("failed"); // --fail-on-high with an affected version
    expect(result.warnings).toEqual([expect.stringContaining("Offline: using cached OSV advisories")]);
    expect(existsSync(cachePath())).toBe(true);
    expect(JSON.parse(readFileSync(cachePath(), "utf-8")).version).toBe(1);
  });
});

describe("OSV cache is never poisoned by a bad response (review finding 1)", () => {
  it("does not record anything when OSV's response is unusable", async () => {
    freshDir();
    vi.stubGlobal("fetch", async () => Response.json({}));
    await expect(createOsvAdvisoryFetcher({ cachePath: cachePath() })([django()])).rejects.toThrow(/expected schema/);
    expect(existsSync(cachePath())).toBe(false);
  });
});

describe("OSV cache fallback: real cause and maximum age (findings D and F)", () => {
  const DAY = 24 * 60 * 60 * 1000;
  function cacheFor(fetchedAt: string): string {
    return JSON.stringify({
      version: 1,
      packages: { [djangoKey]: { vulnIds: [ADVISORY.id], fetchedAt } },
      advisories: { [ADVISORY.id]: ADVISORY },
    });
  }

  it("reports both the OSV failure and the unusable cache", async () => {
    freshDir();
    writeFileSync(cachePath(), "{ corrupt");
    stubOsvDown();
    await expect(createOsvAdvisoryFetcher({ cachePath: cachePath() })([django()])).rejects.toThrow(
      /^OSV lookup failed \(HTTP 400.*\), and the OSV cache can't stand in: OSV cache at .* is unusable/
    );
  });

  it("refuses fallback OSV data older than the limit", async () => {
    freshDir();
    writeFileSync(cachePath(), cacheFor(new Date(Date.now() - 30 * DAY).toISOString()));
    stubOsvDown();
    await expect(createOsvAdvisoryFetcher({ cachePath: cachePath(), maxFallbackAgeMs: 7 * DAY })([django()])).rejects.toThrow(
      /cached OSV data is 30\.0 days old, past the 7\.0 days limit/
    );
  });

  it("allows fallback OSV data within the limit", async () => {
    freshDir();
    writeFileSync(cachePath(), cacheFor(new Date(Date.now() - 1 * DAY).toISOString()));
    stubOsvDown();
    const lookup = await createOsvAdvisoryFetcher({ cachePath: cachePath(), maxFallbackAgeMs: 7 * DAY })([django()]);
    expect(lookup.warnings).toEqual([expect.stringContaining("Results may be stale")]);
  });

  it("does not limit explicit --offline", async () => {
    freshDir();
    writeFileSync(cachePath(), cacheFor(new Date(Date.now() - 90 * DAY).toISOString()));
    const lookup = await createOsvAdvisoryFetcher({ cachePath: cachePath(), offline: true, maxFallbackAgeMs: 7 * DAY })([django()]);
    expect(lookup.advisories.get(djangoKey)).toHaveLength(1);
  });
});
