import { afterEach, describe, it, expect, vi } from "vitest";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pollKev, readCache } from "../src/vulnerability/kev.js";
import type { KevSnapshot } from "../src/vulnerability/types.js";

const feedEntry = {
  cveID: "CVE-2026-00001",
  vendorProject: "Acme",
  product: "Widget",
  vulnerabilityName: "Acme Widget RCE",
  dateAdded: "2026-01-01",
  shortDescription: "test",
  requiredAction: "Apply updates.",
};

const snapshot: KevSnapshot = {
  catalogVersion: "2026.10.01",
  count: 1,
  fetchedAt: "2026-10-01T00:00:00.000Z",
  entries: [{
    cveId: "CVE-2026-00001",
    vendorProject: "Acme",
    product: "Widget",
    vulnerabilityName: "Acme Widget RCE",
    dateAdded: "2026-01-01",
    shortDescription: "test",
  }],
};

let dir: string;
const cachePath = () => join(dir, "kev-cache.json");
function writeCacheFile(content: unknown): void {
  writeFileSync(cachePath(), typeof content === "string" ? content : JSON.stringify(content));
}
function stubFeed(body: unknown, status = 200): void {
  vi.stubGlobal("fetch", async () => new Response(JSON.stringify(body), { status }));
}

afterEach(() => {
  vi.unstubAllGlobals();
  if (dir) rmSync(dir, { recursive: true, force: true });
});
function freshDir(): void {
  dir = mkdtempSync(join(tmpdir(), "osprey-kev-"));
}

describe("KEV cache validation", () => {
  it("accepts a well-formed cache", () => {
    freshDir();
    writeCacheFile(snapshot);
    expect(readCache(cachePath()).entries).toHaveLength(1);
  });

  it.each([
    ["truncated JSON", '{"count": 1, "entries": [', /not valid JSON/],
    ["a foreign JSON file", { name: "some-other-tool" }, /unexpected structure/],
    ["an entry missing its CVE", { ...snapshot, entries: [{ ...snapshot.entries[0], cveId: "" }] }, /entries\.0\.cveId/],
    ["an empty catalog", { ...snapshot, count: 0, entries: [] }, /contains no KEV entries/],
    ["a count that disagrees with the entries", { ...snapshot, count: 1500 }, /records 1500 entries but contains 1/],
    ["a non-date fetchedAt", { ...snapshot, fetchedAt: "yesterday" }, /fetchedAt/],
  ])("rejects %s with a clear, actionable error", (_label, content, message) => {
    freshDir();
    writeCacheFile(content);
    expect(() => readCache(cachePath())).toThrow(message);
    expect(() => readCache(cachePath())).toThrow(/Delete it and run once online/);
  });
});

describe("pollKev", () => {
  it("offline: refuses a corrupt cache instead of auditing against it", async () => {
    freshDir();
    writeCacheFile({ ...snapshot, count: 0, entries: [] });
    await expect(pollKev({ cachePath: cachePath(), offline: true })).rejects.toThrow(/contains no KEV entries/);
  });

  it("offline: reports the cache's age as a result warning", async () => {
    freshDir();
    writeCacheFile(snapshot);
    const result = await pollKev({ cachePath: cachePath(), offline: true });
    expect(result.warnings).toEqual([expect.stringContaining("Offline: using cached KEV snapshot from 2026-10-01T00:00:00.000Z")]);
  });

  it("falls back to a valid cache when the live fetch fails, with a warning", async () => {
    freshDir();
    writeCacheFile(snapshot);
    stubFeed({}, 503);
    const result = await pollKev({ cachePath: cachePath() });
    expect(result.entries).toHaveLength(1);
    expect(result.warnings).toEqual([expect.stringMatching(/Live KEV fetch failed \(HTTP 503.*Results may be stale/)]);
  });

  it("treats an empty live feed as a failure, never as 'nothing is exploited'", async () => {
    freshDir();
    stubFeed({ vulnerabilities: [] });
    await expect(pollKev({ cachePath: cachePath() })).rejects.toThrow(/KEV feed contained no vulnerabilities/);
    expect(existsSync(cachePath())).toBe(false); // and it must not be cached
  });

  it("writes a cache that validates, atomically (no temp files left behind)", async () => {
    freshDir();
    stubFeed({ catalogVersion: "2026.10.02", dateReleased: "2026-10-02", vulnerabilities: [feedEntry] });
    const result = await pollKev({ cachePath: cachePath() });
    expect(result.warnings).toBeUndefined();
    expect(readCache(cachePath()).entries[0].cveId).toBe("CVE-2026-00001");
    expect(readdirSync(dir)).toEqual(["kev-cache.json"]);
    expect(JSON.parse(readFileSync(cachePath(), "utf-8")).catalogVersion).toBe("2026.10.02");
  });
});

describe("KEV cache write failures (review finding 4)", () => {
  it("keeps a successfully fetched catalog when the cache can't be written, with a warning", async () => {
    freshDir();
    const notADirectory = join(dir, "blocker");
    writeFileSync(notADirectory, "a file where the cache directory should be");
    stubFeed({ vulnerabilities: [feedEntry] });
    const result = await pollKev({ cachePath: join(notADirectory, "kev-cache.json") });
    expect(result.entries).toHaveLength(1);
    expect(result.warnings).toEqual([expect.stringMatching(/Could not update the KEV cache at .*kev-cache\.json/)]);
  });
});
