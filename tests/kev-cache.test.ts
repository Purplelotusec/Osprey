import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pollKev } from "../src/vulnerability/kev.js";

describe("KEV cache validation", () => {
  it("rejects malformed offline cache data", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sboim-kev-cache-"));
    const path = join(dir, "cache.json");
    writeFileSync(path, JSON.stringify({ entries: "not-an-array" }));
    try {
      await expect(pollKev({ offline: true, cachePath: path })).rejects.toThrow(/KEV cache did not match/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});