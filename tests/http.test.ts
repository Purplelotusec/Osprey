import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchText } from "../src/network/http.js";

describe("bounded HTTP helper", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("rejects responses larger than the configured limit", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("0123456789")));
    await expect(fetchText("https://example.test", {}, { maxBytes: 5 })).rejects.toThrow(/exceeds 5 bytes/);
  });

  it("aborts stalled responses", async () => {
    vi.stubGlobal("fetch", vi.fn((_url: string, init?: RequestInit) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
    })));
    await expect(fetchText("https://example.test", {}, { timeoutMs: 1 })).rejects.toThrow(/aborted/);
  });
});