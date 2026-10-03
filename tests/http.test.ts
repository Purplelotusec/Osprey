import { afterEach, describe, it, expect, vi } from "vitest";
import { fetchJson, fetchText, HttpError } from "../src/network/http.js";
import { fetchOptionalGitHubFile } from "../src/network/github.js";

/** One scripted fetch outcome; a factory, so every call gets a fresh Response. */
type Step = () => Response | Error;

/** Stubs fetch to play `steps` in order (the last one repeats); returns the call counter. */
function stubFetch(...steps: Step[]): () => number {
  let calls = 0;
  vi.stubGlobal("fetch", async () => {
    const outcome = steps[Math.min(calls++, steps.length - 1)]();
    if (outcome instanceof Error) throw outcome;
    return outcome;
  });
  return () => calls;
}

const ok = (body: string): Step => () => new Response(body);
const status = (code: number, headers: Record<string, string> = {}): Step => () => new Response("error", { status: code, statusText: "Error", headers });
const networkError = (code: string): Step => () => new TypeError("fetch failed", { cause: { code } });

afterEach(() => vi.unstubAllGlobals());

describe("retries for transient failures", () => {
  it.each([500, 502, 503, 429])("retries HTTP %i and succeeds once the server recovers", async (code) => {
    const calls = stubFetch(status(code), status(code), ok("ok"));
    expect(await fetchText("https://example.test/file")).toBe("ok");
    expect(calls()).toBe(3);
  });

  it("retries network failures such as connection timeouts", async () => {
    const calls = stubFetch(networkError("UND_ERR_CONNECT_TIMEOUT"), ok("ok"));
    expect(await fetchText("https://example.test/file")).toBe("ok");
    expect(calls()).toBe(2);
  });

  it("gives up after the retry budget, naming the real cause and the attempt count", async () => {
    const calls = stubFetch(networkError("UND_ERR_CONNECT_TIMEOUT"));
    await expect(fetchText("https://example.test/file")).rejects.toThrow("fetch failed (UND_ERR_CONNECT_TIMEOUT) (after 4 attempts)");
    expect(calls()).toBe(4); // 1 attempt + 3 retries
  });

  it("honours Retry-After on 429", async () => {
    stubFetch(status(429, { "retry-after": "0.05" }), ok("ok"));
    const started = Date.now();
    expect(await fetchText("https://example.test/file")).toBe("ok");
    expect(Date.now() - started).toBeGreaterThanOrEqual(40);
  });

  it("respects an explicit retry count", async () => {
    const calls = stubFetch(status(503));
    await expect(fetchText("https://example.test/file", {}, { retries: 0 })).rejects.toThrow("HTTP 503 Error");
    expect(calls()).toBe(1);
  });
});

describe("failures that a retry can't fix", () => {
  it.each([404, 401, 403, 400])("fails HTTP %i immediately", async (code) => {
    const calls = stubFetch(status(code));
    const error = await fetchText("https://example.test/file").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(HttpError);
    expect((error as HttpError).status).toBe(code);
    expect(calls()).toBe(1);
  });

  it("does not re-download an oversized response", async () => {
    const calls = stubFetch(ok("x".repeat(100)));
    await expect(fetchText("https://example.test/file", {}, { maxBytes: 10 })).rejects.toThrow("exceeds 10 bytes");
    expect(calls()).toBe(1);
  });
});

describe("fetchJson", () => {
  it("retries a truncated (invalid JSON) body", async () => {
    const calls = stubFetch(ok('{"partial":'), ok('{"ok":true}'));
    expect(await fetchJson("https://example.test/api")).toEqual({ ok: true });
    expect(calls()).toBe(2);
  });
});

describe("GitHub fetches", () => {
  const repo = { owner: "owner", repo: "repo" };

  it("recover from a transient failure", async () => {
    const calls = stubFetch(networkError("UND_ERR_CONNECT_TIMEOUT"), status(503), ok("django==4.2.0\n"));
    expect(await fetchOptionalGitHubFile(repo, "requirements.txt")).toBe("django==4.2.0\n");
    expect(calls()).toBe(3);
  });

  it("still treat 404 as absent, without retrying", async () => {
    const calls = stubFetch(status(404));
    expect(await fetchOptionalGitHubFile(repo, "uv.lock")).toBeUndefined();
    expect(calls()).toBe(1);
  });

  it("fail the audit when GitHub stays unavailable", async () => {
    stubFetch(status(503));
    await expect(fetchOptionalGitHubFile(repo, "uv.lock")).rejects.toThrow("Could not fetch uv.lock from owner/repo: HTTP 503 Error (after 4 attempts)");
  });
});
