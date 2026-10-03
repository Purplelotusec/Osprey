const DEFAULT_TIMEOUT_MS = 30_000; // generous: OSV batch responses and large lockfiles can be slow
const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
const DEFAULT_RETRIES = 3;
const DEFAULT_RETRY_DELAY_MS = 500;
/** Upper bound on any single wait, including a server's Retry-After. */
const MAX_RETRY_WAIT_MS = 30_000;

export interface BoundedFetchOptions {
  timeoutMs?: number;
  maxBytes?: number;
  /** Extra attempts after the first for transient failures (default 3). */
  retries?: number;
  /** Base delay before the first retry; doubles each attempt, with jitter (default 500 ms). */
  retryDelay?: number;
}

/** Process-wide retry tuning, e.g. so tests don't wait between attempts. */
export const httpRetryDefaults = { retries: DEFAULT_RETRIES, retryDelayMs: DEFAULT_RETRY_DELAY_MS };

/** A non-2xx response, with its status so callers can tell "not found" from "failed". */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    statusText: string,
    /** From a Retry-After header, when the server sent one. */
    readonly retryAfterMs?: number
  ) {
    super(`HTTP ${status} ${statusText}`);
    this.name = "HttpError";
  }
}

/** A response too large to accept. Retrying would only download it again. */
class ResponseTooLargeError extends Error {}

/**
 * GETs (or otherwise fetches) `url` as text, retrying transient failures:
 * network errors, timeouts, 5xx and 429. Anything else — 404, 401/403, an
 * oversized response — fails immediately, since another attempt can't change it.
 */
export async function fetchText(url: string, init: RequestInit = {}, options: BoundedFetchOptions = {}): Promise<string> {
  return withRetries(() => fetchTextOnce(url, init, options), options);
}

/** Like fetchText, then parses JSON. A body that isn't valid JSON (e.g. truncated) is retried too. */
export async function fetchJson(url: string, init: RequestInit = {}, options: BoundedFetchOptions = {}): Promise<unknown> {
  return withRetries(async () => {
    const body = await fetchTextOnce(url, init, options);
    try {
      return JSON.parse(body);
    } catch {
      throw new Error("HTTP response was not valid JSON");
    }
  }, options);
}

async function withRetries<T>(attempt: () => Promise<T>, options: BoundedFetchOptions): Promise<T> {
  const retries = options.retries ?? httpRetryDefaults.retries;
  const baseDelay = options.retryDelay ?? httpRetryDefaults.retryDelayMs;

  for (let attemptNumber = 0; ; attemptNumber++) {
    try {
      return await attempt();
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      if (!isTransient(error) || attemptNumber >= retries) throw withAttempts(describe(error), attemptNumber + 1);
      await sleep(retryWaitMs(error, baseDelay, attemptNumber));
    }
  }
}

function isTransient(error: Error): boolean {
  if (error instanceof ResponseTooLargeError) return false;
  if (error instanceof HttpError) return error.status === 429 || error.status >= 500;
  return true; // network failure, timeout, or an unparseable (likely truncated) body
}

/** Exponential backoff with jitter, unless the server asked for a specific wait. */
function retryWaitMs(error: Error, baseDelay: number, attemptNumber: number): number {
  if (error instanceof HttpError && error.retryAfterMs !== undefined) return Math.min(error.retryAfterMs, MAX_RETRY_WAIT_MS);
  const exponential = baseDelay * 2 ** attemptNumber;
  return Math.min(exponential / 2 + Math.random() * (exponential / 2), MAX_RETRY_WAIT_MS);
}

/** Node reports every network failure as "fetch failed"; surface the underlying cause. */
function describe(error: Error): Error {
  if (error.name === "AbortError") return new Error("request timed out");
  const cause = (error as { cause?: { code?: string; message?: string } }).cause;
  if (error.message === "fetch failed" && cause) return new Error(`fetch failed (${cause.code ?? cause.message})`);
  return error;
}

function withAttempts(error: Error, attempts: number): Error {
  if (attempts <= 1) return error;
  error.message = `${error.message} (after ${attempts} attempts)`;
  return error;
}

function sleep(ms: number): Promise<void> {
  return ms > 0 ? new Promise((resolve) => setTimeout(resolve, ms)) : Promise.resolve();
}

/** Retry-After is either delay-seconds or an HTTP date. */
function parseRetryAfter(header: string | null): number | undefined {
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const date = Date.parse(header);
  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : undefined;
}

async function fetchTextOnce(url: string, init: RequestInit, options: BoundedFetchOptions): Promise<string> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    if (!response.ok) {
      throw new HttpError(response.status, response.statusText, parseRetryAfter(response.headers.get("retry-after")));
    }

    const contentLength = response.headers.get("content-length");
    if (contentLength && Number(contentLength) > maxBytes) {
      throw new ResponseTooLargeError(`HTTP response exceeds ${maxBytes} bytes`);
    }

    if (!response.body) return "";
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const chunks: string[] = [];
    let totalBytes = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        // Release the stream without waiting on it: the outcome is already decided.
        reader.cancel().catch(() => {});
        throw new ResponseTooLargeError(`HTTP response exceeds ${maxBytes} bytes`);
      }
      chunks.push(decoder.decode(value, { stream: true }));
    }
    chunks.push(decoder.decode());
    return chunks.join("");
  } finally {
    clearTimeout(timeout);
  }
}
