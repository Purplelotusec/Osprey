const DEFAULT_TIMEOUT_MS = 30_000; // Increased from 15s to 30s for large API responses
const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;

export interface BoundedFetchOptions {
  timeoutMs?: number;
  maxBytes?: number;
  retries?: number;
  retryDelay?: number;
}

export async function fetchText(
  url: string,
  init: RequestInit = {},
  options: BoundedFetchOptions = {}
): Promise<string> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status} ${response.statusText}`);

    const contentLength = response.headers.get("content-length");
    if (contentLength && Number(contentLength) > maxBytes) {
      throw new Error(`HTTP response exceeds ${maxBytes} bytes`);
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
        await reader.cancel();
        throw new Error(`HTTP response exceeds ${maxBytes} bytes`);
      }
      chunks.push(decoder.decode(value, { stream: true }));
    }
    chunks.push(decoder.decode());
    return chunks.join("");
  } finally {
    clearTimeout(timeout);
  }
}

export async function fetchJson(
  url: string,
  init: RequestInit = {},
  options: BoundedFetchOptions = {}
): Promise<unknown> {
  const retries = options.retries ?? 3;
  const retryDelay = options.retryDelay ?? 1000;

  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const body = await fetchText(url, init, options);
      try {
        return JSON.parse(body);
      } catch {
        throw new Error("HTTP response was not valid JSON");
      }
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      // Don't retry on 4xx errors (client errors)
      if (lastError.message.match(/HTTP 4\d\d/)) {
        throw lastError;
      }

      // Retry on network errors, timeouts, 5xx errors
      if (attempt < retries) {
        await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
        continue;
      }
    }
  }

  throw lastError ?? new Error("Fetch failed");
}
