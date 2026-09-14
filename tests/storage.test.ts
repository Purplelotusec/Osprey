import { describe, expect, it } from "vitest";
import { validateStorageEndpoint } from "../src/sbom/storage.js";

describe("storage endpoint validation", () => {
  it("rejects non-loopback HTTP before sending credentials", async () => {
    expect(() => validateStorageEndpoint("http://storage.example.test")).toThrow(/HTTPS/);
  });

  it("allows loopback HTTP for local development", async () => {
    expect(() => validateStorageEndpoint("http://127.0.0.1:1")).not.toThrow();
  });

  it("rejects credentials embedded in the endpoint URL", () => {
    expect(() => validateStorageEndpoint("https://user:secret@storage.example.test")).toThrow(/embedded credentials/);
  });
});