import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateSigningKeypair, signSbom, verifySbom, loadPem } from "../src/sbom/signing.js";

describe("SBOM signing", () => {
  let dir: string;
  let privateKeyPath: string;
  let publicKeyPath: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "cra-guard-sign-test-"));
    privateKeyPath = join(dir, "key.pem");
    publicKeyPath = join(dir, "key.pem.pub");
    generateSigningKeypair({ privateKeyPath, publicKeyPath });
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("produces a signature that verifies against the matching public key", () => {
    const sbomJson = JSON.stringify({ bomFormat: "CycloneDX", components: [] });
    const privateKey = loadPem(privateKeyPath, "private key");
    const publicKey = loadPem(publicKeyPath, "public key");

    const envelope = signSbom(sbomJson, privateKey, "test-key");
    const result = verifySbom(sbomJson, envelope, publicKey);

    expect(result.valid).toBe(true);
  });

  it("rejects a signature when the SBOM content changes after signing", () => {
    const original = JSON.stringify({ bomFormat: "CycloneDX", components: [] });
    const tampered = JSON.stringify({ bomFormat: "CycloneDX", components: [{ name: "injected" }] });
    const privateKey = loadPem(privateKeyPath, "private key");
    const publicKey = loadPem(publicKeyPath, "public key");

    const envelope = signSbom(original, privateKey, "test-key");
    const result = verifySbom(tampered, envelope, publicKey);

    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/hash/i);
  });

  it("rejects a signature verified against the wrong public key", () => {
    const otherDir = mkdtempSync(join(tmpdir(), "cra-guard-sign-test-other-"));
    const otherPublicPath = join(otherDir, "other.pem.pub");
    generateSigningKeypair({
      privateKeyPath: join(otherDir, "other.pem"),
      publicKeyPath: otherPublicPath,
    });

    const sbomJson = JSON.stringify({ bomFormat: "CycloneDX", components: [] });
    const privateKey = loadPem(privateKeyPath, "private key");
    const wrongPublicKey = loadPem(otherPublicPath, "public key");

    const envelope = signSbom(sbomJson, privateKey, "test-key");
    const result = verifySbom(sbomJson, envelope, wrongPublicKey);

    expect(result.valid).toBe(false);
    rmSync(otherDir, { recursive: true, force: true });
  });

  it("refuses to overwrite an existing key", () => {
    expect(() => generateSigningKeypair({ privateKeyPath, publicKeyPath })).toThrow(/Refusing to overwrite/);
  });
});
