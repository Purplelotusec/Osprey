import { describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { generateSigningKeypair } from "../src/sbom/signing.js";
import { PipelineStageError, runPipeline } from "../src/sbom/pipeline.js";
import { runKevCheck } from "../src/vulnerability/check.js";

const { putSbom } = vi.hoisted(() => ({ putSbom: vi.fn(async () => undefined) }));
vi.mock("../src/sbom/storage.js", async () => {
  const actual = await vi.importActual<typeof import("../src/sbom/storage.js")>("../src/sbom/storage.js");
  return { ...actual, putSbom };
});

const fixture = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "npm-project");
const storageConfig = {
  endpoint: "https://storage.example.test",
  region: "us-east-1",
  bucket: "test-bucket",
  accessKeyId: "test-access-key",
  secretAccessKey: "test-secret-key",
};

describe("SBOM pipeline Sign and Store stages", () => {
  it("reports signing and storage as skipped when disabled", async () => {
    const result = await runPipeline({ projectDir: fixture });

    expect(result.stages).toEqual({
      generate: { status: "succeeded" },
      sign: { status: "skipped", reason: "Signing not configured" },
      store: { status: "skipped", reason: "Storage not configured" },
      pollKev: { status: "skipped", reason: "Not started" },
      crossCheck: { status: "skipped", reason: "Not started" },
      alert: { status: "skipped", reason: "Not started" },
    });
  });

  it("signs before storing and reports both successful stages", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sboim-pipeline-sign-"));
    const keyPath = join(dir, "signing-key.pem");
    generateSigningKeypair({ privateKeyPath: keyPath, publicKeyPath: `${keyPath}.pub` });
    putSbom.mockClear();

    try {
      const result = await runPipeline({
        projectDir: fixture,
        sign: { privateKeyPath: keyPath, keyId: "ci-key" },
        store: storageConfig,
      });

      expect(result.record.signatureEnvelope?.keyId).toBe("ci-key");
      expect(result.stages.sign).toMatchObject({ status: "succeeded", keyId: "ci-key", algorithm: "ed25519" });
      expect(result.stages.store.status).toBe("succeeded");
      expect(putSbom).toHaveBeenCalledTimes(2);
      expect(putSbom.mock.calls[1][2]).toContain("ci-key");
      expect(JSON.stringify(result)).not.toContain(storageConfig.accessKeyId);
      expect(JSON.stringify(result)).not.toContain(storageConfig.secretAccessKey);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reports signing failure and does not report storage success", async () => {
    putSbom.mockClear();

    await expect(
      runPipeline({
        projectDir: fixture,
        sign: { privateKeyPath: join(tmpdir(), "missing-sboim-key.pem"), keyId: "ci-key" },
        store: storageConfig,
      })
    ).rejects.toMatchObject({
      stage: "sign",
      stages: {
        generate: { status: "succeeded" },
        sign: { status: "failed" },
        store: { status: "skipped", reason: "Skipped because signing failed" },
      },
    });
    expect(putSbom).not.toHaveBeenCalled();
  });

  it("reports storage as skipped when storage is disabled", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sboim-pipeline-sign-only-"));
    const keyPath = join(dir, "signing-key.pem");
    generateSigningKeypair({ privateKeyPath: keyPath, publicKeyPath: `${keyPath}.pub` });

    try {
      const result = await runPipeline({ projectDir: fixture, sign: { privateKeyPath: keyPath, keyId: "local-key" } });
      expect(result.stages.sign.status).toBe("succeeded");
      expect(result.stages.store).toEqual({ status: "skipped", reason: "Storage not configured" });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reports storage failure without claiming success", async () => {
    putSbom.mockRejectedValueOnce(new Error("upload unavailable"));

    await expect(runPipeline({ projectDir: fixture, store: storageConfig })).rejects.toMatchObject({
      stage: "store",
      message: "upload unavailable",
      stages: {
        generate: { status: "succeeded" },
        sign: { status: "skipped", reason: "Signing not configured" },
        store: { status: "failed", reason: "upload unavailable" },
      },
    });
  });

  it("preserves the SBOM pipeline stages in the final structured result", async () => {
    const pipeline = await runPipeline({ projectDir: fixture });
    const result = await runKevCheck({
      subjectName: pipeline.record.sbom.subjectName,
      failOnHigh: false,
      pipeline: {
        subjectName: pipeline.record.sbom.subjectName,
        components: pipeline.record.sbom.components,
        warnings: pipeline.warnings,
        stages: pipeline.stages,
      },
      pollKev: async () => ({ count: 0, entries: [], fetchedAt: "2026-09-14T00:00:00.000Z" }),
      crossCheck: () => [],
      sendAlert: async () => undefined,
    });

    expect(result.stages.generate).toEqual({ status: "succeeded" });
    expect(result.stages.sign).toEqual({ status: "skipped", reason: "Signing not configured" });
    expect(result.stages.store).toEqual({ status: "skipped", reason: "Storage not configured" });
    expect(result.stages.pollKev.status).toBe("succeeded");
  });

  it("preserves successful Sign and Store stages in the final structured result", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sboim-pipeline-final-"));
    const keyPath = join(dir, "signing-key.pem");
    generateSigningKeypair({ privateKeyPath: keyPath, publicKeyPath: `${keyPath}.pub` });
    putSbom.mockClear();

    try {
      const pipeline = await runPipeline({
        projectDir: fixture,
        sign: { privateKeyPath: keyPath, keyId: "final-key" },
        store: storageConfig,
      });
      const result = await runKevCheck({
        subjectName: pipeline.record.sbom.subjectName,
        failOnHigh: false,
        pipeline: {
          subjectName: pipeline.record.sbom.subjectName,
          components: pipeline.record.sbom.components,
          warnings: pipeline.warnings,
          stages: pipeline.stages,
        },
        pollKev: async () => ({ count: 0, entries: [], fetchedAt: "2026-09-14T00:00:00.000Z" }),
        crossCheck: () => [],
        sendAlert: async () => undefined,
      });

      expect(result.stages.sign).toMatchObject({ status: "succeeded", keyId: "final-key" });
      expect(result.stages.store.status).toBe("succeeded");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not overwrite a failed upstream stage in the final result", async () => {
    let pipelineError: unknown;
    try {
      await runPipeline({
        projectDir: fixture,
        sign: { privateKeyPath: join(tmpdir(), "missing-sboim-key-final.pem"), keyId: "ci-key" },
      });
    } catch (error) {
      pipelineError = error;
    }

    expect(pipelineError).toBeInstanceOf(PipelineStageError);
    const error = pipelineError as PipelineStageError;
    const result = await runKevCheck({
      subjectName: "example-app",
      failOnHigh: false,
      pipeline: {
        subjectName: "example-app",
        components: [],
        warnings: [],
        stages: error.stages,
      },
      pollKev: async () => ({ count: 0, entries: [], fetchedAt: "2026-09-14T00:00:00.000Z" }),
      crossCheck: () => [],
      sendAlert: async () => undefined,
    });

    expect(result.status).toBe("failed");
    expect(result.stages.sign.status).toBe("failed");
    expect(result.stages.store).toEqual({ status: "skipped", reason: "Skipped because signing failed" });
    expect(result.stages.pollKev.status).toBe("skipped");
  });

  it("does not overwrite a failed Store stage in the final result", async () => {
    putSbom.mockRejectedValueOnce(new Error("store unavailable"));
    let pipelineError: unknown;
    try {
      await runPipeline({ projectDir: fixture, store: storageConfig });
    } catch (error) {
      pipelineError = error;
    }

    const error = pipelineError as PipelineStageError;
    const result = await runKevCheck({
      subjectName: "example-app",
      failOnHigh: false,
      pipeline: { subjectName: "example-app", components: [], warnings: [], stages: error.stages },
      pollKev: async () => ({ count: 0, entries: [], fetchedAt: "2026-09-14T00:00:00.000Z" }),
      crossCheck: () => [],
      sendAlert: async () => undefined,
    });

    expect(result.status).toBe("failed");
    expect(result.stages.store).toEqual({ status: "failed", reason: "store unavailable", storageKey: error.stages.store.storageKey });
    expect(result.stages.pollKev.status).toBe("skipped");
  });
});
