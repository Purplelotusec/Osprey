import { createHash } from "node:crypto";
import { generateSbom, toCycloneDxJson, type GenerateOptions } from "./generate/index.js";
import { signSbom, loadPem } from "./signing.js";
import { putSbom, sbomStorageKey, envelopeStorageKey, type StorageConfig } from "./storage.js";
import type { SboimStages } from "../pipeline/types.js";
import type { SbomRecord } from "./types.js";

export interface PipelineOptions extends GenerateOptions {
  sign?: { privateKeyPath: string; keyId: string };
  store?: StorageConfig;
}

export interface PipelineResult {
  record: SbomRecord;
  warnings: string[];
  stages: SboimStages;
}

export class PipelineStageError extends Error {
  constructor(
    message: string,
    public readonly stage: keyof SboimStages,
    public readonly stages: SboimStages,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = "PipelineStageError";
  }
}

/**
 * The end-to-end flow this module exists for: generate a real SBOM from a
 * project on disk, sign the exact bytes, and optionally push both to object
 * storage. Each step is independently usable (see generate/, signing.ts,
 * storage.ts) — this just wires the common path together so the CLI (and
 * any future CI action) has one function to call.
 */
export async function runPipeline(opts: PipelineOptions): Promise<PipelineResult> {
  const stages: SboimStages = {
    generate: { status: "skipped", reason: "Not started" },
    sign: { status: "skipped", reason: opts.sign ? "Not started" : "Signing not configured" },
    store: { status: "skipped", reason: opts.store ? "Not started" : "Storage not configured" },
    pollKev: { status: "skipped", reason: "Not started" },
    crossCheck: { status: "skipped", reason: "Not started" },
    alert: { status: "skipped", reason: "Not started" },
  };

  let generated: ReturnType<typeof generateSbom>;
  try {
    generated = generateSbom(opts);
    stages.generate = { status: "succeeded" };
  } catch (err) {
    const message = errorMessage(err);
    stages.generate = { status: "failed", reason: message };
    throw new PipelineStageError(message, "generate", stages, { cause: err });
  }

  const { sbom, warnings } = generated;
  const raw = toCycloneDxJson(sbom);
  const sha256 = createHash("sha256").update(raw).digest("hex");

  const record: SbomRecord = { sbom, raw, sha256 };

  if (opts.sign) {
    try {
      const privateKeyPem = loadPem(opts.sign.privateKeyPath, "private key");
      record.signatureEnvelope = signSbom(raw, privateKeyPem, opts.sign.keyId);
      stages.sign = {
        status: "succeeded",
        keyId: record.signatureEnvelope.keyId,
        algorithm: record.signatureEnvelope.algorithm,
      };
    } catch (err) {
      const message = errorMessage(err);
      stages.sign = { status: "failed", reason: message };
      stages.store = { status: "skipped", reason: "Skipped because signing failed" };
      throw new PipelineStageError(message, "sign", stages, { cause: err });
    }
  }

  if (opts.store) {
    const key = sbomStorageKey(sbom.subjectName, sha256);
    try {
      await putSbom(opts.store, key, raw);
      record.storageKey = key;

      if (record.signatureEnvelope) {
        await putSbom(opts.store, envelopeStorageKey(key), JSON.stringify(record.signatureEnvelope, null, 2));
      }
      stages.store = { status: "succeeded", storageKey: key };
    } catch (err) {
      const message = errorMessage(err);
      stages.store = { status: "failed", reason: message, storageKey: key };
      throw new PipelineStageError(message, "store", stages, { cause: err });
    }
  }

  return { record, warnings, stages };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
