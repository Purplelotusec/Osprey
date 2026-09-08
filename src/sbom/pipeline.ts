import { createHash } from "node:crypto";
import { generateSbom, toCycloneDxJson, type GenerateOptions } from "./generate/index.js";
import { signSbom, loadPem } from "./signing.js";
import { putSbom, sbomStorageKey, envelopeStorageKey, type StorageConfig } from "./storage.js";
import type { SbomRecord } from "./types.js";

export interface PipelineOptions extends GenerateOptions {
  sign?: { privateKeyPath: string; keyId: string };
  store?: StorageConfig;
}

export interface PipelineResult {
  record: SbomRecord;
  warnings: string[];
}

/**
 * The end-to-end flow this module exists for: generate a real SBOM from a
 * project on disk, sign the exact bytes, and optionally push both to object
 * storage. Each step is independently usable (see generate/, signing.ts,
 * storage.ts) — this just wires the common path together so the CLI (and
 * any future CI action) has one function to call.
 */
export async function runPipeline(opts: PipelineOptions): Promise<PipelineResult> {
  const { sbom, warnings } = generateSbom(opts);
  const raw = toCycloneDxJson(sbom);
  const sha256 = createHash("sha256").update(raw).digest("hex");

  const record: SbomRecord = { sbom, raw, sha256 };

  if (opts.sign) {
    const privateKeyPem = loadPem(opts.sign.privateKeyPath, "private key");
    record.signatureEnvelope = signSbom(raw, privateKeyPem, opts.sign.keyId);
  }

  if (opts.store) {
    const key = sbomStorageKey(sbom.subjectName, sha256);
    await putSbom(opts.store, key, raw);
    record.storageKey = key;

    if (record.signatureEnvelope) {
      await putSbom(opts.store, envelopeStorageKey(key), JSON.stringify(record.signatureEnvelope, null, 2));
    }
  }

  return { record, warnings };
}
