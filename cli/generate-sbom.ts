#!/usr/bin/env node
import { Command } from "commander";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { homedir } from "node:os";
import { PipelineStageError, runPipeline } from "../src/sbom/pipeline.js";
import { generateSigningKeypair } from "../src/sbom/signing.js";
import { loadStorageConfigFromEnv } from "../src/sbom/storage.js";

const program = new Command();

program
  .name("cra-sbom")
  .description("Generate, sign, and store a CycloneDX SBOM for a project")
  .option("-p, --path <dir>", "project directory", ".")
  .option("-o, --output <file>", "write the SBOM JSON to this file")
  .option("--ecosystem <type>", "force npm or python instead of auto-detecting")
  .option("--sign", "sign the SBOM with an Ed25519 key", false)
  .option("--key <path>", "path to the Ed25519 private key PEM", join(homedir(), ".cra-guard", "sbom-signing-key.pem"))
  .option("--key-id <id>", "identifier embedded in the signature envelope", "default")
  .option("--generate-key", "generate a new signing keypair at --key (and --key.pub) if missing", false)
  .option("--store", "upload the SBOM (and signature, if signed) to object storage — reads S3_* env vars", false)
  .option("--pipeline-result <file>", "write Generate/Sign/Store stage state for the KEV check")
  .action(async (options) => {
    try {
      const projectDir = resolve(options.path);

      if (options.generateKey) {
        generateSigningKeypair({
          privateKeyPath: options.key,
          publicKeyPath: `${options.key}.pub`,
        });
        console.log(`Generated signing keypair:\n  private: ${options.key}\n  public:  ${options.key}.pub`);
        console.log("Keep the private key secret — anyone with it can produce SBOMs that verify as yours.");
      }

      let storeConfig;
      if (options.store) {
        storeConfig = loadStorageConfigFromEnv();
        if (!storeConfig) {
          console.error(
            "Error: --store requires S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY in the environment."
          );
          process.exit(1);
        }
      }

      const { record, warnings, stages } = await runPipeline({
        projectDir,
        ecosystem: options.ecosystem,
        sign: options.sign ? { privateKeyPath: options.key, keyId: options.keyId } : undefined,
        store: storeConfig,
      });

      if (options.pipelineResult) {
        const pipelineResultPath = resolve(options.pipelineResult);
        mkdirSync(dirname(pipelineResultPath), { recursive: true });
        writeFileSync(
          pipelineResultPath,
          JSON.stringify(
            {
              subjectName: record.sbom.subjectName,
              components: record.sbom.components,
              warnings,
              stages,
            },
            null,
            2
          ) + "\n"
        );
      }

      for (const w of warnings) console.warn(`Warning: ${w}`);

      console.log(`Generated SBOM for ${record.sbom.subjectName} — ${record.sbom.components.length} components`);
      console.log(`sha256: ${record.sha256}`);
      if (record.signatureEnvelope) {
        console.log(`Signed with key "${record.signatureEnvelope.keyId}" at ${record.signatureEnvelope.signedAt}`);
      }
      if (record.storageKey) {
        console.log(`Stored at: ${record.storageKey}`);
      }

      if (options.output) {
        writeFileSync(resolve(options.output), record.raw);
        console.log(`Written to ${resolve(options.output)}`);
        if (record.signatureEnvelope) {
          const envPath = `${resolve(options.output)}.dsse.json`;
          writeFileSync(envPath, JSON.stringify(record.signatureEnvelope, null, 2));
          console.log(`Signature envelope written to ${envPath}`);
        }
      }
    } catch (err) {
      if (options.pipelineResult && err instanceof PipelineStageError) {
        const pipelineResultPath = resolve(options.pipelineResult);
        mkdirSync(dirname(pipelineResultPath), { recursive: true });
        writeFileSync(
          pipelineResultPath,
          JSON.stringify(
            {
              subjectName: resolve(options.path),
              components: [],
              warnings: [],
              stages: err.stages,
            },
            null,
            2
          ) + "\n"
        );
      }
      console.error(`Error: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program.parse();
