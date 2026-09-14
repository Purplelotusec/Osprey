#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { homedir } from "node:os";
import { pollKev } from "../src/vulnerability/kev.js";
import { crossCheck } from "../src/correlation/matcher.js";
import { sendCrossCheckAlert, printCrossCheckResults } from "../src/alerting/webhook.js";
import { generateSbom } from "../src/sbom/generate/index.js";
import { runKevCheck } from "../src/vulnerability/check.js";
import { lookupOsvAdvisories } from "../src/vulnerability/osv.js";
import { z } from "zod";
import type { NormalizedComponent } from "../src/sbom/types.js";
import type { SboimResult } from "../src/vulnerability/types.js";

const program = new Command();

program
  .name("cra-kev")
  .description("Poll CISA KEV and cross-check it against a project's dependencies")
  .option("-p, --path <dir>", "project directory to generate an SBOM from (if --sbom not given)", ".")
  .option("--sbom <file>", "use an existing CycloneDX JSON SBOM instead of generating one")
  .option("--pipeline-result <file>", "reuse Generate/Sign/Store stage state from cra-sbom")
  .option("--cache <file>", "KEV cache file, used as fallback on fetch failure", join(homedir(), ".cra-guard", "kev-cache.json"))
  .option("--offline", "use only the cached KEV snapshot, no network call", false)
  .option("--webhook <url>", "Slack-compatible webhook URL to alert on matches")
  .option("--result <file>", "write a structured machine-readable SBOIM result JSON file")
  .option("--fail-on-high", "exit non-zero if any high-confidence match is found (for CI gating)", false)
  .action(async (options) => {
    const resultPath = options.result ? resolve(options.result) : undefined;
    const pipeline = options.pipelineResult ? loadPipelineResult(resolve(options.pipelineResult)) : undefined;
    const subjectName = pipeline?.subjectName ?? (options.sbom ? options.sbom : resolve(options.path));
    const result = await runKevCheck({
      subjectName,
      webhookUrl: options.webhook,
      failOnHigh: options.failOnHigh,
      pipeline,
      lookupAdvisories: lookupOsvAdvisories,
      generateComponents: () => {
        const components = options.sbom
          ? loadComponentsFromSbomFile(resolve(options.sbom))
          : generateSbom({ projectDir: resolve(options.path) }).sbom.components;
        return components;
      },
      pollKev: async () => {
        console.log(`Polling CISA KEV...`);
        const snapshot = await pollKev({ cachePath: resolve(options.cache), offline: options.offline });
        console.log(`Loaded ${snapshot.entries.length} KEV entries (as of ${snapshot.dateReleased ?? snapshot.fetchedAt})`);
        return snapshot;
      },
      crossCheck: (components, entries) => {
        console.log(`Cross-checking ${components.length} components...`);
        const matches = crossCheck(components, entries);
        printCrossCheckResults(matches, subjectName);
        return matches;
      },
      sendAlert: async (matches) => {
        await sendCrossCheckAlert(matches, { webhookUrl: options.webhook, subjectName });
        console.log(`Alert sent to webhook.`);
      },
    });

    writeResult(resultPath, result);
    if (result.status === "failed" && result.highConfidenceMatchCount > 0 && options.failOnHigh) {
      console.error(`\n${result.highConfidenceMatchCount} high-confidence match(es) — failing per --fail-on-high.`);
    }
    if (result.status === "failed") {
      for (const error of result.errors) console.error(`Error: ${error}`);
      process.exitCode = 1;
    }
  });

  function writeResult(path: string | undefined, result: SboimResult): void {
    if (!path) return;
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(result, null, 2)}\n`);
  }

program.parse();

function loadComponentsFromSbomFile(path: string): NormalizedComponent[] {
  if (!existsSync(path)) throw new Error(`SBOM file not found: ${path}`);
  const parsed = z.object({
    bomFormat: z.literal("CycloneDX"),
    components: z.array(z.object({
      name: z.string(), version: z.string().optional(), purl: z.string().optional(), cpe: z.string().optional(),
      group: z.string().optional(), publisher: z.string().optional(),
    }).passthrough()).default([]),
  }).safeParse(JSON.parse(readFileSync(path, "utf-8")));
  if (!parsed.success) throw new Error(`${path} is not a valid CycloneDX document: ${parsed.error.issues[0]?.message}`);
  return parsed.data.components.map((c) => ({
    purl: c.purl,
    cpe: c.cpe,
    namespace: c.group,
    name: c.name,
    version: c.version,
    vendor: c.publisher,
  }));
}

function loadPipelineResult(path: string) {
  const result = z.object({
    subjectName: z.string(),
    components: z.array(z.object({ name: z.string(), version: z.string().optional(), purl: z.string().optional(), ecosystem: z.string().optional(), namespace: z.string().optional(), vendor: z.string().optional(), cpe: z.string().optional(), isDirect: z.boolean().optional() }).passthrough()),
    warnings: z.array(z.string()),
    stages: z.object({
      generate: z.object({ status: z.enum(["succeeded", "failed", "skipped"]) }).passthrough(),
      sign: z.object({ status: z.enum(["succeeded", "failed", "skipped"]) }).passthrough(),
      store: z.object({ status: z.enum(["succeeded", "failed", "skipped"]) }).passthrough(),
      pollKev: z.object({ status: z.enum(["succeeded", "failed", "skipped"]) }).passthrough(),
      crossCheck: z.object({ status: z.enum(["succeeded", "failed", "skipped"]) }).passthrough(),
      alert: z.object({ status: z.enum(["succeeded", "failed", "skipped"]) }).passthrough(),
    }),
  }).safeParse(JSON.parse(readFileSync(path, "utf-8")));
  if (!result.success) throw new Error(`Invalid SBOIM pipeline result: ${path}: ${result.error.issues[0]?.message}`);
  return result.data;
}
