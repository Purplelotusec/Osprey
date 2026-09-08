#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { homedir } from "node:os";
import { pollKev } from "../src/vulnerability/kev.js";
import { crossCheck } from "../src/correlation/matcher.js";
import { sendCrossCheckAlert, printCrossCheckResults } from "../src/alerting/webhook.js";
import { generateSbom } from "../src/sbom/generate/index.js";
import type { NormalizedComponent } from "../src/sbom/types.js";

const program = new Command();

program
  .name("cra-kev")
  .description("Poll CISA KEV and cross-check it against a project's dependencies")
  .option("-p, --path <dir>", "project directory to generate an SBOM from (if --sbom not given)", ".")
  .option("--sbom <file>", "use an existing CycloneDX JSON SBOM instead of generating one")
  .option("--cache <file>", "KEV cache file, used as fallback on fetch failure", join(homedir(), ".cra-guard", "kev-cache.json"))
  .option("--offline", "use only the cached KEV snapshot, no network call", false)
  .option("--webhook <url>", "Slack-compatible webhook URL to alert on matches")
  .option("--fail-on-high", "exit non-zero if any high-confidence match is found (for CI gating)", false)
  .action(async (options) => {
    try {
      const components = options.sbom
        ? loadComponentsFromSbomFile(resolve(options.sbom))
        : generateSbom({ projectDir: resolve(options.path) }).sbom.components;

      const subjectName = options.sbom ? options.sbom : resolve(options.path);

      console.log(`Polling CISA KEV...`);
      const snapshot = await pollKev({ cachePath: resolve(options.cache), offline: options.offline });
      console.log(`Loaded ${snapshot.entries.length} KEV entries (as of ${snapshot.dateReleased ?? snapshot.fetchedAt})`);

      console.log(`Cross-checking ${components.length} components...`);
      const matches = crossCheck(components, snapshot.entries);

      printCrossCheckResults(matches, subjectName);

      if (options.webhook && matches.length > 0) {
        await sendCrossCheckAlert(matches, { webhookUrl: options.webhook, subjectName });
        console.log(`Alert sent to webhook.`);
      }

      const highConfidenceCount = matches.filter((m) => m.confidence === "high").length;
      if (options.failOnHigh && highConfidenceCount > 0) {
        console.error(`\n${highConfidenceCount} high-confidence match(es) — failing per --fail-on-high.`);
        process.exit(1);
      }
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program.parse();

function loadComponentsFromSbomFile(path: string): NormalizedComponent[] {
  if (!existsSync(path)) throw new Error(`SBOM file not found: ${path}`);
  const doc = JSON.parse(readFileSync(path, "utf-8"));
  if (doc.bomFormat !== "CycloneDX") {
    throw new Error(`${path} is not a CycloneDX document (missing bomFormat: "CycloneDX")`);
  }
  return (doc.components ?? []).map((c: any) => ({
    purl: c.purl,
    cpe: c.cpe,
    namespace: c.group,
    name: c.name,
    version: c.version,
    vendor: c.publisher,
  }));
}
