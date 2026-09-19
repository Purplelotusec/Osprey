#!/usr/bin/env node
import { Command } from "commander";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { homedir } from "node:os";
import { pollKev } from "../src/vulnerability/kev.js";
import { crossCheckWithAdvisories } from "../src/correlation/matcher.js";
import { generateSbom } from "../src/sbom/generate/index.js";
import { generateSbomFromGitHub } from "../src/sbom/generate/remote.js";
import { parseGitHubUrl } from "../src/network/github.js";
import { runKevCheck } from "../src/vulnerability/check.js";
import { lookupOsvAdvisories } from "../src/vulnerability/osv.js";
import { printAuditReport, printAuditSummary } from "../src/output/audit-report.js";
import type { NormalizedComponent } from "../src/sbom/types.js";
import type { SboimResult } from "../src/vulnerability/types.js";

const program = new Command();

program
  .name("cra-audit")
  .description("Audit a project's SBOM against CISA Known Exploited Vulnerabilities (KEV)")
  .option("-p, --path <dir>", "local project directory to audit", ".")
  .option("-u, --url <github-url>", "GitHub repository URL to audit (e.g., owner/repo or https://github.com/owner/repo)")
  .option("--cache <file>", "KEV cache file path", join(homedir(), ".osprey", "kev-cache.json"))
  .option("--offline", "use only cached KEV data (no network request)", false)
  .option("--output <file>", "write detailed JSON result to file")
  .option("--verbose", "show detailed output with additional information", false)
  .option("--fail-on-high", "exit with error code if high-confidence vulnerabilities found", false)
  .option("--show-low", "include low-confidence matches in output (default: true)", true)
  .option("--github-token <token>", "GitHub personal access token for private repos (or set GITHUB_TOKEN env var)")
  .option("--summary", "show only summary output (default: full report)", false)
  .action(async (options) => {
    const startTime = Date.now();

    // Validate options
    if (options.url && options.path !== ".") {
      console.error("Error: Cannot specify both --url and --path options");
      process.exit(1);
    }

    // Get GitHub token from option or environment
    const githubToken = options.githubToken ?? process.env.GITHUB_TOKEN;

    // Determine subject
    const isRemote = Boolean(options.url);
    const subjectName = isRemote
      ? options.url
      : resolve(options.path);

    try {
      console.log(`Auditing: ${subjectName}\n`);

      // Run KEV check
      const result = await runKevCheck({
        subjectName,
        webhookUrl: undefined,
        failOnHigh: options.failOnHigh,
        lookupAdvisories: lookupOsvAdvisories,
        generateComponents: async () => {
          if (isRemote) {
            console.log("Fetching package files from GitHub...");
            const repoInfo = parseGitHubUrl(options.url);
            const sbomResult = await generateSbomFromGitHub({ repoInfo, token: githubToken });
            console.log(`Found ${sbomResult.sbom.components.length} components\n`);
            return sbomResult.sbom.components;
          } else {
            console.log("Generating SBOM from local project...");
            const sbomResult = generateSbom({ projectDir: resolve(options.path) });
            console.log(`Found ${sbomResult.sbom.components.length} components\n`);
            return sbomResult.sbom.components;
          }
        },
        pollKev: async () => {
          console.log("Polling CISA Known Exploited Vulnerabilities (KEV)...");
          const snapshot = await pollKev({
            cachePath: resolve(options.cache),
            offline: options.offline,
          });
          console.log(`Loaded ${snapshot.entries.length} KEV entries (as of ${snapshot.dateReleased ?? snapshot.fetchedAt})\n`);
          return snapshot;
        },
        crossCheck: (components, entries, advisories) => {
          console.log("Cross-checking components against KEV database...\n");
          return crossCheckWithAdvisories(components, entries, advisories);
        },
        sendAlert: async () => {
          // No webhook alert in audit command
        },
      });

      const duration = Date.now() - startTime;

      // Write output file if requested
      if (options.output) {
        const outputPath = resolve(options.output);
        mkdirSync(dirname(outputPath), { recursive: true });
        writeFileSync(outputPath, JSON.stringify(result, null, 2), "utf-8");
        console.log(`\nDetailed results written to: ${outputPath}`);
      }

      // Print report
      if (options.summary) {
        printAuditSummary(result);
      } else {
        printAuditReport(result, {
          verbose: options.verbose,
          showLowConfidence: options.showLow,
        });
      }

      // Print timing
      console.log(`Audit completed in ${(duration / 1000).toFixed(2)}s\n`);

      // Exit with appropriate code
      if (options.failOnHigh && result.highConfidenceMatchCount > 0) {
        process.exit(1);
      }

      if (result.status === "failed") {
        process.exit(1);
      }
    } catch (error) {
      console.error(`\nError: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(1);
    }
  });

program.parse();
