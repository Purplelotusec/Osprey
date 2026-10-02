#!/usr/bin/env node
import { Command } from "commander";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, posix, relative, resolve } from "node:path";
import { renderAnnotations, renderSummary, toSarif, type ManifestFiles } from "../src/reporting/report.js";
import { parseSboimResult } from "../src/reporting/input.js";
import { detectManifestFiles } from "../src/sbom/generate/index.js";

const program = new Command();

program
  .name("cra-report")
  .description("Render an Osprey result (cra --output / cra-kev --result) for GitHub Actions")
  .requiredOption("--result <file>", "structured result JSON to render")
  .option("--summary <file>", "write the Markdown summary to a file")
  .option("--sarif <file>", "write SARIF 2.1.0 for GitHub code scanning")
  .option("--annotations", "print GitHub Actions workflow annotations", false)
  .option("--project <dir>", "audited project directory, used to attach SARIF findings to its dependency files", ".")
  .action((options) => {
    try {
      const result = parseSboimResult(JSON.parse(readFileSync(resolve(options.result), "utf8")));
      const summary = renderSummary(result);

      if (options.summary) write(options.summary, summary);
      if (options.sarif) write(options.sarif, `${JSON.stringify(toSarif(result, manifestPaths(options.project)), null, 2)}\n`);
      if (options.annotations) for (const annotation of renderAnnotations(result)) console.log(annotation);

      // Each step gets its own summary file; GitHub's convention is to append to it.
      if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program.parse();

function write(path: string, content: string): void {
  const target = resolve(path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

/** Dependency files in --project, as repository-relative POSIX paths (SARIF URIs). */
function manifestPaths(projectDir: string): ManifestFiles {
  const root = resolve(projectDir);
  const rel = relative(process.cwd(), root).split(/[\\/]/).filter(Boolean);
  // SARIF URIs resolve against the checkout root (the working directory in CI);
  // a project outside it can only be described relative to itself.
  const prefix = rel[0] === ".." || isAbsolute(rel.join("/")) ? "" : rel.join("/");
  const files: ManifestFiles = {};
  for (const [type, file] of Object.entries(detectManifestFiles(root))) {
    if (file) files[type] = prefix ? posix.join(prefix, file) : file;
  }
  return files;
}
