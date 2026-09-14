#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { renderAnnotations, renderSummary, toSarif } from "../src/reporting/report.js";
import { parseSboimResult } from "../src/reporting/input.js";

const args = process.argv.slice(2);
if (args.includes("--help") || args.includes("-h")) {
  console.log(`Usage: npm run report -- --result <file> [options]

Render an authoritative sboim-result.json for GitHub Actions.

Options:
  --result <file>       structured SBOIM result JSON (required)
  --summary <file>      write Markdown summary to a file
  --sarif <file>        write SARIF 2.1.0 output to a file
  --annotations         emit escaped GitHub Actions annotations
`);
  process.exit(0);
}
const resultPath = option("--result");
const sarifPath = option("--sarif");
const summaryPath = option("--summary");
const annotations = args.includes("--annotations");

if (!resultPath) throw new Error("--result is required");
const result = parseSboimResult(JSON.parse(readFileSync(resolve(resultPath), "utf8")));
const summary = renderSummary(result);

if (summaryPath) writeFileSync(resolve(summaryPath), summary);
if (sarifPath) writeFileSync(resolve(sarifPath), `${JSON.stringify(toSarif(result), null, 2)}\n`);
if (annotations) for (const annotation of renderAnnotations(result)) console.log(annotation);
if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, summary);

function option(name: string): string | undefined {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}
