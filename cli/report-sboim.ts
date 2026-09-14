#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { renderAnnotations, renderSummary, toSarif } from "../src/reporting/report.js";
import type { SboimResult } from "../src/vulnerability/types.js";

const args = process.argv.slice(2);
const resultPath = option("--result");
const sarifPath = option("--sarif");
const summaryPath = option("--summary");
const annotations = args.includes("--annotations");

if (!resultPath) throw new Error("--result is required");
const result = JSON.parse(readFileSync(resolve(resultPath), "utf8")) as SboimResult;
const summary = renderSummary(result);

if (summaryPath) writeFileSync(resolve(summaryPath), summary);
if (sarifPath) writeFileSync(resolve(sarifPath), `${JSON.stringify(toSarif(result), null, 2)}\n`);
if (annotations) for (const annotation of renderAnnotations(result)) console.log(annotation);
if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, summary);

function option(name: string): string | undefined {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}
