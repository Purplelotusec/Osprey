import { z } from "zod";
import type { SboimResult } from "../vulnerability/types.js";

const stageSchema = z.object({
  status: z.enum(["succeeded", "failed", "skipped"]),
  error: z.string().optional(),
  reason: z.string().optional(),
  keyId: z.string().optional(),
  algorithm: z.string().optional(),
  storageKey: z.string().optional(),
});

const resultSchema = z.object({
  schemaVersion: z.literal("1.0"),
  status: z.enum(["passed", "failed"]),
  subjectName: z.string(),
  sbomComponentCount: z.number().int().nonnegative(),
  kevSnapshot: z.object({ entryCount: z.number().int().nonnegative(), dateReleased: z.string().optional(), fetchedAt: z.string() }),
  matches: z.array(z.object({
    component: z.object({ name: z.string(), version: z.string().optional(), namespace: z.string().optional() }).passthrough(),
    kevEntry: z.object({ cveId: z.string(), vendorProject: z.string(), product: z.string(), vulnerabilityName: z.string(), dateAdded: z.string(), shortDescription: z.string() }).passthrough(),
    confidence: z.enum(["high", "low"]),
    matchedOn: z.enum(["purl_ecosystem_name", "vendor_product_name"]),
    identityConfidence: z.enum(["high", "low"]),
    versionStatus: z.enum(["affected", "not_affected", "unknown"]),
    exploitationStatus: z.literal("known_exploited"),
    advisoryIds: z.array(z.string()),
  })),
  highConfidenceMatchCount: z.number().int().nonnegative(),
  lowConfidenceMatchCount: z.number().int().nonnegative(),
  warnings: z.array(z.string()),
  errors: z.array(z.string()),
  stages: z.object({
    generate: stageSchema,
    sign: stageSchema,
    store: stageSchema,
    pollKev: stageSchema,
    crossCheck: stageSchema,
    alert: stageSchema,
  }),
});

export function parseSboimResult(value: unknown): SboimResult {
  const parsed = resultSchema.safeParse(value);
  if (!parsed.success) throw new Error(`Invalid SBOIM result: ${parsed.error.issues[0]?.message}`);
  return parsed.data as SboimResult;
}
