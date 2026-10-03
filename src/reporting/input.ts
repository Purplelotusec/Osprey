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

const count = z.number().int().nonnegative();

/**
 * The schemaVersion 1.0 result written by `cra --output` / `cra-kev --result`.
 * Validated before rendering because it is a file handed between CI steps:
 * a truncated or tampered result must not render as a clean report.
 * `confidence` and `matchedOn` stay permissive so results written by the
 * earlier name-based matcher still render.
 */
const resultSchema = z.object({
  schemaVersion: z.literal("1.0"),
  status: z.enum(["passed", "failed"]),
  subjectName: z.string(),
  sbomComponentCount: count,
  checkedComponentCount: count.optional(),
  kevSnapshot: z.object({ entryCount: count, dateReleased: z.string().optional(), fetchedAt: z.string() }),
  matches: z.array(z.object({
    component: z.object({
      name: z.string(),
      version: z.string().optional(),
      namespace: z.string().optional(),
      ecosystem: z.string().optional(),
      purl: z.string().optional(),
    }).passthrough(),
    kevEntry: z.object({
      cveId: z.string(),
      vendorProject: z.string(),
      product: z.string(),
      vulnerabilityName: z.string(),
      dateAdded: z.string(),
      shortDescription: z.string(),
      requiredAction: z.string().optional(),
      dueDate: z.string().optional(),
      knownRansomwareUse: z.string().optional(),
    }).passthrough(),
    confidence: z.enum(["high", "low"]),
    matchedOn: z.string(),
    identityConfidence: z.enum(["high", "low"]),
    versionStatus: z.enum(["affected", "not_affected", "unknown"]),
    exploitationStatus: z.literal("known_exploited"),
    advisoryIds: z.array(z.string()),
    patchedVersion: z.string().optional(),
    currentVersion: z.string().optional(),
  }).passthrough()),
  highConfidenceMatchCount: count,
  lowConfidenceMatchCount: count,
  affectedCount: count,
  notAffectedCount: count,
  unknownCount: count,
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
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new Error(`Invalid Osprey result: ${issue?.path.join(".") || "(root)"}: ${issue?.message}`);
  }
  return parsed.data as SboimResult;
}
