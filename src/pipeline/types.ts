export type SboimStageStatus = "succeeded" | "failed" | "skipped";

export interface SboimStageResult {
  status: SboimStageStatus;
  error?: string;
  reason?: string;
  keyId?: string;
  algorithm?: string;
  storageKey?: string;
}

export interface SboimStages {
  generate: SboimStageResult;
  sign: SboimStageResult;
  store: SboimStageResult;
  pollKev: SboimStageResult;
  crossCheck: SboimStageResult;
  alert: SboimStageResult;
}
