export interface NormalizedComponent {
  purl?: string;
  cpe?: string;
  ecosystem?: string;
  namespace?: string;
  name: string;
  version?: string;
  vendor?: string;
  /** Direct dependency of the scanned project, vs. transitive. Best-effort. */
  isDirect?: boolean;
}

export interface NormalizedSbom {
  format: "CYCLONEDX_JSON";
  specVersion: "1.5";
  serialNumber: string;
  createdAt: string; // ISO 8601
  toolName: string;
  toolVersion: string;
  subjectName: string; // e.g. the repo/package name this SBOM describes
  subjectVersion?: string;
  components: NormalizedComponent[];
}

export interface SbomRecord {
  sbom: NormalizedSbom;
  raw: string; // canonical JSON string that was hashed/signed/stored
  sha256: string;
  storageKey?: string;
  signatureEnvelope?: SignatureEnvelope;
}

export type {
  SboimStageResult as PipelineStageResult,
  SboimStageStatus as PipelineStageStatus,
  SboimStages as PipelineStages,
} from "../pipeline/types.js";

export interface SignatureEnvelope {
  payloadType: string;
  payloadSha256: string;
  keyId: string;
  algorithm: "ed25519";
  signature: string; // base64
  signedAt: string; // ISO 8601
}
