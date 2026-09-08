import {
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  createHash,
} from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { SignatureEnvelope } from "./types.js";

const PAYLOAD_TYPE = "application/vnd.cyclonedx+json";

export interface KeyPairFiles {
  privateKeyPath: string;
  publicKeyPath: string;
}

/**
 * Generates a new Ed25519 keypair and writes it to disk as PEM files.
 *
 * Ed25519 rather than RSA: shorter keys/signatures, fast, and it's the same
 * signing primitive Sigstore/cosign use — this gives you real, verifiable
 * SBOM signatures without standing up Sigstore's transparency-log/keyless-
 * OIDC infrastructure. Swap in cosign's keyless flow later without changing
 * the envelope shape below (DSSE) if you want public transparency-log
 * anchoring on top of this.
 */
export function generateSigningKeypair(files: KeyPairFiles): void {
  if (existsSync(files.privateKeyPath)) {
    throw new Error(
      `Refusing to overwrite existing key at ${files.privateKeyPath}. Delete it first if you really want a new one — rotating keys invalidates verification of everything signed with the old one.`
    );
  }

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();

  mkdirSync(dirname(files.privateKeyPath), { recursive: true });
  writeFileSync(files.privateKeyPath, privatePem, { mode: 0o600 });
  writeFileSync(files.publicKeyPath, publicPem, { mode: 0o644 });
}

export function loadPem(path: string, kind: "private key" | "public key"): string {
  if (!existsSync(path)) {
    throw new Error(`No ${kind} found at ${path}.`);
  }
  return readFileSync(path, "utf-8");
}

/**
 * Signs the raw SBOM document — sign the exact bytes that will be stored.
 * Never re-serialize JSON between generation and signing; re-serializing
 * can silently reorder keys and produce a payload whose hash no longer
 * matches what a verifier re-hashes.
 */
export function signSbom(rawSbomJson: string, privateKeyPem: string, keyId: string): SignatureEnvelope {
  const payloadSha256 = createHash("sha256").update(rawSbomJson).digest("hex");
  const pae = preAuthEncode(PAYLOAD_TYPE, rawSbomJson);

  // Ed25519 signs the message directly (algorithm=null) rather than a
  // separate pre-hashed digest — this is the one-shot node:crypto API.
  const signature = cryptoSign(null, pae, privateKeyPem);

  return {
    payloadType: PAYLOAD_TYPE,
    payloadSha256,
    keyId,
    algorithm: "ed25519",
    signature: signature.toString("base64"),
    signedAt: new Date().toISOString(),
  };
}

export function verifySbom(
  rawSbomJson: string,
  envelope: SignatureEnvelope,
  publicKeyPem: string
): { valid: boolean; reason?: string } {
  const actualSha256 = createHash("sha256").update(rawSbomJson).digest("hex");
  if (actualSha256 !== envelope.payloadSha256) {
    return {
      valid: false,
      reason: "SBOM content hash does not match the signed hash — content was modified after signing",
    };
  }

  const pae = preAuthEncode(envelope.payloadType, rawSbomJson);
  const valid = cryptoVerify(null, pae, publicKeyPem, Buffer.from(envelope.signature, "base64"));

  return valid ? { valid: true } : { valid: false, reason: "Signature does not verify against the provided public key" };
}

/**
 * DSSE (Dead Simple Signing Envelope) pre-authentication encoding — binds
 * the payload TYPE to the payload bytes before signing, per the in-toto
 * DSSE spec: "DSSEv1" SP len(type) SP type SP len(payload) SP payload.
 * This is what stops a signature valid for one payload type being replayed
 * against a different one.
 */
function preAuthEncode(payloadType: string, payload: string): Buffer {
  const parts = [
    "DSSEv1",
    String(payloadType.length),
    payloadType,
    String(Buffer.byteLength(payload)),
    payload,
  ];
  return Buffer.from(parts.join(" "), "utf-8");
}
