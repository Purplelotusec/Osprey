import { S3Client, PutObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";

export interface StorageConfig {
  endpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  forcePathStyle?: boolean;
}

let client: S3Client | null = null;
let activeConfig: StorageConfig | null = null;

function getClient(config: StorageConfig): S3Client {
  if (client && activeConfig === config) return client;
  client = new S3Client({
    endpoint: config.endpoint,
    region: config.region,
    forcePathStyle: config.forcePathStyle ?? true,
    credentials: { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey },
  });
  activeConfig = config;
  return client;
}

export function sbomStorageKey(subjectName: string, sha256: string): string {
  const safeName = subjectName.replace(/[^a-zA-Z0-9._-]/g, "_");
  return `sboms/${safeName}/${sha256}.json`;
}

export function envelopeStorageKey(sbomKey: string): string {
  return `${sbomKey}.dsse.json`;
}

export async function putSbom(config: StorageConfig, key: string, body: string): Promise<void> {
  const s3 = getClient(config);
  await s3.send(
    new PutObjectCommand({
      Bucket: config.bucket,
      Key: key,
      Body: body,
      ContentType: "application/json",
      ServerSideEncryption: "AES256",
    })
  );
}

export async function getSbom(config: StorageConfig, key: string): Promise<string> {
  const s3 = getClient(config);
  const result = await s3.send(new GetObjectCommand({ Bucket: config.bucket, Key: key }));
  const body = await result.Body?.transformToString("utf-8");
  if (body === undefined) throw new Error(`Empty object body for key ${key}`);
  return body;
}

export function loadStorageConfigFromEnv(): StorageConfig | null {
  const {
    S3_ENDPOINT,
    S3_REGION,
    S3_BUCKET,
    S3_ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY,
    S3_FORCE_PATH_STYLE,
  } = process.env;

  if (!S3_ENDPOINT || !S3_BUCKET || !S3_ACCESS_KEY_ID || !S3_SECRET_ACCESS_KEY) {
    return null;
  }

  return {
    endpoint: S3_ENDPOINT,
    region: S3_REGION ?? "us-east-1",
    bucket: S3_BUCKET,
    accessKeyId: S3_ACCESS_KEY_ID,
    secretAccessKey: S3_SECRET_ACCESS_KEY,
    forcePathStyle: S3_FORCE_PATH_STYLE !== "false",
  };
}
