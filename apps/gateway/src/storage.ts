import {
  CreateBucketCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import type { Config } from "./config.js";

/** True for S3 `NoSuchKey`/`NotFound` errors, which are never retryable. */
export function isNoSuchKeyError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const candidate = error as {
    name?: string;
    Code?: string;
    $metadata?: { httpStatusCode?: number };
  };
  return (
    candidate.name === "NoSuchKey" ||
    candidate.name === "NotFound" ||
    candidate.Code === "NoSuchKey" ||
    candidate.$metadata?.httpStatusCode === 404
  );
}

export class Storage {
  private constructor(
    private readonly client: S3Client,
    private readonly bucket: string,
    private readonly autoCreateBucket: boolean,
  ) {}

  static async create(config: Config): Promise<Storage> {
    const client = new S3Client({
      endpoint: config.S3_ENDPOINT,
      region: config.S3_REGION,
      forcePathStyle: config.S3_FORCE_PATH_STYLE,
      credentials: {
        accessKeyId: config.S3_ACCESS_KEY_ID,
        secretAccessKey: config.S3_SECRET_ACCESS_KEY,
      },
      requestChecksumCalculation: "WHEN_REQUIRED",
      responseChecksumValidation: "WHEN_REQUIRED",
    });

    const storage = new Storage(
      client,
      config.S3_BUCKET,
      config.S3_AUTO_CREATE_BUCKET,
    );
    await storage.ensureBucket();
    return storage;
  }

  private async ensureBucket(attempts = 30): Promise<void> {
    let lastError: unknown;

    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }));
        return;
      } catch (error) {
        const status = (error as { $metadata?: { httpStatusCode?: number } })
          .$metadata?.httpStatusCode;
        const name = (error as { name?: string }).name;

        if (
          this.autoCreateBucket &&
          (status === 404 || name === "NotFound" || name === "NoSuchBucket")
        ) {
          try {
            await this.client.send(new CreateBucketCommand({ Bucket: this.bucket }));
            return;
          } catch (createError) {
            lastError = createError;
          }
        } else {
          lastError = error;
        }
      }

      if (attempt < attempts) {
        await new Promise((resolve) => setTimeout(resolve, 1_000));
      }
    }

    throw new Error(
      `S3 bucket "${this.bucket}" is not available: ${
        lastError instanceof Error ? lastError.message : String(lastError)
      }`,
    );
  }

  async putTarball(key: string, tarball: Buffer): Promise<void> {
    await this.putBuffer(key, tarball, "application/octet-stream");
  }

  async putBuffer(key: string, value: Buffer, contentType: string): Promise<void> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: value,
        ContentType: contentType,
      }),
    );
  }

  async putJson(key: string, value: unknown): Promise<void> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: JSON.stringify(value),
        ContentType: "application/json",
      }),
    );
  }

  async deleteObject(key: string): Promise<void> {
    await this.client.send(
      new DeleteObjectCommand({ Bucket: this.bucket, Key: key }),
    );
  }

  async exists(key: string): Promise<boolean> {
    try {
      await this.client.send(
        new HeadObjectCommand({ Bucket: this.bucket, Key: key }),
      );
      return true;
    } catch (error) {
      if (isNoSuchKeyError(error)) return false;
      throw error;
    }
  }

  async getBuffer(key: string): Promise<Buffer> {
    const response = await this.client.send(
      new GetObjectCommand({ Bucket: this.bucket, Key: key }),
    );
    if (!response.Body) {
      throw new Error(`Object ${key} has no body.`);
    }
    const bytes = await response.Body.transformToByteArray();
    return Buffer.from(bytes);
  }

  async getJson<T>(key: string): Promise<T> {
    const buffer = await this.getBuffer(key);
    return JSON.parse(buffer.toString("utf8")) as T;
  }
}

export function safeKeyPart(value: string): string {
  return value.replace(/^@/, "").replace(/\//g, "__");
}

export function buildTarballKey(
  orgId: string,
  packageName: string,
  version: string,
  digest: string,
): string {
  return `orgs/${orgId}/tarballs/${safeKeyPart(packageName)}/${version}/${digest}.tgz`;
}

export function buildPayloadKey(
  orgId: string,
  packageName: string,
  version: string,
  digest: string,
): string {
  return `orgs/${orgId}/payloads/${safeKeyPart(packageName)}/${version}/${digest}.json`;
}
