import { createHash, randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

export class SpoolError extends Error {
  constructor(
    message: string,
    readonly code: "too_large" | "unavailable",
  ) {
    super(message);
    this.name = "SpoolError";
  }
}

export interface SpooledFile {
  path: string;
  size: number;
  /** SHA-256 hex digest computed while streaming. */
  digest: string;
  cleanup(): Promise<void>;
}

/**
 * Streams a response body to a bounded temp file while hashing it, so the
 * upstream path never holds an unbounded tarball in memory. Callers must run
 * `cleanup()` in a `finally` (or on response finish when streaming a reply).
 */
export async function spoolResponseBody(
  response: Response,
  options: { directory?: string; maxBytes: number },
): Promise<SpooledFile> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > options.maxBytes) {
    throw new SpoolError(
      `Upstream tarball exceeds the ${options.maxBytes} byte limit.`,
      "too_large",
    );
  }
  if (!response.body) {
    throw new SpoolError("Upstream response has no body.", "unavailable");
  }

  const directory =
    options.directory?.trim() || join(tmpdir(), "veripack-spool");
  await mkdir(directory, { recursive: true });
  const path = join(directory, `spool-${randomUUID()}.tgz`);
  const hash = createHash("sha256");
  let size = 0;

  const source = Readable.fromWeb(
    response.body as Parameters<typeof Readable.fromWeb>[0],
  );
  source.on("data", (chunk: Buffer) => {
    size += chunk.length;
    hash.update(chunk);
    if (size > options.maxBytes) {
      source.destroy(
        new SpoolError(
          `Upstream tarball exceeds the ${options.maxBytes} byte limit.`,
          "too_large",
        ),
      );
    }
  });

  try {
    await pipeline(source, createWriteStream(path, { mode: 0o600 }));
  } catch (error) {
    await rm(path, { force: true }).catch(() => undefined);
    throw error;
  }

  let cleaned = false;
  return {
    path,
    size,
    digest: hash.digest("hex"),
    async cleanup() {
      if (cleaned) return;
      cleaned = true;
      await rm(path, { force: true }).catch(() => undefined);
    },
  };
}
