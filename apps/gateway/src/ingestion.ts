import type { Config } from "./config.js";
import type { Db } from "./db.js";
import { insertEvent } from "./releases.js";

/**
 * The shared bounded ingestion path for preflight and publish. One limiter
 * instance is shared per process (mirroring the in-memory rate-limit backend;
 * multi-replica deployments still get the per-process bound plus the shared
 * Postgres rate limit).
 */

export class IngestionError extends Error {
  constructor(
    message: string,
    readonly statusCode: 400 | 408 | 413 | 429,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = "IngestionError";
  }
}

export interface IngestionLimits {
  perUserConcurrency: number;
  globalConcurrency: number;
  perUserRatePerHour: number;
  quotaBytesPerHour: number;
  maxTarballBytes: number;
  timeoutMs: number;
}

export function ingestionLimitsFromConfig(
  config: Pick<
    Config,
    | "INGEST_PER_USER_CONCURRENCY"
    | "INGEST_GLOBAL_CONCURRENCY"
    | "INGEST_PER_USER_RATE_PER_HOUR"
    | "INGEST_QUOTA_BYTES_PER_HOUR"
    | "INGEST_MAX_TARBALL_BYTES"
    | "INGEST_TIMEOUT_MS"
  >,
): IngestionLimits {
  return {
    perUserConcurrency: config.INGEST_PER_USER_CONCURRENCY,
    globalConcurrency: config.INGEST_GLOBAL_CONCURRENCY,
    perUserRatePerHour: config.INGEST_PER_USER_RATE_PER_HOUR,
    quotaBytesPerHour: config.INGEST_QUOTA_BYTES_PER_HOUR,
    maxTarballBytes: config.INGEST_MAX_TARBALL_BYTES,
    timeoutMs: config.INGEST_TIMEOUT_MS,
  };
}

const HOUR_MS = 60 * 60 * 1_000;

interface UserWindow {
  startedAt: number;
  requests: number;
  bytes: number;
}

export class IngestionLimiter {
  private readonly activeByUser = new Map<string, number>();
  private readonly windows = new Map<string, UserWindow>();
  private activeGlobal = 0;

  constructor(readonly limits: IngestionLimits) {}

  /**
   * Acquires a slot or throws IngestionError(429). The caller must invoke the
   * returned release function exactly once (use try/finally).
   */
  acquire(user: string, bytes: number): () => void {
    const now = Date.now();
    const window = this.windowFor(user, now);
    if (window.requests >= this.limits.perUserRatePerHour) {
      throw new IngestionError(
        "Ingestion rate limit exceeded for this identity.",
        429,
        Math.max(1, Math.ceil((window.startedAt + HOUR_MS - now) / 1_000)),
      );
    }
    if (window.bytes + bytes > this.limits.quotaBytesPerHour) {
      throw new IngestionError(
        "Ingestion quota exceeded for this identity.",
        429,
        Math.max(1, Math.ceil((window.startedAt + HOUR_MS - now) / 1_000)),
      );
    }
    if ((this.activeByUser.get(user) ?? 0) >= this.limits.perUserConcurrency) {
      throw new IngestionError(
        "Too many concurrent ingestions for this identity.",
        429,
        5,
      );
    }
    if (this.activeGlobal >= this.limits.globalConcurrency) {
      throw new IngestionError("Ingestion queue is saturated.", 429, 5);
    }

    window.requests += 1;
    window.bytes += bytes;
    this.activeByUser.set(user, (this.activeByUser.get(user) ?? 0) + 1);
    this.activeGlobal += 1;

    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.activeByUser.set(
        user,
        Math.max(0, (this.activeByUser.get(user) ?? 1) - 1),
      );
      this.activeGlobal = Math.max(0, this.activeGlobal - 1);
    };
  }

  /** Runs `fn` with a hard timeout; timeouts surface as IngestionError(408). */
  async withTimeout<T>(fn: () => Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        fn(),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(
            () =>
              reject(
                new IngestionError("Ingestion timed out.", 408),
              ),
            this.limits.timeoutMs,
          );
          timer.unref();
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  private windowFor(user: string, now: number): UserWindow {
    const existing = this.windows.get(user);
    if (existing && now - existing.startedAt < HOUR_MS) return existing;
    const fresh = { startedAt: now, requests: 0, bytes: 0 };
    this.windows.set(user, fresh);
    return fresh;
  }
}

/**
 * Records a resource-limit rejection in the audit log. Best-effort: the
 * rejection response must not depend on the event write.
 */
export async function auditIngestionRejection(
  db: Db | null,
  input: {
    orgId: string;
    actor: string;
    packageName?: string | null;
    error: IngestionError;
  },
): Promise<void> {
  if (!db) return;
  await insertEvent(db, {
    orgId: input.orgId,
    actor: input.actor,
    action: "ingestion.rejected",
    subject: input.packageName ?? null,
    metadata: {
      statusCode: input.error.statusCode,
      reason: input.error.message,
    },
  }).catch(() => undefined);
}

/** Decodes a base64 tarball with an early compressed-size cap. */
export function decodeBase64Tarball(
  encoded: string,
  maxBytes: number,
): Buffer {
  const compact = encoded.replace(/\s+/g, "");
  // Decoded size is ~3/4 of the encoded length; reject before decoding.
  if (Math.floor((compact.length * 3) / 4) > maxBytes) {
    throw new IngestionError(
      `Tarball exceeds the ${maxBytes} byte ingestion limit.`,
      413,
    );
  }
  if (
    compact.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      compact,
    )
  ) {
    throw new IngestionError("tarballBase64 is not valid base64.", 400);
  }
  const tarball = Buffer.from(compact, "base64");
  if (tarball.length === 0) {
    throw new IngestionError("tarballBase64 is empty or invalid.", 400);
  }
  if (tarball.length > maxBytes) {
    throw new IngestionError(
      `Tarball exceeds the ${maxBytes} byte ingestion limit.`,
      413,
    );
  }
  return tarball;
}

/**
 * Deduplicates concurrent and recently repeated work by key (digest +
 * engine + policy for preflights). Completed results are reused for a short
 * window; failures are never cached.
 */
export class WorkDeduper<T> {
  private readonly inflight = new Map<string, Promise<T>>();
  private readonly completed = new Map<string, { value: T; expiresAt: number }>();

  constructor(private readonly ttlMs: number = 60_000) {}

  async run(key: string, fn: () => Promise<T>): Promise<T> {
    const cached = this.completed.get(key);
    if (cached && cached.expiresAt > Date.now()) return cached.value;

    const pending = this.inflight.get(key);
    if (pending) return pending;

    const promise = fn()
      .then((value) => {
        this.completed.set(key, {
          value,
          expiresAt: Date.now() + this.ttlMs,
        });
        return value;
      })
      .finally(() => {
        this.inflight.delete(key);
      });
    this.inflight.set(key, promise);
    return promise;
  }
}
