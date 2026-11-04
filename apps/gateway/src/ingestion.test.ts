import { describe, expect, it } from "vitest";
import {
  IngestionError,
  IngestionLimiter,
  WorkDeduper,
  decodeBase64Tarball,
  type IngestionLimits,
} from "./ingestion.js";

const LIMITS: IngestionLimits = {
  perUserConcurrency: 2,
  globalConcurrency: 3,
  perUserRatePerHour: 3,
  quotaBytesPerHour: 100,
  maxTarballBytes: 16,
  timeoutMs: 20,
};

describe("ingestion limiter", () => {
  it("rejects excess per-user concurrency with 429", () => {
    const limiter = new IngestionLimiter(LIMITS);
    const first = limiter.acquire("alice", 1);
    const second = limiter.acquire("alice", 1);
    expect(() => limiter.acquire("alice", 1)).toThrowError(
      expect.objectContaining({ statusCode: 429, retryAfterSeconds: 5 }),
    );
    first();
    const third = limiter.acquire("alice", 1);
    second();
    third();
  });

  it("enforces the hourly rate and byte quota", () => {
    const limiter = new IngestionLimiter(LIMITS);
    for (let i = 0; i < 3; i += 1) limiter.acquire("bob", 1)();
    expect(() => limiter.acquire("bob", 1)).toThrowError(
      expect.objectContaining({ statusCode: 429 }),
    );

    const quota = new IngestionLimiter(LIMITS);
    quota.acquire("carol", 60)();
    expect(() => quota.acquire("carol", 41)).toThrowError(
      expect.objectContaining({ statusCode: 429 }),
    );
  });

  it("times out long-running work", async () => {
    const limiter = new IngestionLimiter(LIMITS);
    await expect(
      limiter.withTimeout(
        () => new Promise((resolve) => setTimeout(resolve, 60)),
      ),
    ).rejects.toMatchObject({ statusCode: 408 });
    await expect(limiter.withTimeout(async () => 42)).resolves.toBe(42);
  });
});

describe("base64 tarball decoding", () => {
  it("rejects payloads above the compressed-size cap before decoding", () => {
    const encoded = Buffer.alloc(64, 1).toString("base64");
    expect(() => decodeBase64Tarball(encoded, 16)).toThrowError(
      expect.objectContaining({ statusCode: 413 }),
    );
  });

  it("rejects invalid base64 and accepts small payloads", () => {
    expect(() => decodeBase64Tarball("not base64!!", 16)).toThrow(
      IngestionError,
    );
    const decoded = decodeBase64Tarball(
      Buffer.from("hello").toString("base64"),
      16,
    );
    expect(decoded.toString()).toBe("hello");
  });
});

describe("work deduper", () => {
  it("shares concurrent work and reuses recent results", async () => {
    const deduper = new WorkDeduper<number>(60_000);
    let calls = 0;
    const fn = async () => {
      calls += 1;
      return calls;
    };
    const [a, b] = await Promise.all([
      deduper.run("k", fn),
      deduper.run("k", fn),
    ]);
    expect(a).toBe(b);
    expect(calls).toBe(1);
    await expect(deduper.run("k", fn)).resolves.toBe(1);
    expect(calls).toBe(1);
  });

  it("never caches failures", async () => {
    const deduper = new WorkDeduper<number>(60_000);
    let calls = 0;
    const fn = async () => {
      calls += 1;
      if (calls === 1) throw new Error("boom");
      return calls;
    };
    await expect(deduper.run("k", fn)).rejects.toThrow("boom");
    await expect(deduper.run("k", fn)).resolves.toBe(2);
  });
});
