import { describe, expect, it, vi } from "vitest";
import { config as defaultConfig, type Config } from "../config.js";
import { dispatchAuditOutboxOnce } from "./outbox.js";

function testConfig(): Config {
  return {
    ...defaultConfig,
    AUDIT_QUEUE: "veripack-audit",
    AUDIT_JOB_RETRY_LIMIT: 3,
    AUDIT_JOB_RETRY_DELAY_SECONDS: 2,
    AUDIT_OUTBOX_BATCH_SIZE: 100,
    AUDIT_OUTBOX_INTERVAL_MS: 5_000,
  };
}

function makePool(entries: Array<{ release_id: string }>): never {
  return {
    query: async (sql: string) => {
      if (sql.includes("with candidates")) return { rows: entries };
      return { rows: [] };
    },
  } as never;
}

const logger = { info: vi.fn(), error: vi.fn() };

describe("audit outbox dispatcher", () => {
  it("sends each claimed release and marks it sent", async () => {
    const pool = makePool([{ release_id: "release-1" }]);
    const send = vi.fn(async () => "job-1");

    const count = await dispatchAuditOutboxOnce({
      pool,
      boss: { send } as never,
      config: testConfig(),
      logger,
    });

    expect(count).toBe(1);
    expect(send).toHaveBeenCalledWith(
      "veripack-audit",
      { releaseId: "release-1" },
      { retryLimit: 3, retryDelay: 2 },
    );
  });

  it("records a dispatch failure and keeps processing", async () => {
    const pool = makePool([{ release_id: "release-1" }]);
    const send = vi.fn(async () => {
      throw new Error("queue is down");
    });

    const count = await dispatchAuditOutboxOnce({
      pool,
      boss: { send } as never,
      config: testConfig(),
      logger,
    });

    expect(count).toBe(1);
    expect(logger.error).toHaveBeenCalled();
  });

  it("does nothing when the outbox has no due entries", async () => {
    const pool = makePool([]);
    const send = vi.fn(async () => "job-1");

    const count = await dispatchAuditOutboxOnce({
      pool,
      boss: { send } as never,
      config: testConfig(),
      logger,
    });

    expect(count).toBe(0);
    expect(send).not.toHaveBeenCalled();
  });
});
