import { describe, expect, it, vi } from "vitest";
import { config as defaultConfig, type Config } from "../config.js";
import type { ReleaseLifecycle } from "../lifecycle.js";
import type { AuditRow, ReleaseRow } from "../releases.js";
import { startAuditWorker, type AuditWorkerDeps } from "./worker.js";

const RELEASE_ID = "11111111-1111-1111-1111-111111111111";

interface AuditJob {
  data: { releaseId: string };
}

type Handler = (jobs: AuditJob[]) => Promise<void>;

function testConfig(): Config {
  return {
    ...defaultConfig,
    LOG_LEVEL: "silent",
    ORG_ID: "org-a",
    AUDIT_QUEUE: "veripack-audit",
    AUDIT_LLM_BACKEND: "disabled",
    AUDIT_WORKER_HEARTBEAT_INTERVAL_MS: 60_000,
  };
}

function makeRelease(overrides: Partial<ReleaseRow> = {}): ReleaseRow {
  return {
    id: RELEASE_ID,
    org_id: "org-a",
    package_name: "@team/pkg",
    version: "1.0.0",
    tarball_digest: "digest",
    tarball_key: "tarballs/pkg-1.0.0.tgz",
    tarball_filename: "pkg-1.0.0.tgz",
    payload_key: "payloads/pkg-1.0.0.json",
    integrity: null,
    shasum: null,
    status: "pending",
    replay_state: "not_started",
    replay_job_id: null,
    replay_started_at: null,
    publisher: "publisher",
    intent: "Add a helper.",
    manifest: {},
    created_at: new Date("2026-01-01T00:00:00.000Z"),
    updated_at: new Date("2026-01-01T00:00:00.000Z"),
    ...overrides,
  };
}

function makeAudit(): AuditRow {
  return {
    id: "22222222-2222-2222-2222-222222222222",
    org_id: "org-a",
    release_id: RELEASE_ID,
    engine_version: "test",
    policy_version: "policy-1",
    llm_review: null,
    safety_verdict: "clear",
    intent_verdict: "matches",
    risk_tier: "low",
    policy_result: "pass",
    signals: [],
    change_set: {},
    summary: "Passed.",
    started_at: new Date("2026-01-01T00:00:01.000Z"),
    finished_at: new Date("2026-01-01T00:00:02.000Z"),
    created_at: new Date("2026-01-01T00:00:02.000Z"),
  };
}

function makePool(options: {
  release?: ReleaseRow | null;
  audit?: AuditRow | null;
}): never {
  return {
    query: async (sql: string) => {
      if (sql.includes("from releases")) {
        return { rows: options.release ? [options.release] : [] };
      }
      if (sql.includes("from audits")) {
        return { rows: options.audit ? [options.audit] : [] };
      }
      return { rows: [] };
    },
  } as never;
}

function makeLifecycle() {
  const applyDecision = vi.fn<ReleaseLifecycle["applyDecision"]>(async () => ({
    outcome: "applied",
    release: makeRelease({ status: "approved" }),
    replay: "succeeded",
  }));
  const replay = vi.fn<ReleaseLifecycle["replay"]>(async () => ({
    outcome: "applied",
    release: makeRelease({
      status: "approved",
      replay_state: "succeeded",
    }),
    replay: "succeeded",
  }));
  return {
    applyDecision,
    replay,
    lifecycle: { applyDecision, replay } as never,
  };
}

async function start(options: {
  release?: ReleaseRow | null;
  audit?: AuditRow | null;
}): Promise<{
  handler: Handler;
  work: ReturnType<typeof vi.fn>;
  applyDecision: ReturnType<typeof makeLifecycle>["applyDecision"];
  replay: ReturnType<typeof makeLifecycle>["replay"];
  logger: { info: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> };
  stop: () => void;
}> {
  const handlers: Handler[] = [];
  const work = vi.fn(
    async (_queue: string, _options: unknown, handler: Handler) => {
      handlers.push(handler);
      return "worker-1";
    },
  );
  const { applyDecision, replay, lifecycle } = makeLifecycle();
  const logger = { info: vi.fn(), error: vi.fn() };
  const deps = {
    boss: { work } as never,
    pool: makePool(options),
    storage: {} as never,
    lifecycle,
    config: testConfig(),
    logger,
  } as AuditWorkerDeps;
  const handle = await startAuditWorker(deps);
  return {
    handler: handlers[0]!,
    work,
    applyDecision,
    replay,
    logger,
    stop: handle.stop,
  };
}

describe("audit worker handler", () => {
  it("registers one job per invocation instead of relying on the queue default", async () => {
    const { work, handler, stop } = await start({ release: null });

    expect(work).toHaveBeenCalledWith(
      "veripack-audit",
      { batchSize: 1 },
      expect.any(Function),
    );
    expect(handler).toBeTypeOf("function");
    stop();
  });

  it("ignores a job whose release disappeared", async () => {
    const { handler, applyDecision, replay, logger, stop } = await start({
      release: null,
    });

    await handler([{ data: { releaseId: RELEASE_ID } }]);

    expect(applyDecision).not.toHaveBeenCalled();
    expect(replay).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalled();
    stop();
  });

  it("completes a retried low-risk audit through auto-approval", async () => {
    const { handler, applyDecision, stop } = await start({
      release: makeRelease(),
      audit: makeAudit(),
    });

    await handler([{ data: { releaseId: RELEASE_ID } }]);

    expect(applyDecision).toHaveBeenCalledWith(RELEASE_ID, {
      kind: "auto_approve",
      actor: { id: "system:auto", role: "system", type: "system" },
      reason: "Passed.",
    });
    stop();
  });

  it("retries replay for an approved release with failed replay", async () => {
    const { handler, replay, stop } = await start({
      release: makeRelease({
        status: "approved",
        replay_state: "failed",
      }),
      audit: makeAudit(),
    });

    await handler([{ data: { releaseId: RELEASE_ID } }]);

    expect(replay).toHaveBeenCalledWith(RELEASE_ID, {
      id: "system:audit",
      role: "system",
      type: "system",
    });
    stop();
  });

  it("does not throw when a replay retry is refused; the durable job owns retries", async () => {
    const { handler, replay, stop } = await start({
      release: makeRelease({
        status: "approved",
        replay_state: "failed",
      }),
      audit: makeAudit(),
    });
    replay.mockResolvedValueOnce({
      outcome: "refused",
      code: "conflict",
      message: "A replay job is already active for this release.",
    });

    await handler([{ data: { releaseId: RELEASE_ID } }]);

    expect(replay).toHaveBeenCalled();
    stop();
  });
});
