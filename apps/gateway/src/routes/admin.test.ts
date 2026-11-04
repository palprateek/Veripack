import { afterEach, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import { config as defaultConfig, type Config } from "../config.js";
import type { LifecycleErrorCode, ReleaseLifecycle } from "../lifecycle.js";
import type { AuditRow, ReleaseRow } from "../releases.js";
import { buildServer } from "../server.js";

const RELEASE_ID = "11111111-1111-1111-1111-111111111111";

function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    ...defaultConfig,
    LOG_LEVEL: "silent",
    AUTH_MODE: "static",
    VERIPACK_TOKEN: "publisher-secret",
    ADMIN_TOKEN: "admin-secret",
    ADMIN_USER: "operator",
    DEFAULT_PUBLISHER: "publisher",
    ORG_ID: "org-a",
    RATE_LIMIT_BACKEND: "memory",
    ...overrides,
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
    status: "approved",
    replay_state: "succeeded",
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

function makePool(): never {
  return {
    query: async (sql: string) => {
      if (sql.includes("from releases")) return { rows: [makeRelease()] };
      if (sql.includes("from audits")) return { rows: [makeAudit()] };
      return { rows: [] };
    },
  } as never;
}

function makeLifecycle() {
  const applyDecision = vi.fn<ReleaseLifecycle["applyDecision"]>(async () => ({
    outcome: "applied",
    release: makeRelease(),
    replay: "succeeded",
  }));
  const replay = vi.fn<ReleaseLifecycle["replay"]>(async () => ({
    outcome: "applied",
    release: makeRelease({ replay_state: "succeeded" }),
    replay: "succeeded",
  }));
  return {
    applyDecision,
    replay,
    lifecycle: { applyDecision, replay } as never,
  };
}

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp(
  lifecycle: unknown,
  pool: unknown = makePool(),
): Promise<FastifyInstance> {
  const app = await buildServer({
    config: testConfig(),
    pool,
    storage: {},
    verdaccio: { isReachable: async () => true },
    boss: {},
    lifecycle,
  } as never);
  apps.push(app);
  return app;
}

const admin = { authorization: "Bearer admin-secret" };

describe("admin decision routes", () => {
  const routes = [
    ["approve", "approve"],
    ["reject", "reject"],
    ["yank", "yank"],
    ["quarantine", "quarantine"],
  ] as const;

  it.each(routes)(
    "forwards %s to the lifecycle with the admin actor and trimmed reason",
    async (path, kind) => {
      const { applyDecision, lifecycle } = makeLifecycle();
      const app = await makeApp(lifecycle);

      const response = await app.inject({
        method: "POST",
        url: `/admin/releases/${RELEASE_ID}/${path}`,
        headers: admin,
        payload: { reason: "  reviewed by on-call  " },
      });

      expect(response.statusCode).toBe(200);
      expect(applyDecision).toHaveBeenCalledWith(RELEASE_ID, {
        kind,
        actor: { id: "operator", role: "admin", type: "human" },
        reason: "reviewed by on-call",
      });
      expect(response.json()).toMatchObject({
        id: RELEASE_ID,
        status: "approved",
      });
    },
  );

  it("maps every refusal code to its HTTP status", async () => {
    const cases: Array<[LifecycleErrorCode, number]> = [
      ["not_found", 404],
      ["illegal_transition", 409],
      ["reason_required", 400],
      ["forbidden", 403],
      ["audit_pending", 409],
      ["stale_audit", 409],
      ["conflict", 409],
      ["replay_state_unknown", 503],
    ];

    for (const [code, status] of cases) {
      const { applyDecision, lifecycle } = makeLifecycle();
      applyDecision.mockResolvedValueOnce({
        outcome: "refused",
        code,
        message: "refused",
      });
      const app = await makeApp(lifecycle);

      const response = await app.inject({
        method: "POST",
        url: `/admin/releases/${RELEASE_ID}/approve`,
        headers: admin,
      });

      expect(response.statusCode).toBe(status);
      expect(response.json()).toEqual({ error: "refused" });
    }
  });

  it("returns 202 when a second reviewer is still required", async () => {
    const { applyDecision, lifecycle } = makeLifecycle();
    applyDecision.mockResolvedValueOnce({
      outcome: "awaiting_second_reviewer",
      release: makeRelease({ status: "pending" }),
      approvalsRecorded: 1,
      approvalsRequired: 2,
    });
    const app = await makeApp(lifecycle);

    const response = await app.inject({
      method: "POST",
      url: `/admin/releases/${RELEASE_ID}/approve`,
      headers: admin,
    });

    expect(response.statusCode).toBe(202);
    expect(response.json()).toMatchObject({
      decision: "awaiting_second_reviewer",
      approvalsRecorded: 1,
      approvalsRequired: 2,
    });
  });

  it("forwards un-yank to the lifecycle", async () => {
    const { applyDecision, lifecycle } = makeLifecycle();
    const app = await makeApp(lifecycle);

    const response = await app.inject({
      method: "POST",
      url: `/admin/releases/${RELEASE_ID}/un-yank`,
      headers: admin,
      payload: { reason: "  false positive  " },
    });

    expect(response.statusCode).toBe(200);
    expect(applyDecision).toHaveBeenCalledWith(RELEASE_ID, {
      kind: "un_yank",
      actor: { id: "operator", role: "admin", type: "human" },
      reason: "false positive",
    });
  });

  it("retries replay without applying another decision", async () => {
    const { applyDecision, replay, lifecycle } = makeLifecycle();
    const app = await makeApp(lifecycle);

    const response = await app.inject({
      method: "POST",
      url: `/admin/releases/${RELEASE_ID}/replay`,
      headers: admin,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      ok: true,
      id: RELEASE_ID,
      replayState: "succeeded",
    });
    expect(replay).toHaveBeenCalledWith(RELEASE_ID, {
      id: "operator",
      role: "admin",
      type: "human",
    });
    expect(applyDecision).not.toHaveBeenCalled();
  });

  it("rejects an invalid release id before calling the lifecycle", async () => {
    const { applyDecision, lifecycle } = makeLifecycle();
    const app = await makeApp(lifecycle);

    const response = await app.inject({
      method: "POST",
      url: "/admin/releases/not-a-uuid/approve",
      headers: admin,
    });

    expect(response.statusCode).toBe(400);
    expect(applyDecision).not.toHaveBeenCalled();
  });

  it("requires the admin token", async () => {
    const { applyDecision, lifecycle } = makeLifecycle();
    const app = await makeApp(lifecycle);

    const response = await app.inject({
      method: "POST",
      url: `/admin/releases/${RELEASE_ID}/approve`,
      headers: { authorization: "Bearer publisher-secret" },
    });

    expect(response.statusCode).toBe(401);
    expect(applyDecision).not.toHaveBeenCalled();
  });
});
