import { afterEach, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import { config as defaultConfig, type Config } from "../config.js";
import type { ReleaseLifecycle } from "../lifecycle.js";
import type { AuditRow, ReleaseRow } from "../releases.js";
import { buildServer } from "../server.js";

const RELEASE_ID = "11111111-1111-1111-1111-111111111111";

function testConfig(): Config {
  return {
    ...defaultConfig,
    LOG_LEVEL: "silent",
    AUTH_MODE: "static",
    VERIPACK_TOKEN: "publisher-secret",
    REVIEWER_TOKEN: "reviewer-secret",
    REVIEWER_USER: "on-call-reviewer",
    ADMIN_TOKEN: "admin-secret",
    ADMIN_USER: "operator",
    DEFAULT_PUBLISHER: "publisher",
    ORG_ID: "org-a",
    RATE_LIMIT_BACKEND: "memory",
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
    risk_tier: "medium",
    policy_result: "warn",
    signals: [],
    change_set: {},
    summary: "Needs review.",
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
    release: makeRelease({ status: "approved" }),
    replay: "queued",
  }));
  const replay = vi.fn<ReleaseLifecycle["replay"]>(async () => ({
    outcome: "applied",
    release: makeRelease({ status: "approved" }),
    replay: "queued",
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

async function makeApp(lifecycle: unknown): Promise<FastifyInstance> {
  const app = await buildServer({
    config: testConfig(),
    pool: makePool(),
    storage: {},
    verdaccio: { isReachable: async () => true },
    boss: {},
    lifecycle,
  } as never);
  apps.push(app);
  return app;
}

const reviewer = { authorization: "Bearer reviewer-secret" };

describe("review routes", () => {
  it("lists the pending queue for a reviewer", async () => {
    const { lifecycle } = makeLifecycle();
    const app = await makeApp(lifecycle);

    const response = await app.inject({
      method: "GET",
      url: "/review/queue",
      headers: reviewer,
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().releases).toHaveLength(1);
    expect(response.json().releases[0]).toMatchObject({ id: RELEASE_ID });
  });

  it("rejects publisher tokens on the review surface", async () => {
    const { lifecycle } = makeLifecycle();
    const app = await makeApp(lifecycle);

    const response = await app.inject({
      method: "GET",
      url: "/review/queue",
      headers: { authorization: "Bearer publisher-secret" },
    });

    expect(response.statusCode).toBe(401);
  });

  it("forwards approve and reject with the reviewer actor", async () => {
    const { applyDecision, lifecycle } = makeLifecycle();
    const app = await makeApp(lifecycle);

    const approved = await app.inject({
      method: "POST",
      url: `/review/releases/${RELEASE_ID}/approve`,
      headers: reviewer,
    });
    expect(approved.statusCode).toBe(200);
    expect(applyDecision).toHaveBeenCalledWith(RELEASE_ID, {
      kind: "approve",
      actor: { id: "on-call-reviewer", role: "reviewer", type: "human" },
      reason: null,
    });

    const rejected = await app.inject({
      method: "POST",
      url: `/review/releases/${RELEASE_ID}/reject`,
      headers: reviewer,
      payload: { reason: "Install script is unrelated." },
    });
    expect(rejected.statusCode).toBe(200);
    expect(applyDecision).toHaveBeenCalledWith(RELEASE_ID, {
      kind: "reject",
      actor: { id: "on-call-reviewer", role: "reviewer", type: "human" },
      reason: "Install script is unrelated.",
    });
  });

  it("returns 202 while a second reviewer is outstanding", async () => {
    const { applyDecision, lifecycle } = makeLifecycle();
    applyDecision.mockResolvedValueOnce({
      outcome: "awaiting_second_reviewer",
      release: makeRelease(),
      approvalsRecorded: 1,
      approvalsRequired: 2,
    });
    const app = await makeApp(lifecycle);

    const response = await app.inject({
      method: "POST",
      url: `/review/releases/${RELEASE_ID}/approve`,
      headers: reviewer,
    });

    expect(response.statusCode).toBe(202);
    expect(response.json()).toMatchObject({
      decision: "awaiting_second_reviewer",
    });
  });

  it("keeps reviewers off admin-only actions", async () => {
    const { applyDecision, lifecycle } = makeLifecycle();
    const app = await makeApp(lifecycle);

    for (const path of ["quarantine", "un-yank"] as const) {
      const response = await app.inject({
        method: "POST",
        url: `/admin/releases/${RELEASE_ID}/${path}`,
        headers: reviewer,
        payload: { reason: "Trying an admin action." },
      });
      expect(response.statusCode).toBe(401);
    }
    expect(applyDecision).not.toHaveBeenCalled();
  });
});
