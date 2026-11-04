import { createHash, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AuditPolicy, Signal } from "@veripack/shared";
import {
  DEFAULT_AUDIT_POLICY,
  parseAuditPolicy,
} from "./audit/policy.js";
import type { ReleaseReplayTarget } from "./lifecycle.js";
import {
  createPostgresLifecycleStore,
  createPostgresPolicyContextLoader,
} from "./lifecycle-adapters.js";
import { createReleaseLifecycle } from "./lifecycle.js";
import { runMigrations } from "./migrations.js";
import { activatePolicy } from "./policy-store.js";
import {
  claimReplayJob,
  getReplayJob,
} from "./replay-jobs.js";
import { processNextReplayJob } from "./replay-worker.js";
import { insertAudit } from "./releases.js";
import {
  createTestDatabase,
  type TestDatabase,
} from "./test-support/integration-db.js";

const ORG = "org-1";
const FALLBACK = parseAuditPolicy("v1-default-1", "{}");
const logger = { info: () => undefined, error: () => undefined };

const TARBALL = Buffer.from("fake tarball bytes");
const DIGEST = createHash("sha256").update(TARBALL).digest("hex");

async function seedRelease(
  db: TestDatabase,
  options: {
    status?: string;
    riskTier?: "low" | "high";
    policyVersion?: string;
  } = {},
): Promise<string> {
  const releaseId = randomUUID();
  await db.pool.query(
    `insert into releases (
       id, org_id, package_name, version, tarball_digest, tarball_key,
       tarball_filename, payload_key, publisher, intent, manifest, status
     )
     values ($1, $2, '@acme/widget', '1.0.0', $3, $4, 'widget-1.0.0.tgz',
             $5, 'publisher-1', 'Update the README.', '{}'::jsonb, $6)`,
    [
      releaseId,
      ORG,
      DIGEST,
      `tarballs/${releaseId}.tgz`,
      `payloads/${releaseId}.json`,
      options.status ?? "pending",
    ],
  );

  const high = options.riskTier === "high";
  const signals: Signal[] = [
    high
      ? {
          type: "publisher_changed",
          ruleId: "publisher-changed",
          severity: "high",
          source: "deterministic",
          message: "Publisher changed.",
        }
      : {
          type: "docs_tests_only",
          ruleId: "docs-tests-only",
          severity: "info",
          source: "deterministic",
          message: "Only documentation and test files changed.",
        },
  ];
  await insertAudit(db.pool, {
    orgId: ORG,
    releaseId,
    engineVersion: "engine-1",
    policyVersion: options.policyVersion ?? "v1-default-1",
    llmReview: null,
    safetyVerdict: high ? "review" : "clear",
    intentVerdict: "matches",
    riskTier: high ? "high" : "low",
    policyResult: high ? "warn" : "pass",
    signals,
    changeSet: {},
    summary: "Seeded.",
    startedAt: new Date(),
    finishedAt: new Date(),
  });
  return releaseId;
}

function makeLifecycle(db: TestDatabase) {
  return createReleaseLifecycle({
    orgId: ORG,
    store: createPostgresLifecycleStore(db.pool, FALLBACK),
    loadPolicyContext: createPostgresPolicyContextLoader(db.pool, FALLBACK),
    logger,
  });
}

function fakeTarget(overrides: Partial<ReleaseReplayTarget> = {}) {
  const target: ReleaseReplayTarget & { replays: number } = {
    replays: 0,
    loadPayload: async () => ({
      name: "@acme/widget",
      versions: { "1.0.0": {} },
    }),
    loadTarball: async () => TARBALL,
    replay: async () => {
      target.replays += 1;
    },
    ...overrides,
  };
  return target;
}

describe("durable replay (integration)", () => {
  it("commits the approval and its replay job atomically", async () => {
    const db = await createTestDatabase();
    try {
      const releaseId = await seedRelease(db);
      const lifecycle = makeLifecycle(db);

      const result = await lifecycle.applyDecision(releaseId, {
        kind: "approve",
        actor: { id: "admin-1", role: "admin", type: "human" },
      });
      if (result.outcome !== "applied") {
        throw new Error(`Expected applied, got ${result.outcome}`);
      }
      expect(result.replay).toBe("queued");

      const jobs = await db.pool.query<{
        state: string;
        release_id: string;
      }>("select state, release_id from replay_jobs");
      expect(jobs.rows).toEqual([{ state: "queued", release_id: releaseId }]);

      const release = await db.pool.query<{
        status: string;
        replay_state: string;
        replay_job_id: string | null;
      }>("select status, replay_state, replay_job_id from releases");
      expect(release.rows[0]?.status).toBe("approved");
      expect(release.rows[0]?.replay_state).toBe("not_started");
      expect(release.rows[0]?.replay_job_id).not.toBeNull();
    } finally {
      await db.close();
    }
  });

  it("replays a claimed job after verifying the digest", async () => {
    const db = await createTestDatabase();
    try {
      const releaseId = await seedRelease(db, { status: "approved" });
      const lifecycle = makeLifecycle(db);
      const queued = await lifecycle.replay(releaseId, {
        id: "admin-1",
        role: "admin",
        type: "human",
      });
      if (queued.outcome !== "applied") {
        throw new Error(`Expected applied, got ${queued.outcome}`);
      }

      const target = fakeTarget();
      const processed = await processNextReplayJob(
        { pool: db.pool, replayTarget: target, orgId: ORG, logger },
        "worker-a",
      );
      expect(processed).toBe(true);
      expect(target.replays).toBe(1);

      const job = await getReplayJob(db.pool, queued.release.replay_job_id!);
      expect(job?.state).toBe("succeeded");
      const release = await db.pool.query<{ replay_state: string }>(
        "select replay_state from releases where id = $1",
        [releaseId],
      );
      expect(release.rows[0]?.replay_state).toBe("succeeded");
    } finally {
      await db.close();
    }
  });

  it("exhausts a digest-mismatched job into failed instead of publishing", async () => {
    const db = await createTestDatabase();
    try {
      const releaseId = await seedRelease(db, { status: "approved" });
      const lifecycle = makeLifecycle(db);
      await lifecycle.replay(releaseId, {
        id: "admin-1",
        role: "admin",
        type: "human",
      });

      const target = fakeTarget({
        loadTarball: async () => Buffer.from("tampered bytes"),
      });
      await processNextReplayJob(
        {
          pool: db.pool,
          replayTarget: target,
          orgId: ORG,
          logger,
          maxAttempts: 1,
        },
        "worker-a",
      );

      expect(target.replays).toBe(0);
      const jobs = await db.pool.query<{ state: string; last_error: string }>(
        "select state, last_error from replay_jobs",
      );
      expect(jobs.rows[0]?.state).toBe("failed");
      expect(jobs.rows[0]?.last_error).toContain("digest mismatch");
      const release = await db.pool.query<{ replay_state: string }>(
        "select replay_state from releases where id = $1",
        [releaseId],
      );
      expect(release.rows[0]?.replay_state).toBe("failed");
    } finally {
      await db.close();
    }
  });

  it("fails a missing-artifact job immediately and opens a hold", async () => {
    const db = await createTestDatabase();
    try {
      const releaseId = await seedRelease(db, { status: "approved" });
      const lifecycle = makeLifecycle(db);
      await lifecycle.replay(releaseId, {
        id: "admin-1",
        role: "admin",
        type: "human",
      });

      const missing = new Error("The specified key does not exist.");
      missing.name = "NoSuchKey";
      const target = fakeTarget({
        loadTarball: async () => {
          throw missing;
        },
      });
      await processNextReplayJob(
        {
          pool: db.pool,
          replayTarget: target,
          orgId: ORG,
          logger,
          maxAttempts: 3,
          backoffMs: 0,
        },
        "worker-a",
      );

      const jobs = await db.pool.query<{ state: string; attempts: number }>(
        "select state, attempts from replay_jobs",
      );
      expect(jobs.rows[0]?.state).toBe("failed");
      expect(jobs.rows[0]?.attempts).toBe(1);

      const artifact = await db.pool.query<{ state: string }>(
        "select state from release_artifacts where release_id = $1",
        [releaseId],
      );
      expect(artifact.rows[0]?.state).toBe("missing");
      const holds = await db.pool.query<{ count: string }>(
        "select count(*)::text as count from release_holds where release_id = $1 and resolution is null",
        [releaseId],
      );
      expect(holds.rows[0]?.count).toBe("1");
    } finally {
      await db.close();
    }
  });

  it("takes over a job whose lease expired", async () => {
    const db = await createTestDatabase();
    try {
      const releaseId = await seedRelease(db, { status: "approved" });
      const lifecycle = makeLifecycle(db);
      await lifecycle.replay(releaseId, {
        id: "admin-1",
        role: "admin",
        type: "human",
      });

      const first = await claimReplayJob(db.pool, {
        owner: "worker-a",
        leaseMs: 20,
      });
      expect(first?.lease_owner).toBe("worker-a");

      await new Promise((resolve) => setTimeout(resolve, 40));

      const second = await claimReplayJob(db.pool, {
        owner: "worker-b",
        leaseMs: 60_000,
      });
      expect(second?.id).toBe(first?.id);
      expect(second?.lease_owner).toBe("worker-b");
      expect(second?.attempts).toBe(2);
    } finally {
      await db.close();
    }
  });

  it("requires two distinct reviewers when policy demands it", async () => {
    const db = await createTestDatabase();
    try {
      const policy: AuditPolicy = {
        ...DEFAULT_AUDIT_POLICY,
        version: "team-two-reviewer-1",
        review: { medium: "reviewer", high: "two_reviewers" },
      };
      await activatePolicy(db.pool, {
        orgId: ORG,
        version: policy.version,
        policy,
        createdBy: "admin-1",
        direction: "tighten",
        source: "direct",
      });
      const releaseId = await seedRelease(db, {
        riskTier: "high",
        policyVersion: policy.version,
      });
      const lifecycle = makeLifecycle(db);

      const first = await lifecycle.applyDecision(releaseId, {
        kind: "approve",
        actor: { id: "reviewer-1", role: "reviewer", type: "human" },
      });
      expect(first.outcome).toBe("awaiting_second_reviewer");

      const release = await db.pool.query<{ status: string }>(
        "select status from releases where id = $1",
        [releaseId],
      );
      expect(release.rows[0]?.status).toBe("pending");

      const second = await lifecycle.applyDecision(releaseId, {
        kind: "approve",
        actor: { id: "reviewer-2", role: "reviewer", type: "human" },
      });
      if (second.outcome !== "applied") {
        throw new Error(`Expected applied, got ${second.outcome}`);
      }
      expect(second.release.status).toBe("approved");
    } finally {
      await db.close();
    }
  });

  it("recovers pre-P3 wedged in-progress replays at migration time", async () => {
    const db = await createTestDatabase({
      through: "008_v1_policy_requests.sql",
    });
    try {
      const releaseId = randomUUID();
      await db.pool.query(
        `insert into releases (
           id, org_id, package_name, version, tarball_digest, tarball_key,
           tarball_filename, payload_key, publisher, manifest, status,
           replay_state, replay_started_at
         )
         values ($1, $2, '@acme/widget', '1.0.0', 'digest', 'tarballs/w.tgz',
                 'w.tgz', 'payloads/w.json', 'publisher-1', '{}'::jsonb,
                 'approved', 'in_progress', now())`,
        [releaseId, ORG],
      );

      const applied = await runMigrations(db.pool);
      expect(applied).toEqual([
        "009_v1_replay_jobs.sql",
        "010_v1_serving_boundary.sql",
        "011_v1_upstream_cache.sql",
        "012_dashboard_sessions.sql",
      ]);

      const jobs = await db.pool.query<{ state: string }>(
        "select state from replay_jobs where release_id = $1",
        [releaseId],
      );
      expect(jobs.rows).toEqual([{ state: "queued" }]);
      const release = await db.pool.query<{ replay_state: string }>(
        "select replay_state from releases where id = $1",
        [releaseId],
      );
      expect(release.rows[0]?.replay_state).toBe("not_started");
    } finally {
      await db.close();
    }
  });
});
