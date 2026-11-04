import { describe, expect, it } from "vitest";
import { createDb, type Db } from "./db.js";
import {
  StaleAuditError,
  getApprovals,
  getCurrentAudit,
  getReleaseDetail,
  insertAudit,
  insertRelease,
  listAuditsForRelease,
  recordDecision,
  type InsertAuditInput,
  type ReleaseRow,
} from "./releases.js";
import {
  TEST_DATABASE_URL,
  createTestDatabase,
  uniqueRoleName,
  type TestDatabase,
} from "./test-support/integration-db.js";

const ORG_ID = "org-1";

async function seedRelease(
  pool: Db,
  version = "1.0.0",
): Promise<ReleaseRow> {
  return insertRelease(pool, {
    orgId: ORG_ID,
    packageName: "@acme/widget",
    version,
    tarballDigest: `digest-${version}`,
    tarballKey: `tarballs/widget-${version}.tgz`,
    tarballFilename: `widget-${version}.tgz`,
    payloadKey: `payloads/widget-${version}.json`,
    integrity: `sha512-${version}`,
    shasum: `shasum-${version}`,
    publisher: "publisher-1",
    intent: "Fix the retry loop.",
    manifest: {},
  });
}

function auditInput(
  release: ReleaseRow,
  overrides: Partial<InsertAuditInput> = {},
): InsertAuditInput {
  return {
    orgId: release.org_id,
    releaseId: release.id,
    engineVersion: "engine-1",
    policyVersion: "policy-1",
    llmReview: null,
    safetyVerdict: "clear",
    intentVerdict: "matches",
    riskTier: "low",
    policyResult: "pass",
    signals: [],
    changeSet: {},
    summary: "Passed.",
    startedAt: new Date("2026-01-01T00:00:00Z"),
    finishedAt: new Date("2026-01-01T00:00:01Z"),
    ...overrides,
  };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("evidence model", () => {
  it("stores multiple audits, enforces tuple uniqueness, and moves the pointer", async () => {
    const db = await createTestDatabase();
    try {
      const release = await seedRelease(db.pool);
      const first = await insertAudit(db.pool, auditInput(release));
      await delay(20);
      const second = await insertAudit(
        db.pool,
        auditInput(release, {
          engineVersion: "engine-2",
          policyVersion: "policy-2",
        }),
      );

      expect((await getCurrentAudit(db.pool, release.id))?.id).toBe(second.id);

      const history = await listAuditsForRelease(db.pool, release.id);
      expect(history.map((audit) => audit.id)).toEqual([
        second.id,
        first.id,
      ]);

      const detail = await getReleaseDetail(db.pool, ORG_ID, release.id);
      expect(detail?.audit?.id).toBe(second.id);
      expect(detail?.audits.map((audit) => audit.id)).toEqual([
        second.id,
        first.id,
      ]);

      await expect(
        insertAudit(
          db.pool,
          auditInput(release, {
            engineVersion: "engine-1",
            policyVersion: "policy-1",
          }),
        ),
      ).rejects.toMatchObject({ code: "23505" });

      expect(await listAuditsForRelease(db.pool, release.id)).toHaveLength(2);
    } finally {
      await db.close();
    }
  });

  it("requires approval evidence to reference the current audit", async () => {
    const db = await createTestDatabase();
    try {
      const release = await seedRelease(db.pool);
      const first = await insertAudit(db.pool, auditInput(release));
      await delay(20);
      const second = await insertAudit(
        db.pool,
        auditInput(release, {
          engineVersion: "engine-2",
          policyVersion: "policy-2",
        }),
      );

      await expect(
        db.pool.query(
          `insert into approvals (
             org_id, release_id, reviewer_id, reviewer_type, reviewer_role,
             decision, reason, policy_version
           )
           values ($1, $2, 'admin-1', 'human', 'admin', 'approved', 'Looks good.', $3)`,
          [ORG_ID, release.id, second.policy_version],
        ),
      ).rejects.toThrow(/requires an audit id/);

      await expect(
        db.pool.query(
          `insert into approvals (
             org_id, release_id, audit_id, reviewer_id, reviewer_type,
             reviewer_role, decision, reason, policy_version
           )
           values ($1, $2, $3, 'admin-1', 'human', 'admin', 'approved', 'Looks good.', $4)`,
          [ORG_ID, release.id, first.id, first.policy_version],
        ),
      ).rejects.toThrow(/must reference the current audit/);

      // Non-approval decisions must carry the current audit when one exists.
      await expect(
        db.pool.query(
          `insert into approvals (
             org_id, release_id, reviewer_id, reviewer_type, reviewer_role,
             decision, reason, policy_version
           )
           values ($1, $2, 'admin-1', 'human', 'admin', 'rejected', 'No.', null)`,
          [ORG_ID, release.id],
        ),
      ).rejects.toThrow(/must reference the current audit/);

      await db.pool.query(
        `insert into approvals (
           org_id, release_id, audit_id, reviewer_id, reviewer_type,
           reviewer_role, decision, reason, policy_version
         )
         values ($1, $2, $3, 'admin-1', 'human', 'admin', 'rejected', 'No.', $4)`,
        [ORG_ID, release.id, second.id, second.policy_version],
      );

      await expect(
        db.pool.query(
          `insert into approvals (
             org_id, release_id, reviewer_id, reviewer_type, reviewer_role,
             decision, reason, policy_version
           )
           values ($1, $2, 'agent-1', 'agent', 'system', 'rejected', 'No.', null)`,
          [ORG_ID, release.id],
        ),
      ).rejects.toMatchObject({ code: "23514" });
    } finally {
      await db.close();
    }
  });

  it("allows a null audit link only when the release has no audit", async () => {
    const db = await createTestDatabase();
    try {
      const release = await seedRelease(db.pool);

      await db.pool.query(
        `insert into approvals (
           org_id, release_id, reviewer_id, reviewer_type, reviewer_role,
           decision, reason, policy_version
         )
         values ($1, $2, 'admin-1', 'human', 'admin', 'rejected', 'No audit yet.', null)`,
        [ORG_ID, release.id],
      );

      const inserted = await db.pool.query<{ audit_id: string | null }>(
        "select audit_id from approvals where release_id = $1",
        [release.id],
      );
      expect(inserted.rows[0]?.audit_id).toBeNull();
    } finally {
      await db.close();
    }
  });

  it("refuses a decision planned against a stale audit", async () => {
    const db = await createTestDatabase();
    try {
      const release = await seedRelease(db.pool);
      const first = await insertAudit(db.pool, auditInput(release));
      await delay(20);
      const second = await insertAudit(
        db.pool,
        auditInput(release, {
          engineVersion: "engine-2",
          policyVersion: "policy-2",
        }),
      );

      const decision = (auditId: string, policyVersion: string) => ({
        status: "approved" as const,
        decision: "approved" as const,
        auditId,
        reviewerId: "admin-1",
        reviewerType: "human" as const,
        reviewerRole: "admin",
        reason: "Reviewed on call.",
        policyVersion,
        expectedStatus: ["pending" as const],
        replay: false,
      });

      await expect(
        recordDecision(
          db.pool,
          release,
          decision(first.id, first.policy_version),
        ),
      ).rejects.toBeInstanceOf(StaleAuditError);

      await expect(
        recordDecision(
          db.pool,
          release,
          decision(second.id, first.policy_version),
        ),
      ).rejects.toBeInstanceOf(StaleAuditError);

      const updated = await recordDecision(
        db.pool,
        release,
        decision(second.id, second.policy_version),
      );
      expect(updated?.status).toBe("approved");

      const approvals = await getApprovals(db.pool, release.id);
      expect(approvals).toHaveLength(1);
      expect(approvals[0]).toMatchObject({
        audit_id: second.id,
        reviewer_type: "human",
        reviewer_role: "admin",
        policy_version: second.policy_version,
        decision: "approved",
      });
    } finally {
      await db.close();
    }
  });

  it("rejects updates and deletes on audits, approvals, and audit events", async () => {
    const db = await createTestDatabase();
    try {
      const release = await seedRelease(db.pool);
      const audit = await insertAudit(db.pool, auditInput(release));
      await db.pool.query(
        `insert into approvals (
           org_id, release_id, audit_id, reviewer_id, reviewer_type,
           reviewer_role, decision, reason, policy_version
         )
         values ($1, $2, $3, 'admin-1', 'human', 'admin', 'rejected', 'No.', $4)`,
        [ORG_ID, release.id, audit.id, audit.policy_version],
      );
      const events = await db.pool.query<{ id: string }>(
        "select id from audit_events where subject = $1",
        [release.id],
      );
      expect(events.rows.length).toBeGreaterThan(0);

      await expect(
        db.pool.query("update audits set summary = 'tampered' where id = $1", [
          audit.id,
        ]),
      ).rejects.toThrow(/append-only/);
      await expect(
        db.pool.query("delete from audits where id = $1", [audit.id]),
      ).rejects.toThrow(/append-only/);
      await expect(
        db.pool.query("update approvals set reason = 'tampered'"),
      ).rejects.toThrow(/append-only/);
      await expect(db.pool.query("delete from approvals")).rejects.toThrow(
        /append-only/,
      );
      await expect(
        db.pool.query("update audit_events set action = 'tampered' where id = $1", [
          events.rows[0]!.id,
        ]),
      ).rejects.toThrow(/append-only/);
      await expect(
        db.pool.query("delete from audit_events where id = $1", [
          events.rows[0]!.id,
        ]),
      ).rejects.toThrow(/append-only/);
    } finally {
      await db.close();
    }
  });

  it("grants the restricted application role read/append but not mutation", async () => {
    const role = uniqueRoleName();
    const admin = createDb(TEST_DATABASE_URL);
    let db: TestDatabase | null = null;

    try {
      await admin.query(`create role "${role}"`);
      db = await createTestDatabase({ appRole: role });

      const release = await seedRelease(db.pool);
      const audit = await insertAudit(db.pool, auditInput(release));

      const client = await db.pool.connect();
      try {
        await client.query(`set role "${role}"`);

        const read = await client.query<{ count: number }>(
          "select count(*)::int as count from audits",
        );
        expect(read.rows[0]?.count).toBe(1);

        await client.query(
          `insert into audit_events (org_id, actor, action)
           values ($1, 'operator', 'test.event')`,
          [ORG_ID],
        );

        await expect(
          client.query("update audits set summary = 'tampered'"),
        ).rejects.toThrow(/permission denied/);
        await expect(
          client.query("delete from approvals"),
        ).rejects.toThrow(/permission denied/);
        await expect(
          client.query("update audit_events set action = 'tampered'"),
        ).rejects.toThrow(/permission denied/);
        await expect(
          client.query("delete from release_current_audits"),
        ).rejects.toThrow(/permission denied/);
      } finally {
        await client.query("reset role");
        client.release();
      }

      expect((await getCurrentAudit(db.pool, release.id))?.id).toBe(audit.id);
    } finally {
      await db?.close();
      await admin.query(`drop role if exists "${role}"`).catch(() => undefined);
      await admin.end().catch(() => undefined);
    }
  });
});
