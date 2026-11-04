import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { runMigrations } from "./migrations.js";
import { createTestDatabase } from "./test-support/integration-db.js";

const LATEST_MIGRATION = "013_v2_claims_agents.sql";

async function seedReleaseAt006(
  pool: Awaited<ReturnType<typeof createTestDatabase>>["pool"],
  options: { version?: string } = {},
): Promise<{ releaseId: string; auditId: string }> {
  const releaseId = randomUUID();
  const auditId = randomUUID();
  const version = options.version ?? "1.0.0";

  await pool.query(
    `insert into releases (
       id, org_id, package_name, version, tarball_digest, tarball_key,
       tarball_filename, payload_key, publisher, manifest
     )
     values ($1, 'org-1', '@acme/widget', $2, $3, $4, $5, $6, 'publisher-1', '{}'::jsonb)`,
    [
      releaseId,
      version,
      `digest-${version}`,
      `tarballs/widget-${version}.tgz`,
      `widget-${version}.tgz`,
      `payloads/widget-${version}.json`,
    ],
  );

  await pool.query(
    `insert into audits (
       id, org_id, release_id, engine_version, safety_verdict, intent_verdict,
       risk_tier, policy_result, started_at, finished_at
     )
     values ($1, 'org-1', $2, 'engine-1', 'clear', 'matches', 'low', 'pass', now(), now())`,
    [auditId, releaseId],
  );

  return { releaseId, auditId };
}

describe("migration smoke test", () => {
  it("applies 001 through the latest migration and is idempotent", async () => {
    const db = await createTestDatabase();
    try {
      const applied = await db.pool.query<{ name: string }>(
        "select name from schema_migrations order by name",
      );
      expect(applied.rows.map((row) => row.name)).toContain(LATEST_MIGRATION);

      const secondRun = await runMigrations(db.pool);
      expect(secondRun).toEqual([]);
      expect(db.schema).toMatch(/^veripack_test_/);
    } finally {
      await db.close();
    }
  });

  it("backfills the current-audit pointer and approval links from 006", async () => {
    const db = await createTestDatabase({
      through: "006_upstream_audits.sql",
    });
    try {
      const { releaseId, auditId } = await seedReleaseAt006(db.pool);

      await db.pool.query(
        `insert into approvals (
           org_id, release_id, reviewer_id, reviewer_type, decision, reason, policy_version
         )
         values ('org-1', $1, 'admin-1', 'human', 'approved', 'Reviewed.', null)`,
        [releaseId],
      );

      const applied = await runMigrations(db.pool);
      expect(applied).toEqual([
        "007_v1_evidence_model.sql",
        "008_v1_policy_requests.sql",
        "009_v1_replay_jobs.sql",
        "010_v1_serving_boundary.sql",
        "011_v1_upstream_cache.sql",
        "012_dashboard_sessions.sql",
        "013_v2_claims_agents.sql",
      ]);

      const releases = await db.pool.query<{ id: string }>(
        "select id from releases",
      );
      expect(releases.rows.map((row) => row.id)).toEqual([releaseId]);

      const pointer = await db.pool.query<{
        release_id: string;
        audit_id: string;
      }>("select release_id, audit_id from release_current_audits");
      expect(pointer.rows).toEqual([
        { release_id: releaseId, audit_id: auditId },
      ]);

      const approval = await db.pool.query<{
        audit_id: string | null;
        policy_version: string | null;
      }>("select audit_id, policy_version from approvals");
      expect(approval.rows[0]?.audit_id).toBe(auditId);
      expect(approval.rows[0]?.policy_version).toBe("m1-static");
    } finally {
      await db.close();
    }
  });

  it("fails clearly on agent evidence instead of rewriting it", async () => {
    const db = await createTestDatabase({
      through: "006_upstream_audits.sql",
    });
    try {
      const { releaseId } = await seedReleaseAt006(db.pool);
      await db.pool.query(
        `insert into approvals (
           org_id, release_id, reviewer_id, reviewer_type, decision, reason
         )
         values ('org-1', $1, 'agent-1', 'agent', 'rejected', 'Agent verdict.')`,
        [releaseId],
      );

      await expect(runMigrations(db.pool)).rejects.toThrow(
        /reviewer_type = 'agent'/,
      );

      const applied = await db.pool.query<{ name: string }>(
        "select name from schema_migrations order by name",
      );
      expect(applied.rows.map((row) => row.name)).not.toContain(
        LATEST_MIGRATION,
      );

      const approval = await db.pool.query<{ reviewer_type: string }>(
        "select reviewer_type from approvals",
      );
      expect(approval.rows[0]?.reviewer_type).toBe("agent");
    } finally {
      await db.close();
    }
  });
});
