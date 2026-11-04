import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AuditPolicy, Signal } from "@veripack/shared";
import {
  DEFAULT_AUDIT_POLICY,
  diffPolicies,
  parseAuditPolicy,
} from "./audit/policy.js";
import {
  PolicyControlError,
  activatePolicy,
  approvePolicyChangeRequest,
  createPolicyChangeRequest,
  getActivePolicy,
  getPolicyImpact,
} from "./policy-store.js";
import { insertAudit } from "./releases.js";
import { createTestDatabase, type TestDatabase } from "./test-support/integration-db.js";

const ORG = "org-1";
const FALLBACK = parseAuditPolicy("v1-default-1", "{}");

function tightened(version: string): AuditPolicy {
  return {
    ...DEFAULT_AUDIT_POLICY,
    version,
    autoApproval: { ...DEFAULT_AUDIT_POLICY.autoApproval, enabled: false },
  };
}

function loosened(version: string): AuditPolicy {
  return { ...DEFAULT_AUDIT_POLICY, version };
}

async function seedReleaseWithAudit(
  db: TestDatabase,
  status: "pending" | "approved",
): Promise<string> {
  const releaseId = randomUUID();
  const version = status === "pending" ? "1.0.0" : "0.9.0";
  await db.pool.query(
    `insert into releases (
       id, org_id, package_name, version, tarball_digest, tarball_key,
       tarball_filename, payload_key, publisher, intent, manifest, status
     )
     values ($1, $2, '@acme/widget', $3, $4, $5, $6, $7, 'publisher-1',
             'Update the README.', '{}'::jsonb, $8)`,
    [
      releaseId,
      ORG,
      version,
      `digest-${version}`,
      `tarballs/widget-${version}.tgz`,
      `widget-${version}.tgz`,
      `payloads/widget-${version}.json`,
      status,
    ],
  );

  const signals: Signal[] = [
    {
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
    policyVersion: "v1-default-1",
    llmReview: null,
    safetyVerdict: "clear",
    intentVerdict: "matches",
    riskTier: "low",
    policyResult: "pass",
    signals,
    changeSet: {},
    summary: "Passed.",
    startedAt: new Date(),
    finishedAt: new Date(),
  });
  return releaseId;
}

describe("policy control (integration)", () => {
  it("activates a tightening immediately", async () => {
    const db = await createTestDatabase();
    try {
      const candidate = tightened("team-tight-1");
      await activatePolicy(db.pool, {
        orgId: ORG,
        version: candidate.version,
        policy: candidate,
        createdBy: "admin-1",
        direction: "tighten",
        diff: diffPolicies(DEFAULT_AUDIT_POLICY, candidate),
        source: "direct",
      });

      const state = await getActivePolicy(db.pool, ORG, FALLBACK);
      expect(state.active.version).toBe("team-tight-1");
      expect(state.active.autoApproval.enabled).toBe(false);
      expect(state.source).toBe("database");

      const events = await db.pool.query<{ action: string }>(
        "select action from audit_events where action = 'policy.activated'",
      );
      expect(events.rows).toHaveLength(1);
    } finally {
      await db.close();
    }
  });

  it("requires a second admin to loosen before the cooling-off ends", async () => {
    const db = await createTestDatabase();
    try {
      const candidate = loosened("team-loose-1");
      const request = await createPolicyChangeRequest(db.pool, {
        orgId: ORG,
        requestedBy: "admin-1",
        basePolicyId: null,
        candidate,
        diff: diffPolicies(tightened("team-tight-1"), candidate),
        direction: "loosen",
        reason: "Docs-only auto-approval is safe for this team.",
      });

      await expect(
        approvePolicyChangeRequest(db.pool, {
          orgId: ORG,
          requestId: request.id,
          approver: "admin-1",
        }),
      ).rejects.toMatchObject({ code: "cooling_off" });

      const approved = await approvePolicyChangeRequest(db.pool, {
        orgId: ORG,
        requestId: request.id,
        approver: "admin-2",
      });
      expect(approved.request.status).toBe("approved");
      expect(approved.request.second_approver).toBe("admin-2");

      const state = await getActivePolicy(db.pool, ORG, FALLBACK);
      expect(state.active.version).toBe("team-loose-1");
    } finally {
      await db.close();
    }
  });

  it("lets the requester loosen after the cooling-off deadline", async () => {
    const db = await createTestDatabase();
    try {
      const t0 = new Date("2026-01-01T00:00:00.000Z");
      const candidate = loosened("team-loose-2");
      const request = await createPolicyChangeRequest(db.pool, {
        orgId: ORG,
        requestedBy: "admin-1",
        basePolicyId: null,
        candidate,
        diff: diffPolicies(tightened("team-tight-1"), candidate),
        direction: "loosen",
        reason: "Cooling-off elapsed.",
        now: t0,
      });

      const approved = await approvePolicyChangeRequest(db.pool, {
        orgId: ORG,
        requestId: request.id,
        approver: "admin-1",
        now: new Date(t0.getTime() + 25 * 60 * 60 * 1_000),
      });
      expect(approved.request.status).toBe("approved");
    } finally {
      await db.close();
    }
  });

  it("expires loosening requests left open past the grace window", async () => {
    const db = await createTestDatabase();
    try {
      const t0 = new Date("2026-01-01T00:00:00.000Z");
      const candidate = loosened("team-loose-3");
      const request = await createPolicyChangeRequest(db.pool, {
        orgId: ORG,
        requestedBy: "admin-1",
        basePolicyId: null,
        candidate,
        diff: diffPolicies(tightened("team-tight-1"), candidate),
        direction: "loosen",
        reason: "Stale request.",
        now: t0,
      });

      const error: unknown = await approvePolicyChangeRequest(db.pool, {
        orgId: ORG,
        requestId: request.id,
        approver: "admin-2",
        now: new Date(t0.getTime() + 9 * 24 * 60 * 60 * 1_000),
      }).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(PolicyControlError);
      expect((error as PolicyControlError).code).toBe("expired");

      const stored = await db.pool.query<{ status: string }>(
        "select status from policy_change_requests where id = $1",
        [request.id],
      );
      expect(stored.rows[0]?.status).toBe("expired");
    } finally {
      await db.close();
    }
  });

  it("reports impact for pending releases only and never changes approved releases", async () => {
    const db = await createTestDatabase();
    try {
      const pendingId = await seedReleaseWithAudit(db, "pending");
      const approvedId = await seedReleaseWithAudit(db, "approved");

      const candidate: AuditPolicy = {
        ...DEFAULT_AUDIT_POLICY,
        version: "team-ban-1",
        packages: { banned: ["@acme/*"], requiredVerdicts: {} },
      };
      const impact = await getPolicyImpact(db.pool, ORG, candidate);
      expect(impact.map((entry) => entry.releaseId)).toEqual([pendingId]);
      expect(impact[0]?.candidatePolicyResult).toBe("block");

      await activatePolicy(db.pool, {
        orgId: ORG,
        version: candidate.version,
        policy: candidate,
        createdBy: "admin-1",
        direction: "tighten",
        diff: diffPolicies(DEFAULT_AUDIT_POLICY, candidate),
        source: "direct",
      });

      const statuses = await db.pool.query<{ id: string; status: string }>(
        "select id, status from releases order by version",
      );
      expect(statuses.rows).toContainEqual({ id: approvedId, status: "approved" });
      expect(statuses.rows).toContainEqual({ id: pendingId, status: "pending" });
    } finally {
      await db.close();
    }
  });

  it("rejects a stored database policy with unknown keys", async () => {
    const db = await createTestDatabase();
    try {
      const invalid = {
        ...DEFAULT_AUDIT_POLICY,
        version: "team-invalid-1",
        blockCriticalFindings: false,
      };
      const inserted = await db.pool.query<{ id: string }>(
        `insert into policy_versions (org_id, version, policy, created_by)
         values ($1, 'team-invalid-1', $2::jsonb, 'admin-1') returning id`,
        [ORG, JSON.stringify(invalid)],
      );
      await db.pool.query(
        `insert into active_policy_versions (org_id, policy_id)
         values ($1, $2)`,
        [ORG, inserted.rows[0]!.id],
      );

      await expect(getActivePolicy(db.pool, ORG, FALLBACK)).rejects.toThrow(
        /Invalid audit policy|Unrecognized key/,
      );
    } finally {
      await db.close();
    }
  });
});
