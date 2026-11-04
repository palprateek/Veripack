import { createHash, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AuditPolicy } from "@veripack/shared";
import { DEFAULT_AUDIT_POLICY } from "./audit/policy.js";
import {
  createAgentReview,
  listAgentReviews,
  panelConsensus,
} from "./agent-reviews.js";
import {
  createClaim,
  decideClaim,
  getApprovedClaim,
} from "./claims.js";
import { exportComplianceEvents } from "./ops/export.js";
import { evaluateRevocationFlags } from "./ops/revocation.js";
import { recordInstallEvent } from "./serving.js";
import {
  createTestDatabase,
  type TestDatabase,
} from "./test-support/integration-db.js";

const ORG = "org-1";

async function seedRelease(
  db: TestDatabase,
  status: string,
  version: string,
): Promise<string> {
  const releaseId = randomUUID();
  await db.pool.query(
    `insert into releases (
       id, org_id, package_name, version, tarball_digest, tarball_key,
       tarball_filename, payload_key, publisher, manifest, status, replay_state
     )
     values ($1, $2, '@acme/widget', $3, 'digest', $4, $5, $6, 'publisher-1',
             '{}'::jsonb, $7, 'succeeded')`,
    [
      releaseId,
      ORG,
      version,
      `tarballs/${releaseId}.tgz`,
      `widget-${version}.tgz`,
      `payloads/${releaseId}.json`,
      status,
    ],
  );
  return releaseId;
}

describe("V2 claims, agents, thresholds, export (integration)", () => {
  it("approves a claim and makes the name exclusive", async () => {
    const db = await createTestDatabase();
    try {
      const claim = await createClaim(db.pool, {
        orgId: ORG,
        packageName: "@acme/widget",
        claimant: "publisher-1",
        reason: "We own the widget product line.",
      });
      expect(claim.status).toBe("pending");
      expect(await getApprovedClaim(db.pool, ORG, "@acme/widget")).toBeNull();

      const decided = await decideClaim(db.pool, {
        orgId: ORG,
        claimId: claim.id,
        decision: "approved",
        decidedBy: "admin-1",
      });
      expect(decided?.status).toBe("approved");
      const approved = await getApprovedClaim(db.pool, ORG, "@acme/widget");
      expect(approved?.claimant).toBe("publisher-1");

      // A second pending claim for the same name is rejected by the index.
      await expect(
        createClaim(db.pool, {
          orgId: ORG,
          packageName: "@acme/widget",
          claimant: "publisher-2",
          reason: "Squatting attempt.",
        }).then(() =>
          createClaim(db.pool, {
            orgId: ORG,
            packageName: "@acme/widget",
            claimant: "publisher-3",
            reason: "Another pending claim.",
          }),
        ),
      ).rejects.toThrow();
    } finally {
      await db.close();
    }
  });

  it("records append-only agent reviews and a panel consensus", async () => {
    const db = await createTestDatabase();
    try {
      const releaseId = await seedRelease(db, "pending", "1.0.0");
      await createAgentReview(db.pool, {
        orgId: ORG,
        releaseId,
        agentId: "llm:llama",
        recommendation: "approve",
        confidence: 0.9,
        rationale: "Docs-only change.",
      });
      await createAgentReview(db.pool, {
        orgId: ORG,
        releaseId,
        agentId: "static-advisor",
        recommendation: "approve",
        confidence: 1,
        rationale: "No signals above info.",
      });

      const reviews = await listAgentReviews(db.pool, releaseId);
      expect(reviews).toHaveLength(2);
      expect(panelConsensus(reviews).consensus).toBe("approve");

      await expect(
        db.pool.query("delete from agent_reviews"),
      ).rejects.toThrow(/append-only/);
    } finally {
      await db.close();
    }
  });

  it("flags young low-install releases once for quarantine review", async () => {
    const db = await createTestDatabase();
    try {
      const releaseId = await seedRelease(db, "approved", "1.0.0");
      const policy: AuditPolicy = {
        ...DEFAULT_AUDIT_POLICY,
        revocation: { flagBelowInstalls: 5, withinDays: 30 },
      };

      const first = await evaluateRevocationFlags(db.pool, ORG, policy);
      expect(first.map((release) => release.id)).toEqual([releaseId]);

      // Idempotent: already flagged releases are not flagged again.
      const second = await evaluateRevocationFlags(db.pool, ORG, policy);
      expect(second).toEqual([]);

      await recordInstallEvent(db.pool, {
        orgId: ORG,
        actor: "installer",
        packageName: "@acme/widget",
        version: "1.0.0",
        decision: "allowed",
        source: "tarball",
      });
      const other = await seedRelease(db, "approved", "1.1.0");
      const third = await evaluateRevocationFlags(db.pool, ORG, {
        ...policy,
        revocation: { flagBelowInstalls: 1, withinDays: 30 },
      });
      // 1 install is not below a threshold of 1; only the new release flags.
      expect(third.map((release) => release.id)).toEqual([other]);
      void other;
    } finally {
      await db.close();
    }
  });

  it("exports compliance events as JSON Lines", async () => {
    const db = await createTestDatabase();
    try {
      const releaseId = await seedRelease(db, "approved", "1.0.0");
      void releaseId;
      await recordInstallEvent(db.pool, {
        orgId: ORG,
        actor: "installer",
        packageName: "@acme/widget",
        version: "1.0.0",
        decision: "allowed",
        source: "tarball",
      });

      const stored = new Map<string, Buffer>();
      const store = {
        putBuffer: async (key: string, value: Buffer) => {
          stored.set(key, value);
        },
      };
      const result = await exportComplianceEvents(db.pool, store, {
        orgId: ORG,
        actor: "admin-1",
      });

      expect(result.counts.installEvents).toBe(1);
      const body = stored.get(result.key)?.toString("utf8") ?? "";
      const lines = body.trim().split("\n").map((line) => JSON.parse(line));
      expect(lines.some((line) => line.kind === "install_event")).toBe(true);
      expect(
        createHash("sha256").update(body).digest("hex"),
      ).toBeTypeOf("string");
    } finally {
      await db.close();
    }
  });
});
