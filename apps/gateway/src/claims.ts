import type { Db, Queryable } from "./db.js";
import { insertEvent } from "./releases.js";

/**
 * V2 package name claims. An approved claim makes a name exclusive to the
 * claimant; publishing someone else's claimed name is refused. Claims never
 * transfer existing releases — disputes are decided by admins.
 */

export type ClaimStatus = "pending" | "approved" | "rejected";

export interface PackageClaimRow {
  id: string;
  org_id: string;
  package_name: string;
  claimant: string;
  reason: string;
  status: ClaimStatus;
  decided_by: string | null;
  decided_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export async function createClaim(
  db: Db,
  input: {
    orgId: string;
    packageName: string;
    claimant: string;
    reason: string;
  },
): Promise<PackageClaimRow> {
  const result = await db.query<PackageClaimRow>(
    `insert into package_claims (org_id, package_name, claimant, reason)
     values ($1, $2, $3, $4)
     returning *`,
    [input.orgId, input.packageName, input.claimant, input.reason],
  );
  const claim = result.rows[0]!;
  await insertEvent(db, {
    orgId: input.orgId,
    actor: input.claimant,
    action: "package.claim_requested",
    subject: input.packageName,
    metadata: { claimId: claim.id, reason: input.reason },
  });
  return claim;
}

export async function listClaims(
  db: Queryable,
  orgId: string,
  status?: ClaimStatus,
): Promise<PackageClaimRow[]> {
  const result = await db.query<PackageClaimRow>(
    `select * from package_claims
      where org_id = $1 and ($2::text is null or status = $2)
      order by created_at desc
      limit 100`,
    [orgId, status ?? null],
  );
  return result.rows;
}

export async function getApprovedClaim(
  db: Queryable,
  orgId: string,
  packageName: string,
): Promise<PackageClaimRow | null> {
  const result = await db.query<PackageClaimRow>(
    `select * from package_claims
      where org_id = $1 and package_name = $2 and status = 'approved'
      limit 1`,
    [orgId, packageName],
  );
  return result.rows[0] ?? null;
}

export async function decideClaim(
  db: Db,
  input: {
    orgId: string;
    claimId: string;
    decision: "approved" | "rejected";
    decidedBy: string;
  },
): Promise<PackageClaimRow | null> {
  const result = await db.query<PackageClaimRow>(
    `update package_claims
        set status = $3, decided_by = $4, decided_at = now(), updated_at = now()
      where org_id = $1 and id = $2 and status = 'pending'
      returning *`,
    [input.orgId, input.claimId, input.decision, input.decidedBy],
  );
  const claim = result.rows[0] ?? null;
  if (claim) {
    await insertEvent(db, {
      orgId: input.orgId,
      actor: input.decidedBy,
      action: `package.claim_${input.decision}`,
      subject: claim.package_name,
      metadata: { claimId: claim.id, claimant: claim.claimant },
    });
  }
  return claim;
}
