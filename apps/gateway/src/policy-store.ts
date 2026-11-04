import type {
  AuditPolicy,
  PolicyResult,
  RiskTier,
  Signal,
} from "@veripack/shared";
import {
  diffPolicies,
  evaluatePolicy,
  parseAuditPolicy,
  policyDirection,
  type PolicyChangeDirection,
  type PolicyDiffEntry,
} from "./audit/policy.js";
import type { Db, DbClient, Queryable } from "./db.js";
import { withTransaction } from "./db.js";

export interface PolicyVersionRow {
  id: string;
  org_id: string;
  version: string;
  policy: AuditPolicy;
  created_by: string;
  created_at: Date;
  active: boolean;
}

export interface PolicyState {
  active: AuditPolicy;
  activeId: string | null;
  source: "database" | "environment";
  createdBy: string | null;
  createdAt: string | null;
}

export type PolicyRequestStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "expired";

export interface PolicyChangeRequestRow {
  id: string;
  org_id: string;
  requested_by: string;
  base_policy_id: string | null;
  candidate_policy: AuditPolicy;
  diff: PolicyDiffEntry[];
  direction: PolicyChangeDirection;
  reason: string;
  status: PolicyRequestStatus;
  cooling_off_deadline: Date;
  second_approver: string | null;
  decided_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export type PolicyControlErrorCode =
  | "not_found"
  | "conflict"
  | "cooling_off"
  | "expired"
  | "forbidden"
  | "invalid";

export class PolicyControlError extends Error {
  constructor(
    readonly code: PolicyControlErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "PolicyControlError";
  }
}

/** A pending loosening request cannot sit open forever. */
export const POLICY_REQUEST_GRACE_MS = 7 * 24 * 60 * 60 * 1_000;
export const POLICY_COOLING_OFF_MS = 24 * 60 * 60 * 1_000;

function mapRow(row: PolicyVersionRow): PolicyVersionRow {
  return {
    ...row,
    policy:
      typeof row.policy === "string"
        ? (JSON.parse(row.policy) as AuditPolicy)
        : row.policy,
  };
}

function mapRequestRow(row: PolicyChangeRequestRow): PolicyChangeRequestRow {
  return {
    ...row,
    candidate_policy:
      typeof row.candidate_policy === "string"
        ? (JSON.parse(row.candidate_policy) as AuditPolicy)
        : row.candidate_policy,
    diff:
      typeof row.diff === "string"
        ? (JSON.parse(row.diff) as PolicyDiffEntry[])
        : row.diff,
  };
}

export async function getActivePolicy(
  db: Queryable,
  orgId: string,
  fallback: AuditPolicy,
): Promise<PolicyState> {
  const result = await db.query<PolicyVersionRow>(
    `select p.id, p.org_id, p.version, p.policy, p.created_by, p.created_at,
            true as active
       from active_policy_versions active
       join policy_versions p on p.id = active.policy_id
      where active.org_id = $1
      limit 1`,
    [orgId],
  );
  const row = result.rows[0];
  if (!row) {
    // Keep partially migrated databases readable while the pointer table is
    // introduced. New writes never use the legacy active flag.
    const legacy = await db.query<PolicyVersionRow>(
      `select id, org_id, version, policy, created_by, created_at,
              true as active
         from policy_versions
        where org_id = $1
          and coalesce((policy ->> 'active')::boolean, false) = true
        order by created_at desc
        limit 1`,
      [orgId],
    );
    const legacyRow = legacy.rows[0];
    if (!legacyRow) {
      return {
        active: fallback,
        activeId: null,
        source: "environment",
        createdBy: null,
        createdAt: null,
      };
    }
    const mappedLegacy = mapRow(legacyRow);
    const legacyActive = parseAuditPolicy(
      mappedLegacy.version,
      JSON.stringify(mappedLegacy.policy),
    );
    return {
      active: legacyActive,
      activeId: mappedLegacy.id,
      source: "database",
      createdBy: mappedLegacy.created_by,
      createdAt: mappedLegacy.created_at.toISOString(),
    };
  }

  const mapped = mapRow(row);
  const active = parseAuditPolicy(mapped.version, JSON.stringify(mapped.policy));
  return {
    active,
    activeId: mapped.id,
    source: "database",
    createdBy: mapped.created_by,
    createdAt: mapped.created_at.toISOString(),
  };
}

export async function listPolicyVersions(
  db: Queryable,
  orgId: string,
  limit = 50,
): Promise<PolicyVersionRow[]> {
  const result = await db.query<PolicyVersionRow>(
    `select p.id, p.org_id, p.version, p.policy, p.created_by, p.created_at,
            (active.policy_id is not null) as active
       from policy_versions p
       left join active_policy_versions active
         on active.org_id = p.org_id and active.policy_id = p.id
      where p.org_id = $1
      order by p.created_at desc
      limit $2`,
    [orgId, Math.min(Math.max(limit, 1), 200)],
  );
  return result.rows.map(mapRow);
}

export async function getPolicyVersion(
  db: Queryable,
  orgId: string,
  version: string,
): Promise<PolicyVersionRow | null> {
  const result = await db.query<PolicyVersionRow>(
    `select p.id, p.org_id, p.version, p.policy, p.created_by, p.created_at,
            (active.policy_id is not null) as active
       from policy_versions p
       left join active_policy_versions active
         on active.org_id = p.org_id and active.policy_id = p.id
      where p.org_id = $1 and p.version = $2
      limit 1`,
    [orgId, version],
  );
  const row = result.rows[0];
  return row ? mapRow(row) : null;
}

export interface ActivatePolicyInput {
  orgId: string;
  version: string;
  policy: AuditPolicy;
  createdBy: string;
  direction?: PolicyChangeDirection | "none";
  diff?: PolicyDiffEntry[];
  source?: "direct" | "change_request";
  sourceRequestId?: string | null;
}

async function insertPolicyVersion(
  client: DbClient,
  input: ActivatePolicyInput,
  validated: AuditPolicy,
): Promise<PolicyVersionRow> {
  const result = await client.query<PolicyVersionRow>(
    `insert into policy_versions (org_id, version, policy, created_by)
     values ($1, $2, $3::jsonb, $4)
     returning id, org_id, version, policy, created_by, created_at, false as active`,
    [input.orgId, validated.version, JSON.stringify(validated), input.createdBy],
  );
  const saved = result.rows[0]!;
  await client.query(
    `insert into active_policy_versions (org_id, policy_id)
     values ($1, $2)
     on conflict (org_id) do update
       set policy_id = excluded.policy_id,
           activated_at = now()`,
    [input.orgId, saved.id],
  );
  await client.query(
    `insert into audit_events (org_id, actor, action, metadata)
     values ($1, $2, 'policy.activated', $3)`,
    [
      input.orgId,
      input.createdBy,
      JSON.stringify({
        version: validated.version,
        policyId: saved.id,
        direction: input.direction ?? "none",
        diff: input.diff ?? [],
        source: input.source ?? "direct",
        requestId: input.sourceRequestId ?? null,
      }),
    ],
  );
  return saved;
}

export async function activatePolicy(
  db: Db,
  input: ActivatePolicyInput,
): Promise<PolicyVersionRow> {
  const validated = parseAuditPolicy(input.version, JSON.stringify(input.policy));
  return withTransaction(db, async (client) => {
    const saved = await insertPolicyVersion(client, input, validated);
    return mapRow({ ...saved, active: true });
  });
}

export interface CreatePolicyChangeRequestInput {
  orgId: string;
  requestedBy: string;
  basePolicyId: string | null;
  candidate: AuditPolicy;
  diff: PolicyDiffEntry[];
  direction: PolicyChangeDirection;
  reason: string;
  now?: Date;
}

export async function createPolicyChangeRequest(
  db: Db,
  input: CreatePolicyChangeRequestInput,
): Promise<PolicyChangeRequestRow> {
  const validated = parseAuditPolicy(
    input.candidate.version,
    JSON.stringify(input.candidate),
  );
  const now = input.now ?? new Date();
  const deadline = new Date(now.getTime() + POLICY_COOLING_OFF_MS);

  return withTransaction(db, async (client) => {
    const result = await client.query<PolicyChangeRequestRow>(
      `insert into policy_change_requests (
         org_id, requested_by, base_policy_id, candidate_policy, diff,
         direction, reason, status, cooling_off_deadline
       )
       values ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, 'pending', $8)
       returning *`,
      [
        input.orgId,
        input.requestedBy,
        input.basePolicyId,
        JSON.stringify(validated),
        JSON.stringify(input.diff),
        input.direction,
        input.reason,
        deadline,
      ],
    );

    await client.query(
      `insert into audit_events (org_id, actor, action, metadata)
       values ($1, $2, 'policy.change_requested', $3)`,
      [
        input.orgId,
        input.requestedBy,
        JSON.stringify({
          requestId: result.rows[0]!.id,
          version: validated.version,
          direction: input.direction,
          reason: input.reason,
          diff: input.diff,
          coolingOffDeadline: deadline.toISOString(),
        }),
      ],
    );

    return mapRequestRow(result.rows[0]!);
  });
}

export async function listPolicyChangeRequests(
  db: Queryable,
  orgId: string,
  status?: PolicyRequestStatus,
): Promise<PolicyChangeRequestRow[]> {
  const result = await db.query<PolicyChangeRequestRow>(
    `select *
       from policy_change_requests
      where org_id = $1
        and ($2::text is null or status = $2)
      order by created_at desc
      limit 100`,
    [orgId, status ?? null],
  );
  return result.rows.map(mapRequestRow);
}

export async function getPolicyChangeRequest(
  db: Queryable,
  orgId: string,
  requestId: string,
): Promise<PolicyChangeRequestRow | null> {
  const result = await db.query<PolicyChangeRequestRow>(
    `select * from policy_change_requests where org_id = $1 and id = $2`,
    [orgId, requestId],
  );
  const row = result.rows[0];
  return row ? mapRequestRow(row) : null;
}

export interface ApprovePolicyChangeRequestInput {
  orgId: string;
  requestId: string;
  approver: string;
  now?: Date;
}

export interface ApprovedPolicyChange {
  request: PolicyChangeRequestRow;
  policy: PolicyVersionRow;
}

/**
 * A loosening request is completed by a second admin immediately, or by the
 * requesting admin once the 24-hour cooling-off has elapsed. Requests left
 * open beyond the grace window expire and cannot be approved.
 */
export async function approvePolicyChangeRequest(
  db: Db,
  input: ApprovePolicyChangeRequestInput,
): Promise<ApprovedPolicyChange> {
  const now = input.now ?? new Date();

  const outcome = await withTransaction(db, async (client) => {
    const selected = await client.query<PolicyChangeRequestRow>(
      `select * from policy_change_requests
        where org_id = $1 and id = $2
        for update`,
      [input.orgId, input.requestId],
    );
    const raw = selected.rows[0];
    if (!raw) {
      throw new PolicyControlError("not_found", "Policy change request not found.");
    }
    const request = mapRequestRow(raw);

    if (request.status !== "pending") {
      throw new PolicyControlError(
        "conflict",
        `Policy change request is already ${request.status}.`,
      );
    }

    if (
      now.getTime() >
      request.cooling_off_deadline.getTime() + POLICY_REQUEST_GRACE_MS
    ) {
      await client.query(
        `update policy_change_requests
            set status = 'expired', updated_at = now()
          where id = $1`,
        [request.id],
      );
      return { expired: true as const };
    }

    if (
      input.approver === request.requested_by &&
      now.getTime() < request.cooling_off_deadline.getTime()
    ) {
      throw new PolicyControlError(
        "cooling_off",
        `This loosening requires a second admin or the cooling-off period ending at ${request.cooling_off_deadline.toISOString()}.`,
      );
    }

    const validated = parseAuditPolicy(
      request.candidate_policy.version,
      JSON.stringify(request.candidate_policy),
    );
    const policy = await insertPolicyVersion(
      client,
      {
        orgId: input.orgId,
        version: validated.version,
        policy: validated,
        createdBy: input.approver,
        direction: request.direction,
        diff: request.diff,
        source: "change_request",
        sourceRequestId: request.id,
      },
      validated,
    );

    const updated = await client.query<PolicyChangeRequestRow>(
      `update policy_change_requests
          set status = 'approved',
              second_approver = $2,
              decided_at = $3,
              updated_at = now()
        where id = $1
        returning *`,
      [request.id, input.approver, now],
    );

    await client.query(
      `insert into audit_events (org_id, actor, action, metadata)
       values ($1, $2, 'policy.change_approved', $3)`,
      [
        input.orgId,
        input.approver,
        JSON.stringify({
          requestId: request.id,
          version: validated.version,
          policyId: policy.id,
          requestedBy: request.requested_by,
          secondApprover: input.approver,
        }),
      ],
    );

    return {
      expired: false as const,
      request: mapRequestRow(updated.rows[0]!),
      policy: mapRow({ ...policy, active: true }),
    };
  });

  if (outcome.expired) {
    throw new PolicyControlError(
      "expired",
      "Policy change request expired before it was approved.",
    );
  }
  return { request: outcome.request, policy: outcome.policy };
}

export async function rejectPolicyChangeRequest(
  db: Db,
  input: {
    orgId: string;
    requestId: string;
    approver: string;
    reason: string;
    now?: Date;
  },
): Promise<PolicyChangeRequestRow> {
  const now = input.now ?? new Date();
  return withTransaction(db, async (client) => {
    const selected = await client.query<PolicyChangeRequestRow>(
      `select * from policy_change_requests
        where org_id = $1 and id = $2
        for update`,
      [input.orgId, input.requestId],
    );
    const raw = selected.rows[0];
    if (!raw) {
      throw new PolicyControlError("not_found", "Policy change request not found.");
    }
    const request = mapRequestRow(raw);
    if (request.status !== "pending") {
      throw new PolicyControlError(
        "conflict",
        `Policy change request is already ${request.status}.`,
      );
    }

    const updated = await client.query<PolicyChangeRequestRow>(
      `update policy_change_requests
          set status = 'rejected',
              second_approver = $2,
              decided_at = $3,
              updated_at = now()
        where id = $1
        returning *`,
      [request.id, input.approver, now],
    );

    await client.query(
      `insert into audit_events (org_id, actor, action, metadata)
       values ($1, $2, 'policy.change_rejected', $3)`,
      [
        input.orgId,
        input.approver,
        JSON.stringify({
          requestId: request.id,
          version: request.candidate_policy.version,
          requestedBy: request.requested_by,
          reason: input.reason,
        }),
      ],
    );

    return mapRequestRow(updated.rows[0]!);
  });
}

export interface PolicyImpactEntry {
  releaseId: string;
  packageName: string;
  version: string;
  currentRiskTier: RiskTier | null;
  currentPolicyResult: PolicyResult | null;
  candidateRiskTier: RiskTier;
  candidatePolicyResult: PolicyResult;
  candidateAutoApprove: boolean;
  changed: boolean;
}

/**
 * Re-evaluates the current audit evidence of every pending release under a
 * candidate policy. Approved releases are never included: activation does not
 * retroactively change them.
 */
export async function getPolicyImpact(
  db: Queryable,
  orgId: string,
  candidate: AuditPolicy,
): Promise<PolicyImpactEntry[]> {
  const result = await db.query<{
    id: string;
    package_name: string;
    version: string;
    intent: string | null;
    signals: Signal[] | string;
    risk_tier: RiskTier;
    policy_result: PolicyResult;
  }>(
    `select r.id, r.package_name, r.version, r.intent,
            a.signals, a.risk_tier, a.policy_result
       from releases r
       join release_current_audits c on c.release_id = r.id
       join audits a on a.id = c.audit_id
      where r.org_id = $1
        and r.status = 'pending'
      order by r.created_at asc`,
    [orgId],
  );

  return result.rows.map((row) => {
    const signals: Signal[] =
      typeof row.signals === "string"
        ? (JSON.parse(row.signals) as Signal[])
        : row.signals;
    const evaluation = evaluatePolicy(
      {
        signals,
        intent: row.intent,
        firstRelease: signals.some((signal) => signal.type === "first_release"),
        previousUnavailable: signals.some(
          (signal) => signal.type === "previous_artifact_unavailable",
        ),
        packageName: row.package_name,
        scopeKey: `private:${orgId}`,
      },
      candidate,
    );
    return {
      releaseId: row.id,
      packageName: row.package_name,
      version: row.version,
      currentRiskTier: row.risk_tier,
      currentPolicyResult: row.policy_result,
      candidateRiskTier: evaluation.riskTier,
      candidatePolicyResult: evaluation.policyResult,
      candidateAutoApprove: evaluation.autoApprove,
      changed:
        row.risk_tier !== evaluation.riskTier ||
        row.policy_result !== evaluation.policyResult,
    };
  });
}

export function publicPolicyVersion(row: PolicyVersionRow) {
  const policy = parseAuditPolicy(row.version, JSON.stringify(row.policy));
  return {
    id: row.id,
    version: policy.version,
    policy,
    active: row.active,
    createdBy: row.created_by,
    createdAt: row.created_at.toISOString(),
  };
}

export function publicPolicyChangeRequest(row: PolicyChangeRequestRow) {
  return {
    id: row.id,
    requestedBy: row.requested_by,
    basePolicyId: row.base_policy_id,
    candidate: parseAuditPolicy(
      row.candidate_policy.version,
      JSON.stringify(row.candidate_policy),
    ),
    diff: row.diff,
    direction: row.direction,
    reason: row.reason,
    status: row.status,
    coolingOffDeadline: row.cooling_off_deadline.toISOString(),
    secondApprover: row.second_approver,
    decidedAt: row.decided_at?.toISOString() ?? null,
    createdAt: row.created_at.toISOString(),
  };
}

/** Convenience used by the API to preview a candidate before storing it. */
export function describePolicyChange(before: AuditPolicy, after: AuditPolicy) {
  const diff = diffPolicies(before, after);
  return { diff, direction: policyDirection(diff) };
}
