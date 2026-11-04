import type {
  Approval,
  ApprovalDecision,
  AuditEvent,
  AuditReport,
  IntentVerdict,
  LlmReview,
  PolicyResult,
  ReleaseDetail,
  ReleaseStatus,
  ReleaseSummary,
  ReviewerType,
  RiskTier,
  SafetyVerdict,
  Signal,
} from "@veripack/shared";
import { withTransaction, type Db, type Queryable } from "./db.js";
import { insertReplayJob } from "./replay-jobs.js";

export interface ReleaseRow {
  id: string;
  org_id: string;
  package_name: string;
  version: string;
  tarball_digest: string;
  tarball_key: string;
  tarball_filename: string;
  payload_key: string;
  integrity: string | null;
  shasum: string | null;
  status: ReleaseStatus;
  replay_state: ReplayState;
  replay_job_id: string | null;
  replay_started_at: Date | null;
  publisher: string;
  intent: string | null;
  manifest: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
}

export type ReplayState =
  | "not_started"
  | "in_progress"
  | "succeeded"
  | "failed";

export interface AuditRow {
  id: string;
  org_id: string;
  release_id: string;
  engine_version: string;
  policy_version: string;
  llm_review: LlmReview | null;
  safety_verdict: SafetyVerdict;
  intent_verdict: IntentVerdict;
  risk_tier: RiskTier;
  policy_result: PolicyResult;
  signals: Signal[];
  change_set: Record<string, unknown>;
  summary: string | null;
  started_at: Date;
  finished_at: Date;
  created_at: Date;
}

export interface ApprovalRow {
  id: string;
  org_id: string;
  release_id: string;
  audit_id: string | null;
  reviewer_id: string;
  reviewer_type: ReviewerType;
  reviewer_role: string | null;
  decision: ApprovalDecision;
  reason: string | null;
  policy_version: string | null;
  created_at: Date;
}

/**
 * Raised when the audit a decision was planned against is no longer the
 * current audit at commit time. The lifecycle turns this into a `stale_audit`
 * refusal so the caller reloads the release and its evidence.
 */
export class StaleAuditError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StaleAuditError";
  }
}

export function isStaleAuditError(error: unknown): error is StaleAuditError {
  return error instanceof StaleAuditError;
}

export interface EventRow {
  id: string;
  org_id: string;
  actor: string;
  action: string;
  subject: string | null;
  metadata: Record<string, unknown>;
  created_at: Date;
}

export interface InsertReleaseInput {
  orgId: string;
  packageName: string;
  version: string;
  tarballDigest: string;
  tarballKey: string;
  tarballFilename: string;
  payloadKey: string;
  integrity: string;
  shasum: string;
  publisher: string;
  intent: string | null;
  manifest: Record<string, unknown>;
  eventMetadata?: Record<string, unknown>;
}

export async function insertRelease(
  db: Db,
  input: InsertReleaseInput,
): Promise<ReleaseRow> {
  return withTransaction(db, async (client) => {
    const result = await client.query<ReleaseRow>(
      `insert into releases (
         org_id, package_name, version, tarball_digest, tarball_key,
         tarball_filename, payload_key, integrity, shasum, status, publisher,
         intent, manifest
       )
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, $11, $12)
       returning *`,
      [
        input.orgId,
        input.packageName,
        input.version,
        input.tarballDigest,
        input.tarballKey,
        input.tarballFilename,
        input.payloadKey,
        input.integrity,
        input.shasum,
        input.publisher,
        input.intent,
        JSON.stringify(input.manifest),
      ],
    );

    const release = result.rows[0]!;
    await client.query(
      `insert into audit_outbox (release_id)
       values ($1)
       on conflict (release_id) do nothing`,
      [release.id],
    );
    await client.query(
      `insert into audit_events (org_id, actor, action, subject, metadata)
       values ($1, $2, 'release.published', $3, $4)`,
      [
        release.org_id,
        input.publisher,
        release.id,
        JSON.stringify({
          packageName: release.package_name,
          version: release.version,
          tarballDigest: release.tarball_digest,
          attachmentName: release.tarball_filename,
          ...(input.eventMetadata ?? {}),
        }),
      ],
    );
    return release;
  });
}

export async function getReleaseById(
  db: Queryable,
  orgId: string,
  releaseId: string,
): Promise<ReleaseRow | null> {
  const result = await db.query<ReleaseRow>(
    "select * from releases where org_id = $1 and id = $2",
    [orgId, releaseId],
  );
  return result.rows[0] ?? null;
}

export async function getReleaseByPackageVersion(
  db: Queryable,
  orgId: string,
  packageName: string,
  version: string,
): Promise<ReleaseRow | null> {
  const result = await db.query<ReleaseRow>(
    "select * from releases where org_id = $1 and package_name = $2 and version = $3",
    [orgId, packageName, version],
  );
  return result.rows[0] ?? null;
}


export async function listReleases(
  db: Queryable,
  orgId: string,
  options: { status?: ReleaseStatus; packageName?: string; limit?: number },
): Promise<ReleaseSummary[]> {
  const result = await db.query<
    ReleaseRow & {
      audit_risk_tier: RiskTier | null;
      audit_safety_verdict: SafetyVerdict | null;
      audit_intent_verdict: IntentVerdict | null;
      audit_policy_result: PolicyResult | null;
    }
  >(
    `select r.*,
            a.risk_tier as audit_risk_tier,
            a.safety_verdict as audit_safety_verdict,
            a.intent_verdict as audit_intent_verdict,
            a.policy_result as audit_policy_result
     from releases r
     left join lateral (
       select risk_tier, safety_verdict, intent_verdict, policy_result
       from audits
       where release_id = r.id
       order by created_at desc
       limit 1
     ) a on true
     where r.org_id = $1
       and ($2::text is null or r.status = $2)
       and ($3::text is null or r.package_name = $3)
     order by r.created_at desc
     limit $4`,
    [orgId, options.status ?? null, options.packageName ?? null, options.limit ?? 100],
  );

  return result.rows.map((row) =>
    mapReleaseSummary(row, {
      risk_tier: row.audit_risk_tier,
      safety_verdict: row.audit_safety_verdict,
      intent_verdict: row.audit_intent_verdict,
      policy_result: row.audit_policy_result,
    }),
  );
}

export async function listPackageNames(
  db: Queryable,
  orgId: string,
): Promise<string[]> {
  const result = await db.query<{ package_name: string }>(
    "select distinct package_name from releases where org_id = $1",
    [orgId],
  );
  return result.rows.map((row) => row.package_name);
}

export async function getCurrentAudit(
  db: Queryable,
  releaseId: string,
): Promise<AuditRow | null> {
  const result = await db.query<AuditRow>(
    `select a.*
       from audits a
       join release_current_audits c on c.audit_id = a.id
      where c.release_id = $1`,
    [releaseId],
  );
  return result.rows[0] ?? null;
}

export async function listAuditsForRelease(
  db: Queryable,
  releaseId: string,
): Promise<AuditRow[]> {
  const result = await db.query<AuditRow>(
    `select *
       from audits
      where release_id = $1
      order by created_at desc, id desc`,
    [releaseId],
  );
  return result.rows;
}

export interface InsertAuditInput {
  orgId: string;
  releaseId: string;
  engineVersion: string;
  policyVersion: string;
  llmReview: LlmReview | null;
  safetyVerdict: SafetyVerdict;
  intentVerdict: IntentVerdict;
  riskTier: RiskTier;
  policyResult: PolicyResult;
  signals: Signal[];
  changeSet: Record<string, unknown>;
  summary: string;
  startedAt: Date;
  finishedAt: Date;
}

export async function insertAudit(
  db: Db,
  input: InsertAuditInput,
): Promise<AuditRow> {
  return withTransaction(db, async (client) => {
    const result = await client.query<AuditRow>(
      `insert into audits (
         org_id, release_id, engine_version, policy_version, llm_review, safety_verdict, intent_verdict,
         risk_tier, policy_result, signals, change_set, summary, started_at,
         finished_at
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        returning *`,
      [
        input.orgId,
        input.releaseId,
        input.engineVersion,
        input.policyVersion,
        input.llmReview ? JSON.stringify(input.llmReview) : null,
        input.safetyVerdict,
        input.intentVerdict,
        input.riskTier,
        input.policyResult,
        JSON.stringify(input.signals),
        JSON.stringify(input.changeSet),
        input.summary,
        input.startedAt,
        input.finishedAt,
      ],
    );

    const audit = result.rows[0]!;
    await client.query(
      `insert into release_current_audits (release_id, audit_id)
       values ($1, $2)
       on conflict (release_id) do update
          set audit_id = excluded.audit_id,
              updated_at = now()`,
      [input.releaseId, audit.id],
    );
    return audit;
  });
}

export async function insertEvent(
  db: Queryable,
  input: {
    orgId: string;
    actor: string;
    action: string;
    subject?: string | null;
    metadata?: Record<string, unknown>;
  },
): Promise<EventRow> {
  const result = await db.query<EventRow>(
    `insert into audit_events (org_id, actor, action, subject, metadata)
     values ($1, $2, $3, $4, $5)
     returning *`,
    [
      input.orgId,
      input.actor,
      input.action,
      input.subject ?? null,
      JSON.stringify(input.metadata ?? {}),
    ],
  );
  return result.rows[0]!;
}

export async function getApprovals(
  db: Queryable,
  releaseId: string,
): Promise<ApprovalRow[]> {
  const result = await db.query<ApprovalRow>(
    "select * from approvals where release_id = $1 order by created_at asc",
    [releaseId],
  );
  return result.rows;
}

export async function getEvents(
  db: Queryable,
  releaseId: string,
): Promise<EventRow[]> {
  const result = await db.query<EventRow>(
    "select * from audit_events where subject = $1 order by created_at asc",
    [releaseId],
  );
  return result.rows;
}

export interface DecisionInput {
  status: ReleaseStatus;
  decision: ApprovalDecision;
  /** Audit the decision was planned against; required for approvals and overrides. */
  auditId: string | null;
  reviewerId: string;
  reviewerType: ReviewerType;
  reviewerRole: string;
  reason: string | null;
  policyVersion: string | null;
  expectedStatus?: ReleaseStatus | ReleaseStatus[];
  replay?: boolean;
  /** Self-approvals are flagged in the event log for the dashboard warning. */
  selfApproved?: boolean;
}

export async function recordDecision(
  db: Db,
  release: ReleaseRow,
  input: DecisionInput,
): Promise<ReleaseRow | null> {
  return withTransaction(db, async (client) => {
    const requiresCurrentAudit =
      input.decision === "approved" || input.decision === "overridden";

    // Locking the pointer row serializes this decision against a concurrent
    // audit insert, which upserts the same row. Without the lock, an audit
    // could become current between this check and the approval insert.
    const current = await client.query<{
      audit_id: string;
      policy_version: string;
    }>(
      `select c.audit_id, a.policy_version
         from release_current_audits c
         join audits a on a.id = c.audit_id
        where c.release_id = $1
        for update of c`,
      [release.id],
    );
    const currentAudit = current.rows[0] ?? null;

    if (requiresCurrentAudit) {
      if (!input.auditId || !input.policyVersion) {
        throw new StaleAuditError(
          "Approvals and overrides must reference the current audit and its policy version.",
        );
      }
      if (
        !currentAudit ||
        currentAudit.audit_id !== input.auditId ||
        currentAudit.policy_version !== input.policyVersion
      ) {
        throw new StaleAuditError(
          "The release audit changed before the decision could be recorded.",
        );
      }
    } else if (input.auditId === null && currentAudit) {
      // An audit completed between the lifecycle load and this commit. Refuse
      // so the caller reloads instead of recording evidence with a null link.
      throw new StaleAuditError(
        "An audit completed before the decision could be recorded.",
      );
    }

    const expectedStatuses = input.expectedStatus
      ? Array.isArray(input.expectedStatus)
        ? input.expectedStatus
        : [input.expectedStatus]
      : [release.status];
    const updated = await client.query<ReleaseRow>(
      `update releases
       set status = $1,
           updated_at = now()
       where id = $2
         and org_id = $3
         and status = any($4::text[])
         and replay_state <> 'in_progress'
       returning *`,
      [input.status, release.id, release.org_id, expectedStatuses],
    );

    if (updated.rows.length === 0) return null;

    await client.query(
      `insert into approvals (
         org_id, release_id, audit_id, reviewer_id, reviewer_type,
         reviewer_role, decision, reason, policy_version
       )
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        release.org_id,
        release.id,
        input.auditId,
        input.reviewerId,
        input.reviewerType,
        input.reviewerRole,
        input.decision,
        input.reason,
        input.policyVersion,
      ],
    );

    await client.query(
      `insert into audit_events (org_id, actor, action, subject, metadata)
       values ($1, $2, $3, $4, $5)`,
      [
        release.org_id,
        input.reviewerId,
        `release.${input.decision}`,
        release.id,
        JSON.stringify({
          decision: input.decision,
          reason: input.reason,
          reviewerType: input.reviewerType,
          reviewerRole: input.reviewerRole,
          auditId: input.auditId,
          status: input.status,
          policyVersion: input.policyVersion,
        }),
      ],
    );

    if (input.selfApproved) {
      await client.query(
        `insert into audit_events (org_id, actor, action, subject, metadata)
         values ($1, $2, 'release.self_approved', $3, $4)`,
        [
          release.org_id,
          input.reviewerId,
          release.id,
          JSON.stringify({
            decision: input.decision,
            auditId: input.auditId,
            policyVersion: input.policyVersion,
          }),
        ],
      );
    }

    let recorded = updated.rows[0]!;
    if (input.replay) {
      // The decision, approval, event, and replay job commit together; the
      // replay worker picks the job up asynchronously.
      const job = await insertReplayJob(client, {
        orgId: release.org_id,
        releaseId: release.id,
      });
      recorded = { ...recorded, replay_job_id: job.id, replay_state: "not_started" };
    }

    return recorded;
  });
}

/**
 * Records one approval towards a multi-reviewer decision without moving the
 * release. The approval row and the awaiting event are the durable record;
 * a later distinct reviewer completes the decision via recordDecision.
 */
export async function recordPartialApproval(
  db: Db,
  release: ReleaseRow,
  input: DecisionInput,
): Promise<ReleaseRow | null> {
  return withTransaction(db, async (client) => {
    const current = await client.query<{
      audit_id: string;
      policy_version: string;
    }>(
      `select c.audit_id, a.policy_version
         from release_current_audits c
         join audits a on a.id = c.audit_id
        where c.release_id = $1
        for update of c`,
      [release.id],
    );
    const currentAudit = current.rows[0] ?? null;
    if (
      !input.auditId ||
      !currentAudit ||
      currentAudit.audit_id !== input.auditId ||
      currentAudit.policy_version !== input.policyVersion
    ) {
      throw new StaleAuditError(
        "The release audit changed before the approval could be recorded.",
      );
    }

    const locked = await client.query<ReleaseRow>(
      `select * from releases
        where id = $1 and org_id = $2
        for update`,
      [release.id, release.org_id],
    );
    const lockedRelease = locked.rows[0];
    if (!lockedRelease) return null;
    const expectedStatuses = input.expectedStatus
      ? Array.isArray(input.expectedStatus)
        ? input.expectedStatus
        : [input.expectedStatus]
      : [release.status];
    if (!expectedStatuses.includes(lockedRelease.status)) return null;

    await client.query(
      `insert into approvals (
         org_id, release_id, audit_id, reviewer_id, reviewer_type,
         reviewer_role, decision, reason, policy_version
       )
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        release.org_id,
        release.id,
        input.auditId,
        input.reviewerId,
        input.reviewerType,
        input.reviewerRole,
        input.decision,
        input.reason,
        input.policyVersion,
      ],
    );

    await client.query(
      `insert into audit_events (org_id, actor, action, subject, metadata)
       values ($1, $2, 'release.awaiting_second_reviewer', $3, $4)`,
      [
        release.org_id,
        input.reviewerId,
        release.id,
        JSON.stringify({
          decision: input.decision,
          auditId: input.auditId,
          policyVersion: input.policyVersion,
        }),
      ],
    );

    return lockedRelease;
  });
}

export async function getReleaseDetail(
  db: Queryable,
  orgId: string,
  releaseId: string,
): Promise<ReleaseDetail | null> {
  const release = await getReleaseById(db, orgId, releaseId);
  if (!release) return null;

  const [audit, audits, approvals, events] = await Promise.all([
    getCurrentAudit(db, releaseId),
    listAuditsForRelease(db, releaseId),
    getApprovals(db, releaseId),
    getEvents(db, releaseId),
  ]);

  return {
    ...mapReleaseSummary(release, audit),
    manifest: release.manifest,
    audit: audit ? mapAudit(audit) : null,
    audits: audits.map(mapAudit),
    approvals: approvals.map(mapApproval),
    events: events.map(mapEvent),
  };
}

export function mapReleaseSummary(
  row: ReleaseRow,
  audit?: {
    risk_tier?: RiskTier | null;
    safety_verdict?: SafetyVerdict | null;
    intent_verdict?: IntentVerdict | null;
    policy_result?: PolicyResult | null;
  } | null,
): ReleaseSummary {
  return {
    id: row.id,
    orgId: row.org_id,
    packageName: row.package_name,
    version: row.version,
    tarballDigest: row.tarball_digest,
    integrity: row.integrity,
    shasum: row.shasum,
    status: row.status,
    publisher: row.publisher,
    intent: row.intent,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
    riskTier: audit?.risk_tier ?? null,
    safetyVerdict: audit?.safety_verdict ?? null,
    intentVerdict: audit?.intent_verdict ?? null,
    policyResult: audit?.policy_result ?? null,
  };
}

export function mapAudit(row: AuditRow): AuditReport {
  return {
    id: row.id,
    releaseId: row.release_id,
    engineVersion: row.engine_version,
    policyVersion: row.policy_version,
    llmReview: row.llm_review,
    safetyVerdict: row.safety_verdict,
    intentVerdict: row.intent_verdict,
    riskTier: row.risk_tier,
    policyResult: row.policy_result,
    signals: row.signals,
    changeSet: row.change_set,
    summary: row.summary,
    startedAt: row.started_at.toISOString(),
    finishedAt: row.finished_at.toISOString(),
    createdAt: row.created_at.toISOString(),
  };
}

export function mapApproval(row: ApprovalRow): Approval {
  return {
    id: row.id,
    releaseId: row.release_id,
    auditId: row.audit_id,
    reviewerId: row.reviewer_id,
    reviewerType: row.reviewer_type,
    reviewerRole: row.reviewer_role,
    decision: row.decision,
    reason: row.reason,
    policyVersion: row.policy_version,
    createdAt: row.created_at.toISOString(),
  };
}

export function mapEvent(row: EventRow): AuditEvent {
  return {
    id: row.id,
    orgId: row.org_id,
    actor: row.actor,
    action: row.action,
    subject: row.subject,
    metadata: row.metadata,
    createdAt: row.created_at.toISOString(),
  };
}

export function isUniqueViolation(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: string }).code === "23505"
  );
}
