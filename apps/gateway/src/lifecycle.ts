import type {
  ApprovalDecision,
  PolicyResult,
  PolicyReviewAuthority,
  ReleaseStatus,
  ReviewerType,
  RiskTier,
} from "@veripack/shared";
import type { NpmPublishPayload } from "./npm/payload.js";
import {
  isStaleAuditError,
  isUniqueViolation,
  type ReleaseRow,
} from "./releases.js";

export interface LifecycleActor {
  id: string;
  role: "publisher" | "reviewer" | "admin" | "system";
  type: ReviewerType;
}

/**
 * Every way a release decision enters the registry. Route and queue adapters
 * translate their input into one of these; they never supply source statuses.
 */
export type LifecycleDecision =
  | { kind: "approve"; actor: LifecycleActor; reason?: string | null }
  | { kind: "auto_approve"; actor: LifecycleActor; reason?: string | null }
  | { kind: "policy_block"; actor: LifecycleActor; reason?: string | null }
  | { kind: "reject"; actor: LifecycleActor; reason?: string | null }
  | { kind: "yank"; actor: LifecycleActor; reason?: string | null }
  | { kind: "un_yank"; actor: LifecycleActor; reason?: string | null }
  | { kind: "quarantine"; actor: LifecycleActor; reason?: string | null };

export type LifecycleErrorCode =
  | "not_found"
  | "illegal_transition"
  | "reason_required"
  | "forbidden"
  | "audit_pending"
  | "stale_audit"
  | "conflict"
  | "replay_state_unknown";

export type LifecycleOutcome =
  | {
      outcome: "applied";
      release: ReleaseRow;
      replay: "queued" | "succeeded" | "not_required";
    }
  | {
      outcome: "awaiting_second_reviewer";
      release: ReleaseRow;
      approvalsRecorded: number;
      approvalsRequired: number;
    }
  | { outcome: "refused"; code: LifecycleErrorCode; message: string };

export interface AuditSummary {
  auditId: string;
  engineVersion: string;
  policyVersion: string;
  policyResult: PolicyResult;
  riskTier: RiskTier;
  /** Authority the active policy requires for this audit's risk tier. */
  reviewAuthority: PolicyReviewAuthority;
  /** Distinct human approvals the active policy requires (1 or 2). */
  requiredApprovals: number;
  /** True when the audit was produced under the currently active policy. */
  policyCurrent: boolean;
}

export interface CommitDecisionInput {
  release: ReleaseRow;
  fromStatuses: ReleaseStatus[];
  toStatus: ReleaseStatus;
  approval: ApprovalDecision;
  actor: LifecycleActor;
  reason: string | null;
  auditId: string | null;
  policyVersion: string | null;
  replay: boolean;
  selfApproved: boolean;
}

export interface LifecycleEvent {
  orgId: string;
  actor: string;
  action: string;
  subject: string | null;
  metadata: Record<string, unknown>;
}

/**
 * Port for release persistence. The Postgres adapter lives in
 * lifecycle-adapters.ts; tests supply an in-memory adapter.
 */
export interface ReleaseLifecycleStore {
  loadRelease(orgId: string, releaseId: string): Promise<ReleaseRow | null>;
  latestAudit(orgId: string, releaseId: string): Promise<AuditSummary | null>;
  /** Distinct human reviewer ids that already approved this audit. */
  auditApprovals(releaseId: string, auditId: string): Promise<string[]>;
  /** Decision history, oldest first, used to restore status on un-yank. */
  approvalHistory(releaseId: string): Promise<ApprovalDecision[]>;
  commitDecision(input: CommitDecisionInput): Promise<ReleaseRow | null>;
  /** Records an approval towards a two-reviewer decision; no transition. */
  recordPartialApproval(input: CommitDecisionInput): Promise<ReleaseRow | null>;
  /** Enqueues a durable replay job for an approved release. */
  enqueueReplay(release: ReleaseRow): Promise<ReleaseRow | null>;
  appendEvent(event: LifecycleEvent): Promise<void>;
}

/** Port for the publish replay. Used by the replay worker, not decisions. */
export interface ReleaseReplayTarget {
  loadPayload(release: ReleaseRow): Promise<NpmPublishPayload | null>;
  loadTarball(release: ReleaseRow): Promise<Buffer | null>;
  replay(payload: NpmPublishPayload): Promise<void>;
}

export interface ReleaseLifecycleLogger {
  info(obj: unknown, message?: string): void;
  error(obj: unknown, message?: string): void;
}

export interface PolicyContext {
  version: string;
  selfApproval: { enabled: boolean; maxRiskTier: RiskTier };
}

export interface ReleaseLifecycleDeps {
  orgId: string;
  store: ReleaseLifecycleStore;
  /**
   * Loads the active policy context for each decision. When omitted,
   * self-approval is disabled and audits are treated as policy-current.
   */
  loadPolicyContext?: (
    orgId: string,
  ) => Promise<PolicyContext | null>;
  logger?: ReleaseLifecycleLogger;
}

export interface ReleaseLifecycle {
  /**
   * Apply a decision to a release. Owns transition legality, reviewer
   * eligibility, the approval row, the audit event, and replay.
   */
  applyDecision(
    releaseId: string,
    decision: LifecycleDecision,
  ): Promise<LifecycleOutcome>;
  /** Retry replay for an already-approved release. Writes no approval row. */
  replay(releaseId: string, actor: LifecycleActor): Promise<LifecycleOutcome>;
}

interface PlannedDecision {
  fromStatuses: ReleaseStatus[];
  toStatus: ReleaseStatus;
  approval: ApprovalDecision;
  reason: string | null;
  auditId: string | null;
  policyVersion: string | null;
  replay: boolean;
  selfApproved: boolean;
}

interface PlanContext {
  selfApprovalEnabled: boolean;
  selfApprovalMaxTier: RiskTier;
  priorDecision: ApprovalDecision | null;
}

type PlanResult =
  | { ok: true; plan: PlannedDecision }
  | { ok: false; code: LifecycleErrorCode; message: string };

const APPROVE_SOURCES: ReleaseStatus[] = ["pending", "rejected"];
const YANK_SOURCES: ReleaseStatus[] = ["approved", "overridden"];
const QUARANTINE_SOURCES: ReleaseStatus[] = [
  "pending",
  "approved",
  "overridden",
];
const REJECT_SOURCES_WITH_QUARANTINE: ReleaseStatus[] = [
  "pending",
  "quarantined",
];

function normalizeReason(value: string | null | undefined): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, 2_000) : null;
}

function planned(
  plan: Omit<PlannedDecision, "selfApproved"> & { selfApproved?: boolean },
): PlanResult {
  return { ok: true, plan: { ...plan, selfApproved: plan.selfApproved ?? false } };
}

function refuse(code: LifecycleErrorCode, message: string): PlanResult {
  return { ok: false, code, message };
}

function forbidden(message: string): PlanResult {
  return refuse("forbidden", message);
}

function reasonRequired(message: string): PlanResult {
  return refuse("reason_required", message);
}

function illegal(message: string): PlanResult {
  return refuse("illegal_transition", message);
}

function isSystem(actor: LifecycleActor): boolean {
  return actor.type === "system" && actor.role === "system";
}

/**
 * The transition matrix. Callers supply a decision and an actor; the legal
 * source statuses and the target status are decided here.
 */
const RISK_RANK: Record<RiskTier, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function planDecision(
  release: ReleaseRow,
  audit: AuditSummary | null,
  decision: LifecycleDecision,
  context: PlanContext,
): PlanResult {
  const reason = normalizeReason(decision.reason);

  if (decision.kind === "approve") {
    if (isSystem(decision.actor)) {
      return forbidden("System decisions cannot use the approve command.");
    }
    if (!APPROVE_SOURCES.includes(release.status)) {
      return illegal(
        `Cannot approve a release in status "${release.status}".`,
      );
    }
    if (!audit) {
      return refuse(
        "audit_pending",
        "The audit has not completed yet. Wait for evidence before approving this release.",
      );
    }
    if (!audit.policyCurrent) {
      return refuse(
        "stale_audit",
        "The current audit was produced under a previous policy. Re-audit the release or hold the decision.",
      );
    }

    const overriding =
      audit.policyResult === "block" || release.status === "rejected";
    if (overriding) {
      if (decision.actor.role !== "admin") {
        return forbidden(
          "Only an administrator can override a blocked or rejected release.",
        );
      }
      if (!reason) {
        return reasonRequired("Overriding a release requires a reason.");
      }
      return planned({
        fromStatuses: [release.status],
        toStatus: "overridden",
        approval: "overridden",
        reason,
        auditId: audit.auditId,
        policyVersion: audit.policyVersion,
        replay: true,
      });
    }

    const selfApproval = release.publisher === decision.actor.id;
    if (selfApproval) {
      if (!context.selfApprovalEnabled) {
        return forbidden(
          "Publishers cannot approve their own releases. Self-approval is disabled by policy.",
        );
      }
      if (!reason) {
        return reasonRequired("Self-approval requires a reason.");
      }
      if (
        RISK_RANK[audit.riskTier] > RISK_RANK[context.selfApprovalMaxTier]
      ) {
        return forbidden(
          "Self-approval is allowed only up to medium risk. An independent reviewer or admin is required.",
        );
      }
    } else if (decision.actor.role === "publisher") {
      return forbidden("Publishers cannot approve another publisher's release.");
    }

    if (
      decision.actor.role === "reviewer" &&
      audit.reviewAuthority !== "reviewer"
    ) {
      return forbidden(
        "This release's risk tier requires an administrator to approve it.",
      );
    }

    return planned({
      fromStatuses: [release.status],
      toStatus: "approved",
      approval: "approved",
      reason: reason ?? "Approved by admin.",
      auditId: audit.auditId,
      policyVersion: audit.policyVersion,
      replay: true,
      selfApproved: selfApproval,
    });
  }

  if (decision.kind === "auto_approve") {
    if (!isSystem(decision.actor)) {
      return forbidden("Automatic approval is a system decision.");
    }
    if (release.status !== "pending") {
      return illegal(
        `Cannot auto-approve a release in status "${release.status}".`,
      );
    }
    if (!audit || audit.policyResult !== "pass") {
      return illegal("Automatic approval requires a passing audit.");
    }
    if (!audit.policyCurrent) {
      return refuse(
        "stale_audit",
        "The current audit was produced under a previous policy. Re-audit the release or hold the decision.",
      );
    }
    return planned({
      fromStatuses: ["pending"],
      toStatus: "approved",
      approval: "approved",
      reason: reason ?? "Low-risk auto-approval.",
      auditId: audit.auditId,
      policyVersion: audit.policyVersion,
      replay: true,
    });
  }

  if (decision.kind === "policy_block") {
    if (!isSystem(decision.actor)) {
      return forbidden("A policy block is a system decision.");
    }
    if (release.status !== "pending") {
      return illegal(
        `Cannot block a release in status "${release.status}".`,
      );
    }
    if (!audit || audit.policyResult !== "block") {
      return illegal("A policy block requires a blocking audit.");
    }
    return planned({
      fromStatuses: ["pending"],
      toStatus: "rejected",
      approval: "rejected",
      reason: reason ?? "Blocked by policy.",
      auditId: audit.auditId,
      policyVersion: audit.policyVersion,
      replay: false,
    });
  }

  if (decision.kind === "reject") {
    if (isSystem(decision.actor)) {
      return forbidden("System decisions use policy_block, not reject.");
    }
    if (decision.actor.role === "publisher") {
      return forbidden("Publishers cannot reject releases.");
    }
    if (
      decision.actor.role === "reviewer" &&
      release.status === "quarantined"
    ) {
      return forbidden(
        "Confirming a quarantine as rejected requires an administrator.",
      );
    }
    if (
      decision.actor.role === "reviewer" &&
      audit &&
      audit.reviewAuthority !== "reviewer"
    ) {
      return forbidden(
        "This release's risk tier requires an administrator to reject it.",
      );
    }
    if (!REJECT_SOURCES_WITH_QUARANTINE.includes(release.status)) {
      return illegal(
        `Cannot reject a release in status "${release.status}".`,
      );
    }
    if (!reason) {
      return reasonRequired("Rejecting a release requires a reason.");
    }
    return planned({
      fromStatuses: [release.status],
      toStatus: "rejected",
      approval: "rejected",
      reason,
      auditId: audit?.auditId ?? null,
      policyVersion: audit?.policyVersion ?? null,
      replay: false,
    });
  }

  if (decision.kind === "yank") {
    if (isSystem(decision.actor)) {
      return forbidden("System decisions cannot yank a release.");
    }
    if (decision.actor.role === "reviewer") {
      return forbidden("Reviewers cannot yank releases.");
    }
    if (!YANK_SOURCES.includes(release.status)) {
      return illegal(
        `Only approved or overridden releases can be yanked (status is "${release.status}").`,
      );
    }
    if (release.status === "overridden" && decision.actor.role !== "admin") {
      return forbidden("Only an administrator can yank an overridden release.");
    }
    if (
      decision.actor.role === "publisher" &&
      release.publisher !== decision.actor.id
    ) {
      return forbidden("Publishers can yank only their own releases.");
    }
    if (!reason) {
      return reasonRequired("Yanking a release requires a reason.");
    }
    return planned({
      fromStatuses: [release.status],
      toStatus: "yanked",
      approval: "yanked",
      reason,
      auditId: audit?.auditId ?? null,
      policyVersion: audit?.policyVersion ?? null,
      replay: false,
    });
  }

  if (decision.kind === "un_yank") {
    if (decision.actor.role !== "admin") {
      return forbidden("Only an administrator can un-yank a release.");
    }
    if (release.status !== "yanked") {
      return illegal(
        `Only yanked releases can be un-yanked (status is "${release.status}").`,
      );
    }
    if (!reason) {
      return reasonRequired("Un-yanking a release requires a reason.");
    }
    if (!audit) {
      return refuse(
        "audit_pending",
        "Un-yank requires a fresh audit. Wait for evidence before restoring this release.",
      );
    }
    if (!audit.policyCurrent) {
      return refuse(
        "stale_audit",
        "Un-yank requires a fresh audit under the active policy. Re-audit the release first.",
      );
    }
    const restoreOverridden = context.priorDecision === "overridden";
    return planned({
      fromStatuses: ["yanked"],
      toStatus: restoreOverridden ? "overridden" : "approved",
      approval: restoreOverridden ? "overridden" : "approved",
      reason,
      auditId: audit.auditId,
      policyVersion: audit.policyVersion,
      replay: true,
    });
  }

  if (isSystem(decision.actor)) {
    return forbidden("System decisions cannot quarantine a release.");
  }
  if (decision.actor.role !== "admin") {
    return forbidden("Only an administrator can quarantine a release.");
  }
  if (!QUARANTINE_SOURCES.includes(release.status)) {
    return illegal(
      `Cannot quarantine a release in status "${release.status}".`,
    );
  }
  if (!reason) {
    return reasonRequired("Quarantining a release requires a reason.");
  }
  return planned({
    fromStatuses: [release.status],
    toStatus: "quarantined",
    approval: "quarantined",
    reason,
    auditId: audit?.auditId ?? null,
    policyVersion: audit?.policyVersion ?? null,
    replay: false,
  });
}

function notFound(): LifecycleOutcome {
  return { outcome: "refused", code: "not_found", message: "Release not found." };
}

function conflict(message: string): LifecycleOutcome {
  return { outcome: "refused", code: "conflict", message };
}

export function createReleaseLifecycle(
  deps: ReleaseLifecycleDeps,
): ReleaseLifecycle {
  const { orgId, store, loadPolicyContext, logger } = deps;

  async function policyContext(): Promise<PolicyContext | null> {
    try {
      return (await loadPolicyContext?.(orgId)) ?? null;
    } catch (error) {
      logger?.error(
        { error: error instanceof Error ? error.message : String(error) },
        "failed to load the active policy context; self-approval stays disabled",
      );
      return null;
    }
  }

  return {
    async applyDecision(releaseId, decision) {
      const release = await store.loadRelease(orgId, releaseId);
      if (!release) return notFound();

      const [audit, context, history] = await Promise.all([
        store.latestAudit(orgId, releaseId),
        policyContext(),
        decision.kind === "un_yank"
          ? store.approvalHistory(releaseId)
          : Promise.resolve([] as ApprovalDecision[]),
      ]);
      const priorDecision = [...history]
        .reverse()
        .find((entry) => entry === "approved" || entry === "overridden");

      const result = planDecision(release, audit, decision, {
        selfApprovalEnabled: context?.selfApproval.enabled ?? false,
        selfApprovalMaxTier: context?.selfApproval.maxRiskTier ?? "medium",
        priorDecision: priorDecision ?? null,
      });
      if (!result.ok) {
        return {
          outcome: "refused",
          code: result.code,
          message: result.message,
        };
      }

      const commitInput: CommitDecisionInput = {
        release,
        fromStatuses: result.plan.fromStatuses,
        toStatus: result.plan.toStatus,
        approval: result.plan.approval,
        actor: decision.actor,
        reason: result.plan.reason,
        auditId: result.plan.auditId,
        policyVersion: result.plan.policyVersion,
        replay: result.plan.replay,
        selfApproved: result.plan.selfApproved,
      };

      // Two-reviewer decisions record the first approval without moving the
      // release; a second distinct human completes it.
      if (
        decision.kind === "approve" &&
        audit &&
        result.plan.toStatus === "approved" &&
        audit.requiredApprovals > 1
      ) {
        const existing = await store.auditApprovals(
          releaseId,
          audit.auditId,
        );
        if (existing.includes(decision.actor.id)) {
          return conflict(
            "You have already approved this release. A second distinct reviewer is required.",
          );
        }
        if (existing.length + 1 < audit.requiredApprovals) {
          let recorded: ReleaseRow | null;
          try {
            recorded = await store.recordPartialApproval(commitInput);
          } catch (error) {
            if (isStaleAuditError(error)) {
              return {
                outcome: "refused",
                code: "stale_audit",
                message:
                  "The release audit changed before the approval could be recorded. Reload and try again.",
              };
            }
            throw error;
          }
          if (!recorded) {
            return conflict(
              "The release changed before the approval could be recorded. Reload and try again.",
            );
          }
          return {
            outcome: "awaiting_second_reviewer",
            release: recorded,
            approvalsRecorded: existing.length + 1,
            approvalsRequired: audit.requiredApprovals,
          };
        }
      }

      let committed: ReleaseRow | null;
      try {
        committed = await store.commitDecision(commitInput);
      } catch (error) {
        if (isStaleAuditError(error)) {
          return {
            outcome: "refused",
            code: "stale_audit",
            message:
              "The release audit changed before the decision could be recorded. Reload and try again.",
          };
        }
        if (isUniqueViolation(error)) {
          return conflict(
            "A replay job is already active for this release. Reload and try again.",
          );
        }
        throw error;
      }
      if (!committed) {
        return conflict(
          "The release changed before the decision could be recorded. Reload and try again.",
        );
      }

      return {
        outcome: "applied",
        release: committed,
        replay: result.plan.replay ? "queued" : "not_required",
      };
    },

    async replay(releaseId, actor) {
      const release = await store.loadRelease(orgId, releaseId);
      if (!release) return notFound();

      if (release.status !== "approved" && release.status !== "overridden") {
        return {
          outcome: "refused",
          code: "illegal_transition",
          message: `Only approved or overridden releases can be replayed (status is "${release.status}").`,
        };
      }
      if (release.replay_state === "succeeded") {
        return { outcome: "applied", release, replay: "succeeded" };
      }
      if (release.replay_state === "in_progress") {
        return conflict("The release replay is already running.");
      }

      let queued: ReleaseRow | null;
      try {
        queued = await store.enqueueReplay(release);
      } catch (error) {
        if (isUniqueViolation(error)) {
          return conflict("A replay job is already active for this release.");
        }
        throw error;
      }
      if (!queued) {
        return conflict(
          "The release changed before the replay could be queued.",
        );
      }

      await store
        .appendEvent({
          orgId,
          actor: actor.id,
          action: "release.replay_queued",
          subject: release.id,
          metadata: { replayJobId: queued.replay_job_id },
        })
        .catch(() => undefined);
      return { outcome: "applied", release: queued, replay: "queued" };
    },
  };
}
