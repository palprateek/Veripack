import type { AuditPolicy } from "@veripack/shared";
import type { Db } from "./db.js";
import type {
  PolicyContext,
  ReleaseLifecycleStore,
  ReleaseReplayTarget,
} from "./lifecycle.js";
import type { NpmPublishPayload } from "./npm/payload.js";
import {
  getApprovals,
  getCurrentAudit,
  getReleaseById,
  insertEvent,
  recordDecision,
  recordPartialApproval,
} from "./releases.js";
import { enqueueReplayJob } from "./replay-jobs.js";
import { evaluatePolicy } from "./audit/policy.js";
import { getActivePolicy } from "./policy-store.js";
import type { Storage } from "./storage.js";
import type { VerdaccioClient } from "./verdaccio.js";

export function createPostgresLifecycleStore(
  db: Db,
  policyFallback: AuditPolicy,
): ReleaseLifecycleStore {
  return {
    loadRelease: (orgId, releaseId) =>
      getReleaseById(db, orgId, releaseId),

    async latestAudit(orgId, releaseId) {
      const audit = await getCurrentAudit(db, releaseId);
      if (!audit) return null;

      const [release, policyState] = await Promise.all([
        getReleaseById(db, orgId, releaseId),
        getActivePolicy(db, orgId, policyFallback),
      ]);
      const evaluation = evaluatePolicy(
        {
          signals: audit.signals,
          intent: release?.intent ?? null,
          firstRelease: audit.signals.some(
            (signal) => signal.type === "first_release",
          ),
          previousUnavailable: audit.signals.some(
            (signal) => signal.type === "previous_artifact_unavailable",
          ),
          packageName: release?.package_name ?? "",
          scopeKey: `private:${orgId}`,
        },
        policyState.active,
      );

      return {
        auditId: audit.id,
        engineVersion: audit.engine_version,
        policyVersion: audit.policy_version,
        policyResult: audit.policy_result,
        riskTier: audit.risk_tier,
        reviewAuthority: evaluation.reviewAuthority,
        requiredApprovals: evaluation.requiredApprovals,
        policyCurrent: audit.policy_version === policyState.active.version,
      };
    },

    async auditApprovals(releaseId, auditId) {
      const approvals = await getApprovals(db, releaseId);
      return [
        ...new Set(
          approvals
            .filter(
              (approval) =>
                approval.audit_id === auditId &&
                approval.reviewer_type === "human" &&
                approval.decision === "approved",
            )
            .map((approval) => approval.reviewer_id),
        ),
      ];
    },

    async approvalHistory(releaseId) {
      const approvals = await getApprovals(db, releaseId);
      return approvals.map((approval) => approval.decision);
    },

    commitDecision: (input) =>
      recordDecision(db, input.release, {
        status: input.toStatus,
        decision: input.approval,
        auditId: input.auditId,
        reviewerId: input.actor.id,
        reviewerType: input.actor.type,
        reviewerRole: input.actor.role,
        reason: input.reason,
        policyVersion: input.policyVersion,
        expectedStatus: input.fromStatuses,
        replay: input.replay,
        selfApproved: input.selfApproved,
      }),

    recordPartialApproval: (input) =>
      recordPartialApproval(db, input.release, {
        status: input.toStatus,
        decision: input.approval,
        auditId: input.auditId,
        reviewerId: input.actor.id,
        reviewerType: input.actor.type,
        reviewerRole: input.actor.role,
        reason: input.reason,
        policyVersion: input.policyVersion,
        expectedStatus: input.fromStatuses,
        replay: false,
      }),

    async enqueueReplay(release) {
      await enqueueReplayJob(db, {
        orgId: release.org_id,
        releaseId: release.id,
      });
      return getReleaseById(db, release.org_id, release.id);
    },

    async appendEvent(event) {
      await insertEvent(db, {
        orgId: event.orgId,
        actor: event.actor,
        action: event.action,
        subject: event.subject,
        metadata: event.metadata,
      });
    },
  };
}

/** Loads the active policy context the lifecycle needs for each decision. */
export function createPostgresPolicyContextLoader(
  db: Db,
  policyFallback: AuditPolicy,
): (orgId: string) => Promise<PolicyContext> {
  return async (orgId) => {
    const state = await getActivePolicy(db, orgId, policyFallback);
    return {
      version: state.active.version,
      selfApproval: { ...state.active.selfApproval },
    };
  };
}

export function createStorageReplayTarget(
  storage: Storage,
  verdaccio: VerdaccioClient,
): ReleaseReplayTarget {
  return {
    loadPayload: (release) =>
      storage.getJson<NpmPublishPayload>(release.payload_key),
    loadTarball: (release) => storage.getBuffer(release.tarball_key),
    replay: (payload) => verdaccio.replay(payload),
  };
}
