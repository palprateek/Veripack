import { describe, expect, it } from "vitest";
import type {
  AuditSummary,
  CommitDecisionInput,
  LifecycleActor,
  LifecycleEvent,
  LifecycleOutcome,
  ReleaseLifecycleStore,
} from "./lifecycle.js";
import { createReleaseLifecycle } from "./lifecycle.js";
import { StaleAuditError, type ReleaseRow } from "./releases.js";
import type { ApprovalDecision, ReleaseStatus } from "@veripack/shared";

const RELEASE_ID = "11111111-1111-1111-1111-111111111111";
const ORG_ID = "org-1";

const ADMIN: LifecycleActor = {
  id: "admin-1",
  role: "admin",
  type: "human",
};
const REVIEWER: LifecycleActor = {
  id: "reviewer-1",
  role: "reviewer",
  type: "human",
};
const REVIEWER_2: LifecycleActor = {
  id: "reviewer-2",
  role: "reviewer",
  type: "human",
};
const PUBLISHER: LifecycleActor = {
  id: "publisher-1",
  role: "publisher",
  type: "human",
};
const OTHER_PUBLISHER: LifecycleActor = {
  id: "publisher-2",
  role: "publisher",
  type: "human",
};
const SYSTEM_AUTO: LifecycleActor = {
  id: "system:auto",
  role: "system",
  type: "system",
};

const PASS_AUDIT: AuditSummary = {
  auditId: "33333333-3333-3333-3333-333333333333",
  engineVersion: "engine-1",
  policyResult: "pass",
  policyVersion: "policy-1",
  riskTier: "low",
  reviewAuthority: "reviewer",
  requiredApprovals: 1,
  policyCurrent: true,
};
const MEDIUM_AUDIT: AuditSummary = {
  ...PASS_AUDIT,
  auditId: "55555555-5555-5555-5555-555555555555",
  policyResult: "warn",
  riskTier: "medium",
};
const BLOCK_AUDIT: AuditSummary = {
  auditId: "44444444-4444-4444-4444-444444444444",
  engineVersion: "engine-1",
  policyResult: "block",
  policyVersion: "policy-1",
  riskTier: "critical",
  reviewAuthority: "admin",
  requiredApprovals: 1,
  policyCurrent: true,
};

function makeRelease(
  overrides: Partial<ReleaseRow> = {},
): ReleaseRow {
  return {
    id: RELEASE_ID,
    org_id: ORG_ID,
    package_name: "@acme/widget",
    version: "1.0.1",
    tarball_digest: "digest-1",
    tarball_key: "tarballs/widget.tgz",
    tarball_filename: "widget-1.0.1.tgz",
    payload_key: "payloads/widget.json",
    integrity: null,
    shasum: null,
    status: "pending",
    replay_state: "not_started",
    replay_job_id: null,
    replay_started_at: null,
    publisher: "publisher-1",
    intent: "Fix the retry loop.",
    manifest: {},
    created_at: new Date("2026-01-01T00:00:00Z"),
    updated_at: new Date("2026-01-01T00:00:00Z"),
    ...overrides,
  };
}

class MemoryStore implements ReleaseLifecycleStore {
  release: ReleaseRow | null;
  audit: AuditSummary | null;
  staleAtCommit = false;
  approvals: CommitDecisionInput[] = [];
  partials: CommitDecisionInput[] = [];
  history: ApprovalDecision[] = [];
  events: LifecycleEvent[] = [];

  constructor(release: ReleaseRow | null, audit: AuditSummary | null) {
    this.release = release;
    this.audit = audit;
  }

  async loadRelease(
    _orgId: string,
    releaseId: string,
  ): Promise<ReleaseRow | null> {
    return this.release?.id === releaseId ? this.release : null;
  }

  async latestAudit(
    _orgId: string,
    releaseId: string,
  ): Promise<AuditSummary | null> {
    return this.release?.id === releaseId ? this.audit : null;
  }

  async auditApprovals(
    _releaseId: string,
    _auditId: string,
  ): Promise<string[]> {
    return this.partials.map((input) => input.actor.id);
  }

  async approvalHistory(_releaseId: string): Promise<ApprovalDecision[]> {
    return this.history;
  }

  async commitDecision(
    input: CommitDecisionInput,
  ): Promise<ReleaseRow | null> {
    if (this.staleAtCommit) {
      throw new StaleAuditError("The release audit changed.");
    }
    const current = this.release;
    if (
      !current ||
      !input.fromStatuses.includes(current.status) ||
      current.replay_state === "in_progress"
    ) {
      return null;
    }

    const updated: ReleaseRow = {
      ...current,
      status: input.toStatus,
      replay_job_id: input.replay ? "job-1" : current.replay_job_id,
      replay_state: input.replay ? "not_started" : current.replay_state,
      updated_at: new Date("2026-01-01T00:00:01Z"),
    };
    this.release = updated;
    this.approvals.push(input);
    this.history.push(input.approval);
    this.events.push({
      orgId: current.org_id,
      actor: input.actor.id,
      action: `release.${input.approval}`,
      subject: current.id,
      metadata: {},
    });
    if (input.selfApproved) {
      this.events.push({
        orgId: current.org_id,
        actor: input.actor.id,
        action: "release.self_approved",
        subject: current.id,
        metadata: {},
      });
    }
    return updated;
  }

  async recordPartialApproval(
    input: CommitDecisionInput,
  ): Promise<ReleaseRow | null> {
    if (this.staleAtCommit) {
      throw new StaleAuditError("The release audit changed.");
    }
    const current = this.release;
    if (!current || !input.fromStatuses.includes(current.status)) {
      return null;
    }
    this.partials.push(input);
    this.events.push({
      orgId: current.org_id,
      actor: input.actor.id,
      action: "release.awaiting_second_reviewer",
      subject: current.id,
      metadata: {},
    });
    return current;
  }

  async enqueueReplay(release: ReleaseRow): Promise<ReleaseRow | null> {
    const current = this.release;
    if (!current || current.id !== release.id) return null;
    if (current.replay_state === "in_progress") return null;
    const updated: ReleaseRow = {
      ...current,
      replay_job_id: "job-2",
      replay_state: "not_started",
    };
    this.release = updated;
    return updated;
  }

  async appendEvent(event: LifecycleEvent): Promise<void> {
    this.events.push(event);
  }
}

function setup(options: {
  status?: ReleaseStatus;
  replayState?: ReleaseRow["replay_state"];
  audit?: AuditSummary | null;
  publisher?: string;
  selfApproval?: { enabled: boolean; maxRiskTier: "low" | "medium" | "high" | "critical" };
  priorDecisions?: ApprovalDecision[];
  staleAtCommit?: boolean;
} = {}) {
  const store = new MemoryStore(
    makeRelease({
      status: options.status ?? "pending",
      replay_state: options.replayState ?? "not_started",
      publisher: options.publisher ?? "publisher-1",
    }),
    options.audit === undefined ? PASS_AUDIT : options.audit,
  );
  store.history = options.priorDecisions ?? [];
  store.staleAtCommit = options.staleAtCommit ?? false;
  const lifecycle = createReleaseLifecycle({
    orgId: ORG_ID,
    store,
    loadPolicyContext: async () => ({
      version: "policy-1",
      selfApproval: options.selfApproval ?? {
        enabled: false,
        maxRiskTier: "medium" as const,
      },
    }),
  });
  return { store, lifecycle };
}

function applied(result: LifecycleOutcome) {
  if (result.outcome !== "applied") {
    throw new Error(
      `Expected applied, received ${result.outcome}: ${
        result.outcome === "refused" ? result.message : ""
      }`,
    );
  }
  return result;
}

function refused(result: LifecycleOutcome) {
  if (result.outcome !== "refused") {
    throw new Error(`Expected refused, received ${result.outcome}`);
  }
  return result;
}

describe("release lifecycle", () => {
  it("approves a pending release and queues a durable replay", async () => {
    const { store, lifecycle } = setup();

    const result = applied(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: ADMIN,
      }),
    );

    expect(result.release.status).toBe("approved");
    expect(result.replay).toBe("queued");
    expect(store.release?.replay_job_id).toBe("job-1");
    expect(store.approvals).toHaveLength(1);
    expect(store.approvals[0]?.approval).toBe("approved");
    expect(store.approvals[0]?.reason).toBe("Approved by admin.");
    expect(store.approvals[0]?.auditId).toBe(PASS_AUDIT.auditId);
    expect(store.approvals[0]?.policyVersion).toBe(PASS_AUDIT.policyVersion);
    expect(store.events.map((event) => event.action)).toContain(
      "release.approved",
    );
  });

  it("refuses approval before an audit exists", async () => {
    const { lifecycle } = setup({ audit: null });

    const result = refused(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: ADMIN,
      }),
    );

    expect(result.code).toBe("audit_pending");
  });

  it("refuses approval when the audit is stale under the active policy", async () => {
    const { lifecycle } = setup({
      audit: { ...PASS_AUDIT, policyCurrent: false },
    });

    const result = refused(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: ADMIN,
      }),
    );

    expect(result.code).toBe("stale_audit");
  });

  it("reports a stale-audit refusal when the audit changes at commit", async () => {
    const { lifecycle } = setup({ staleAtCommit: true });

    const result = refused(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: ADMIN,
      }),
    );

    expect(result.code).toBe("stale_audit");
  });

  it("requires an admin reason to override a deterministic block", async () => {
    const { store, lifecycle } = setup({ audit: BLOCK_AUDIT });

    const noReason = refused(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: ADMIN,
      }),
    );
    expect(noReason.code).toBe("reason_required");
    expect(store.release?.status).toBe("pending");

    const overridden = applied(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: ADMIN,
        reason: "Incident reviewed; the download is pinned to an internal mirror.",
      }),
    );

    expect(overridden.release.status).toBe("overridden");
    expect(store.approvals[0]?.approval).toBe("overridden");
    expect(store.approvals[0]?.reason).toContain("Incident reviewed");
  });

  it("forbids non-admins from overriding a deterministic block", async () => {
    const { lifecycle } = setup({ audit: BLOCK_AUDIT });

    for (const actor of [OTHER_PUBLISHER, REVIEWER]) {
      const result = refused(
        await lifecycle.applyDecision(RELEASE_ID, {
          kind: "approve",
          actor,
          reason: "Looks fine to me.",
        }),
      );
      expect(result.code).toBe("forbidden");
    }
  });

  it("refuses self-approval unless policy enables it, with a reason, at medium risk or below", async () => {
    const disabled = setup();
    const blocked = refused(
      await disabled.lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: PUBLISHER,
        reason: "Solo team.",
      }),
    );
    expect(blocked.code).toBe("forbidden");

    const enabled = { enabled: true, maxRiskTier: "medium" as const };
    const noReason = setup({ selfApproval: enabled });
    const missingReason = refused(
      await noReason.lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: PUBLISHER,
      }),
    );
    expect(missingReason.code).toBe("reason_required");

    const highRisk = setup({
      selfApproval: enabled,
      audit: { ...MEDIUM_AUDIT, riskTier: "high" },
    });
    const tooRisky = refused(
      await highRisk.lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: PUBLISHER,
        reason: "Solo team.",
      }),
    );
    expect(tooRisky.code).toBe("forbidden");

    const allowed = setup({ selfApproval: enabled, audit: MEDIUM_AUDIT });
    const result = applied(
      await allowed.lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: PUBLISHER,
        reason: "Solo team; reviewed the diff twice.",
      }),
    );
    expect(result.release.status).toBe("approved");
    expect(allowed.store.approvals[0]?.selfApproved).toBe(true);
    expect(
      allowed.store.events.map((event) => event.action),
    ).toContain("release.self_approved");
  });

  it("lets reviewers approve medium/high within policy but not override or quarantine", async () => {
    const { lifecycle } = setup({ audit: MEDIUM_AUDIT });
    const approved = applied(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: REVIEWER,
      }),
    );
    expect(approved.release.status).toBe("approved");

    const adminTier = setup({
      audit: { ...MEDIUM_AUDIT, reviewAuthority: "admin" },
    });
    const forbiddenApprove = refused(
      await adminTier.lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: REVIEWER,
      }),
    );
    expect(forbiddenApprove.code).toBe("forbidden");

    const { lifecycle: quarantineAttempt } = setup({ status: "approved" });
    const forbiddenQuarantine = refused(
      await quarantineAttempt.applyDecision(RELEASE_ID, {
        kind: "quarantine",
        actor: REVIEWER,
        reason: "Suspicious.",
      }),
    );
    expect(forbiddenQuarantine.code).toBe("forbidden");
  });

  it("records the first of two required approvals without transitioning", async () => {
    const audit: AuditSummary = {
      ...MEDIUM_AUDIT,
      riskTier: "high",
      requiredApprovals: 2,
    };
    const { store, lifecycle } = setup({ audit });

    const first = await lifecycle.applyDecision(RELEASE_ID, {
      kind: "approve",
      actor: REVIEWER,
    });
    if (first.outcome !== "awaiting_second_reviewer") {
      throw new Error(`Expected awaiting_second_reviewer, got ${first.outcome}`);
    }
    expect(first.approvalsRecorded).toBe(1);
    expect(store.release?.status).toBe("pending");
    expect(store.partials).toHaveLength(1);

    const duplicate = refused(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: REVIEWER,
      }),
    );
    expect(duplicate.code).toBe("conflict");

    const second = applied(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: REVIEWER_2,
      }),
    );
    expect(second.release.status).toBe("approved");
    expect(second.replay).toBe("queued");
  });

  it("requires a reason to override a rejected release", async () => {
    const { lifecycle } = setup({ status: "rejected" });

    const noReason = refused(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: ADMIN,
      }),
    );
    expect(noReason.code).toBe("reason_required");

    const overridden = applied(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "approve",
        actor: ADMIN,
        reason: "Rejected by mistake during the policy rollout.",
      }),
    );
    expect(overridden.release.status).toBe("overridden");
  });

  it("rejects pending releases with a reason only", async () => {
    const { lifecycle } = setup();

    const noReason = refused(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "reject",
        actor: ADMIN,
      }),
    );
    expect(noReason.code).toBe("reason_required");

    const rejected = applied(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "reject",
        actor: ADMIN,
        reason: "The install script is unrelated to the stated intent.",
      }),
    );
    expect(rejected.release.status).toBe("rejected");
    expect(rejected.replay).toBe("not_required");
  });

  it("moves a quarantined release to terminal rejected", async () => {
    const { lifecycle } = setup({ status: "quarantined" });

    const rejected = applied(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "reject",
        actor: ADMIN,
        reason: "Incident confirmed malicious.",
      }),
    );
    expect(rejected.release.status).toBe("rejected");

    const reviewerAttempt = setup({ status: "quarantined" });
    const forbidden = refused(
      await reviewerAttempt.lifecycle.applyDecision(RELEASE_ID, {
        kind: "reject",
        actor: REVIEWER,
        reason: "Confirmed.",
      }),
    );
    expect(forbidden.code).toBe("forbidden");
  });

  it("refuses an illegal transition instead of trusting the caller", async () => {
    const { lifecycle } = setup({ status: "approved" });

    const result = refused(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "reject",
        actor: ADMIN,
        reason: "Too late.",
      }),
    );

    expect(result.code).toBe("illegal_transition");
    expect(result.message).toContain('status "approved"');
  });

  it("yanks approved releases only, by the owner or an admin", async () => {
    const pending = setup();
    const illegalYank = refused(
      await pending.lifecycle.applyDecision(RELEASE_ID, {
        kind: "yank",
        actor: ADMIN,
        reason: "Not installable yet.",
      }),
    );
    expect(illegalYank.code).toBe("illegal_transition");

    const other = setup({ status: "approved" });
    const forbiddenYank = refused(
      await other.lifecycle.applyDecision(RELEASE_ID, {
        kind: "yank",
        actor: OTHER_PUBLISHER,
        reason: "Not mine.",
      }),
    );
    expect(forbiddenYank.code).toBe("forbidden");

    const own = setup({ status: "approved" });
    const ownYank = applied(
      await own.lifecycle.applyDecision(RELEASE_ID, {
        kind: "yank",
        actor: PUBLISHER,
        reason: "Dependency was revoked upstream.",
      }),
    );
    expect(ownYank.release.status).toBe("yanked");

    const overriddenSetup = setup({ status: "overridden" });
    const publisherYank = refused(
      await overriddenSetup.lifecycle.applyDecision(RELEASE_ID, {
        kind: "yank",
        actor: PUBLISHER,
        reason: "Revoked.",
      }),
    );
    expect(publisherYank.code).toBe("forbidden");
  });

  it("restricts quarantine to pending, approved, and overridden releases", async () => {
    const approved = setup({ status: "approved" });
    const quarantined = applied(
      await approved.lifecycle.applyDecision(RELEASE_ID, {
        kind: "quarantine",
        actor: ADMIN,
        reason: "Confirmed malicious behavior.",
      }),
    );
    expect(quarantined.release.status).toBe("quarantined");

    for (const status of ["yanked", "rejected", "quarantined"] as const) {
      const attempt = setup({ status });
      const result = refused(
        await attempt.lifecycle.applyDecision(RELEASE_ID, {
          kind: "quarantine",
          actor: ADMIN,
          reason: "Again.",
        }),
      );
      expect(result.code).toBe("illegal_transition");
    }
  });

  it("un-yanks with a fresh audit and restores the prior decision", async () => {
    const approved = setup({
      status: "yanked",
      priorDecisions: ["approved", "yanked"],
    });
    const restored = applied(
      await approved.lifecycle.applyDecision(RELEASE_ID, {
        kind: "un_yank",
        actor: ADMIN,
        reason: "False positive; upstream revoked the advisory.",
      }),
    );
    expect(restored.release.status).toBe("approved");
    expect(restored.replay).toBe("queued");

    const overriddenSetup = setup({
      status: "yanked",
      priorDecisions: ["overridden", "yanked"],
    });
    const restoredOverride = applied(
      await overriddenSetup.lifecycle.applyDecision(RELEASE_ID, {
        kind: "un_yank",
        actor: ADMIN,
        reason: "False positive.",
      }),
    );
    expect(restoredOverride.release.status).toBe("overridden");

    const stale = setup({
      status: "yanked",
      audit: { ...PASS_AUDIT, policyCurrent: false },
    });
    const staleResult = refused(
      await stale.lifecycle.applyDecision(RELEASE_ID, {
        kind: "un_yank",
        actor: ADMIN,
        reason: "Restore.",
      }),
    );
    expect(staleResult.code).toBe("stale_audit");

    const reviewerAttempt = setup({ status: "yanked" });
    const forbidden = refused(
      await reviewerAttempt.lifecycle.applyDecision(RELEASE_ID, {
        kind: "un_yank",
        actor: REVIEWER,
        reason: "Restore.",
      }),
    );
    expect(forbidden.code).toBe("forbidden");
  });

  it("auto-approves through a system actor with a passing audit", async () => {
    const human = setup();
    const forbidden = refused(
      await human.lifecycle.applyDecision(RELEASE_ID, {
        kind: "auto_approve",
        actor: ADMIN,
      }),
    );
    expect(forbidden.code).toBe("forbidden");

    const blocked = setup({ audit: BLOCK_AUDIT });
    const illegal = refused(
      await blocked.lifecycle.applyDecision(RELEASE_ID, {
        kind: "auto_approve",
        actor: SYSTEM_AUTO,
      }),
    );
    expect(illegal.code).toBe("illegal_transition");

    const auto = setup();
    const result = applied(
      await auto.lifecycle.applyDecision(RELEASE_ID, {
        kind: "auto_approve",
        actor: SYSTEM_AUTO,
      }),
    );
    expect(result.release.status).toBe("approved");
    expect(result.replay).toBe("queued");
  });

  it("records a policy block as a system rejection without replay", async () => {
    const { store, lifecycle } = setup({ audit: BLOCK_AUDIT });

    const result = applied(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "policy_block",
        actor: SYSTEM_AUTO,
        reason: "Critical deterministic finding.",
      }),
    );

    expect(result.release.status).toBe("rejected");
    expect(result.replay).toBe("not_required");
    expect(store.approvals[0]?.actor.id).toBe("system:auto");
    expect(store.approvals[0]?.approval).toBe("rejected");
  });

  it("queues a replay retry without writing another approval", async () => {
    const { store, lifecycle } = setup({
      status: "approved",
      replayState: "failed",
    });

    const result = applied(await lifecycle.replay(RELEASE_ID, ADMIN));

    expect(result.replay).toBe("queued");
    expect(store.approvals).toHaveLength(0);
    expect(store.release?.replay_job_id).toBe("job-2");
    expect(store.events.map((event) => event.action)).toContain(
      "release.replay_queued",
    );
  });

  it("treats an already-replayed release as idempotent", async () => {
    const { lifecycle } = setup({
      status: "approved",
      replayState: "succeeded",
    });

    const result = applied(await lifecycle.replay(RELEASE_ID, ADMIN));

    expect(result.release.replay_state).toBe("succeeded");
    expect(result.replay).toBe("succeeded");
  });

  it("returns not_found for an unknown release", async () => {
    const { lifecycle } = setup();

    const result = refused(
      await lifecycle.applyDecision("22222222-2222-2222-2222-222222222222", {
        kind: "approve",
        actor: ADMIN,
      }),
    );

    expect(result.code).toBe("not_found");
  });

  it("reports a conflict when the release is already replaying", async () => {
    const { lifecycle } = setup({
      status: "approved",
      replayState: "in_progress",
    });

    const result = refused(
      await lifecycle.applyDecision(RELEASE_ID, {
        kind: "yank",
        actor: ADMIN,
        reason: "Racing a replay.",
      }),
    );

    expect(result.code).toBe("conflict");
  });
});
