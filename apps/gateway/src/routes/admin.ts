import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import {
  RELEASE_STATUSES,
  type ReleaseStatus,
} from "@veripack/shared";
import {
  assertStepUp,
  authenticateAdmin,
  type AuthUser,
} from "../auth.js";
import type { AppContext } from "../context.js";
import type {
  LifecycleActor,
  LifecycleErrorCode,
  LifecycleOutcome,
} from "../lifecycle.js";
import {
  getCurrentAudit,
  getReleaseById,
  getReleaseByPackageVersion,
  getReleaseDetail,
  insertEvent,
  isUniqueViolation,
  listReleases,
  type ReleaseRow,
} from "../releases.js";
import {
  activatePolicy,
  approvePolicyChangeRequest,
  createPolicyChangeRequest,
  describePolicyChange,
  getActivePolicy,
  getPolicyImpact,
  getPolicyVersion,
  listPolicyChangeRequests,
  listPolicyVersions,
  PolicyControlError,
  publicPolicyChangeRequest,
  publicPolicyVersion,
  rejectPolicyChangeRequest,
  type PolicyRequestStatus,
} from "../policy-store.js";
import {
  DistTagError,
  createBlocklistEntry,
  deleteDistTag,
  getArtifactState,
  getDistTags,
  hasOpenHold,
  listBlocklistEntries,
  listInstallEvents,
  markArtifactPresent,
  resolveReleaseHold,
  revokeBlocklistEntry,
  setDistTag,
} from "../serving.js";
import { isInstallable } from "../registry-view.js";
import { validatePackageName } from "../npm/names.js";
import { createHash } from "node:crypto";
import { forceUpstreamReaudit } from "../upstream-audit.js";
import { parseAuditPolicy } from "../audit/policy.js";
import { getSessionStepUpUntil } from "../dashboard.js";
import { rebuildRegistry } from "../ops/registry-rebuild.js";
import { runSandbox } from "../sandbox.js";
import { dispatchAuditOutboxOnce, requeueAuditOutbox } from "../audit/outbox.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function readReason(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return null;
  const reason = (body as { reason?: unknown }).reason;
  if (typeof reason !== "string") return null;
  const trimmed = reason.trim();
  return trimmed ? trimmed.slice(0, 2_000) : null;
}

function sendError(reply: FastifyReply, status: number, message: string): void {
  reply.code(status).send({ error: message });
}

interface PolicyBody {
  version: string;
  policy: Record<string, unknown>;
  reason: string | null;
  dryRun: boolean;
  direction?: "tighten" | "loosen";
}

function readPolicyBody(body: unknown): PolicyBody | null {
  if (typeof body !== "object" || body === null) return null;
  const value = body as {
    version?: unknown;
    policy?: unknown;
    reason?: unknown;
    dryRun?: unknown;
    direction?: unknown;
  };
  if (
    typeof value.version !== "string" ||
    typeof value.policy !== "object" ||
    value.policy === null ||
    Array.isArray(value.policy)
  ) {
    return null;
  }
  const version = value.version.trim().slice(0, 120);
  if (!version) return null;
  const serialized = JSON.stringify(value.policy);
  if (serialized.length > 64 * 1024) return null;

  let direction: "tighten" | "loosen" | undefined;
  if (value.direction !== undefined) {
    if (value.direction !== "tighten" && value.direction !== "loosen") {
      return null;
    }
    direction = value.direction;
  }

  const reason =
    typeof value.reason === "string"
      ? value.reason.trim().slice(0, 2_000) || null
      : null;

  return {
    version,
    policy: value.policy as Record<string, unknown>,
    reason,
    dryRun: value.dryRun === true,
    direction,
  };
}

function sendPolicyControlFailure(
  reply: FastifyReply,
  error: unknown,
): boolean {
  if (!(error instanceof PolicyControlError)) return false;
  const status =
    error.code === "not_found"
      ? 404
      : error.code === "forbidden"
        ? 403
        : error.code === "invalid"
          ? 400
          : 409;
  sendError(reply, status, error.message);
  return true;
}

async function loadRelease(
  request: FastifyRequest,
  reply: FastifyReply,
  context: AppContext,
): Promise<ReleaseRow | null> {
  const { id } = request.params as { id?: string };
  if (!id || !UUID.test(id)) {
    sendError(reply, 400, "Invalid release id.");
    return null;
  }

  const release = await getReleaseById(context.pool, context.config.ORG_ID, id);
  if (!release) {
    sendError(reply, 404, "Release not found.");
    return null;
  }
  return release;
}

function readReleaseId(
  request: FastifyRequest,
  reply: FastifyReply,
): string | null {
  const { id } = request.params as { id?: string };
  if (!id || !UUID.test(id)) {
    sendError(reply, 400, "Invalid release id.");
    return null;
  }
  return id;
}

const REFUSAL_STATUS: Record<LifecycleErrorCode, number> = {
  not_found: 404,
  illegal_transition: 409,
  reason_required: 400,
  forbidden: 403,
  audit_pending: 409,
  stale_audit: 409,
  conflict: 409,
  replay_state_unknown: 503,
};

function lifecycleActor(user: AuthUser): LifecycleActor {
  return { id: user.username, role: user.role, type: "human" };
}

function sendLifecycleFailure(
  reply: FastifyReply,
  result: Exclude<LifecycleOutcome, { outcome: "applied" }>,
): void {
  if (result.outcome === "awaiting_second_reviewer") {
    reply.code(202).send({
      decision: "awaiting_second_reviewer",
      approvalsRecorded: result.approvalsRecorded,
      approvalsRequired: result.approvalsRequired,
    });
    return;
  }
  sendError(reply, REFUSAL_STATUS[result.code], result.message);
}

export async function registerAdminRoutes(
  app: FastifyInstance,
  context: AppContext,
): Promise<void> {
  /** High-risk actions need a fresh step-up assertion; returns false after replying 403. */
  const requireStepUp = async (
    reply: FastifyReply,
    user: AuthUser,
    request?: FastifyRequest,
  ): Promise<boolean> => {
    try {
      assertStepUp(user, context.config);
      return true;
    } catch (error) {
      // Dashboard sessions carry step-up in the session store, not the token.
      const sessionId = request?.headers["x-veripack-session-id"];
      if (typeof sessionId === "string" && sessionId) {
        const until = await getSessionStepUpUntil(context.pool, sessionId);
        if (until !== null && until > Date.now()) return true;
      }
      sendError(
        reply,
        403,
        error instanceof Error ? error.message : "Step-up authentication required.",
      );
      return false;
    }
  };

  app.get("/admin/policy", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const fallback = parseAuditPolicy(
      context.config.AUDIT_POLICY_VERSION,
      context.config.AUDIT_POLICY_JSON,
    );
    const active = await getActivePolicy(
      context.pool,
      context.config.ORG_ID,
      fallback,
    );
    const history = await listPolicyVersions(context.pool, context.config.ORG_ID);
    reply.send({
      active: {
        ...active.active,
        id: active.activeId,
        source: active.source,
        createdBy: active.createdBy,
        createdAt: active.createdAt,
      },
      history: history.map(publicPolicyVersion),
    });
  });

  app.get("/admin/policy/history", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const query = request.query as { limit?: string };
    const limit = Math.min(
      Math.max(Number.parseInt(query.limit ?? "50", 10) || 50, 1),
      200,
    );
    const history = await listPolicyVersions(
      context.pool,
      context.config.ORG_ID,
      limit,
    );
    reply.send({ history: history.map(publicPolicyVersion) });
  });

  const updatePolicy = async (
    request: FastifyRequest,
    reply: FastifyReply,
  ) => {
    const admin = await authenticateAdmin(request, context.config);
    const body = readPolicyBody(request.body);
    if (!body) {
      sendError(
        reply,
        400,
        "Policy update must contain a non-empty version, a policy object, and an optional tighten/loosen direction.",
      );
      return;
    }

    let candidate;
    try {
      candidate = parseAuditPolicy(body.version, JSON.stringify(body.policy));
    } catch (error) {
      sendError(reply, 400, error instanceof Error ? error.message : "Invalid policy.");
      return;
    }

    const fallback = parseAuditPolicy(
      context.config.AUDIT_POLICY_VERSION,
      context.config.AUDIT_POLICY_JSON,
    );
    const active = await getActivePolicy(
      context.pool,
      context.config.ORG_ID,
      fallback,
    );
    const { diff, direction } = describePolicyChange(
      active.active,
      candidate,
    );

    if (
      body.direction !== undefined &&
      direction !== "none" &&
      body.direction !== direction
    ) {
      sendError(
        reply,
        400,
        `Policy change is a ${direction}, not a ${body.direction}.`,
      );
      return;
    }

    if (candidate.version === active.active.version && diff.length > 0) {
      sendError(
        reply,
        400,
        `Policy changed semantically but kept version "${candidate.version}"; bump the policy version.`,
      );
      return;
    }

    const impact = await getPolicyImpact(
      context.pool,
      context.config.ORG_ID,
      candidate,
    );

    if (body.dryRun) {
      reply.send({ dryRun: true, policy: candidate, diff, direction, impact });
      return;
    }

    if (direction === "loosen" && !(await requireStepUp(reply, admin, request))) {
      return;
    }

    if (direction === "loosen") {
      if (!body.reason) {
        sendError(reply, 400, "Loosening a policy requires a recorded reason.");
        return;
      }
      try {
        const request = await createPolicyChangeRequest(context.pool, {
          orgId: context.config.ORG_ID,
          requestedBy: admin.username,
          basePolicyId: active.activeId,
          candidate,
          diff,
          direction,
          reason: body.reason,
        });
        reply.code(202).send({
          request: publicPolicyChangeRequest(request),
          diff,
          direction,
          impact,
        });
      } catch (error) {
        if (sendPolicyControlFailure(reply, error)) return;
        if (isUniqueViolation(error)) {
          sendError(
            reply,
            409,
            `A pending request for policy version "${candidate.version}" already exists.`,
          );
          return;
        }
        throw error;
      }
      return;
    }

    try {
      const saved = await activatePolicy(context.pool, {
        orgId: context.config.ORG_ID,
        version: candidate.version,
        policy: candidate,
        createdBy: admin.username,
        direction,
        diff,
        source: "direct",
      });
      reply.code(201).send({
        policy: publicPolicyVersion(saved),
        diff,
        direction,
        impact,
      });
    } catch (error) {
      if (sendPolicyControlFailure(reply, error)) return;
      if (isUniqueViolation(error)) {
        sendError(
          reply,
          409,
          `Policy version "${candidate.version}" already exists.`,
        );
        return;
      }
      throw new Error(
        `Policy update failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  };

  app.put("/admin/policy", updatePolicy);
  app.post("/admin/policy", updatePolicy);

  app.get("/admin/policy/impact", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const query = request.query as { version?: string };
    let candidate;

    if (query.version) {
      const stored = await getPolicyVersion(
        context.pool,
        context.config.ORG_ID,
        query.version,
      );
      if (stored) {
        candidate = parseAuditPolicy(
          stored.version,
          JSON.stringify(stored.policy),
        );
      } else {
        const pending = await listPolicyChangeRequests(
          context.pool,
          context.config.ORG_ID,
          "pending",
        );
        const request = pending.find(
          (item) => item.candidate_policy.version === query.version,
        );
        if (!request) {
          sendError(reply, 404, `Policy version "${query.version}" not found.`);
          return;
        }
        candidate = request.candidate_policy;
      }
    } else {
      const fallback = parseAuditPolicy(
        context.config.AUDIT_POLICY_VERSION,
        context.config.AUDIT_POLICY_JSON,
      );
      candidate = (
        await getActivePolicy(context.pool, context.config.ORG_ID, fallback)
      ).active;
    }

    const impact = await getPolicyImpact(
      context.pool,
      context.config.ORG_ID,
      candidate,
    );
    reply.send({ version: candidate.version, impact });
  });

  app.get("/admin/policy/requests", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const query = request.query as { status?: string };
    const allowed: PolicyRequestStatus[] = [
      "pending",
      "approved",
      "rejected",
      "expired",
    ];
    if (query.status && !allowed.includes(query.status as PolicyRequestStatus)) {
      sendError(reply, 400, `Unknown policy request status "${query.status}".`);
      return;
    }
    const requests = await listPolicyChangeRequests(
      context.pool,
      context.config.ORG_ID,
      query.status as PolicyRequestStatus | undefined,
    );
    reply.send({ requests: requests.map(publicPolicyChangeRequest) });
  });

  app.post("/admin/policy/requests/:id/approve", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const { id } = request.params as { id?: string };
    if (!id || !UUID.test(id)) {
      sendError(reply, 400, "Invalid policy request id.");
      return;
    }
    try {
      const result = await approvePolicyChangeRequest(context.pool, {
        orgId: context.config.ORG_ID,
        requestId: id,
        approver: admin.username,
      });
      reply.send({
        request: publicPolicyChangeRequest(result.request),
        policy: publicPolicyVersion(result.policy),
      });
    } catch (error) {
      if (sendPolicyControlFailure(reply, error)) return;
      throw error;
    }
  });

  app.post("/admin/policy/requests/:id/reject", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const { id } = request.params as { id?: string };
    if (!id || !UUID.test(id)) {
      sendError(reply, 400, "Invalid policy request id.");
      return;
    }
    const reason = readReason(request.body);
    if (!reason) {
      sendError(reply, 400, "Rejecting a policy request requires a reason.");
      return;
    }
    try {
      const rejected = await rejectPolicyChangeRequest(context.pool, {
        orgId: context.config.ORG_ID,
        requestId: id,
        approver: admin.username,
        reason,
      });
      reply.send({ request: publicPolicyChangeRequest(rejected) });
    } catch (error) {
      if (sendPolicyControlFailure(reply, error)) return;
      throw error;
    }
  });

  app.get("/admin/blocklist", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const entries = await listBlocklistEntries(
      context.pool,
      context.config.ORG_ID,
    );
    reply.send({ entries });
  });

  app.post("/admin/blocklist", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const body = (request.body ?? {}) as {
      packageName?: unknown;
      version?: unknown;
      digest?: unknown;
      reason?: unknown;
    };
    const packageName =
      typeof body.packageName === "string" ? body.packageName.trim() : "";
    const nameError = packageName
      ? validatePackageName(packageName)
      : "A package name is required.";
    if (nameError) {
      sendError(reply, 400, nameError);
      return;
    }
    const reason = readReason(request.body);
    if (!reason) {
      sendError(reply, 400, "Blocklisting a package requires a reason.");
      return;
    }
    const entry = await createBlocklistEntry(context.pool, {
      orgId: context.config.ORG_ID,
      packageName,
      version: typeof body.version === "string" ? body.version : null,
      tarballDigest: typeof body.digest === "string" ? body.digest : null,
      reason,
      createdBy: admin.username,
    });
    reply.code(201).send({ entry });
  });

  app.delete("/admin/blocklist/:id", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const { id } = request.params as { id?: string };
    if (!id || !UUID.test(id)) {
      sendError(reply, 400, "Invalid blocklist entry id.");
      return;
    }
    const reason = readReason(request.body) ?? "Revoked by admin.";
    const entry = await revokeBlocklistEntry(context.pool, {
      orgId: context.config.ORG_ID,
      entryId: id,
      reason,
      revokedBy: admin.username,
    });
    if (!entry) {
      sendError(reply, 404, "Blocklist entry not found or already revoked.");
      return;
    }
    reply.send({ entry });
  });

  app.post("/admin/upstream-audits/force", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const body = (request.body ?? {}) as {
      packageName?: unknown;
      digest?: unknown;
    };
    const packageName =
      typeof body.packageName === "string" ? body.packageName.trim() : "";
    if (!packageName) {
      sendError(reply, 400, "packageName is required.");
      return;
    }
    const deleted = await forceUpstreamReaudit(context.pool, {
      packageName,
      tarballDigest: typeof body.digest === "string" ? body.digest : null,
    });
    await insertEvent(context.pool, {
      orgId: context.config.ORG_ID,
      actor: admin.username,
      action: "upstream.force_reaudit",
      subject: packageName,
      metadata: {
        packageName,
        digest: typeof body.digest === "string" ? body.digest : null,
        deleted,
      },
    });
    reply.send({ ok: true, packageName, deleted });
  });

  app.get("/admin/verdaccio/identity", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    reply.send({
      active: context.verdaccio.activeIdentity,
      configured: context.verdaccio.configuredIdentities(),
    });
  });

  app.post("/admin/verdaccio/identity/rotate", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    if (!(await requireStepUp(reply, admin, request))) return;
    const body = (request.body ?? {}) as { identity?: unknown };
    const identity =
      typeof body.identity === "string" ? body.identity.trim() : "";
    if (!identity) {
      sendError(reply, 400, "identity is required.");
      return;
    }
    try {
      const result = await context.verdaccio.rotateIdentity(identity);
      await insertEvent(context.pool, {
        orgId: context.config.ORG_ID,
        actor: admin.username,
        action: "verdaccio.identity_rotated",
        metadata: { previous: result.previous, active: result.active },
      });
      reply.send({ ok: true, ...result });
    } catch (error) {
      sendError(
        reply,
        409,
        error instanceof Error ? error.message : "Identity rotation failed.",
      );
    }
  });

  app.post("/admin/registry/rebuild", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const report = await rebuildRegistry(context.pool, async (release) => {
      try {
        return await context.storage.exists(release.tarball_key);
      } catch {
        return false;
      }
    });
    await insertEvent(context.pool, {
      orgId: context.config.ORG_ID,
      actor: admin.username,
      action: "registry.rebuilt",
      metadata: {
        queued: report.queued.length,
        alreadySucceeded: report.alreadySucceeded.length,
        unresolved: report.unresolved.length,
      },
    });
    reply.send({ ok: true, ...report });
  });

  app.get("/admin/install-events", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const query = request.query as { package?: string; limit?: string };
    const limit = Math.min(
      Math.max(Number.parseInt(query.limit ?? "100", 10) || 100, 1),
      500,
    );
    const events = await listInstallEvents(
      context.pool,
      context.config.ORG_ID,
      { packageName: query.package, limit },
    );
    reply.send({ events });
  });

  app.get("/admin/dist-tags", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const query = request.query as { package?: string };
    if (!query.package) {
      sendError(reply, 400, "A package query parameter is required.");
      return;
    }
    const tags = await getDistTags(
      context.pool,
      context.config.ORG_ID,
      query.package,
    );
    reply.send({ package: query.package, tags });
  });

  app.put("/admin/dist-tags", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const body = (request.body ?? {}) as {
      packageName?: unknown;
      tag?: unknown;
      version?: unknown;
      override?: unknown;
    };
    const packageName =
      typeof body.packageName === "string" ? body.packageName.trim() : "";
    const tag = typeof body.tag === "string" ? body.tag.trim() : "";
    const version = typeof body.version === "string" ? body.version.trim() : "";
    if (!packageName || !tag || !version) {
      sendError(reply, 400, "packageName, tag, and version are required.");
      return;
    }
    const release = await getReleaseByPackageVersion(
      context.pool,
      context.config.ORG_ID,
      packageName,
      version,
    );
    if (!release || !isInstallable(release)) {
      sendError(reply, 409, `${packageName}@${version} is not installable.`);
      return;
    }
    try {
      await setDistTag(context.pool, {
        orgId: context.config.ORG_ID,
        packageName,
        tag,
        version,
        updatedBy: admin.username,
        allowBackward: body.override === true,
        source: "admin",
      });
    } catch (error) {
      if (error instanceof DistTagError) {
        sendError(reply, 409, error.message);
        return;
      }
      throw error;
    }
    let mirrored = true;
    try {
      await context.verdaccio.setDistTag(packageName, tag, version);
    } catch (error) {
      mirrored = false;
      request.log.error(
        { err: error, packageName, tag },
        "dist-tag mirror failed; database remains authoritative",
      );
      await insertEvent(context.pool, {
        orgId: context.config.ORG_ID,
        actor: admin.username,
        action: "package.dist_tag_mirror_failed",
        subject: packageName,
        metadata: { packageName, tag, version },
      }).catch(() => undefined);
    }
    reply.send({ ok: true, package: packageName, tag, version, mirrored });
  });

  app.delete("/admin/dist-tags", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const body = (request.body ?? {}) as {
      packageName?: unknown;
      tag?: unknown;
    };
    const query = request.query as { package?: string; tag?: string };
    const packageName =
      (typeof body.packageName === "string" ? body.packageName.trim() : "") ||
      query.package ||
      "";
    const tag =
      (typeof body.tag === "string" ? body.tag.trim() : "") || query.tag || "";
    if (!packageName || !tag) {
      sendError(reply, 400, "packageName and tag are required.");
      return;
    }
    const deleted = await deleteDistTag(context.pool, {
      orgId: context.config.ORG_ID,
      packageName,
      tag,
      updatedBy: admin.username,
      source: "admin",
    });
    if (!deleted) {
      sendError(reply, 404, "Dist-tag not found.");
      return;
    }
    let mirrored = true;
    try {
      await context.verdaccio.deleteDistTag(packageName, tag);
    } catch (error) {
      mirrored = false;
      request.log.error(
        { err: error, packageName, tag },
        "dist-tag mirror failed; database remains authoritative",
      );
    }
    reply.send({ ok: true, package: packageName, tag, mirrored });
  });

  app.get("/admin/releases/:id/artifact", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const release = await loadRelease(request, reply, context);
    if (!release) return;
    const [artifact, holdOpen] = await Promise.all([
      getArtifactState(context.pool, release.id),
      hasOpenHold(context.pool, release.id),
    ]);
    reply.send({
      releaseId: release.id,
      status: release.status,
      tarballDigest: release.tarball_digest,
      artifact: artifact
        ? {
            state: artifact.state,
            missingSince: artifact.missing_since?.toISOString() ?? null,
            lastCheckedAt: artifact.last_checked_at.toISOString(),
          }
        : null,
      holdOpen,
    });
  });

  app.post("/admin/releases/:id/artifact/reupload", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const release = await loadRelease(request, reply, context);
    if (!release) return;

    const body = (request.body ?? {}) as { tarballBase64?: unknown };
    if (typeof body.tarballBase64 !== "string" || !body.tarballBase64) {
      sendError(reply, 400, "tarballBase64 is required.");
      return;
    }
    const tarball = Buffer.from(body.tarballBase64, "base64");
    const digest = createHash("sha256").update(tarball).digest("hex");
    if (digest !== release.tarball_digest) {
      sendError(
        reply,
        409,
        `Uploaded bytes do not match the recorded digest ${release.tarball_digest}.`,
      );
      return;
    }

    await context.storage.putTarball(release.tarball_key, tarball);
    await markArtifactPresent(context.pool, release.org_id, release.id);
    await resolveReleaseHold(
      context.pool,
      release.id,
      "reuploaded",
      admin.username,
    );
    await insertEvent(context.pool, {
      orgId: release.org_id,
      actor: admin.username,
      action: "artifact.reuploaded",
      subject: release.id,
      metadata: { digest },
    });

    if (release.status === "pending") {
      await requeueAuditOutbox(context.pool, release.id);
      await dispatchAuditOutboxOnce(
        {
          pool: context.pool,
          boss: context.boss,
          config: context.config,
          logger: {
            info: (obj, message) => request.log.info(obj, message),
            error: (obj, message) => request.log.error(obj, message),
          },
        },
        release.id,
      );
    }

    reply.send({ ok: true, releaseId: release.id, digest });
  });

  app.get("/admin/releases", async (request, reply) => {
    await authenticateAdmin(request, context.config);

    const query = request.query as {
      status?: string;
      package?: string;
      limit?: string;
    };

    let status: ReleaseStatus | undefined;
    if (query.status) {
      if (!RELEASE_STATUSES.includes(query.status as ReleaseStatus)) {
        sendError(reply, 400, `Unknown release status "${query.status}".`);
        return;
      }
      status = query.status as ReleaseStatus;
    }

    const limit = Math.min(
      Math.max(Number.parseInt(query.limit ?? "100", 10) || 100, 1),
      200,
    );

    const releases = await listReleases(context.pool, context.config.ORG_ID, {
      status,
      packageName: query.package,
      limit,
    });

    reply.send({ releases });
  });

  app.get("/admin/releases/:id", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const { id } = request.params as { id?: string };
    if (!id || !UUID.test(id)) {
      sendError(reply, 400, "Invalid release id.");
      return;
    }

    const release = await getReleaseDetail(
      context.pool,
      context.config.ORG_ID,
      id,
    );
    if (!release) {
      sendError(reply, 404, "Release not found.");
      return;
    }

    reply.send({ release });
  });

  app.post("/admin/releases/:id/approve", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const releaseId = readReleaseId(request, reply);
    if (!releaseId) return;

    // Approving a blocked or rejected release is an override: high-risk.
    const existing = await getReleaseById(
      context.pool,
      context.config.ORG_ID,
      releaseId,
    );
    if (existing) {
      const audit = await getCurrentAudit(context.pool, releaseId);
      const isOverride =
        existing.status === "rejected" || audit?.policy_result === "block";
      if (isOverride && !(await requireStepUp(reply, admin, request))) return;
    }

    const result = await context.lifecycle.applyDecision(releaseId, {
      kind: "approve",
      actor: lifecycleActor(admin),
      reason: readReason(request.body),
    });
    if (result.outcome === "awaiting_second_reviewer") {
      const detail = await getReleaseDetail(
        context.pool,
        context.config.ORG_ID,
        releaseId,
      );
      reply.code(202).send({
        ...detail,
        decision: "awaiting_second_reviewer",
        approvalsRecorded: result.approvalsRecorded,
        approvalsRequired: result.approvalsRequired,
      });
      return;
    }
    if (result.outcome !== "applied") {
      sendLifecycleFailure(reply, result);
      return;
    }

    const detail = await getReleaseDetail(
      context.pool,
      context.config.ORG_ID,
      releaseId,
    );
    reply.send(detail);
  });

  app.post("/admin/releases/:id/reject", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const releaseId = readReleaseId(request, reply);
    if (!releaseId) return;

    const result = await context.lifecycle.applyDecision(releaseId, {
      kind: "reject",
      actor: lifecycleActor(admin),
      reason: readReason(request.body),
    });
    if (result.outcome !== "applied") {
      sendLifecycleFailure(reply, result);
      return;
    }

    await resolveReleaseHold(
      context.pool,
      releaseId,
      "rejected",
      admin.username,
    ).catch(() => undefined);

    const detail = await getReleaseDetail(
      context.pool,
      context.config.ORG_ID,
      releaseId,
    );
    reply.send(detail);
  });

  app.post("/admin/releases/:id/yank", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const releaseId = readReleaseId(request, reply);
    if (!releaseId) return;

    const result = await context.lifecycle.applyDecision(releaseId, {
      kind: "yank",
      actor: lifecycleActor(admin),
      reason: readReason(request.body),
    });
    if (result.outcome !== "applied") {
      sendLifecycleFailure(reply, result);
      return;
    }

    const detail = await getReleaseDetail(
      context.pool,
      context.config.ORG_ID,
      releaseId,
    );
    reply.send(detail);
  });

  app.post("/admin/releases/:id/un-yank", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const releaseId = readReleaseId(request, reply);
    if (!releaseId) return;

    if (!(await requireStepUp(reply, admin, request))) return;

    const result = await context.lifecycle.applyDecision(releaseId, {
      kind: "un_yank",
      actor: lifecycleActor(admin),
      reason: readReason(request.body),
    });
    if (result.outcome !== "applied") {
      sendLifecycleFailure(reply, result);
      return;
    }

    const detail = await getReleaseDetail(
      context.pool,
      context.config.ORG_ID,
      releaseId,
    );
    reply.send(detail);
  });

  app.post("/admin/releases/:id/quarantine", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const releaseId = readReleaseId(request, reply);
    if (!releaseId) return;

    if (!(await requireStepUp(reply, admin, request))) return;

    const result = await context.lifecycle.applyDecision(releaseId, {
      kind: "quarantine",
      actor: lifecycleActor(admin),
      reason: readReason(request.body),
    });
    if (result.outcome !== "applied") {
      sendLifecycleFailure(reply, result);
      return;
    }

    const detail = await getReleaseDetail(
      context.pool,
      context.config.ORG_ID,
      releaseId,
    );
    reply.send(detail);
  });

  app.post("/admin/releases/:id/replay", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const releaseId = readReleaseId(request, reply);
    if (!releaseId) return;

    const result = await context.lifecycle.replay(
      releaseId,
      lifecycleActor(admin),
    );
    if (result.outcome !== "applied") {
      sendLifecycleFailure(reply, result);
      return;
    }

    reply.send({ ok: true, id: releaseId, replayState: result.replay });
  });

  app.post("/admin/releases/:id/audit", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const release = await loadRelease(request, reply, context);
    if (!release) return;

    if (release.status !== "pending") {
      sendError(reply, 409, "Only pending releases can be re-queued for audit.");
      return;
    }

    await requeueAuditOutbox(context.pool, release.id);
    await dispatchAuditOutboxOnce(
      {
        pool: context.pool,
        boss: context.boss,
        config: context.config,
        logger: {
          info: (obj, message) => request.log.info(obj, message),
          error: (obj, message) => request.log.error(obj, message),
        },
      },
      release.id,
    );

    await insertEvent(context.pool, {
      orgId: release.org_id,
      actor: admin.username,
      action: "audit.requeued",
      subject: release.id,
      metadata: {},
    });

    reply.code(202).send({ ok: true, id: release.id, status: "pending" });
  });

  app.post("/admin/releases/:id/sandbox", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const release = await loadRelease(request, reply, context);
    if (!release) return;

    if (context.config.SANDBOX_MODE === "disabled") {
      sendError(reply, 503, "Dynamic sandbox execution is disabled by configuration.");
      return;
    }

    const tarball = await context.storage.getBuffer(release.tarball_key);
    const result = await runSandbox(tarball, context.config);
    await insertEvent(context.pool, {
      orgId: release.org_id,
      actor: admin.username,
      action: "release.sandbox_completed",
      subject: release.id,
      metadata: {
        exitCode: result.exitCode,
        signal: result.signal,
        timedOut: result.timedOut,
        durationMs: result.durationMs,
      },
    });
    reply.send({ ok: true, releaseId: release.id, result });
  });
}
