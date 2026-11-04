import { timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import {
  authenticateAdmin,
  authenticatePublisher,
} from "../auth.js";
import {
  createAgentReview,
  listAgentReviews,
  panelConsensus,
} from "../agent-reviews.js";
import {
  createClaim,
  decideClaim,
  listClaims,
  type ClaimStatus,
} from "../claims.js";
import type { AppContext } from "../context.js";
import { evaluateRevocationFlags } from "../ops/revocation.js";
import { exportComplianceEvents } from "../ops/export.js";
import { parseAuditPolicy } from "../audit/policy.js";
import { getActivePolicy } from "../policy-store.js";
import {
  getReleaseByPackageVersion,
  getCurrentAudit,
} from "../releases.js";
import { validatePackageName } from "../npm/names.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function sendError(reply: FastifyReply, status: number, message: string): void {
  reply.code(status).send({ error: message });
}

function readReason(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return null;
  const reason = (body as { reason?: unknown }).reason;
  if (typeof reason !== "string") return null;
  const trimmed = reason.trim();
  return trimmed ? trimmed.slice(0, 2_000) : null;
}

/**
 * V2 surface: package claims, the advisory agent panel, threshold-revocation
 * flags, compliance export, and the CLI audit-status lookup used by
 * `veripack run`.
 */
export async function registerV2Routes(
  app: FastifyInstance,
  context: AppContext,
): Promise<void> {
  // --- Package claims -----------------------------------------------------
  app.post("/claims", async (request, reply) => {
    const publisher = await authenticatePublisher(request, context.config);
    const body = (request.body ?? {}) as {
      packageName?: unknown;
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
      sendError(reply, 400, "Claiming a package name requires a reason.");
      return;
    }
    try {
      const claim = await createClaim(context.pool, {
        orgId: context.config.ORG_ID,
        packageName,
        claimant: publisher.username,
        reason,
      });
      reply.code(201).send({ claim });
    } catch {
      sendError(
        reply,
        409,
        `A pending or approved claim already exists for ${packageName}.`,
      );
    }
  });

  app.get("/admin/claims", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const query = request.query as { status?: string };
    const claims = await listClaims(
      context.pool,
      context.config.ORG_ID,
      query.status as ClaimStatus | undefined,
    );
    reply.send({ claims });
  });

  for (const decision of ["approve", "reject"] as const) {
    app.post(`/admin/claims/:id/${decision}`, async (request, reply) => {
      const admin = await authenticateAdmin(request, context.config);
      const { id } = request.params as { id?: string };
      if (!id || !UUID.test(id)) {
        sendError(reply, 400, "Invalid claim id.");
        return;
      }
      const claim = await decideClaim(context.pool, {
        orgId: context.config.ORG_ID,
        claimId: id,
        decision: decision === "approve" ? "approved" : "rejected",
        decidedBy: admin.username,
      });
      if (!claim) {
        sendError(reply, 404, "Pending claim not found.");
        return;
      }
      reply.send({ claim });
    });
  }

  // --- Agent panel ----------------------------------------------------------
  app.post("/agent/reviews", async (request, reply) => {
    const presented = (request.headers.authorization ?? "").replace(
      /^Bearer\s+/i,
      "",
    );
    const expected = context.config.AGENT_TOKEN;
    const a = Buffer.from(presented);
    const b = Buffer.from(expected);
    if (!expected || a.length !== b.length || !timingSafeEqual(a, b)) {
      sendError(reply, 401, "Agent authentication required.");
      return;
    }
    const body = (request.body ?? {}) as {
      releaseId?: unknown;
      auditId?: unknown;
      recommendation?: unknown;
      confidence?: unknown;
      rationale?: unknown;
    };
    const releaseId = typeof body.releaseId === "string" ? body.releaseId : "";
    if (!releaseId || !UUID.test(releaseId)) {
      sendError(reply, 400, "A valid releaseId is required.");
      return;
    }
    if (
      body.recommendation !== "approve" &&
      body.recommendation !== "reject" &&
      body.recommendation !== "needs_info"
    ) {
      sendError(reply, 400, "recommendation must be approve, reject, or needs_info.");
      return;
    }
    const rationale = readReason(request.body);
    if (!rationale) {
      sendError(reply, 400, "An agent review requires a rationale.");
      return;
    }
    const review = await createAgentReview(context.pool, {
      orgId: context.config.ORG_ID,
      releaseId,
      auditId: typeof body.auditId === "string" ? body.auditId : null,
      agentId: context.config.AGENT_USER,
      recommendation: body.recommendation,
      confidence:
        typeof body.confidence === "number" ? body.confidence : null,
      rationale,
    });
    reply.code(201).send({ review });
  });

  app.get("/admin/releases/:id/agent-reviews", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const { id } = request.params as { id?: string };
    if (!id || !UUID.test(id)) {
      sendError(reply, 400, "Invalid release id.");
      return;
    }
    const reviews = await listAgentReviews(context.pool, id);
    reply.send({ reviews, panel: panelConsensus(reviews) });
  });

  // --- Threshold revocation -------------------------------------------------
  app.post("/admin/revocation/evaluate", async (request, reply) => {
    await authenticateAdmin(request, context.config);
    const fallback = parseAuditPolicy(
      context.config.AUDIT_POLICY_VERSION,
      context.config.AUDIT_POLICY_JSON,
    );
    const policy = (
      await getActivePolicy(context.pool, context.config.ORG_ID, fallback)
    ).active;
    const flagged = await evaluateRevocationFlags(
      context.pool,
      context.config.ORG_ID,
      policy,
    );
    reply.send({
      ok: true,
      flagged: flagged.map((release) => ({
        releaseId: release.id,
        packageName: release.package_name,
        version: release.version,
      })),
    });
  });

  // --- Compliance export ------------------------------------------------------
  app.post("/admin/exports", async (request, reply) => {
    const admin = await authenticateAdmin(request, context.config);
    const body = (request.body ?? {}) as { from?: unknown; to?: unknown };
    const result = await exportComplianceEvents(context.pool, context.storage, {
      orgId: context.config.ORG_ID,
      actor: admin.username,
      from: typeof body.from === "string" ? new Date(body.from) : null,
      to: typeof body.to === "string" ? new Date(body.to) : null,
    });
    reply.code(201).send({ ok: true, ...result });
  });

  // --- CLI audit status (veripack run) ---------------------------------------
  app.get("/-/veripack/audit-status", async (request, reply) => {
    await authenticatePublisher(request, context.config);
    const query = request.query as { package?: string; version?: string };
    if (!query.package) {
      sendError(reply, 400, "package is required.");
      return;
    }
    const release = query.version
      ? await getReleaseByPackageVersion(
          context.pool,
          context.config.ORG_ID,
          query.package,
          query.version,
        )
      : null;
    if (release) {
      const audit = await getCurrentAudit(context.pool, release.id);
      reply.send({
        packageName: release.package_name,
        version: release.version,
        source: "private",
        status: release.status,
        riskTier: audit?.risk_tier ?? null,
        policyResult: audit?.policy_result ?? null,
        summary: audit?.summary ?? null,
      });
      return;
    }
    reply.send({
      packageName: query.package,
      version: query.version ?? null,
      source: "upstream",
      status: "unknown",
      riskTier: null,
      policyResult: null,
      summary:
        "No private release found. Public upstream packages are audited at download time.",
    });
  });

}
