import type { FastifyInstance, FastifyReply } from "fastify";
import { authenticateReviewer, type AuthUser } from "../auth.js";
import type { AppContext } from "../context.js";
import type {
  LifecycleActor,
  LifecycleOutcome,
} from "../lifecycle.js";
import {
  getReleaseDetail,
  listReleases,
} from "../releases.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const REFUSAL_STATUS: Record<string, number> = {
  not_found: 404,
  illegal_transition: 409,
  reason_required: 400,
  forbidden: 403,
  audit_pending: 409,
  stale_audit: 409,
  conflict: 409,
  replay_state_unknown: 503,
};

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

function reviewerActor(user: AuthUser): LifecycleActor {
  return {
    id: user.username,
    role: user.role === "admin" ? "admin" : "reviewer",
    type: "human",
  };
}

async function sendDecision(
  reply: FastifyReply,
  context: AppContext,
  releaseId: string,
  result: LifecycleOutcome,
): Promise<void> {
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
    sendError(reply, REFUSAL_STATUS[result.code] ?? 409, result.message);
    return;
  }
  const detail = await getReleaseDetail(
    context.pool,
    context.config.ORG_ID,
    releaseId,
  );
  reply.send(detail);
}

/**
 * Reviewer surface. Reviewers approve or reject pending releases within
 * policy; overrides, quarantine, yank, and policy changes stay on /admin.
 */
export async function registerReviewRoutes(
  app: FastifyInstance,
  context: AppContext,
): Promise<void> {
  app.get("/review/queue", async (request, reply) => {
    await authenticateReviewer(request, context.config);
    const releases = await listReleases(context.pool, context.config.ORG_ID, {
      status: "pending",
      limit: 100,
    });
    reply.send({ releases });
  });

  for (const kind of ["approve", "reject"] as const) {
    app.post(
      `/review/releases/:id/${kind}`,
      async (request, reply) => {
        const user = await authenticateReviewer(request, context.config);
        const { id } = request.params as { id?: string };
        if (!id || !UUID.test(id)) {
          sendError(reply, 400, "Invalid release id.");
          return;
        }
        const result = await context.lifecycle.applyDecision(id, {
          kind,
          actor: reviewerActor(user),
          reason: readReason(request.body),
        });
        await sendDecision(reply, context, id, result);
      },
    );
  }
}
