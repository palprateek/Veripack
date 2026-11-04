import { timingSafeEqual } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { AppContext } from "../context.js";
import {
  challengeMfa,
  createDashboardSession,
  csrfMatches,
  enrollMfa,
  getDashboardSession,
  getMfa,
  isLoginRateLimited,
  recordAuthEvent,
  revokeDashboardSession,
  rotateDashboardSession,
  setStepUp,
  verifyMfaEnrollment,
} from "../dashboard.js";

/**
 * Internal dashboard session API. Only the web tier calls this, authenticated
 * with the shared DASHBOARD_INTERNAL_SECRET; browsers never see it.
 */
export async function registerDashboardRoutes(
  app: FastifyInstance,
  context: AppContext,
): Promise<void> {
  const secret = context.config.DASHBOARD_INTERNAL_SECRET;

  function assertInternal(request: FastifyRequest, reply: FastifyReply): boolean {
    if (!secret) {
      reply.code(503).send({ error: "Dashboard sessions are not configured." });
      return false;
    }
    const presented = request.headers["x-veripack-dashboard-key"];
    const a = Buffer.from(typeof presented === "string" ? presented : "");
    const b = Buffer.from(secret);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      reply.code(401).send({ error: "Dashboard internal authentication failed." });
      return false;
    }
    return true;
  }

  function body(request: FastifyRequest): Record<string, unknown> {
    return typeof request.body === "object" && request.body !== null
      ? (request.body as Record<string, unknown>)
      : {};
  }

  function stringField(
    value: Record<string, unknown>,
    field: string,
  ): string {
    const raw = value[field];
    return typeof raw === "string" ? raw : "";
  }

  app.post("/-/dashboard/auth-events", async (request, reply) => {
    if (!assertInternal(request, reply)) return;
    const input = body(request);
    const subject = stringField(input, "subject");
    const action = stringField(input, "action");
    if (!subject || !action) {
      reply.code(400).send({ error: "subject and action are required." });
      return;
    }
    await recordAuthEvent(context.pool, {
      subject,
      actor: stringField(input, "actor") || subject,
      action,
      success: input.success !== false,
      metadata:
        typeof input.metadata === "object" && input.metadata !== null
          ? (input.metadata as Record<string, unknown>)
          : {},
    });
    reply.send({ ok: true });
  });

  app.post("/-/dashboard/sessions", async (request, reply) => {
    if (!assertInternal(request, reply)) return;
    const input = body(request);
    const subject = stringField(input, "subject");
    const accessToken = stringField(input, "accessToken");
    const role = stringField(input, "role") || "publisher";
    if (!subject || !accessToken) {
      reply.code(400).send({ error: "subject and accessToken are required." });
      return;
    }

    if (await isLoginRateLimited(context.pool, subject)) {
      await recordAuthEvent(context.pool, {
        subject,
        action: "login_rate_limited",
        success: false,
      });
      reply
        .code(429)
        .send({ error: "Too many failed login attempts. Try again later." });
      return;
    }

    // Production admins must complete MFA before a session exists.
    let mfaLevel: "none" | "totp" = "none";
    if (role === "admin") {
      const mfa = await getMfa(context.pool, subject);
      if (context.config.NODE_ENV === "production" && !mfa?.enabled) {
        reply.code(403).send({
          error: "Administrator MFA enrollment is required.",
          code: "mfa_enrollment_required",
        });
        return;
      }
      if (mfa?.enabled) {
        if (input.mfaVerified !== true) {
          reply.code(403).send({
            error: "Administrator MFA verification is required.",
            code: "mfa_required",
          });
          return;
        }
        mfaLevel = "totp";
      }
    }

    const created = await createDashboardSession(context.pool, secret, {
      subject,
      displayName: stringField(input, "displayName") || null,
      role,
      accessToken,
      mfaLevel,
    });
    reply.code(201).send({
      sessionId: created.sessionId,
      csrfToken: created.csrfToken,
      idleExpiresAt: created.idleExpiresAt.toISOString(),
      absoluteExpiresAt: created.absoluteExpiresAt.toISOString(),
    });
  });

  app.post("/-/dashboard/sessions/validate", async (request, reply) => {
    if (!assertInternal(request, reply)) return;
    const input = body(request);
    const sessionId = stringField(input, "sessionId");
    if (!sessionId) {
      reply.code(400).send({ error: "sessionId is required." });
      return;
    }
    const lookup = await getDashboardSession(context.pool, secret, sessionId, {
      touch: true,
    });
    if (!lookup.valid) {
      reply.code(401).send({ error: "Dashboard session is not valid." });
      return;
    }
    const csrfToken = stringField(input, "csrfToken");
    reply.send({
      subject: lookup.session.subject,
      displayName: lookup.session.display_name,
      role: lookup.session.role,
      accessToken: lookup.accessToken,
      mfaLevel: lookup.session.mfa_level,
      csrfValid: csrfToken ? csrfMatches(lookup.session, csrfToken) : undefined,
      stepUpUntil: lookup.session.step_up_deadline?.getTime() ?? null,
      idleExpiresAt: lookup.session.idle_expires_at.toISOString(),
      absoluteExpiresAt: lookup.session.absolute_expires_at.toISOString(),
    });
  });

  app.post("/-/dashboard/sessions/rotate", async (request, reply) => {
    if (!assertInternal(request, reply)) return;
    const sessionId = stringField(body(request), "sessionId");
    const rotated = await rotateDashboardSession(context.pool, secret, sessionId);
    if (!rotated) {
      reply.code(401).send({ error: "Dashboard session is not valid." });
      return;
    }
    reply.send({
      sessionId: rotated.sessionId,
      csrfToken: rotated.csrfToken,
      idleExpiresAt: rotated.idleExpiresAt.toISOString(),
      absoluteExpiresAt: rotated.absoluteExpiresAt.toISOString(),
    });
  });

  app.post("/-/dashboard/sessions/revoke", async (request, reply) => {
    if (!assertInternal(request, reply)) return;
    const sessionId = stringField(body(request), "sessionId");
    await revokeDashboardSession(context.pool, sessionId, "logout");
    reply.send({ ok: true });
  });

  app.post("/-/dashboard/sessions/step-up", async (request, reply) => {
    if (!assertInternal(request, reply)) return;
    const input = body(request);
    const sessionId = stringField(input, "sessionId");
    const lookup = await getDashboardSession(context.pool, secret, sessionId);
    if (!lookup.valid) {
      reply.code(401).send({ error: "Dashboard session is not valid." });
      return;
    }
    const ok = await challengeMfa(context.pool, secret, lookup.session.subject, {
      code: stringField(input, "code") || undefined,
      recoveryCode: stringField(input, "recoveryCode") || undefined,
    });
    if (!ok) {
      reply.code(403).send({ error: "Step-up verification failed." });
      return;
    }
    const deadline = await setStepUp(context.pool, sessionId);
    // Privilege changed: rotate the session id.
    const rotated = await rotateDashboardSession(context.pool, secret, sessionId);
    reply.send({
      ok: true,
      stepUpUntil: deadline?.getTime() ?? null,
      sessionId: rotated?.sessionId,
      csrfToken: rotated?.csrfToken,
    });
  });

  app.get("/-/dashboard/mfa/status", async (request, reply) => {
    if (!assertInternal(request, reply)) return;
    const subject = (request.query as { subject?: string }).subject ?? "";
    if (!subject) {
      reply.code(400).send({ error: "subject is required." });
      return;
    }
    const mfa = await getMfa(context.pool, subject);
    reply.send({ subject, enrolled: Boolean(mfa), enabled: mfa?.enabled ?? false });
  });

  app.post("/-/dashboard/mfa/enroll", async (request, reply) => {
    if (!assertInternal(request, reply)) return;
    const subject = stringField(body(request), "subject");
    if (!subject) {
      reply.code(400).send({ error: "subject is required." });
      return;
    }
    const enrolled = await enrollMfa(context.pool, secret, subject);
    reply.send(enrolled);
  });

  app.post("/-/dashboard/mfa/verify", async (request, reply) => {
    if (!assertInternal(request, reply)) return;
    const input = body(request);
    const subject = stringField(input, "subject");
    const recoveryCodes = await verifyMfaEnrollment(
      context.pool,
      secret,
      subject,
      stringField(input, "code"),
    );
    if (!recoveryCodes) {
      reply.code(403).send({ error: "MFA verification failed." });
      return;
    }
    reply.send({ ok: true, recoveryCodes });
  });

  app.post("/-/dashboard/mfa/challenge", async (request, reply) => {
    if (!assertInternal(request, reply)) return;
    const input = body(request);
    const subject = stringField(input, "subject");
    const ok = await challengeMfa(context.pool, secret, subject, {
      code: stringField(input, "code") || undefined,
      recoveryCode: stringField(input, "recoveryCode") || undefined,
    });
    if (!ok) {
      reply.code(403).send({ error: "MFA challenge failed." });
      return;
    }
    reply.send({ ok: true });
  });
}
