import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
} from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { ZodError } from "zod";
import { authenticatePublisher } from "./auth.js";
import type { AppContext } from "./context.js";
import { registerAdminRoutes } from "./routes/admin.js";
import { distTagHandler, publishHandler } from "./routes/publish.js";
import { readHandler } from "./routes/read.js";
import { registerGithubRoutes } from "./routes/github.js";
import { checkPostgresRateLimit } from "./rate-limit.js";
import {
  IngestionLimiter,
  ingestionLimitsFromConfig,
} from "./ingestion.js";
import { MetricsRegistry } from "./metrics.js";
import { registerPreflightRoutes } from "./routes/preflight.js";
import { registerDashboardRoutes } from "./routes/dashboard.js";
import { registerV2Routes } from "./routes/v2.js";
import { registerReviewRoutes } from "./routes/review.js";

export async function buildServer(context: AppContext): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: context.config.LOG_LEVEL,
      redact: [
        "req.headers.authorization",
        "req.headers.cookie",
        "res.headers.set-cookie",
      ],
    },
    bodyLimit: context.config.BODY_LIMIT_BYTES,
    trustProxy: context.config.TRUST_PROXY,
  });

  context.ingestion ??= new IngestionLimiter(
    ingestionLimitsFromConfig(context.config),
  );
  const metrics = new MetricsRegistry();
  app.addHook("onRequest", async (request, reply) => {
    (request as FastifyRequest & { trustStartedAt?: number }).trustStartedAt = Date.now();
    if (context.config.RATE_LIMIT_BACKEND !== "postgres") return;
    const result = await checkPostgresRateLimit(
      context.pool,
      `ip:${request.ip}`,
      context.config.RATE_LIMIT_MAX,
      context.config.RATE_LIMIT_WINDOW_MS,
    );
    reply.header("x-ratelimit-limit", context.config.RATE_LIMIT_MAX);
    reply.header("x-ratelimit-remaining", result.remaining);
    reply.header("x-ratelimit-reset", Math.ceil(result.resetAt / 1_000));
    if (!result.allowed) {
      reply.code(429).send({ error: "Rate limit exceeded." });
    }
  });
  app.addHook("onResponse", async (request, reply) => {
    const startedAt = (request as FastifyRequest & { trustStartedAt?: number }).trustStartedAt;
    const route = request.routeOptions.url ?? request.url.split("?")[0] ?? "unknown";
    metrics.increment("veripack_gateway_requests_total", {
      method: request.method,
      route,
      status: reply.statusCode,
    });
    if (startedAt) metrics.observe("veripack_gateway_request_duration_seconds", (Date.now() - startedAt) / 1_000, { route });
  });

  await app.register(helmet, {
    contentSecurityPolicy: false,
  });

  if (context.config.RATE_LIMIT_BACKEND === "memory") {
    await app.register(rateLimit, {
      global: true,
      max: context.config.RATE_LIMIT_MAX,
      timeWindow: context.config.RATE_LIMIT_WINDOW_MS,
      keyGenerator: (request) => request.ip,
    });
  }

  await app.register(cors, {
    origin: context.config.CORS_ORIGINS,
    credentials: false,
    methods: ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  });

  app.get("/", async () => ({
    name: "veripack",
    version: "0.1.0",
    message: "Private trusted registry. Publish through this endpoint.",
  }));

  const readiness = async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      await context.pool.query("select 1");
    } catch (error) {
      request.log.error({ err: error }, "database readiness check failed");
      reply.code(503).send({
        ok: false,
        db: false,
        error: "Database is unavailable.",
      });
      return;
    }

    const verdaccioClient = context.verdaccio as {
      isReachable(): Promise<boolean>;
      isAuthenticated?: () => Promise<boolean>;
    };
    const verdaccio = verdaccioClient.isAuthenticated
      ? await verdaccioClient.isAuthenticated()
      : await verdaccioClient.isReachable();
    let auditWorker = true;
    if (context.config.AUDIT_WORKER_REQUIRED) {
      try {
        const result = await context.pool.query<{ alive: boolean }>(
          `select exists(
             select 1
               from audit_worker_heartbeats
              where last_seen_at > now() - ($1::text || ' milliseconds')::interval
           ) as alive`,
          [context.config.AUDIT_WORKER_STALE_MS],
        );
        auditWorker = result.rows[0]?.alive === true;
      } catch (error) {
        request.log.error({ err: error }, "audit worker readiness check failed");
        auditWorker = false;
      }
    }
    const ready = verdaccio && auditWorker;
    reply.code(ready ? 200 : 503).send({
      ok: ready,
      db: true,
      verdaccio,
      auditWorker,
    });
  };

  app.get("/health", readiness);
  app.get("/readyz", readiness);
  app.get("/livez", async () => ({ ok: true }));

  app.get("/metrics", async (request, reply) => {
    if (context.config.METRICS_TOKEN) {
      const authorization = request.headers.authorization ?? "";
      if (authorization !== `Bearer ${context.config.METRICS_TOKEN}`) {
        reply.code(401).send({ error: "Metrics authentication required." });
        return;
      }
    }
    if (!context.config.METRICS_ENABLED) {
      reply.code(404).send({ error: "Metrics are disabled." });
      return;
    }
    reply.type("text/plain; version=0.0.4").send(await metrics.render(context.pool));
  });

  app.get("/-/ping", async () => ({}));

  app.get("/-/whoami", async (request, reply) => {
    const user = await authenticatePublisher(request, context.config);
    reply.send({ username: user.username, role: user.role, orgId: user.orgId });
  });

  await registerAdminRoutes(app, context);
  await registerV2Routes(app, context);
  await registerDashboardRoutes(app, context);
  await registerReviewRoutes(app, context);
  await registerGithubRoutes(app, context);
  await registerPreflightRoutes(app, context);

  // Publish is a PUT of one package document. Dist-tag and login PUTs are
  // recognized inside the handler and proxied to Verdaccio.
  app.put("/*", async (request, reply) =>
    publishHandler(request, reply, context),
  );

  const proxyRead = async (request: FastifyRequest, reply: FastifyReply) =>
    readHandler(request, reply, context);

  app.get("/*", proxyRead);
  app.post("/*", proxyRead);
  app.delete("/*", async (request, reply) =>
    distTagHandler(request, reply, context),
  );
  app.patch("/*", proxyRead);

  app.setErrorHandler((error, request, reply) => {
    if (reply.sent) return;

    const errorStatus =
      typeof error === "object" &&
      error !== null &&
      "statusCode" in error &&
      typeof (error as { statusCode?: unknown }).statusCode === "number"
        ? (error as { statusCode: number }).statusCode
        : 500;

    const status = error instanceof ZodError ? 400 : errorStatus;

    if (status >= 500) {
      request.log.error({ err: error }, "request failed");
    } else {
      request.log.warn({ err: error }, "request rejected");
    }

    reply.code(status).send({
      error:
        error instanceof ZodError
          ? error.issues.map((issue) => issue.message).join("; ")
          : status >= 500
            ? "Internal server error."
            : error instanceof Error
            ? error.message
            : "Internal server error.",
    });
  });

  return app;
}
