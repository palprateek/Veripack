import { startAuditWorker } from "./audit/worker.js";
import { parseAuditPolicy } from "./audit/policy.js";
import { startAuditOutboxDispatcher } from "./audit/outbox.js";
import { config } from "./config.js";
import { createDb, waitForDb } from "./db.js";
import {
  createPostgresLifecycleStore,
  createPostgresPolicyContextLoader,
  createStorageReplayTarget,
} from "./lifecycle-adapters.js";
import { createReleaseLifecycle } from "./lifecycle.js";
import { startReplayWorker } from "./replay-worker.js";
import { runMigrations } from "./migrations.js";
import { startQueue } from "./queue.js";
import { buildServer } from "./server.js";
import { Storage } from "./storage.js";
import { VerdaccioClient } from "./verdaccio.js";

async function main(): Promise<void> {
  // Invalid policy configuration must prevent boot, not surface on the first
  // publish. The worker parses the same values at startup.
  parseAuditPolicy(config.AUDIT_POLICY_VERSION, config.AUDIT_POLICY_JSON);

  const pool = createDb(config.DATABASE_URL, {
    ssl: config.DATABASE_SSL,
    rejectUnauthorized: config.DATABASE_SSL_REJECT_UNAUTHORIZED,
  });
  await waitForDb(pool);

  const applied = await runMigrations(pool);
  if (applied.length > 0) {
    console.log(`Applied migrations: ${applied.join(", ")}`);
  }

  const storage = await Storage.create(config);
  const verdaccio = new VerdaccioClient(config);
  const boss = await startQueue(config);

  let auditWorkerId: string | undefined;
  let auditWorkerStop: (() => void) | undefined;
  const bootstrapLogger = {
    info: (obj: unknown, message?: string) => console.info(message, obj),
    error: (obj: unknown, message?: string) => console.error(message, obj),
  };
  const policyFallback = parseAuditPolicy(
    config.AUDIT_POLICY_VERSION,
    config.AUDIT_POLICY_JSON,
  );
  const policyContextLoader = createPostgresPolicyContextLoader(
    pool,
    policyFallback,
  );
  const lifecycle = createReleaseLifecycle({
    orgId: config.ORG_ID,
    store: createPostgresLifecycleStore(pool, policyFallback),
    loadPolicyContext: async (orgId) => {
      const context = await policyContextLoader(orgId);
      return {
        ...context,
        selfApproval: {
          ...context.selfApproval,
          // Kept for local development only; production uses the policy.
          enabled:
            context.selfApproval.enabled || config.ALLOW_SELF_APPROVAL,
        },
      };
    },
    logger: bootstrapLogger,
  });
  const context = { config, pool, storage, verdaccio, boss, lifecycle };
  let replayWorkerStop: (() => void) | undefined;
  if (config.PROCESS_ROLE !== "gateway") {
    const worker = await startAuditWorker({
      boss,
      pool,
      storage,
      lifecycle,
      config,
      logger: bootstrapLogger,
    });
    auditWorkerId = worker.workerId;
    auditWorkerStop = worker.stop;

    const replayWorker = startReplayWorker({
      pool,
      replayTarget: createStorageReplayTarget(storage, verdaccio),
      orgId: config.ORG_ID,
      logger: bootstrapLogger,
      leaseMs: config.REPLAY_LEASE_MS,
      pollMs: config.REPLAY_POLL_MS,
      maxAttempts: config.REPLAY_MAX_ATTEMPTS,
      backoffMs: config.REPLAY_BACKOFF_MS,
    });
    replayWorkerStop = replayWorker.stop;
  }
  const appContext = { ...context, auditWorkerId };
  const app = config.PROCESS_ROLE === "worker" ? null : await buildServer(appContext);
  const outboxStop = startAuditOutboxDispatcher({
    pool,
    boss,
    config,
    logger: app?.log ?? bootstrapLogger,
  });

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    app?.log.info({ signal }, "shutting down");
    try {
      await app?.close();
      outboxStop();
      auditWorkerStop?.();
      replayWorkerStop?.();
      await boss.stop();
      await pool.end();
      process.exit(0);
    } catch (error) {
      if (app) app.log.error({ err: error }, "shutdown failed");
      else console.error("shutdown failed", error);
      process.exit(1);
    }
  };

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));

  if (app) {
    await app.listen({ host: config.GATEWAY_HOST, port: config.GATEWAY_PORT });
    app.log.info(
      {
        port: config.GATEWAY_PORT,
        org: config.ORG_ID,
        publicRegistryUrl: config.PUBLIC_REGISTRY_URL,
        processRole: config.PROCESS_ROLE,
      },
      "trust gateway is listening",
    );
  } else {
    console.info(`veripack audit worker is running for queue ${config.AUDIT_QUEUE}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
