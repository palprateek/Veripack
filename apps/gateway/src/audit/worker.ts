import type { PgBoss } from "pg-boss";
import { hostname } from "node:os";
import { randomUUID } from "node:crypto";
import type { Config } from "../config.js";
import type { Db } from "../db.js";
import type { NpmPublishPayload, NpmVersionManifest } from "../npm/payload.js";
import {
  getCurrentAudit,
  getReleaseById,
  insertAudit,
  listPackageNames,
  insertEvent,
  isUniqueViolation,
  type AuditRow,
  type ReleaseRow,
} from "../releases.js";
import {
  countInstallableReleases,
  getPreviousInstallableRelease,
} from "../registry-view.js";
import type { ReleaseLifecycle } from "../lifecycle.js";
import { isNoSuchKeyError, type Storage } from "../storage.js";
import { markArtifactMissing } from "../serving.js";
import { createAgentReview } from "../agent-reviews.js";
import { createLlmBackend, type LlmAuditBackend } from "./llm.js";
import { createArtifactCache, runAudit } from "./run.js";
import { parseAuditPolicy, type AuditPolicy } from "./policy.js";
import { getActivePolicy } from "../policy-store.js";
import { runSandbox } from "../sandbox.js";

export interface AuditLogger {
  info(obj: unknown, message?: string): void;
  error(obj: unknown, message?: string): void;
}

export interface AuditWorkerDeps {
  boss: PgBoss;
  pool: Db;
  storage: Storage;
  lifecycle: ReleaseLifecycle;
  config: Config;
  logger: AuditLogger;
}

export interface AuditWorkerHandle {
  workerId: string;
  stop(): void;
}

interface AuditJobData {
  releaseId: string;
}

export async function startAuditWorker(
  deps: AuditWorkerDeps,
): Promise<AuditWorkerHandle> {
  const fallbackPolicy = parseAuditPolicy(
    deps.config.AUDIT_POLICY_VERSION,
    deps.config.AUDIT_POLICY_JSON,
  );
  const llm = createLlmBackend({
    backend: deps.config.AUDIT_LLM_BACKEND,
    url: deps.config.AUDIT_LLM_URL,
    apiKey: deps.config.AUDIT_LLM_API_KEY,
    model: deps.config.AUDIT_LLM_MODEL,
    timeoutMs: deps.config.AUDIT_LLM_TIMEOUT_MS,
    temperature: deps.config.AUDIT_LLM_TEMPERATURE,
    maxTokens: deps.config.AUDIT_LLM_MAX_TOKENS,
  });

  const workerId = `${hostname()}:${process.pid}:${randomUUID()}`;
  const heartbeat = async () => {
    await deps.pool.query(
      `insert into audit_worker_heartbeats (worker_id, process_role, last_seen_at)
       values ($1, $2, now())
       on conflict (worker_id) do update
         set last_seen_at = excluded.last_seen_at,
             process_role = excluded.process_role,
             updated_at = now()`,
      [workerId, deps.config.PROCESS_ROLE],
    );
    await deps.pool.query(
      `delete from audit_worker_heartbeats
        where worker_id <> $1
          and last_seen_at < now() - interval '1 day'`,
      [workerId],
    );
  };
  await heartbeat();
  const heartbeatTimer = setInterval(() => {
    heartbeat().catch((error) =>
      deps.logger.error(
        { workerId, error: error instanceof Error ? error.message : String(error) },
        "audit worker heartbeat failed",
      ),
    );
  }, deps.config.AUDIT_WORKER_HEARTBEAT_INTERVAL_MS);
  heartbeatTimer.unref();

  await deps.boss.work<AuditJobData>(
    deps.config.AUDIT_QUEUE,
    // A replay failure throws, which fails the whole pg-boss batch. Keep one
    // release per invocation instead of relying on the library default.
    { batchSize: 1 },
    async (jobs) => {
      for (const job of jobs) {
        await processRelease(deps, fallbackPolicy, llm, job.data.releaseId);
      }
    },
  );

  deps.logger.info(
    { queue: deps.config.AUDIT_QUEUE, llmBackend: llm.id, workerId },
    "audit worker is listening",
  );

  return {
    workerId,
    stop: () => clearInterval(heartbeatTimer),
  };
}

async function resumeWithAudit(
  deps: AuditWorkerDeps,
  release: ReleaseRow,
  audit: AuditRow,
): Promise<void> {
  // A previous attempt computed the audit but stopped before the release was
  // installable. Retry the decision or the replay without recomputing
  // immutable evidence.
  if (
    release.status === "pending" &&
    audit.policy_result === "pass" &&
    audit.risk_tier === "low"
  ) {
    const outcome = await deps.lifecycle.applyDecision(release.id, {
      kind: "auto_approve",
      actor: { id: "system:auto", role: "system", type: "system" },
      reason: audit.summary ?? "Low-risk auto-approval.",
    });
    return;
  }

  if (
    (release.status === "approved" || release.status === "overridden") &&
    release.replay_state === "failed"
  ) {
    const outcome = await deps.lifecycle.replay(release.id, {
      id: "system:audit",
      role: "system",
      type: "system",
    });
  }
}

async function processRelease(
  deps: AuditWorkerDeps,
  fallbackPolicy: AuditPolicy,
  llm: LlmAuditBackend,
  releaseId: string,
): Promise<void> {
  const { pool, config, logger } = deps;
  const release = await getReleaseById(pool, config.ORG_ID, releaseId);
  if (!release) {
    logger.error({ releaseId }, "audit job references a missing release");
    return;
  }

  const policy = (
    await getActivePolicy(pool, config.ORG_ID, fallbackPolicy)
  ).active;

  const existingAudit = await getCurrentAudit(pool, release.id);
  if (existingAudit) {
    await resumeWithAudit(deps, release, existingAudit);
    return;
  }

  let tarball: Buffer;
  try {
    tarball = await deps.storage.getBuffer(release.tarball_key);
  } catch (error) {
    if (isNoSuchKeyError(error)) {
      // Terminal for this audit attempt: hold the pending release instead of
      // retrying or auto-rejecting it.
      await markArtifactMissing(pool, release.org_id, release.id).catch(
        () => undefined,
      );
      await insertEvent(pool, {
        orgId: release.org_id,
        actor: "system:audit",
        action: "artifact.missing",
        subject: release.id,
        metadata: { packageName: release.package_name },
      }).catch(() => undefined);
      logger.error(
        { releaseId: release.id },
        "release tarball is missing from storage; release held as artifact_missing",
      );
      return;
    }
    throw error;
  }

  const [previous, releaseCount, payload] = await Promise.all([
    getPreviousInstallableRelease(
      pool,
      release.org_id,
      release.package_name,
      release.created_at,
    ),
    countInstallableReleases(pool, release.org_id, release.package_name),
    deps.storage.getJson<NpmPublishPayload>(release.payload_key),
  ]);

  if (!payload) {
    throw new Error(`Missing stored publish payload for release ${release.id}.`);
  }

  let previousTarball: Buffer | null = null;
  if (previous) {
    try {
      previousTarball = await deps.storage.getBuffer(previous.tarball_key);
    } catch (error) {
      logger.error(
        {
          releaseId: release.id,
          previousReleaseId: previous.id,
          error: error instanceof Error ? error.message : String(error),
        },
        "previous release tarball is unavailable; the audit diff will be incomplete",
      );
    }
  }

  const { result, llmReview, startedAt } = await runAudit(
    {
      releaseId: release.id,
      packageName: release.package_name,
      version: release.version,
      publisher: release.publisher,
      manifest: release.manifest as NpmVersionManifest,
      intent: release.intent,
      tarball,
      tarballDigest: release.tarball_digest,
      previous: previous
        ? {
            version: previous.version,
            publisher: previous.publisher,
            manifest: previous.manifest as NpmVersionManifest,
            tarball: previousTarball,
            tarballDigest: previous.tarball_digest,
          }
        : null,
      firstRelease: releaseCount === 0,
      policy,
      scopeKey: `private:${release.org_id}`,
      engineVersion: config.AUDIT_ENGINE_VERSION,
      existingPackageNames: await listPackageNames(pool, release.org_id),
      cache: createArtifactCache(pool),
      sandbox: config.SANDBOX_ENABLE_ON_AUDIT
        ? (value) => runSandbox(value, config)
        : null,
      llm,
    },
    logger,
  );
  const finishedAt = new Date();

  let audit: AuditRow;
  try {
    audit = await insertAudit(pool, {
      orgId: release.org_id,
      releaseId: release.id,
      engineVersion: config.AUDIT_ENGINE_VERSION,
      policyVersion: result.policyVersion,
      llmReview,
      safetyVerdict: result.safetyVerdict,
      intentVerdict: result.intentVerdict,
      riskTier: result.riskTier,
      policyResult: result.policyResult,
      signals: result.signals,
      changeSet: result.changeSet,
      summary: result.summary,
      startedAt,
      finishedAt,
    });
  } catch (error) {
    if (!isUniqueViolation(error)) throw error;
    // A lease takeover can run the same audit twice. The immutable evidence
    // from the first worker wins; retry the decision or replay against it
    // instead of failing the job.
    const raced = await getCurrentAudit(pool, release.id);
    if (!raced) throw error;
    logger.info(
      { releaseId: release.id, auditId: raced.id },
      "audit was already recorded by another worker",
    );
    await resumeWithAudit(deps, release, raced);
    return;
  }

  if (llmReview) {
    // The agent panel records the LLM advisor's structured recommendation.
    // It is advisory evidence only; it never approves a release.
    await createAgentReview(pool, {
      orgId: release.org_id,
      releaseId: release.id,
      auditId: audit.id,
      agentId: `llm:${llmReview.backend}`,
      recommendation:
        result.policyResult === "block"
          ? "reject"
          : result.riskTier === "low"
            ? "approve"
            : "needs_info",
      confidence: llmReview.confidence,
      rationale: result.summary,
    }).catch(() => undefined);
  }

  await insertEvent(pool, {
    orgId: release.org_id,
    actor: "system:audit",
    action: "audit.completed",
    subject: release.id,
    metadata: {
      auditId: audit.id,
      riskTier: result.riskTier,
      safetyVerdict: result.safetyVerdict,
      intentVerdict: result.intentVerdict,
      policyResult: result.policyResult,
      policyVersion: result.policyVersion,
      llmBackend: llmReview?.backend ?? llm.id,
      llmReview: Boolean(llmReview),
    },
  });

  if (result.policyResult === "block") {
    if (release.status === "pending") {
      const outcome = await deps.lifecycle.applyDecision(release.id, {
        kind: "policy_block",
        actor: { id: "system:policy", role: "system", type: "system" },
        reason: result.summary,
      });
      if (outcome.outcome === "refused") {
        logger.info(
          { releaseId: release.id, code: outcome.code },
          "release decision changed while the audit was completing",
        );
      }
    }
    return;
  }

  if (result.autoApprove && release.status === "pending") {
    const outcome = await deps.lifecycle.applyDecision(release.id, {
      kind: "auto_approve",
      actor: { id: "system:auto", role: "system", type: "system" },
      reason: audit.summary ?? "Low-risk auto-approval.",
    });
    if (outcome.outcome === "refused") {
      logger.info(
        { releaseId: release.id, code: outcome.code },
        "release was decided before auto-approval could start",
      );
    }
    return;
  }

  if (release.status !== "pending") {
    logger.info(
      {
        releaseId: release.id,
        packageName: release.package_name,
        version: release.version,
        status: release.status,
        riskTier: result.riskTier,
      },
      "release was already decided before its audit completed",
    );
    return;
  }

  await insertEvent(pool, {
    orgId: release.org_id,
    actor: "system:audit",
    action: "release.awaiting_review",
    subject: release.id,
    metadata: {
      riskTier: result.riskTier,
      policyResult: result.policyResult,
      policyVersion: result.policyVersion,
    },
  });

  logger.info(
    {
      releaseId: release.id,
      packageName: release.package_name,
      version: release.version,
      riskTier: result.riskTier,
    },
    "release is awaiting review",
  );
}

