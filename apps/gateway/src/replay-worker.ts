import { createHash, randomUUID } from "node:crypto";
import { hostname } from "node:os";
import type { Db } from "./db.js";
import type { ReleaseReplayTarget } from "./lifecycle.js";
import { getReleaseById, insertEvent } from "./releases.js";
import { isNoSuchKeyError } from "./storage.js";
import { markArtifactMissing } from "./serving.js";
import {
  claimReplayJob,
  completeReplayJob,
  failReplayJob,
  recoverExpiredReplayJobs,
  type ReplayJobRow,
} from "./replay-jobs.js";

export interface ReplayWorkerLogger {
  info(obj: unknown, message?: string): void;
  error(obj: unknown, message?: string): void;
}

export interface ReplayWorkerDeps {
  pool: Db;
  replayTarget: ReleaseReplayTarget;
  orgId: string;
  logger: ReplayWorkerLogger;
  leaseMs?: number;
  pollMs?: number;
  maxAttempts?: number;
  backoffMs?: number;
  /** Called when a job exhausts its attempts; wired to alerting/metrics. */
  onJobExhausted?: (job: ReplayJobRow, error: string) => void;
}

export interface ReplayWorkerHandle {
  workerId: string;
  stop(): void;
}

/**
 * Processes one claimed job. Returns false when no job was claimable.
 * Exported for tests; the interval worker below is the production loop.
 */
export async function processNextReplayJob(
  deps: ReplayWorkerDeps,
  workerId: string,
): Promise<boolean> {
  const job = await claimReplayJob(deps.pool, {
    owner: workerId,
    leaseMs: deps.leaseMs ?? 60_000,
  });
  if (!job) return false;

  const release = await getReleaseById(deps.pool, job.org_id, job.release_id);
  try {
    if (!release) {
      throw new Error(`Replay job references missing release ${job.release_id}.`);
    }

    // Verify the stored bytes still match the audited digest before anything
    // is published to Verdaccio.
    const tarball = await deps.replayTarget.loadTarball(release);
    if (!tarball) {
      throw new Error(`Missing stored tarball for release ${release.id}.`);
    }
    const digest = createHash("sha256").update(tarball).digest("hex");
    if (digest !== release.tarball_digest) {
      throw new Error(
        `Tarball digest mismatch for release ${release.id}: expected ${release.tarball_digest}, computed ${digest}.`,
      );
    }

    const payload = await deps.replayTarget.loadPayload(release);
    if (!payload) {
      throw new Error(`Missing stored publish payload for release ${release.id}.`);
    }
    await deps.replayTarget.replay(payload);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // A missing artifact never heals by retrying: hold the release and fail
    // the job so an admin can re-upload bytes matching the digest.
    const missingArtifact = isNoSuchKeyError(error);
    if (missingArtifact && release) {
      await markArtifactMissing(deps.pool, release.org_id, release.id).catch(
        () => undefined,
      );
      await insertEvent(deps.pool, {
        orgId: release.org_id,
        actor: workerId,
        action: "artifact.missing",
        subject: release.id,
        metadata: { jobId: job.id },
      }).catch(() => undefined);
    }
    const result = await failReplayJob(deps.pool, {
      jobId: job.id,
      owner: workerId,
      error: message,
      maxAttempts: missingArtifact ? job.attempts : (deps.maxAttempts ?? 3),
      backoffMs: deps.backoffMs ?? 30_000,
    });
    if (result?.exhausted) {
      deps.logger.error(
        { jobId: job.id, releaseId: job.release_id, error: message },
        "replay job exhausted its attempts",
      );
      deps.onJobExhausted?.(result.job, message);
      if (release) {
        await insertEvent(deps.pool, {
          orgId: release.org_id,
          actor: workerId,
          action: "release.replay_failed",
          subject: release.id,
          metadata: { jobId: job.id, error: message },
        }).catch(() => undefined);
      }
    } else {
      deps.logger.info(
        { jobId: job.id, releaseId: job.release_id, error: message },
        "replay attempt failed; job requeued with backoff",
      );
    }
    return true;
  }

  const completed = await completeReplayJob(deps.pool, {
    jobId: job.id,
    owner: workerId,
  });
  if (!completed) {
    // The lease was taken over while replaying; the new owner owns the state.
    deps.logger.info(
      { jobId: job.id, releaseId: job.release_id },
      "replay finished after lease takeover; completion recorded by the new owner",
    );
    return true;
  }

  await insertEvent(deps.pool, {
    orgId: job.org_id,
    actor: workerId,
    action: "release.replayed",
    subject: job.release_id,
    metadata: { jobId: job.id },
  }).catch(() => undefined);
  return true;
}

export function startReplayWorker(
  deps: ReplayWorkerDeps,
): ReplayWorkerHandle {
  const workerId = `${hostname()}:${process.pid}:${randomUUID()}`;
  const pollMs = deps.pollMs ?? 2_000;
  let stopped = false;
  let timer: NodeJS.Timeout | undefined;

  const tick = async () => {
    if (stopped) return;
    try {
      // One job per tick keeps a slow Verdaccio from starving the loop.
      await processNextReplayJob(deps, workerId);
    } catch (error) {
      deps.logger.error(
        {
          workerId,
          error: error instanceof Error ? error.message : String(error),
        },
        "replay worker tick failed",
      );
    } finally {
      if (!stopped) {
        timer = setTimeout(tick, pollMs);
        timer.unref();
      }
    }
  };

  void recoverExpiredReplayJobs(deps.pool)
    .then((recovered) => {
      if (recovered > 0) {
        deps.logger.info(
          { workerId, recovered },
          "recovered expired replay leases at startup",
        );
      }
    })
    .catch((error) =>
      deps.logger.error(
        {
          workerId,
          error: error instanceof Error ? error.message : String(error),
        },
        "failed to recover expired replay leases at startup",
      ),
    )
    .finally(() => {
      if (!stopped) void tick();
    });

  deps.logger.info({ workerId }, "replay worker is listening");

  return {
    workerId,
    stop: () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    },
  };
}
