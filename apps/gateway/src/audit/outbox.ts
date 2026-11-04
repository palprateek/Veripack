import type { PgBoss } from "pg-boss";
import type { Config } from "../config.js";
import type { Db } from "../db.js";

export interface OutboxLogger {
  info(obj: unknown, message?: string): void;
  error(obj: unknown, message?: string): void;
}

export interface AuditOutboxDeps {
  pool: Db;
  boss: PgBoss;
  config: Pick<
    Config,
    | "AUDIT_QUEUE"
    | "AUDIT_JOB_RETRY_LIMIT"
    | "AUDIT_JOB_RETRY_DELAY_SECONDS"
    | "AUDIT_JOB_EXPIRE_SECONDS"
    | "AUDIT_OUTBOX_BATCH_SIZE"
    | "AUDIT_OUTBOX_INTERVAL_MS"
  >;
  logger: OutboxLogger;
}

interface ClaimedEntry {
  release_id: string;
}

/**
 * Claim entries before sending them to pg-boss. A crashed dispatcher leaves the
 * row unsent, but the short lease makes it eligible again after the backoff.
 */
async function claimEntries(
  deps: AuditOutboxDeps,
  releaseId: string | null,
): Promise<ClaimedEntry[]> {
  const result = await deps.pool.query<ClaimedEntry>(
    `with candidates as (
       select release_id
         from audit_outbox
        where sent_at is null
          and next_attempt_at <= now()
          and ($2::uuid is null or release_id = $2::uuid)
        order by next_attempt_at, created_at
        for update skip locked
        limit $1
     )
     update audit_outbox outbox
        set attempts = outbox.attempts + 1,
            next_attempt_at = now() + ($3::text || ' seconds')::interval,
            last_error = null
       from candidates
      where outbox.release_id = candidates.release_id
      returning outbox.release_id`,
    [deps.config.AUDIT_OUTBOX_BATCH_SIZE, releaseId, deps.config.AUDIT_OUTBOX_INTERVAL_MS / 1000],
  );
  return result.rows;
}

async function recoverLostDispatches(deps: AuditOutboxDeps): Promise<void> {
  await deps.pool.query(
    `update audit_outbox outbox
        set sent_at = null,
            next_attempt_at = now(),
            last_error = coalesce(last_error, 'queue dispatch lease expired')
       from releases r
      where outbox.release_id = r.id
        and outbox.sent_at is not null
        and outbox.sent_at < now() - ($1::text || ' seconds')::interval
        and r.status = 'pending'
        and not exists (
          select 1 from audits audit where audit.release_id = r.id
        )`,
    [Math.max(60, deps.config.AUDIT_JOB_EXPIRE_SECONDS * 2)],
  );
}

async function markSent(pool: Db, releaseId: string): Promise<void> {
  await pool.query(
    `update audit_outbox
        set sent_at = now(), last_error = null
      where release_id = $1 and sent_at is null`,
    [releaseId],
  );
}

async function markFailed(pool: Db, releaseId: string, error: unknown): Promise<void> {
  const message = (error instanceof Error ? error.message : String(error)).slice(0, 1_000);
  await pool.query(
    `update audit_outbox
        set last_error = $2,
            next_attempt_at = now() +
              (least(300, greatest(2, attempts * 2))::text || ' seconds')::interval
      where release_id = $1 and sent_at is null`,
    [releaseId, message],
  );
}

export async function dispatchAuditOutboxOnce(
  deps: AuditOutboxDeps,
  releaseId: string | null = null,
): Promise<number> {
  await recoverLostDispatches(deps);
  const entries = await claimEntries(deps, releaseId);
  for (const entry of entries) {
    try {
      await deps.boss.send(
        deps.config.AUDIT_QUEUE,
        { releaseId: entry.release_id },
        {
          retryLimit: deps.config.AUDIT_JOB_RETRY_LIMIT,
          retryDelay: deps.config.AUDIT_JOB_RETRY_DELAY_SECONDS,
        },
      );
      await markSent(deps.pool, entry.release_id);
    } catch (error) {
      await markFailed(deps.pool, entry.release_id, error);
      deps.logger.error(
        {
          releaseId: entry.release_id,
          error: error instanceof Error ? error.message : String(error),
        },
        "failed to dispatch audit outbox entry",
      );
    }
  }
  return entries.length;
}

export async function requeueAuditOutbox(pool: Db, releaseId: string): Promise<void> {
  await pool.query(
    `insert into audit_outbox (release_id, sent_at, next_attempt_at, last_error)
     values ($1, null, now(), null)
     on conflict (release_id) do update
       set sent_at = null,
           next_attempt_at = now(),
           last_error = null`,
    [releaseId],
  );
}

export function startAuditOutboxDispatcher(
  deps: AuditOutboxDeps,
): () => void {
  const run = () =>
    dispatchAuditOutboxOnce(deps).catch((error) =>
      deps.logger.error(
        { error: error instanceof Error ? error.message : String(error) },
        "audit outbox dispatcher failed",
      ),
    );

  const timer = setInterval(run, deps.config.AUDIT_OUTBOX_INTERVAL_MS);
  timer.unref();
  run();
  return () => clearInterval(timer);
}
