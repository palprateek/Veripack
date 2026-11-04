import { withTransaction, type Db, type DbClient, type Queryable } from "./db.js";

export type ReplayJobState = "queued" | "running" | "succeeded" | "failed";

export interface ReplayJobRow {
  id: string;
  org_id: string;
  release_id: string;
  state: ReplayJobState;
  attempts: number;
  lease_owner: string | null;
  lease_expires_at: Date | null;
  available_at: Date;
  last_error: string | null;
  created_at: Date;
  updated_at: Date;
}

/**
 * Inserts a queued job and points the release projection at it. Callers run
 * this inside the decision transaction so approval and enqueue are atomic.
 */
export async function insertReplayJob(
  client: DbClient,
  input: { orgId: string; releaseId: string },
): Promise<ReplayJobRow> {
  const result = await client.query<ReplayJobRow>(
    `insert into replay_jobs (org_id, release_id, state)
     values ($1, $2, 'queued')
     returning *`,
    [input.orgId, input.releaseId],
  );
  const job = result.rows[0]!;
  await client.query(
    `update releases
        set replay_job_id = $1,
            replay_state = 'not_started',
            replay_started_at = null,
            updated_at = now()
      where id = $2`,
    [job.id, input.releaseId],
  );
  return job;
}

/** Enqueues a replay job in its own transaction. */
export async function enqueueReplayJob(
  db: Db,
  input: { orgId: string; releaseId: string },
): Promise<ReplayJobRow> {
  return withTransaction(db, (client) => insertReplayJob(client, input));
}

export async function getReplayJob(
  db: Queryable,
  jobId: string,
): Promise<ReplayJobRow | null> {
  const result = await db.query<ReplayJobRow>(
    "select * from replay_jobs where id = $1",
    [jobId],
  );
  return result.rows[0] ?? null;
}

/**
 * Claims the next due job, or a running job whose lease has expired, with
 * FOR UPDATE SKIP LOCKED so competing workers never take the same job.
 */
export async function claimReplayJob(
  db: Db,
  input: { owner: string; leaseMs: number },
): Promise<ReplayJobRow | null> {
  return withTransaction(db, async (client) => {
    const result = await client.query<ReplayJobRow>(
      `with candidate as (
         select id
           from replay_jobs
          where (state = 'queued' and available_at <= now())
             or (state = 'running' and lease_expires_at < now())
          order by coalesce(available_at, created_at), created_at
          for update skip locked
          limit 1
       )
       update replay_jobs job
          set state = 'running',
              attempts = job.attempts + 1,
              lease_owner = $1,
              lease_expires_at = now() + ($2::text || ' milliseconds')::interval,
              updated_at = now()
         from candidate
        where job.id = candidate.id
        returning job.*`,
      [input.owner, String(input.leaseMs)],
    );
    const job = result.rows[0] ?? null;
    if (job) {
      await client.query(
        `update releases
            set replay_state = 'in_progress',
                replay_started_at = now(),
                updated_at = now()
          where id = $1`,
        [job.release_id],
      );
    }
    return job;
  });
}

export async function completeReplayJob(
  db: Db,
  input: { jobId: string; owner: string },
): Promise<ReplayJobRow | null> {
  return withTransaction(db, async (client) => {
    const result = await client.query<ReplayJobRow>(
      `update replay_jobs
          set state = 'succeeded',
              lease_owner = null,
              lease_expires_at = null,
              last_error = null,
              updated_at = now()
        where id = $1
          and state = 'running'
          and lease_owner = $2
        returning *`,
      [input.jobId, input.owner],
    );
    const job = result.rows[0] ?? null;
    if (job) {
      await client.query(
        `update releases
            set replay_state = 'succeeded',
                updated_at = now()
          where id = $1`,
        [job.release_id],
      );
    }
    return job;
  });
}

export interface FailReplayJobResult {
  job: ReplayJobRow;
  exhausted: boolean;
}

/**
 * Records a failed attempt. The job returns to `queued` after a backoff until
 * the attempt budget is exhausted, when it becomes terminally `failed`.
 */
export async function failReplayJob(
  db: Db,
  input: {
    jobId: string;
    owner: string;
    error: string;
    maxAttempts: number;
    backoffMs: number;
  },
): Promise<FailReplayJobResult | null> {
  return withTransaction(db, async (client) => {
    const current = await client.query<ReplayJobRow>(
      `select * from replay_jobs
        where id = $1 and state = 'running' and lease_owner = $2
        for update`,
      [input.jobId, input.owner],
    );
    const job = current.rows[0];
    if (!job) return null;

    const exhausted = job.attempts >= input.maxAttempts;
    const updated = await client.query<ReplayJobRow>(
      exhausted
        ? `update replay_jobs
              set state = 'failed',
                  lease_owner = null,
                  lease_expires_at = null,
                  last_error = $2,
                  updated_at = now()
            where id = $1
            returning *`
        : `update replay_jobs
              set state = 'queued',
                  lease_owner = null,
                  lease_expires_at = null,
                  last_error = $2,
                  available_at = now() + ($3::text || ' milliseconds')::interval,
                  updated_at = now()
            where id = $1
            returning *`,
      exhausted
        ? [input.jobId, input.error]
        : [input.jobId, input.error, String(input.backoffMs)],
    );
    const next = updated.rows[0]!;
    await client.query(
      `update releases
          set replay_state = $2,
              updated_at = now()
        where id = $1`,
      [next.release_id, exhausted ? "failed" : "not_started"],
    );
    return { job: next, exhausted };
  });
}

/**
 * Resets running jobs whose lease expired back to `queued`. Claiming already
 * takes expired leases over; this sweep keeps the projection truthful for
 * jobs nobody has claimed yet.
 */
export async function recoverExpiredReplayJobs(db: Db): Promise<number> {
  return withTransaction(db, async (client) => {
    const result = await client.query<ReplayJobRow>(
      `update replay_jobs
          set state = 'queued',
              lease_owner = null,
              lease_expires_at = null,
              available_at = now(),
              updated_at = now()
        where state = 'running'
          and lease_expires_at < now()
        returning *`,
    );
    for (const job of result.rows) {
      await client.query(
        `update releases
            set replay_state = 'not_started',
                replay_started_at = null,
                updated_at = now()
          where id = $1 and replay_state = 'in_progress'`,
        [job.release_id],
      );
    }
    return result.rows.length;
  });
}
