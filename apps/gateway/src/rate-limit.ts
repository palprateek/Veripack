import type { Queryable } from "./db.js";

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

export async function checkPostgresRateLimit(
  db: Queryable,
  bucketKey: string,
  max: number,
  windowMs: number,
): Promise<RateLimitResult> {
  const now = Date.now();
  const windowStart = Math.floor(now / windowMs) * windowMs;
  const result = await db.query<{ request_count: number | string }>(
    `insert into rate_limit_buckets (bucket_key, window_start, request_count)
     values ($1, $2, 1)
     on conflict (bucket_key) do update
       set request_count = case
             when rate_limit_buckets.window_start = excluded.window_start
               then rate_limit_buckets.request_count + 1
             else 1
           end,
           window_start = excluded.window_start,
           updated_at = now()
     returning request_count`,
    [bucketKey, windowStart],
  );
  const count = Number(result.rows[0]?.request_count ?? 1);
  return {
    allowed: count <= max,
    remaining: Math.max(max - count, 0),
    resetAt: windowStart + windowMs,
  };
}
