import type { PgBoss } from "pg-boss";
import type { Config } from "./config.js";
import type { Db } from "./db.js";
import type { IngestionLimiter } from "./ingestion.js";
import type { ReleaseLifecycle } from "./lifecycle.js";
import type { Storage } from "./storage.js";
import type { VerdaccioClient } from "./verdaccio.js";

export interface AppContext {
  config: Config;
  pool: Db;
  storage: Storage;
  verdaccio: VerdaccioClient;
  boss: PgBoss;
  lifecycle: ReleaseLifecycle;
  auditWorkerId?: string;
  /** Shared bounded-ingestion limiter (filled by buildServer when absent). */
  ingestion?: IngestionLimiter;
}
