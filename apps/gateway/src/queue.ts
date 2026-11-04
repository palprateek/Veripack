import { PgBoss } from "pg-boss";
import type { Config } from "./config.js";

export interface AuditJobData {
  releaseId: string;
}

export async function startQueue(config: Config): Promise<PgBoss> {
  const boss = new PgBoss({
    connectionString: config.DATABASE_URL,
    schema: "pgboss",
    application_name: "veripack-gateway",
    max: config.QUEUE_MAX_CONNECTIONS,
  });

  boss.on("error", (error) => {
    console.error("pg-boss error", error);
  });

  await boss.start();
  await boss.createQueue(config.AUDIT_QUEUE, {
    retryLimit: config.AUDIT_JOB_RETRY_LIMIT,
    retryDelay: config.AUDIT_JOB_RETRY_DELAY_SECONDS,
    expireInSeconds: config.AUDIT_JOB_EXPIRE_SECONDS,
    deleteAfterSeconds: config.AUDIT_JOB_DELETE_AFTER_SECONDS,
  });

  return boss;
}
