import { config } from "./config.js";
import { createDb, waitForDb } from "./db.js";
import { runMigrations } from "./migrations.js";

const pool = createDb(config.DATABASE_URL, {
  ssl: config.DATABASE_SSL,
  rejectUnauthorized: config.DATABASE_SSL_REJECT_UNAUTHORIZED,
});

try {
  await waitForDb(pool);
  const applied = await runMigrations(pool, {
    appRole: config.EVIDENCE_APP_ROLE || undefined,
  });
  if (applied.length === 0) {
    console.log("Database schema is up to date.");
  } else {
    console.log(`Applied migrations: ${applied.join(", ")}`);
  }
} finally {
  await pool.end();
}
