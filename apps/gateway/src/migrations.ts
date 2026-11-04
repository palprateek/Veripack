import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Db } from "./db.js";

// Works from both src/ (tsx) and dist/ (compiled) because both are one level
// below the app root.
const migrationsDir = fileURLToPath(new URL("../migrations", import.meta.url));

export interface RunMigrationsOptions {
  /**
   * Stop after this migration filename. Used by integration tests that need a
   * database seeded at an earlier schema version.
   */
  through?: string;
  /**
   * Role that receives the restricted evidence grants. The setting is scoped to
   * each migration transaction and read by 007_v1_evidence_model.sql.
   */
  appRole?: string;
}

export async function runMigrations(
  pool: Db,
  options: RunMigrationsOptions = {},
): Promise<string[]> {
  await pool.query(`
    create table if not exists schema_migrations (
      name text primary key,
      applied_at timestamptz not null default now()
    )
  `);

  const files = (await readdir(migrationsDir))
    .filter((name) => name.endsWith(".sql"))
    .filter((name) => !options.through || name <= options.through)
    .sort();

  const applied = new Set(
    (await pool.query<{ name: string }>("select name from schema_migrations"))
      .rows.map((row) => row.name),
  );

  const newlyApplied: string[] = [];

  for (const file of files) {
    if (applied.has(file)) continue;

    const sql = await readFile(join(migrationsDir, file), "utf8");
    const client = await pool.connect();
    try {
      await client.query("begin");
      if (options.appRole) {
        await client.query(
          "select set_config('veripack.app_role', $1, true)",
          [options.appRole],
        );
      }
      await client.query(sql);
      await client.query("insert into schema_migrations (name) values ($1)", [file]);
      await client.query("commit");
      newlyApplied.push(file);
    } catch (error) {
      await client.query("rollback").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  return newlyApplied;
}
