import { randomUUID } from "node:crypto";
import { createDb, type Db } from "../db.js";
import { runMigrations } from "../migrations.js";

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ??
  "postgres://veripack:veripack@localhost:5432/veripack";

export interface TestDatabaseOptions {
  /** Set to false when a test needs to seed an older schema first. */
  migrate?: boolean;
  /** Passed to runMigrations; use a migration filename such as 006_upstream_audits.sql. */
  through?: string;
  /** Role that receives restricted evidence grants during migration 007. */
  appRole?: string;
}

export interface TestDatabase {
  pool: Db;
  schema: string;
  close(): Promise<void>;
}

function redact(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.password) parsed.password = "<redacted>";
    return parsed.toString();
  } catch {
    return "<invalid TEST_DATABASE_URL>";
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Creates a unique schema in the integration database, points a pool at it,
 * and applies the migrations. Closing the handle drops the schema.
 */
export async function createTestDatabase(
  options: TestDatabaseOptions = {},
): Promise<TestDatabase> {
  const schema = `veripack_test_${Date.now()}_${randomUUID()
    .replaceAll("-", "")
    .slice(0, 10)}`;
  const admin = createDb(TEST_DATABASE_URL);
  let pool: Db | null = null;

  try {
    await admin.query(`create schema "${schema}"`);
    pool = createDb(TEST_DATABASE_URL, { searchPath: schema });

    if (options.migrate !== false) {
      await runMigrations(pool, {
        through: options.through,
        appRole: options.appRole,
      });
    }

    let closed = false;
    return {
      pool,
      schema,
      async close() {
        if (closed) return;
        closed = true;
        await pool?.end().catch(() => undefined);
        const cleanup = createDb(TEST_DATABASE_URL);
        try {
          await cleanup.query(`drop schema if exists "${schema}" cascade`);
        } finally {
          await cleanup.end().catch(() => undefined);
        }
      },
    };
  } catch (error) {
    await pool?.end().catch(() => undefined);
    await admin
      .query(`drop schema if exists "${schema}" cascade`)
      .catch(() => undefined);
    throw new Error(
      `Integration database setup failed for ${redact(
        TEST_DATABASE_URL,
      )} (schema ${schema}): ${messageOf(error)}`,
      { cause: error },
    );
  } finally {
    await admin.end().catch(() => undefined);
  }
}

export function uniqueRoleName(): string {
  return `veripack_test_role_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
}
