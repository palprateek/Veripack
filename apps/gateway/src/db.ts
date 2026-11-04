import pg from "pg";

const { Pool } = pg;

export type Db = pg.Pool;
export type DbClient = pg.PoolClient;
export type Queryable = Pick<Db, "query"> | Pick<DbClient, "query">;

export interface DbOptions {
  ssl?: boolean;
  rejectUnauthorized?: boolean;
  /**
   * Sets the libpq `search_path` for every connection in the pool. The value
   * must be a plain identifier; integration tests use generated schema names.
   */
  searchPath?: string;
}

export function createDb(
  connectionString: string,
  options: DbOptions = {},
): Db {
  return new Pool({
    connectionString,
    ...(options.ssl
      ? {
          ssl: { rejectUnauthorized: options.rejectUnauthorized ?? true },
        }
      : {}),
    ...(options.searchPath
      ? { options: `-c search_path=${options.searchPath}` }
      : {}),
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
  });
}

export async function waitForDb(pool: Db, attempts = 30): Promise<void> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      await pool.query("select 1");
      return;
    } catch (error) {
      lastError = error;
      if (attempt === attempts) break;
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
  }
  throw new Error(
    `Postgres did not become ready after ${attempts} attempts: ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }`,
  );
}

export async function withTransaction<T>(
  pool: Db,
  fn: (client: DbClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("begin");
    const result = await fn(client);
    await client.query("commit");
    return result;
  } catch (error) {
    await client.query("rollback").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
