import pg from "pg";

export interface PoolOptions {
  /** Enable TLS to PostgreSQL with certificate verification. */
  ssl?: boolean;
}

/**
 * Single shared connection pool (module singleton — a pool, not domain state).
 * Bounded with connect/statement timeouts so a hung DB cannot exhaust the pool
 * indefinitely; optional TLS with certificate verification.
 */
let pool: pg.Pool | undefined;

export function getPool(databaseUrl: string, options: PoolOptions = {}): pg.Pool {
  if (!pool) {
    pool = new pg.Pool({
      connectionString: databaseUrl,
      max: 10,
      connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 30000,
      statement_timeout: 10000,
      query_timeout: 10000,
      ...(options.ssl ? { ssl: { rejectUnauthorized: true } } : {}),
    });
  }
  return pool;
}

export async function pingDb(p: pg.Pool): Promise<boolean> {
  try {
    await p.query("select 1");
    return true;
  } catch {
    return false;
  }
}

export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = undefined;
  }
}
