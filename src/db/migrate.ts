/**
 * Minimal in-house migration runner (no external migration tooling).
 * Applies `migrations/*.sql` in lexical order inside a transaction, tracking
 * applied files in a `schema_migrations` table.
 *
 * Run with: npm run migrate
 */
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pino from "pino";
import type pg from "pg";
import { loadConfig } from "../config.js";
import { getPool } from "./pool.js";

const migrationsDir = join(dirname(fileURLToPath(import.meta.url)), "migrations");

export async function runMigrations(
  pool: pg.Pool,
  log: { info: (obj: unknown, msg?: string) => void } = { info: () => {} },
): Promise<void> {
  await pool.query(
    `create table if not exists schema_migrations (
       id text primary key,
       applied_at timestamptz not null default now()
     )`,
  );

  const files = (await readdir(migrationsDir)).filter((f) => f.endsWith(".sql")).sort();

  for (const file of files) {
    const { rows } = await pool.query("select 1 from schema_migrations where id = $1", [file]);
    if (rows.length > 0) {
      log.info({ file }, "skip (already applied)");
      continue;
    }
    const sql = await readFile(join(migrationsDir, file), "utf8");
    const client = await pool.connect();
    try {
      await client.query("begin");
      await client.query(sql);
      await client.query("insert into schema_migrations (id) values ($1)", [file]);
      await client.query("commit");
      log.info({ file }, "applied");
    } catch (err) {
      await client.query("rollback");
      throw err;
    } finally {
      client.release();
    }
  }
}

async function main(): Promise<void> {
  const log = pino({ level: process.env.LOG_LEVEL ?? "info" });
  const config = loadConfig();
  const pool = getPool(config.databaseUrl, { ssl: config.databaseSsl });
  await runMigrations(pool, log);
  await pool.end();
  log.info("migrations complete");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    pino().error({ err }, "migration failed");
    process.exitCode = 1;
  });
}
