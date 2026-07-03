/**
 * Client registration seeder (P1 has no dynamic registration — that is P2+).
 * Reads a JSON array of client records and upserts them, so the dev/conformance
 * clients are provisioned reproducibly.
 *
 * Run with: npm run seed:clients -- path/to/clients.json
 * Each entry: { "client_id": "...", "client_name": "...", "metadata": { ... } }
 * where metadata follows src/domain/clients.ts (redirect_uris, jwks/jwks_uri,
 * token_endpoint_auth_method=private_key_jwt, scope, ...).
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import pino from "pino";
import { z } from "zod";
import { loadConfig } from "../config.js";
import { getPool } from "./pool.js";
import { createPgStorage } from "./repositories/pg.js";
import { parseClientMetadata } from "../domain/clients.js";
import type { ClientRepository } from "./repositories/types.js";

const seedSchema = z.array(
  z.object({
    client_id: z.string().min(1),
    client_name: z.string().nullable().default(null),
    metadata: z.record(z.string(), z.unknown()),
  }),
);

export async function seedClients(repo: ClientRepository, json: string): Promise<number> {
  const entries = seedSchema.parse(JSON.parse(json));
  for (const entry of entries) {
    // Fail fast on non-compliant registrations (defence in depth: loadClient
    // re-validates on read, but reject at write time for a clear error).
    parseClientMetadata(entry.metadata);
    await repo.upsert({
      clientId: entry.client_id,
      clientName: entry.client_name,
      metadata: entry.metadata,
    });
  }
  return entries.length;
}

async function main(): Promise<void> {
  const log = pino({ level: process.env.LOG_LEVEL ?? "info" });
  const path = process.argv[2];
  if (!path) throw new Error("usage: npm run seed:clients -- <clients.json>");
  const config = loadConfig();
  if (config.storage !== "postgres") throw new Error("seed:clients requires STORAGE=postgres");
  const pool = getPool(config.databaseUrl, { ssl: config.databaseSsl });
  const count = await seedClients(createPgStorage(pool).clients, await readFile(path, "utf8"));
  await pool.end();
  log.info({ count }, "clients seeded");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    pino().error({ err }, "client seeding failed");
    process.exitCode = 1;
  });
}
