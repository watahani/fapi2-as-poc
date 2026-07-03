/**
 * Key rotation CLI (NFR-4 / FAPI2 §6.8): introduce a new active ES256 signing
 * key. The previous key is retired but remains published in the JWKS until its
 * retention horizon so outstanding tokens keep verifying.
 *
 * Run with: npm run keys:rotate
 */
import { fileURLToPath } from "node:url";
import pino from "pino";
import { loadConfig } from "../config.js";
import { getPool } from "./pool.js";
import { createPgStorage } from "./repositories/pg.js";
import { KeyStore } from "../crypto/keys.js";

export async function rotateKeys(): Promise<{ oldKid: string | null; newKid: string }> {
  const config = loadConfig();
  // Rotating an ephemeral in-memory keystore would be a no-op that misleads
  // the operator into thinking the live key changed.
  if (config.storage !== "postgres") {
    throw new Error("keys:rotate requires STORAGE=postgres (in-memory rotation would not persist)");
  }
  const storage = createPgStorage(getPool(config.databaseUrl, { ssl: config.databaseSsl }));
  const keystore = new KeyStore(storage.keys, { kek: config.keystoreKek });
  await keystore.ensure();
  const oldKid = keystore.activeKid();
  const newKid = await keystore.rotate();
  return { oldKid, newKid };
}

async function main(): Promise<void> {
  const log = pino({ level: process.env.LOG_LEVEL ?? "info" });
  const { oldKid, newKid } = await rotateKeys();
  log.info({ oldKid, newKid }, "signing key rotated");
  const config = loadConfig();
  if (config.storage === "postgres") {
    await getPool(config.databaseUrl, { ssl: config.databaseSsl }).end();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    pino().error({ err }, "key rotation failed");
    process.exitCode = 1;
  });
}
