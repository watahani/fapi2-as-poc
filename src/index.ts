import { fileURLToPath } from "node:url";
import Fastify, { type FastifyInstance } from "fastify";
import { loadConfig, type AppConfig } from "./config.js";
import { getPool, pingDb } from "./db/pool.js";
import { registerEndpoints } from "./endpoints/index.js";
import { MockPdp } from "./authz/adapters/mock.js";
import type { PolicyDecisionPoint } from "./authz/pdp.js";

export interface AppDeps {
  config?: AppConfig;
  pdp?: PolicyDecisionPoint;
}

/**
 * P0 skeleton: boots Fastify and wires the config, DB pool, and the
 * separation boundaries (PDP for authZ, endpoints for the protocol engine).
 * The FAPI 2.0 protocol implementation is added in src/endpoints + src/domain
 * during P1.
 */
export function buildApp(deps: AppDeps = {}): FastifyInstance {
  const config = deps.config ?? loadConfig();
  const pdp = deps.pdp ?? new MockPdp();
  const pool = getPool(config.databaseUrl, { ssl: config.databaseSsl });

  const app = Fastify({
    logger: { level: config.logLevel },
    // FAPI flows carry large signed request objects / DPoP proofs.
    bodyLimit: 256 * 1024,
  });

  // Liveness: the process is up.
  app.get("/health", async () => ({ status: "ok" }));

  // Readiness: dependencies are reachable. Kept minimal — no config/issuer/pdp
  // disclosure to unauthenticated callers.
  app.get("/healthz", async (_req, reply) => {
    const dbUp = await pingDb(pool);
    reply.code(dbUp ? 200 : 503);
    return { status: dbUp ? "ok" : "degraded", db: dbUp ? "up" : "down" };
  });

  // Protocol engine boundary (no-op in P0).
  registerEndpoints(app, { config, pdp, pool });

  return app;
}

async function main(): Promise<void> {
  const config = loadConfig();
  const app = buildApp({ config });
  await app.listen({ port: config.port, host: "0.0.0.0" });
}

// Start only when executed directly (not when imported by tests).
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    process.stderr.write(`fatal: failed to start authorization server: ${String(err)}\n`);
    process.exitCode = 1;
  });
}
