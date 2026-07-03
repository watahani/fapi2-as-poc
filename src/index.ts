import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Fastify, { type FastifyInstance } from "fastify";
import { loadConfig, type AppConfig } from "./config.js";
import { getPool } from "./db/pool.js";
import { createMemoryStorage } from "./db/repositories/memory.js";
import { createPgStorage } from "./db/repositories/pg.js";
import type { Storage } from "./db/repositories/types.js";
import { KeyStore } from "./crypto/keys.js";
import { registerEndpoints } from "./endpoints/index.js";
import { MockPdp } from "./authz/adapters/mock.js";
import type { PolicyDecisionPoint } from "./authz/pdp.js";
import { DevLoginProvider, type AuthenticationProvider } from "./domain/interaction.js";

export interface AppDeps {
  config?: AppConfig;
  pdp?: PolicyDecisionPoint;
  storage?: Storage;
  authProvider?: AuthenticationProvider;
}

/**
 * Boots Fastify and wires the separation boundaries: config, storage (memory
 * for tests / postgres in deployment), the ES256 keystore, the PDP (authZ
 * delegation), and the protocol endpoints (src/endpoints + src/domain).
 */
export function buildApp(deps: AppDeps = {}): FastifyInstance {
  const config = deps.config ?? loadConfig();
  const pdp = deps.pdp ?? new MockPdp();
  const storage =
    deps.storage ??
    (config.storage === "postgres"
      ? createPgStorage(getPool(config.databaseUrl, { ssl: config.databaseSsl }))
      : createMemoryStorage());
  // FAPI mandates TLS. Normally a proxy terminates it; when TLS files are
  // configured the AS serves https directly (used by the conformance harness).
  // FAPI2 §5.2.2: with TLS 1.2 only BCP195 (RFC 9325) recommended cipher
  // suites are permitted; TLS 1.3's suites are all acceptable.
  const https = config.tls
    ? {
        key: readFileSync(config.tls.keyFile),
        cert: readFileSync(config.tls.certFile),
        minVersion: "TLSv1.2" as const,
        honorCipherOrder: true,
        ciphers: [
          "ECDHE-ECDSA-AES128-GCM-SHA256",
          "ECDHE-RSA-AES128-GCM-SHA256",
          "ECDHE-ECDSA-AES256-GCM-SHA384",
          "ECDHE-RSA-AES256-GCM-SHA384",
          "ECDHE-ECDSA-CHACHA20-POLY1305",
          "ECDHE-RSA-CHACHA20-POLY1305",
          "DHE-RSA-AES128-GCM-SHA256",
          "DHE-RSA-AES256-GCM-SHA384",
        ].join(":"),
      }
    : null;

  const app = Fastify({
    ...(https ? { https } : {}),
    logger: {
      level: config.logLevel,
      // Never let credentials reach log aggregation, including via future
      // request logging (Authorization/DPoP headers, cookies). pino '*'
      // covers one level, so body paths are listed explicitly; the standing
      // rule is: never log raw request bodies.
      redact: {
        paths: [
          "req.headers.authorization",
          "req.headers.dpop",
          "req.headers.cookie",
          "req.body.client_assertion",
          "*.client_assertion",
          "*.privateJwk",
          "err.record.privateJwk",
        ],
        remove: true,
      },
    },
    // FAPI flows carry signed request objects / DPoP proofs; PAR requests
    // beyond this bound get 413 (RFC 9126 §2.3).
    bodyLimit: 256 * 1024,
    // Behind an ingress this must be set so req.ip (the rate-limit key) is the
    // real client rather than the proxy; unset it is false (safe when direct).
    trustProxy: config.trustProxy,
  });

  const keystore = new KeyStore(storage.keys, {
    kek: config.keystoreKek,
    warn: (msg) => app.log.warn({ security: "keystore" }, msg),
  });

  // An unset NODE_ENV must not silently run with dev-grade security (the
  // production guard only throws when NODE_ENV=production).
  for (const warning of config.devModeWarnings) {
    app.log.warn({ security: "dev-mode" }, warning);
  }

  // Liveness: the process is up.
  app.get("/health", async () => ({ status: "ok" }));

  // Readiness: the domain storage actually wired into the endpoints is
  // usable. Kept minimal — no config/issuer/pdp disclosure to unauthenticated
  // callers. `storage` names the backend so a misconfigured non-durable
  // deployment is observable.
  // The ping is cached briefly AND deduplicated in flight so unauthenticated
  // probe traffic cannot amplify load onto a slow/down DB.
  let lastPing: { at: number; up: boolean } | undefined;
  let pendingPing: Promise<boolean> | undefined;
  app.get("/healthz", async (_req, reply) => {
    if (!lastPing || Date.now() - lastPing.at > 2000) {
      pendingPing ??= storage.ping().then((up) => {
        lastPing = { at: Date.now(), up };
        pendingPing = undefined;
        return up;
      });
      await pendingPing;
    }
    const dbUp = (lastPing as { up: boolean }).up;
    reply.code(dbUp ? 200 : 503);
    return {
      status: dbUp ? "ok" : "degraded",
      db: dbUp ? "up" : "down",
      storage: deps.storage ? "injected" : config.storage,
    };
  });

  const authProvider = deps.authProvider ?? new DevLoginProvider(config);
  registerEndpoints(app, { config, pdp, storage, keystore, authProvider });

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
