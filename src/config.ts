/**
 * Centralised configuration loaded from the environment.
 * Single source of truth for runtime config; validated with zod.
 *
 * Protocol-affecting defaults cite their governing requirement
 * (docs/REQUIREMENTS-P1.md).
 */
import { z } from "zod";

const schema = z.object({
  PORT: z.coerce.number().int().positive().default(3000),
  ISSUER: z.string().url().default("https://localhost:3000"),
  LOG_LEVEL: z.string().default("info"),
  DATABASE_URL: z
    .string()
    .default("postgresql://authserver:devpassword@localhost:5432/authserver"),
  // Domain storage backend. "memory" exists for tests / conformance layer 1
  // (Docker-free) and is rejected in production by the fail-closed guard.
  STORAGE: z.enum(["memory", "postgres"]).default("postgres"),
  PDP_KIND: z.enum(["mock", "authzen-http"]).default("mock"),
  PDP_AUTHZEN_URL: z.string().default("http://localhost:8080/access/v1/evaluation"),
  PDP_AUTHZEN_TOKEN: z.string().default(""),
  // "true" enables TLS to PostgreSQL with certificate verification.
  DATABASE_SSL: z.string().default("false"),
  // Optional cache layer (added only when needed; empty = disabled).
  REDIS_URL: z.string().default(""),
  // Authentication delegation (phase 2). Empty = built-in dev interaction.
  EXTERNAL_IDP_URL: z.string().default(""),
  // Subject auto-authenticated by the built-in dev interaction (P1; replaced
  // by external IdP delegation in P2).
  DEV_INTERACTION_SUB: z.string().default("dev-user"),

  // --- Protocol lifetimes (seconds) ---
  // FAPI2-GEN-11: authorization codes shall have a maximum lifetime of 60s.
  AUTH_CODE_TTL_SEC: z.coerce.number().int().positive().max(60).default(60),
  // FAPI2-AUTHZ-12: PAR request_uri expires_in shall be less than 600s.
  PAR_TTL_SEC: z.coerce.number().int().positive().max(599).default(90),
  // FAPI2-SEC-1: access tokens should be short-lived. Capped at 24h so
  // retired signing keys can safely age out of the JWKS (crypto/keys.ts
  // RETIRED_KEY_RETENTION_MS) after every signed token expired.
  ACCESS_TOKEN_TTL_SEC: z.coerce.number().int().positive().max(86400).default(300),
  REFRESH_TOKEN_TTL_SEC: z.coerce.number().int().positive().default(14 * 24 * 3600),
  ID_TOKEN_TTL_SEC: z.coerce.number().int().positive().max(86400).default(300),
  // PKJWT-6: reject client assertions with an unreasonably distant exp.
  CLIENT_ASSERTION_MAX_LIFETIME_SEC: z.coerce.number().int().positive().default(300),

  // --- Clock skew / DPoP ---
  // FAPI2-GEN-13: iat/nbf up to 10s in the future may be accepted; values
  // more than 60s in the future shall be rejected (hence max 60).
  CLOCK_SKEW_FUTURE_ACCEPT_SEC: z.coerce.number().int().min(0).max(60).default(10),
  // DPOP-6: accept proofs only for a limited time after creation.
  DPOP_PROOF_MAX_AGE_SEC: z.coerce.number().int().positive().default(60),
  // FAPI2-GEN-10 / DPOP-15..17: server-provided nonce mechanism (MAY).
  DPOP_NONCE_REQUIRED: z.string().default("false"),
  // HMAC secret for stateless DPoP nonces; generated at boot when empty.
  DPOP_NONCE_SECRET: z.string().default(""),

  // JWTAT-6: default resource indicator used as the JWT AT `aud` when the
  // request carries no resource parameter. Empty = the issuer identifier.
  ACCESS_TOKEN_AUDIENCE: z.string().default(""),

  // Base64 32-byte key-encryption key: private signing JWKs are AES-256-GCM
  // envelope-encrypted at rest when set. Required in production so a leaked
  // DB dump alone cannot forge tokens.
  KEYSTORE_KEK: z.string().default(""),
});

export type AppConfig = Readonly<{
  port: number;
  issuer: string;
  logLevel: string;
  databaseUrl: string;
  databaseSsl: boolean;
  storage: "memory" | "postgres";
  pdp: Readonly<{ kind: "mock" | "authzen-http"; authzenUrl: string; authzenToken: string }>;
  redisUrl: string;
  externalIdpUrl: string;
  devInteractionSub: string;
  authCodeTtlSec: number;
  parTtlSec: number;
  accessTokenTtlSec: number;
  refreshTokenTtlSec: number;
  idTokenTtlSec: number;
  clientAssertionMaxLifetimeSec: number;
  clockSkewFutureAcceptSec: number;
  dpopProofMaxAgeSec: number;
  dpopNonceRequired: boolean;
  dpopNonceSecret: string;
  accessTokenAudience: string;
  /** Decoded key-encryption key (32 bytes) or undefined when not configured. */
  keystoreKek: Buffer | undefined;
  /** Dev-grade settings in effect (empty in production — the guard threw). */
  devModeWarnings: readonly string[];
}>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = schema.parse(env);

  const issuerUrl = new URL(parsed.ISSUER);
  const isLoopback = issuerUrl.hostname === "localhost" || issuerUrl.hostname === "127.0.0.1";

  const keystoreKek = parsed.KEYSTORE_KEK ? Buffer.from(parsed.KEYSTORE_KEK, "base64") : undefined;
  if (keystoreKek && keystoreKek.length !== 32) {
    throw new Error("KEYSTORE_KEK must be base64 of exactly 32 bytes (AES-256-GCM)");
  }

  // Dev-grade settings, itemised: in production they fail closed; elsewhere
  // buildApp logs them prominently so an unset NODE_ENV deployment cannot
  // silently run allow-all/volatile/plaintext (fail-open would otherwise be
  // one missing env var away).
  const devGrade: string[] = [];
  if (parsed.PDP_KIND === "mock") devGrade.push("PDP_KIND=mock authorizes everything");
  if (parsed.STORAGE !== "postgres") devGrade.push(`STORAGE=${parsed.STORAGE} is volatile (no durable state)`);
  if (isLoopback) devGrade.push("ISSUER is a loopback host");
  if (issuerUrl.protocol !== "https:") devGrade.push("ISSUER is not https");
  if (isDevDatabaseUrl(parsed.DATABASE_URL)) {
    devGrade.push("DATABASE_URL uses the built-in dev default / loopback");
  }
  if (parsed.DATABASE_SSL !== "true") devGrade.push("DATABASE_SSL is disabled");
  if (!keystoreKek) devGrade.push("KEYSTORE_KEK unset: private signing keys stored unencrypted");

  // Fail closed in production: never ship allow-all authZ or dev defaults.
  if ((env.NODE_ENV ?? "") === "production" && devGrade.length > 0) {
    throw new Error(`insecure production config: ${devGrade.join("; ")}`);
  }

  // FAPI2-AUTHZ-8 / RFC 9207 §2: the issuer identifier must be an https URL
  // without query or fragment components. http is tolerated outside
  // production for loopback only (local conformance harness — TLS termination
  // is a deployment concern, deploy/conformance/README.md).
  if (issuerUrl.protocol !== "https:" && !isLoopback) {
    throw new Error("ISSUER must use the https scheme [RFC8414 §2; FAPI2 5.2.1]");
  }
  // A bare trailing "?"/"#" yields empty .search/.hash, so check the raw
  // string; issuer comparison is byte-for-byte (RFC8414 §3.3), so reject any
  // non-canonical form (incl. trailing slash) instead of normalising it.
  if (parsed.ISSUER.includes("?") || parsed.ISSUER.includes("#")) {
    throw new Error("ISSUER must not contain query or fragment components [RFC8414 §2]");
  }
  if (parsed.ISSUER.endsWith("/")) {
    throw new Error("ISSUER must not end with a trailing slash (issuer comparison is byte-for-byte)");
  }
  const issuer = parsed.ISSUER;

  return {
    port: parsed.PORT,
    issuer,
    logLevel: parsed.LOG_LEVEL,
    databaseUrl: parsed.DATABASE_URL,
    databaseSsl: parsed.DATABASE_SSL === "true",
    storage: parsed.STORAGE,
    pdp: {
      kind: parsed.PDP_KIND,
      authzenUrl: parsed.PDP_AUTHZEN_URL,
      authzenToken: parsed.PDP_AUTHZEN_TOKEN,
    },
    redisUrl: parsed.REDIS_URL,
    externalIdpUrl: parsed.EXTERNAL_IDP_URL,
    devInteractionSub: parsed.DEV_INTERACTION_SUB,
    authCodeTtlSec: parsed.AUTH_CODE_TTL_SEC,
    parTtlSec: parsed.PAR_TTL_SEC,
    accessTokenTtlSec: parsed.ACCESS_TOKEN_TTL_SEC,
    refreshTokenTtlSec: parsed.REFRESH_TOKEN_TTL_SEC,
    idTokenTtlSec: parsed.ID_TOKEN_TTL_SEC,
    clientAssertionMaxLifetimeSec: parsed.CLIENT_ASSERTION_MAX_LIFETIME_SEC,
    clockSkewFutureAcceptSec: parsed.CLOCK_SKEW_FUTURE_ACCEPT_SEC,
    dpopProofMaxAgeSec: parsed.DPOP_PROOF_MAX_AGE_SEC,
    dpopNonceRequired: parsed.DPOP_NONCE_REQUIRED === "true",
    dpopNonceSecret: parsed.DPOP_NONCE_SECRET,
    accessTokenAudience: parsed.ACCESS_TOKEN_AUDIENCE || issuer,
    keystoreKek,
    devModeWarnings: devGrade,
  };
}

/** Best-effort dev-credential detection (defence in depth, not a substitute
 * for secret management): loopback DB hosts or the well-known dev password. */
function isDevDatabaseUrl(databaseUrl: string): boolean {
  try {
    const u = new URL(databaseUrl);
    const loopback =
      u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]" ||
      u.hostname.startsWith("127.");
    return loopback || u.password === "devpassword";
  } catch {
    return true; // unparseable URL is never production-grade
  }
}

/** Route paths relative to the server root, honouring an issuer path prefix.
 * Used for BOTH route registration and metadata URLs so they provably agree. */
export function endpointPaths(config: AppConfig) {
  const prefix = new URL(config.issuer).pathname.replace(/\/$/, "");
  return {
    authorization: `${prefix}/authorize`,
    token: `${prefix}/token`,
    par: `${prefix}/par`,
    jwks: `${prefix}/jwks`,
    revocation: `${prefix}/revoke`,
    introspection: `${prefix}/introspect`,
  } as const;
}

/** Endpoint URLs are always derived from the configured issuer (never from
 * request headers) so metadata, iss responses, and DPoP htu comparison agree. */
export function endpointUrls(config: AppConfig) {
  const origin = new URL(config.issuer).origin;
  const paths = endpointPaths(config);
  return {
    authorization: `${origin}${paths.authorization}`,
    token: `${origin}${paths.token}`,
    par: `${origin}${paths.par}`,
    jwks: `${origin}${paths.jwks}`,
    revocation: `${origin}${paths.revocation}`,
    introspection: `${origin}${paths.introspection}`,
  } as const;
}
