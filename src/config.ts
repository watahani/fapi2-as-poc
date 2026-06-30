/**
 * Centralised configuration loaded from the environment.
 * Single source of truth for runtime config; validated with zod.
 */
import { z } from "zod";

const schema = z.object({
  PORT: z.coerce.number().int().positive().default(3000),
  ISSUER: z.string().url().default("https://localhost:3000"),
  LOG_LEVEL: z.string().default("info"),
  DATABASE_URL: z
    .string()
    .default("postgresql://authserver:devpassword@localhost:5432/authserver"),
  PDP_KIND: z.enum(["mock", "authzen-http"]).default("mock"),
  PDP_AUTHZEN_URL: z.string().default("http://localhost:8080/access/v1/evaluation"),
  PDP_AUTHZEN_TOKEN: z.string().default(""),
  // "true" enables TLS to PostgreSQL with certificate verification.
  DATABASE_SSL: z.string().default("false"),
  // Optional cache layer (added only when needed; empty = disabled).
  REDIS_URL: z.string().default(""),
  // Authentication delegation (phase 2). Empty = built-in dev interaction.
  EXTERNAL_IDP_URL: z.string().default(""),
});

export type AppConfig = Readonly<{
  port: number;
  issuer: string;
  logLevel: string;
  databaseUrl: string;
  databaseSsl: boolean;
  pdp: Readonly<{ kind: "mock" | "authzen-http"; authzenUrl: string; authzenToken: string }>;
  redisUrl: string;
  externalIdpUrl: string;
}>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = schema.parse(env);

  // Fail closed in production: never ship allow-all authZ or dev defaults.
  if ((env.NODE_ENV ?? "") === "production") {
    const problems: string[] = [];
    if (parsed.PDP_KIND === "mock") {
      problems.push("PDP_KIND must not be 'mock' (allow-all) in production");
    }
    if (/localhost|127\.0\.0\.1/.test(parsed.ISSUER)) {
      problems.push("ISSUER must not be localhost in production");
    }
    if (parsed.DATABASE_URL.includes("devpassword") || parsed.DATABASE_URL.includes("@localhost")) {
      problems.push("DATABASE_URL must be configured (not the built-in dev default) in production");
    }
    if (problems.length > 0) {
      throw new Error(`insecure production config: ${problems.join("; ")}`);
    }
  }

  return {
    port: parsed.PORT,
    issuer: parsed.ISSUER,
    logLevel: parsed.LOG_LEVEL,
    databaseUrl: parsed.DATABASE_URL,
    databaseSsl: parsed.DATABASE_SSL === "true",
    pdp: {
      kind: parsed.PDP_KIND,
      authzenUrl: parsed.PDP_AUTHZEN_URL,
      authzenToken: parsed.PDP_AUTHZEN_TOKEN,
    },
    redisUrl: parsed.REDIS_URL,
    externalIdpUrl: parsed.EXTERNAL_IDP_URL,
  };
}
