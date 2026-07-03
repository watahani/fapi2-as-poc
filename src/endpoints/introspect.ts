/**
 * Token introspection endpoint (RFC 7662). Client-authenticated; a client may
 * introspect only the tokens it owns. `active` is true only after every state
 * check passes (expiry, revocation, signature via resolveToken); an inactive
 * or foreign token discloses nothing beyond active:false (§2.2 / §4).
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { endpointPaths } from "../config.js";
import { authenticateClient } from "../domain/client-auth.js";
import { invalidRequest } from "../domain/errors.js";
import { resolveToken } from "../domain/token-lookup.js";
import type { EndpointDeps } from "./index.js";

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v !== "" ? v : undefined;

export function registerIntrospect(app: FastifyInstance, deps: EndpointDeps): void {
  const path = endpointPaths(deps.config).introspection;

  app.post(path, async (req: FastifyRequest, reply: FastifyReply) => {
    if (!deps.rateLimiter.allow(req.ip)) {
      return reply.headers({ "cache-control": "no-store" }).code(429).send({
        error: "invalid_request",
        error_description: "too many requests",
      });
    }
    if (!req.headers["content-type"]?.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
      throw invalidRequest("content-type must be application/x-www-form-urlencoded [RFC7662 §2.1]");
    }
    const body = (req.body ?? {}) as Record<string, unknown>;

    const client = await authenticateClient(
      { body, authorizationHeader: req.headers.authorization },
      deps,
    );

    const token = str(body.token);
    if (!token) throw invalidRequest("token is required [RFC7662 §2.1]");

    const inactive = () => reply.headers({ "cache-control": "no-store" }).send({ active: false });

    const resolved = await resolveToken(token, str(body.token_type_hint), deps);
    // Foreign or unknown token → active:false, no disclosure (§2.2 / §4).
    if (!resolved || resolved.record.clientId !== client.clientId) return inactive();

    const now = Date.now();
    if (resolved.kind === "refresh_token") {
      const r = resolved.record;
      if (r.revokedAt !== null || r.expiresAt.getTime() <= now) return inactive();
      return reply.headers({ "cache-control": "no-store" }).send({
        active: true,
        token_type: "refresh_token",
        client_id: r.clientId,
        scope: r.scope,
        exp: Math.floor(r.expiresAt.getTime() / 1000),
        iss: deps.config.issuer,
      });
    }

    const a = resolved.record;
    if (a.revokedAt !== null || a.expiresAt.getTime() <= now) return inactive();
    return reply.headers({ "cache-control": "no-store" }).send({
      active: true,
      // RFC 9449 §6.2: DPoP token type ONLY for DPoP-bound tokens (all ATs in
      // this profile are, but stay correct if a Bearer token ever exists).
      token_type: a.cnfJkt ? "DPoP" : "Bearer",
      scope: a.scope,
      client_id: a.clientId,
      sub: a.subject,
      aud: deps.config.accessTokenAudience,
      iss: deps.config.issuer,
      exp: Math.floor(a.expiresAt.getTime() / 1000),
      jti: a.jti,
      ...(a.cnfJkt ? { cnf: { jkt: a.cnfJkt } } : {}),
    });
  });
}
