/**
 * Token revocation endpoint (RFC 7009). Client-authenticated; revokes a
 * refresh or access token the caller owns. Per §2.2 an invalid/unknown token
 * still returns 200; to avoid an ownership oracle, a token belonging to a
 * different client is treated the same (no-op 200) rather than disclosed.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { endpointPaths } from "../config.js";
import { authenticateClient } from "../domain/client-auth.js";
import { invalidRequest } from "../domain/errors.js";
import { resolveToken } from "../domain/token-lookup.js";
import type { EndpointDeps } from "./index.js";

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v !== "" ? v : undefined;

export function registerRevoke(app: FastifyInstance, deps: EndpointDeps): void {
  const path = endpointPaths(deps.config).revocation;

  app.post(path, async (req: FastifyRequest, reply: FastifyReply) => {
    if (!deps.rateLimiter.allow(req.ip)) {
      return reply.headers({ "cache-control": "no-store" }).code(429).send({
        error: "invalid_request",
        error_description: "too many requests",
      });
    }
    if (!req.headers["content-type"]?.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
      throw invalidRequest("content-type must be application/x-www-form-urlencoded [RFC7009 §2.1]");
    }
    const body = (req.body ?? {}) as Record<string, unknown>;

    // §2/§2.1: authenticate the client before acting on request contents.
    const client = await authenticateClient(
      { body, authorizationHeader: req.headers.authorization },
      deps,
    );

    const token = str(body.token);
    if (!token) throw invalidRequest("token is required [RFC7009 §2.1]");

    // §2.1: an unrecognised token_type_hint is IGNORED (the server extends its
    // search across all supported token types), not an error.
    const rawHint = str(body.token_type_hint);
    const hint = rawHint === "access_token" || rawHint === "refresh_token" ? rawHint : undefined;

    const resolved = await resolveToken(token, hint, deps);
    const now = new Date();
    // Only revoke a token the authenticated client owns (REV-3); unknown /
    // other-client tokens fall through to the uniform 200 (§2.2).
    if (resolved && resolved.record.clientId === client.clientId) {
      if (resolved.kind === "refresh_token") {
        await deps.storage.refreshTokens.revoke(resolved.record.tokenHash, now);
        // §2.2: revoking a refresh token cascades to the grant's access tokens.
        await deps.storage.accessTokens.revokeByGrant(resolved.record.grantId, now);
      } else {
        await deps.storage.accessTokens.revoke(resolved.record.jti, now);
      }
      req.log.info(
        { audit: "revoke", clientId: client.clientId, kind: resolved.kind },
        "token revoked",
      );
    }

    // §2.2: 200 regardless of whether a token was actually revoked.
    return reply.headers({ "cache-control": "no-store" }).code(200).send();
  });
}
