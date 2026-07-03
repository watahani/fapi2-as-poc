/**
 * Pushed Authorization Request endpoint (RFC 9126; FAPI2 5.3.2.2(2)(4)).
 * Thin handler: client authentication + domain delegation; protocol logic
 * lives in src/domain/par.ts / client-auth.ts.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { endpointPaths } from "../config.js";
import { authenticateClient } from "../domain/client-auth.js";
import { invalidRequest } from "../domain/errors.js";
import { pushAuthorizationRequest } from "../domain/par.js";
import type { EndpointDeps } from "./index.js";

export function registerPar(app: FastifyInstance, deps: EndpointDeps): void {
  const path = endpointPaths(deps.config).par;

  app.post(path, async (req: FastifyRequest, reply: FastifyReply) => {
    // RFC 9126 §2.3: per-source rate limiting → 429. Client identity is not
    // authenticated yet, so the (trustProxy-resolved) address is the key.
    if (!deps.rateLimiter.allow(req.ip)) {
      return reply
        .headers({ "cache-control": "no-store" })
        .code(429)
        .send({ error: "invalid_request", error_description: "too many requests" });
    }
    // Media types are case-insensitive (RFC 9110 §8.3.1).
    if (!req.headers["content-type"]?.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
      throw invalidRequest("content-type must be application/x-www-form-urlencoded [RFC9126 §2]");
    }
    const body = (req.body ?? {}) as Record<string, unknown>;

    // §2.1 step 1: authenticate exactly as at the token endpoint
    // (private_key_jwt; FAPI2 5.3.2.2(4)).
    const client = await authenticateClient(
      { body, authorizationHeader: req.headers.authorization },
      deps,
    );

    const result = await pushAuthorizationRequest(body, client, deps);
    req.log.info(
      { audit: "par", clientId: client.clientId, expiresIn: result.expires_in },
      "pushed authorization request accepted",
    );
    // §2.2: 201 Created, JSON, uncacheable.
    return reply
      .headers({ "cache-control": "no-cache, no-store" })
      .code(201)
      .send(result);
  });

  // RFC 9126 §2.3: only POST is defined — anything else is 405.
  app.route({
    method: ["GET", "PUT", "DELETE", "PATCH", "OPTIONS"],
    url: path,
    handler: async (_req, reply) =>
      reply
        .header("allow", "POST")
        .code(405)
        .send({ error: "invalid_request", error_description: "method not allowed [RFC9126 §2.3]" }),
  });
}
